from __future__ import print_function

import os
import sys
import re
import atexit
from signal import signal, SIGABRT, SIGINT, SIGTERM
import logging
import webbrowser
try:
    from shlex import quote
except ImportError:
    from pipes import quote

from pexpect import pxssh

from .version import __version__
from .utils import (join_cmd, check_dns, try_quit_xquartz, check_port_occupied)
from .pysectools import (zero, Pinentry, PINENTRY_PATH)
from .config_manager import (JO2_DEFAULTS, CFG_SEARCH_LOCATIONS, generate_config, ConfigManager)

SRUN_CALL_FORMAT = "srun -t {time} --mem {mem} -c {cores} --pty -p interactive --x11 /bin/bash"

# patterns to search for in ssh
SITE_PATTERN_FORMAT = "\s(https?://((localhost)|(127\.0\.0\.1)):{}[\w\-./%?=]+)\s"  # {} formatted with jupyter port
PASSWORD_PATTERN = re.compile(b"[\w-]+@[\w-]+'s password: ")  # e.g. "user@compute-e-16-175's password: "
PASSWORD_REQUEST_PATTERN = re.compile(b"[\w-]+@[\w-]+'s password: ")  # e.g. "user@compute-e-16-175's password: "

if hasattr(sys.stdout, 'buffer'):
    STDOUT_BUFFER = sys.stdout.buffer
else:
    STDOUT_BUFFER = sys.stdout


class CustomSSH(pxssh.pxssh):
    def login(self, server, username, password='', *args, **kwargs):
        """Login to an SSH server while checking the DNS, silencing logs,
        and suppressing the traceback for pxssh exceptions (such as incorrect password errors).
        :return: True if login is successful
        """
        logger = logging.getLogger(__name__)
        try:
            logger.debug("RUN: ssh {}@{}".format(username, server))
            dns_err, host = check_dns(server)
            if dns_err == 1:
                logger.debug("RUN: ssh {}@{}".format(username, host))
            elif dns_err == 2:
                logger.error("Unable to resolve server.")
                return False
            self.force_password = True
            self.silence_logs()
            return super(CustomSSH, self).login(host, username, password, *args, **kwargs)
        except pxssh.ExceptionPxssh as err:
            logger.error("pxssh error: {}".format(err))
            return False

    def silence_logs(self):
        """Prevent printing into any logfile.
        :return: previous logfile, logfile_read, logfile_send"""
        logfile, logfile_read, logfile_send = self.logfile, self.logfile_read, self.logfile_send
        self.logfile, self.logfile_read, self.logfile_send = None, None, None
        return logfile, logfile_read, logfile_send

    def sendline(self, s='', silence=True):
        """Send s, and log to logger.debug() if silence == False"""
        if not silence:
            logger = logging.getLogger(__name__)
            logger.debug("SEND: {}".format(s))
        return super(CustomSSH, self).sendline(s)

    def sendlineprompt(self, s='', timeout=-1, silence=True, check_exit_status=False):
        """Send s with sendline and then prompt() once.
        :param s: the string to send
        :param timeout: number of seconds to wait for prompt; use default if -1
        :param silence: silence printing of s to debug log
        :param check_exit_status: check the exit status and print a warning if the command exited with an error
        :return: output of sendline(), output of prompt()
        """
        value = self.sendline(s, silence)
        prompt = self.prompt(timeout)
        if check_exit_status and not silence:
            exit_code = self.get_exit_code()
            exit_message = self.before.split(b'\n')[-2].strip().decode()
            if exit_code > 0:
                logger = logging.getLogger(__name__)
                logger.warning("ERROR: in: {0}\n       code {1}: {2}".format(s, exit_code, exit_message))
        return value, prompt

    def sendpass(self, password, restore_logs=False):
        """Silence all logfiles and send password as a line.
        :param password: The password
        :param restore_logs: Restore the previous logfiles after sending the password
        """
        logfile, logfile_read, logfile_send = self.silence_logs()
        return_val = self.sendline(password, silence=True)
        if restore_logs:
            self.logfile, self.logfile_read, self.logfile_send = logfile, logfile_read, logfile_send
        return return_val

    def get_exit_code(self):
        """Get the exit code of the previous command.
        Maintains the `self.before`, `self.match`, and `self.after` variables.
        :return: The exit code as an int
        """
        before = self.before
        match = self.match
        after = self.after
        self.sendline("echo $?", silence=True)
        self.prompt()
        exit_code = int(self.before.split(b'\n')[1].strip())
        self.before = before
        self.match = match
        self.after = after
        return exit_code

    def digest_all_prompts(self, timeout=0.5):
        """Digest all prompts until there is a delay of <timeout>."""
        if timeout == -1:
            timeout = self.timeout
        while self.prompt(timeout):
            pass


class FilteredOut(object):
    def __init__(self, txtctrl, by):
        self.txtctrl = txtctrl
        self.by = by

    def write(self, bytestr):
        try:
            if bytestr[:len(self.by)] == self.by:
                self.txtctrl.write(bytestr)
        except IndexError:
            pass

    def flush(self):
        self.txtctrl.flush()

    def exit_on_find(self, bytestr):
        if self.by in bytestr:
            sys.exit(0)
        return bytestr


class JupyterO2Exception(Exception):
    pass


class JupyterO2Error(JupyterO2Exception):
    pass


class JupyterO2(object):
    def __init__(
            self,
            config,
            user=JO2_DEFAULTS.get("DEFAULT_USER"),
            host=JO2_DEFAULTS.get("DEFAULT_HOST"),
            subcommand=JO2_DEFAULTS.get("DEFAULT_JP_SUBCOMMAND"),
            jp_port=JO2_DEFAULTS.get("DEFAULT_JP_PORT"),
            port_retries=int(JO2_DEFAULTS.get("PORT_RETRIES")),
            jp_time=JO2_DEFAULTS.get("DEFAULT_JP_TIME"),
            jp_mem=JO2_DEFAULTS.get("DEFAULT_JP_MEM"),
            jp_cores=JO2_DEFAULTS.get("DEFAULT_JP_CORES"),
            keepalive=False,
            keepxquartz=False,
            forcegetpass=JO2_DEFAULTS.get("FORCE_GETPASS"),
            forwardx11trusted=False,
    ):
        self.logger = logging.getLogger(__name__)

        self.user = user
        self.host = host
        self.subcommand = subcommand
        self.keep_alive = keepalive
        self.keep_xquartz = keepxquartz

        module_load_call = config.get('Settings', 'MODULE_LOAD_CALL')
        source_jupyter_call = config.get('Settings', 'SOURCE_JUPYTER_CALL')
        init_jupyter_commands = config.get('Settings', 'INIT_JUPYTER_COMMANDS')
        jp_call_format = config.get('Settings', 'RUN_JUPYTER_CALL_FORMAT')

        # find an open port starting with the supplied port
        success = False
        for port in range(jp_port, jp_port + port_retries + 1):
            port_occupied = check_port_occupied(port)
            if port_occupied:
                self.logger.debug("Port {0} is not available, error {1}: {2}".format(
                    port, port_occupied.errno, port_occupied.strerror))
            else:
                self.logger.debug("Port {} is available, using for Jupyter-O2.".format(port))
                self.jp_port = port
                success = True
                break
        if not success:
            self.logger.error("Port {0} and the next {1} ports are already occupied.".format(jp_port, port_retries))
            raise JupyterO2Error("Could not find an available port.")
        self.logger.debug("")

        self.srun_call = SRUN_CALL_FORMAT.format(
            time=quote(jp_time),
            mem=quote(jp_mem),
            cores=jp_cores
        )

        self.init_jupyter_commands = []
        if module_load_call:
            self.init_jupyter_commands.append(join_cmd("module load", module_load_call))
        if source_jupyter_call:
            self.init_jupyter_commands.append(join_cmd("source", source_jupyter_call))
        if init_jupyter_commands:
            self.init_jupyter_commands.extend(init_jupyter_commands.strip().split('\n'))
        self.logger.debug("\n    ".join(["Will initialize Jupyter with commands:"] + self.init_jupyter_commands) + "\n")

        self.jp_call = jp_call_format.format(
            subcommand=quote(subcommand),
            port=self.jp_port
        )
        self.logger.debug("Will run Jupyter with command:\n    {}\n".format(self.jp_call))

        self.__o2_pass = ""
        self._pinentry = Pinentry(pinentry_path=PINENTRY_PATH, fallback_to_getpass=True, force_getpass=forcegetpass)

        login_ssh_options = {
            "ForwardX11": "yes",
            "LocalForward": "{} 127.0.0.1:{}".format(jp_port, jp_port),
            "PubkeyAuthentication": "no"
        }
        if forwardx11trusted:
            login_ssh_options["ForwardX11Trusted"] = "yes"

        self._login_ssh = CustomSSH(timeout=60, ignore_sighup=False, options=login_ssh_options)

        self._second_ssh = CustomSSH(timeout=10, ignore_sighup=False, options={"PubkeyAuthentication": "no"})

        # perform close() on exit or interrupt
        atexit.register(self.close)
        self.flag_exit = False
        for sig in (SIGABRT, SIGINT, SIGTERM):
            signal(sig, self.term)

    def run(self):
        """Run the standard JupyterO2 sequence"""
        self.ask_for_pin()
        if self.connect() or self.keep_alive:
            self.logger.info("Starting pexpect interactive mode.")
            self.interact()

    def ask_for_pin(self):
        """Prompt for an O2 password"""
        self.__o2_pass = self._pinentry.ask(
            prompt="Enter your passphrase: ",
            description="Connect to O2 server for jupyter {}".format(self.subcommand),
            error="No password entered",
            validator=lambda x: x is not None and len(x) > 0
        )
        self._pinentry.close()

    def connect(self):
        """Connect to Jupyter

        First SSH into an interactive node and run jupyter.
        Then SSH into that node to set up forwarding.
        Finally, open the jupyter notebook page in the browser.

        :return: True if connection is successful
        """
        # start login ssh
        self.logger.info("Connecting to {}@{}".format(self.user, self.host))
        if not self._login_ssh.login(self.host, self.user, self.__o2_pass):
            return False
        self.logger.info("Connected.")

        # get the login hostname
        self._login_ssh.sendlineprompt("hostname")
        jp_login_host = self._login_ssh.before.decode('utf-8').strip().split('\n')[1]
        self.logger.info("Hostname: {}\n".format(jp_login_host))

        # enter an interactive session
        self.logger.info("Starting an interactive session.")
        self._login_ssh.PROMPT = PASSWORD_REQUEST_PATTERN
        self._login_ssh.logfile_read = FilteredOut(STDOUT_BUFFER, b'srun:')
        if not self._login_ssh.sendlineprompt(self.srun_call, silence=False)[1]:
            self.logger.error(
                "The timeout ({}) was reached without receiving a password request."
                .format(self._login_ssh.timeout))
            return False
        self._login_ssh.sendpass(self.__o2_pass)

        # within interactive session: get the name of the interactive node
        self._login_ssh.PROMPT = self._login_ssh.UNIQUE_PROMPT
        self._login_ssh.sendlineprompt("unset PROMPT_COMMAND; PS1='[PEXPECT]\$ '")
        self._login_ssh.sendlineprompt("hostname | sed 's/\..*//'")
        jp_interactive_host = self._login_ssh.before.decode('utf-8').strip().split('\n')[1]
        self.logger.info("Interactive session started.")
        self.logger.info("Node: {}\n".format(jp_interactive_host))

        # start jupyter
        self.logger.info("Starting Jupyter {}.".format(self.subcommand))
        for command in self.init_jupyter_commands:
            self._login_ssh.sendlineprompt(command, silence=False, check_exit_status=True)
        self._login_ssh.sendline(self.jp_call, silence=False)
        self._login_ssh.logfile_read = STDOUT_BUFFER

        # get the address jupyter is running at
        site_pat = re.compile(SITE_PATTERN_FORMAT.format(self.jp_port).encode('utf-8'))
        self._login_ssh.PROMPT = site_pat
        if not self._login_ssh.prompt():  # timed out; failed to launch jupyter
            self.logger.error("Failed to launch jupyter. (timed out, {})".format(self._login_ssh.timeout))
            return False
        jp_site = self._login_ssh.after.decode('utf-8').strip()
        self.logger.info("Jupyter {} started.".format(self.subcommand))

        # log in to the second ssh
        self.logger.info("\nStarting a second connection to the login node.")
        if not self._second_ssh.login(jp_login_host, self.user, self.__o2_pass):
            return False
        self.logger.info("Connected.")

        # ssh into the running interactive node
        self.logger.info("Connecting to the interactive node.")
        jp_interactive_command = "ssh -N -L {0}:127.0.0.1:{0} {1}".format(self.jp_port, jp_interactive_host)
        self._second_ssh.PROMPT = PASSWORD_REQUEST_PATTERN
        if not self._second_ssh.sendlineprompt(jp_interactive_command, silence=False)[1]:
            self.logger.error("The timeout ({}) was reached.".format(self._second_ssh.timeout))
            return False
        self._second_ssh.sendpass(self.__o2_pass)
        zero(self.__o2_pass)  # password is not needed anymore
        self.__o2_pass = None
        self._second_ssh.logfile_read = STDOUT_BUFFER  # print any errors/output from self.__second_ssh to stdout
        self.logger.info("Connected.")

        # open Jupyter in browser
        print("\nJupyter is ready! Access at:\n{}\nOpening in browser...\n".format(jp_site))
        try:
            webbrowser.open(jp_site, new=2)
        except webbrowser.Error as error:
            self.logger.error("Error: {}\nPlease open the Jupyter page manually.".format(error))

        # quit XQuartz because the application is not necessary to keep the connection open.
        if not self.keep_xquartz:
            try_quit_xquartz()

        return True

    def interact(self):
        """Keep the ssh session alive and allow input such as Ctrl-C to close Jupyter."""
        self._login_ssh.silence_logs()
        if self.keep_alive:  # exit when you log out of the login shell
            interact_filter = FilteredOut(None, b'[PEXPECT]$ logout')
            self._login_ssh.interact(output_filter=interact_filter.exit_on_find)
        else:  # exit when jupyter exits and [PEXPECT]$ appears
            interact_filter = FilteredOut(None, b'[PEXPECT]$ ')
            self._login_ssh.interact(output_filter=interact_filter.exit_on_find)

    def close(self, cprint=print, *__):
        """Close JupyterO2.
        :param cprint: allows printing to be disabled if necessary using `cprint=lambda x, end=None, flush=None: None`
        """
        def _cprint(*args, **kwargs):
            if sys.version_info[:2] < (3, 3):
                kwargs.pop('flush', None)
            cprint(*args, **kwargs)
        _cprint("Cleaning up\r\n", end="", flush=True)
        zero(self.__o2_pass)
        self._pinentry.close()
        if not self._login_ssh.closed:
            _cprint("Closing login_ssh\n", end="", flush=True)
            self._login_ssh.close(force=True)
        if not self._second_ssh.closed:
            _cprint("Closing second_ssh\n", end="", flush=True)
            self._second_ssh.close(force=True)

    def term(self, *__):
        """Terminate JupyterO2 and exit."""
        if not self.flag_exit:
            self.flag_exit = True
            try:
                self.close()
            except RuntimeError:  # printing from signal can cause RuntimeError: reentrant call
                self.close(cprint=lambda x, end=None, flush=None: None)
            sys.stdout.close()
            sys.stderr.close()
            sys.stdin.close()
            os.closerange(0, 3)
            os._exit(1)


def main():
    # load the config file
    config_mgr = ConfigManager()
    cfg_locations = config_mgr.read()
    config = config_mgr.get_config()

    # parse the command line arguments
    pargs = config_mgr.get_arg_parser().parse_args()
    pargs = vars(pargs)

    # print the current version and exit
    if pargs.pop('version'):
        print(__version__)
        return 0

    # generate the config file and exit
    do_gen_config = pargs.pop('generate_config')
    if do_gen_config is not None:
        cfg_path = generate_config(do_gen_config)
        print('Generated config file at:\n    {}'.format(cfg_path))
        return 0

    # print the paths where config files are located, in descending order of precedence, and exit
    if pargs.pop('paths'):
        print('\n    '.join(["Searching for config file in:"] + CFG_SEARCH_LOCATIONS[::-1]))
        print('\n    '.join(["Found config file in:"] + cfg_locations[::-1]))
        return 0

    # configure the logging level
    logging.basicConfig(level=logging.INFO, format="%(msg)s")
    if pargs.pop('verbose'):
        logging.getLogger().setLevel(logging.DEBUG)  # set root logger level

    logger = logging.getLogger(__name__)

    if not cfg_locations:
        logger.warning("Config file could not be read. Using internal defaults.")
    else:
        logger.debug("Config file(s) read from (in decreasing priority):\n{}\n"
                     .format('\n'.join(cfg_locations[::-1])))

    if not pargs['subcommand']:
        default_jp_subcommand = config.get('Defaults', 'DEFAULT_JP_SUBCOMMAND')
        # # removed error message so that program will use the default subcommand
        # JO2_ARG_PARSER.error("the following arguments are required: subcommand")
        logger.warning("Jupyter subcommand not provided. Using default: {}".format(default_jp_subcommand))
        pargs['subcommand'] = default_jp_subcommand

    # start Jupyter-O2
    logger.debug(
        "\n ".join(
            ["Running Jupyter-O2 with options:"] +
            [
                " " * (max(map(len, pargs.keys())) - len(pair[0])) +
                ": ".join(str(item) for item in pair) for pair in pargs.items()
            ]
        ) +
        "\n"
    )
    try:
        jupyter_o2_runner = JupyterO2(config, **pargs)
        jupyter_o2_runner.run()
    except JupyterO2Exception as err:
        logger.error("{0}: {1}".format(err.__class__.__name__, err))
        return 1
