import os
import sys
from errno import EEXIST
try:
    from ConfigParser import SafeConfigParser as ConfigParser
except ImportError:
    from configparser import ConfigParser
import argparse

DNS_SERVER_GROUPS = [  # dns servers that have entries for loginXX.o2.rc.hms.harvard.edu
    ["134.174.17.6", "134.174.141.2"],  # HMS nameservers
    ["128.103.1.1", "128.103.201.100", "128.103.200.101"],  # HU nameservers
]
# test that you can access the login nodes (on macs) with nslookup login01.o2.rc.hms.harvard.edu <DNS>

JO2_DEFAULTS = {
    "DEFAULT_USER": "",
    "DEFAULT_HOST": "o2.hms.harvard.edu",
    "DEFAULT_JP_PORT": 8887,
    "DEFAULT_JP_TIME": "0-12:00",
    "DEFAULT_JP_MEM": "1G",
    "DEFAULT_JP_CORES": 1,
    "DEFAULT_JP_SUBCOMMAND": "notebook",

    "MODULE_LOAD_CALL": "",
    "SOURCE_JUPYTER_CALL": "",
    "INIT_JUPYTER_COMMANDS": "",
    "RUN_JUPYTER_CALL_FORMAT": "jupyter {subcommand} --port={port} --no-browser",
    "PORT_RETRIES": 10,
    "FORCE_GETPASS": False,

    "USE_INTERNAL_INTERACTIVE_SESSION": True,
    "INTERACTIVE_CALL_FORMAT": "srun -t {time} --mem {mem} -c {cores} --pty -p interactive --x11 /bin/bash",
    "START_INTERACTIVE_SESSION_TIMEOUT": -1,
    "INTERACTIVE_REQUIRES_PASSWORD": False,
    "INTERNAL_SSH_REQUIRES_PASSWORD": False,
    "PASSWORD_REQUEST_PATTERN": "[\w-]+@[\w-]+'s password: ",
    "DNS_SERVER_GROUPS": DNS_SERVER_GROUPS,
}
JO2_DEFAULTS_STR = {key: str(value) for key, value in JO2_DEFAULTS.items()}

CFG_FILENAME = "jupyter-o2.cfg"
CFG_DIR = "jupyter-o2"

CFG_SEARCH_LOCATIONS = [                                        # In order of increasing priority:
    os.path.join("/etc", CFG_DIR, CFG_FILENAME),                # /etc/jupyter-o2/jupyter-o2.cfg
    os.path.join("/usr/local/etc", CFG_DIR, CFG_FILENAME),      # /usr/local/etc/jupyter-o2/jupyter-o2.cfg
    os.path.join(sys.prefix, "etc", CFG_DIR, CFG_FILENAME),     # etc/jupyter-o2/jupyter-o2.cfg
    os.path.join(os.path.expanduser("~"), "." + CFG_FILENAME),  # ~/.jupyter-o2.cfg
    CFG_FILENAME,                                               # ./jupyter-o2.cfg
]


def generate_config_file(config_dir=None):
    """Write the default configuration file. Overwrites any existing config file.
    :param config_dir: The directory to place the config file,
    or None or True to use the default directory.
    :return: The config file location
    """
    from pkg_resources import resource_string

    if config_dir is None or config_dir is True:
        config_dir = os.path.join(sys.prefix, "etc", CFG_DIR)
    elif config_dir is False:
        return

    config_path = os.path.join(config_dir, CFG_FILENAME)

    resource_package = __name__
    resource_path = '/'.join((CFG_FILENAME,))

    # py27-compatible version of os.makedirs(config_dir, exist_ok=True)
    try:
        os.makedirs(config_dir)
    except OSError as e:
        if e.errno != EEXIST:
            raise

    default_config = resource_string(resource_package, resource_path)

    with open(config_path, 'wb') as config_file:
        config_file.write(default_config)

    return config_path


def get_base_arg_parser():
    parser = argparse.ArgumentParser(description='Launch and connect to a Jupyter session on O2')
    parser.add_argument("subcommand", type=str, nargs='?', help="the subcommand to launch (optional)")
    parser.add_argument("-u", "--user", default=JO2_DEFAULTS.get("DEFAULT_USER"), type=str,
                        help="your O2 username")
    parser.add_argument("--host", type=str, default=JO2_DEFAULTS.get("DEFAULT_HOST"),
                        help="host to connect to")
    parser.add_argument("-p", "--port", dest="jp_port", metavar="PORT", type=int,
                        default=JO2_DEFAULTS.get("DEFAULT_JP_PORT"),
                        help="available port on your system")
    parser.add_argument("-t", "--time", dest="jp_time", metavar="TIME", type=str,
                        default=JO2_DEFAULTS.get("DEFAULT_JP_TIME"),
                        help="maximum time for Jupyter session")
    parser.add_argument("-m", "--mem", dest="jp_mem", metavar="MEM", type=str,
                        default=JO2_DEFAULTS.get("DEFAULT_JP_MEM"),
                        help="memory to allocate for Jupyter")
    parser.add_argument("-c", "-n", dest="jp_cores", metavar="CORES", type=int,
                        default=JO2_DEFAULTS.get("DEFAULT_JP_CORES"),
                        help="cores to allocate for Jupyter")
    parser.add_argument("-k", "--keepalive", default=False, action='store_true',
                        help="keep interactive session alive after exiting Jupyter")
    parser.add_argument("--kq", "--keepxquartz", dest="keepxquartz", default=False, action='store_true',
                        help="do not quit XQuartz")
    parser.add_argument("--force-getpass", dest="forcegetpass", action='store_true',
                        default=JO2_DEFAULTS.get("FORCE_GETPASS"),
                        help="use getpass instead of pinentry for password entry")
    parser.add_argument('--no-browser', dest="no_browser", action='store_true',
                        help="run without opening the browser")
    parser.add_argument("-Y", "--ForwardX11Trusted", dest="forwardx11trusted", default=False,
                        action='store_true',
                        help="enable trusted X11 forwarding, equivalent to ssh -Y")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="increase verbosity level")
    parser.add_argument('--version', action='store_true',
                        help="show the current version and exit")
    parser.add_argument('--paths', action='store_true',
                        help="show configuration paths and exit")
    parser.add_argument('--generate-config', action='store_true',
                        help="generate the default configuration file")
    return parser


class ConfigManager(object):
    def __init__(self):
        self.config = ConfigParser(defaults=JO2_DEFAULTS_STR)
        self.config.add_section('Defaults')
        self.config.add_section('Settings')
        self.config.add_section('Remote Environment Settings')
        self.cfg_locations = self.config.read(CFG_SEARCH_LOCATIONS)

    def get_arg_parser(self):
        """Get an arg parser populated with this ConfigManager's defaults."""
        parser = get_base_arg_parser()
        parser.set_defaults(
            user=self.config.get('Defaults', 'DEFAULT_USER'),
            host=self.config.get('Defaults', 'DEFAULT_HOST'),
            jp_port=self.config.getint('Defaults', 'DEFAULT_JP_PORT'),
            jp_time=self.config.get('Defaults', 'DEFAULT_JP_TIME'),
            jp_mem=self.config.get('Defaults', 'DEFAULT_JP_MEM'),
            jp_cores=self.config.getint('Defaults', 'DEFAULT_JP_CORES'),
            forcegetpass=self.config.getboolean('Settings', 'FORCE_GETPASS'),
        )
        return parser
