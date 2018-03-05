from __future__ import print_function

import sys
import logging
from time import sleep
import subprocess
import shlex
try:
    from shlex import quote
except ImportError:
    from pipes import quote
import socket

try:
    import dns.resolver
except ImportError:
    dns = None
try:
    from Quartz import CGWindowListCopyWindowInfo, kCGWindowListOptionAll, kCGNullWindowID
    from PyObjCTools import Conversion
    quartz_supported = True
except ImportError:
    quartz_supported = False


def join_cmd(cmd, args_string):
    """Create a bash command by joining cmd and args_string. Resistant to injection within args_string."""
    return ' '.join([cmd] + [quote(item) for item in shlex.split(args_string)])


if dns is not None:
    DNS_SERVER_GROUPS = [  # dns servers that have entries for loginXX.o2.rc.hms.harvard.edu
        dns.resolver.Resolver().nameservers,                    # current nameservers, checked first
        ["134.174.17.6", "134.174.141.2"],                      # HMS nameservers
        ["128.103.1.1", "128.103.201.100", "128.103.200.101"],  # HU nameservers
    ]
    # test that you can access the login nodes with nslookup login01.o2.rc.hms.harvard.edu <DNS>
else:
    DNS_SERVER_GROUPS = None


def check_dns(hostname, dns_groups=DNS_SERVER_GROUPS):
    """Check if hostname is reachable by any group of dns servers.

    :return: tuple of (dns error code, hostname)
    """
    if dns is not None:
        dns_err_code = 0
        for dns_servers in dns_groups:
            try:
                my_resolver = dns.resolver.Resolver()
                my_resolver.nameservers = dns_servers
                if dns_err_code > 0:
                    eprint("Could not resolve domain. Trying with nameservers: {}".format(dns_servers))
                    answer = my_resolver.query(hostname)
                    hostname = answer[0].address
                    dns_err_code = 1
                else:
                    my_resolver.query(hostname)
                break
            except dns.resolver.NXDOMAIN:
                dns_err_code = 2
    else:
        dns_err_code = -1
    if dns_err_code == 1:
        print("Found IP: {}".format(hostname))
    elif dns_err_code == 2:
        eprint("No IP found for {}".format(hostname))
    return dns_err_code, hostname


def check_port_occupied(port, address="127.0.0.1"):
    """Check if a port is occupied by attempting to bind the socket and returning any resulting error.

    :return: socket.error if the port is in use, otherwise False
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((address, port))
    except socket.error as e:
        return e
    finally:
        s.close()
    return False


if sys.version_info[:2] < (3, 3):
    old_print = print
    def print(*args, **kwargs):
        """
        Compatibility print function for python 2.7,
        where print() does not accept the flush parameter.
        """
        flush = kwargs.pop('flush', False)
        old_print(*args, **kwargs)
        if flush:
            file = kwargs.get('file', sys.stdout)
            # Why might file=None? IDK, but it works for print(i, file=None)
            file.flush() if file is not None else sys.stdout.flush()
else:
    old_print = print
    print = print


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def try_quit_xquartz():
    """Quit XQuartz on macs
    First attempts to check if there is a window open in XQuartz, using Quartz (pyobjc-framework-Quartz).
    If Quartz is installed, and there is a window open in XQuartz, it will not quit XQuartz.
    If Quartz is not installed and there is a window open in XQuartz,
        XQuartz open a dialog to ask if you really want to quit it.
    Otherwise XQuartz will silently quit.
    """
    logger = logging.getLogger(__name__)
    if sys.platform != "darwin":
        return
    if not quartz_supported:
        logger.warning("Quitting XQuartz is not supported. Import pyobjc-framework-Quartz with pip.")
    try:
        if not xquartz_is_open():
            return
        print("Quitting XQuartz... ", end='')
        open_windows = get_xquartz_open_windows()
        if open_windows is None:
            pass
        elif not open_windows:
            quit_xquartz()
        else:
            print("\nXQuartz window(s) are open. Not quitting.")
            try:
                logger.debug("Open windows: {}".format(
                    [(window['kCGWindowName'], window['kCGWindowNumber']) for window in open_windows]))
            except KeyError:
                pass
        sleep(0.25)
        if not xquartz_is_open():
            print("Success.")
        else:
            print("Failed to quit.")
    except Exception as error:
        logger.error("Error: {}".format(error.__class__))
        logger.error(error)
        print("Failed to quit XQuartz.")


def get_xquartz_open_windows():
    """
    Get info on all open XQuartz windows.
    Requires pyobjc-framework-Quartz (install with pip)
    :return: a list of open windows as python dictionaries
    """
    if quartz_supported:
        # need to use kCGWindowListOptionAll to include windows that are not currently on screen (e.g. minimized)
        windows = CGWindowListCopyWindowInfo(kCGWindowListOptionAll, kCGNullWindowID)

        # then filter for XQuartz main windows
        open_windows = [window for window in windows if window['kCGWindowOwnerName'] == "XQuartz" and
                        window['kCGWindowLayer'] == 0 and 'kCGWindowName' in window.keys() and
                        window['kCGWindowName'] not in ['', 'X11 Application Menu', 'X11 Preferences']]

        # convert from NSDictionary to python dictionary
        open_windows = Conversion.pythonCollectionFromPropertyList(open_windows)
        return open_windows
    else:
        return None


def xquartz_is_open():
    try:
        proc = subprocess.check_output(["pgrep", "-f", "XQuartz"])
        return len(proc) > 0
    except subprocess.CalledProcessError as error:
        if error.returncode == 1:
            return False  # pgrep returns with exit code 1 if XQuartz is not open
        else:  # syntax error or fatal error
            raise error


def quit_xquartz():
    if sys.platform == "darwin":
        subprocess.call(['osascript', '-e', 'quit app "XQuartz"'])
