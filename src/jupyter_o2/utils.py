import sys
import logging
from time import sleep
import subprocess
import signal
import shlex
import ast

from shlex import quote
import socket


def join_cmd(cmd, args_string):
    """
    Create a bash command by joining cmd and args_string.
    Resistant to injection within args_string.
    """
    return " ".join([cmd] + [quote(item) for item in shlex.split(args_string)])


def check_dns(hostname, dns_groups=None):
    """
    Check if hostname is reachable by any group of dns servers.

    :return: tuple of (dns error code, hostname)
    """
    try:
        from dns.resolver import Resolver, NXDOMAIN
    except ImportError:
        return -1, hostname
    from .config_manager import ConfigManager

    if dns_groups is None:
        dns_server_groups = ast.literal_eval(
            ConfigManager().config.get(
                "Remote Environment Settings", "DNS_SERVER_GROUPS"
            )
        )

        dns_groups = [Resolver().nameservers] + dns_server_groups

    dns_err_code = 0
    for dns_servers in dns_groups:
        try:
            my_resolver = Resolver()
            my_resolver.nameservers = dns_servers
            if dns_err_code > 0:
                print(
                    "Could not resolve domain. "
                    f"Trying with nameservers: {dns_servers}",
                    file=sys.stderr,
                )
                answer = my_resolver.resolve(hostname)
                hostname = answer[0].address
                dns_err_code = 1
            else:
                my_resolver.resolve(hostname)
            break
        except NXDOMAIN:
            dns_err_code = 2
    if dns_err_code == 1:
        print(f"Found IP: {hostname}")
    elif dns_err_code == 2:
        print(f"No IP found for {hostname}", file=sys.stderr)
    return dns_err_code, hostname


def check_port_occupied(port, address="127.0.0.1"):
    """
    Check if a port is occupied by attempting to bind the socket

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


def try_quit_xquartz():
    """
    Quit XQuartz on macs
    First attempts to check if there is a window open in XQuartz,
        using Quartz (pyobjc-framework-Quartz).
    If Quartz is installed, and there is a window open in XQuartz,
        it will not quit XQuartz.
    If Quartz is not installed and there is a window open in XQuartz,
        XQuartz open a dialog to ask if you really want to quit it.
    Otherwise XQuartz will silently quit.
    """
    logger = logging.getLogger(__name__)
    if sys.platform != "darwin":
        return
    try:
        if not xquartz_is_open():
            return
        print("Quitting XQuartz... ", end="")
        open_windows = get_xquartz_open_windows()
        if open_windows is None:
            pass
        elif not open_windows:
            quit_xquartz()
        else:
            print("\nXQuartz window(s) are open. Not quitting.")
            try:
                logger.debug(
                    "Open windows: {}".format(
                        [
                            (window["kCGWindowName"], window["kCGWindowNumber"])
                            for window in open_windows
                        ]
                    )
                )
            except KeyError:
                pass
        sleep(0.25)
        if not xquartz_is_open():
            print("Success.")
        else:
            print("Failed to quit.")
    except Exception as error:
        logger.error(f"Error: {error.__class__}: {error}")
        print("Failed to quit XQuartz.")


def get_xquartz_open_windows():
    """
    Get info on all open XQuartz windows.
    Requires pyobjc-framework-Quartz (install with pip)
    :return: a list of open windows as python dictionaries
    """
    # pyobjc-framework-Quartz can segfault if the wrong version is installed
    logger = logging.getLogger(__name__)
    p = subprocess.Popen([sys.executable, "-c", "import Quartz"])
    p.communicate()
    if p.returncode == -signal.SIGSEGV:
        logger.warning(
            "Import of pyobjc-framework-Quartz failed due to a segmentation fault. "
            "The installed version is incompatible with your system."
        )
        return None

    try:
        from Quartz import (
            CGWindowListCopyWindowInfo,
            kCGWindowListOptionAll,
            kCGNullWindowID,
        )
        from PyObjCTools import Conversion
    except ImportError:
        logger.warning(
            "Import of pyobjc-framework-Quartz failed. Try installing with pip."
        )
        return None
    # need to use kCGWindowListOptionAll to include windows
    # that are not currently on screen (e.g. minimized)
    windows = CGWindowListCopyWindowInfo(kCGWindowListOptionAll, kCGNullWindowID)

    # then filter for XQuartz main windows
    open_windows = [
        window
        for window in windows
        if window["kCGWindowOwnerName"] == "XQuartz"
        and window["kCGWindowLayer"] == 0
        and "kCGWindowName" in window.keys()
        and window["kCGWindowName"]
        not in ["", "X11 Application Menu", "X11 Preferences"]
    ]

    # convert from NSDictionary to python dictionary
    open_windows = Conversion.pythonCollectionFromPropertyList(open_windows)
    return open_windows


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
        subprocess.call(["osascript", "-e", 'quit app "XQuartz"'])
