from __future__ import print_function

import sys
import os
import subprocess
import ctypes
import getpass  # fallback if pinentry is not installed (optional "brew install pinentry" on macs)

if sys.platform.startswith("linux"):
    PINENTRY_PATH = "/usr/bin/pinentry"
elif sys.platform == "darwin":
    PINENTRY_PATH = "/usr/local/bin/pinentry"
else:
    PINENTRY_PATH = "pinentry"


#################################################################
# pin entry and security functions are slightly modified        #
# from pysectools (Greg V <greg@unrelenting.technology>),       #
# which is free for distribution under the terms of the         #
# Do What The Fuck You Want To Public License, Version 2,       #
# as published by Sam Hocevar.                                  #
#                                                               #
# - updated Pinentry for python 3:                              #
#   - uses bytestrings                                          #
#   - flushes stdin after writing                               #
# - removed shell=True from subprocess.call()                   #
# - uses a print function that accepts the flush parameter      #
#################################################################


def zero(s):
    """
    Tries to securely erase a secret string from memory
    (overwrite it with zeros.)

    Only works on CPython.

    Returns True if successful, False otherwise.
    """
    try:
        bufsize = len(s) + 1
        offset = sys.getsizeof(s) - bufsize
        location = id(s) + offset
        ctypes.memset(location, 0, bufsize)
        return True
    except Exception:
        return False


def cmd_exists(cmd):
    return subprocess.call(["type", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0


class PinentryException(Exception):
    pass


class PinentryUnavailableException(PinentryException):
    pass


class PinentryClosedException(PinentryException):
    pass


class PinentryErrorException(PinentryException):
    pass


class Pinentry(object):
    def __init__(self, pinentry_path=PINENTRY_PATH, fallback_to_getpass=True):
        if not cmd_exists(pinentry_path):
            if fallback_to_getpass and os.isatty(sys.stdout.fileno()):
                self._ask = self._ask_with_getpass
                self._close = self._close_getpass
            else:
                raise PinentryUnavailableException()
        else:
            self.process = subprocess.Popen(pinentry_path,
                                            stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT,
                                            close_fds=True)
            self._ask = self._ask_with_pinentry
            self._close = self._close_pinentry
        self._closed = False

    def ask(self,
            prompt="Enter the password: ",
            description=None,
            error="Wrong password!",
            validator=lambda x: x is not None):
        if self._closed:
            raise PinentryClosedException()
        return self._ask(prompt, description, error, validator)

    def close(self):
        self._closed = True
        return self._close()

    @staticmethod
    def _ask_with_getpass(prompt, description, error, validator):
        if description:
            print(description, file=sys.stdout)
            sys.stdout.flush()
        password = None
        while not validator(password):
            if password is not None:
                print(error, file=sys.stderr)
            password = getpass.getpass(prompt)
        return password

    def _close_getpass(self): pass

    def _ask_with_pinentry(self, prompt, description, error, validator):
        self._waitfor("OK")
        env = os.environ.get
        self._comm("OPTION lc-ctype=%s" % env("LC_CTYPE", env("LC_ALL", "en_US.UTF-8")))
        try:
            self._comm("OPTION ttyname=%s" % env("TTY", os.ttyname(sys.stdout.fileno())))
        except Exception:
            pass
        if env('TERM'):
            self._comm("OPTION ttytype=%s" % env("TERM"))
        if prompt:
            self._comm("SETPROMPT %s" % self._esc(prompt))
        if description:
            self._comm("SETDESC %s" % self._esc(description))
        password = None
        while not validator(password):
            if password is not None:
                self._comm("SETERROR %s" % self._esc(error))
            self.process.stdin.write(b"GETPIN\n")
            self.process.stdin.flush()
            try:
                password = self._waitfor("D ", breakat="OK", errat="ERR")
            except PinentryErrorException:
                sys.exit(0)
            if password is not None:
                password = password[2:].replace("\n", "")
        return password

    def _close_pinentry(self):
        return self.process.kill()

    def _waitfor(self, what, breakat=None, errat=None):
        out = ""
        while not out.startswith(what):
            if breakat is not None and out.startswith(breakat):
                break
            elif errat is not None and out.startswith(errat):
                raise PinentryErrorException()
            out = self.process.stdout.readline().decode('utf-8')
        return out

    def _comm(self, x):
        self.process.stdin.write(x.encode('utf-8') + b"\n")
        self.process.stdin.flush()
        self._waitfor("OK")

    @staticmethod
    def _esc(x):
        return x.replace("%", "%25").replace("\n", "%0A")
