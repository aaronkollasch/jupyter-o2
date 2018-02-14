from pbr.version import VersionInfo
from .utils import (
    eprint,
    join_cmd,
    cmd_exists,
    check_dns,
    try_quit_xquartz,
    get_xquartz_open_windows,
    xquartz_is_open,
    quit_xquartz
)
from .pysectools import (
    zero,
    Pinentry,
    PinentryException,
    PinentryUnavailableException,
    PinentryClosedException,
    PinentryErrorException
)
from .jupyter_o2 import main, JupyterO2, JO2_ARG_PARSER

_v = VersionInfo('jupyter-o2').semantic_version()
__version__ = _v.release_string()
version_info = _v.version_tuple()

__author__ = "Aaron Kollasch"
__copyright__ = "Copyright 2017-2018, Aaron Kollasch"
__email__ = "awkollasch@gmail.com"
__status__ = "Production"
