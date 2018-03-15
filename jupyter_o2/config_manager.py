import os
import sys
import pkg_resources
from errno import EEXIST
try:
    from ConfigParser import SafeConfigParser as ConfigParser
except ImportError:
    from configparser import ConfigParser

JO2_DEFAULTS = {
    "DEFAULT_USER": "",
    "DEFAULT_HOST": "o2.hms.harvard.edu",
    "DEFAULT_JP_PORT": "8887",
    "DEFAULT_JP_TIME": "0-12:00",
    "DEFAULT_JP_MEM": "1G",
    "DEFAULT_JP_CORES": "1",
    "DEFAULT_JP_SUBCOMMAND": "notebook",
    "MODULE_LOAD_CALL": "",
    "SOURCE_JUPYTER_CALL": "",
    "RUN_JUPYTER_CALL_FORMAT": "jupyter {subcommand} --port={port} --browser='none'",
    "PORT_RETRIES": "10",
}

config = ConfigParser(defaults=JO2_DEFAULTS)
config.add_section('Defaults')
config.add_section('Settings')

CFG_FILENAME = "jupyter-o2.cfg"
CFG_DIR = "jupyter-o2"

CFG_SEARCH_LOCATIONS = [                                        # In order of increasing priority:
    os.path.join("/etc", CFG_DIR, CFG_FILENAME),                # /etc/jupyter-o2/jupyter-o2.cfg
    os.path.join("/usr/local/etc", CFG_DIR, CFG_FILENAME),      # /usr/local/etc/jupyter-o2/jupyter-o2.cfg
    os.path.join(sys.prefix, "etc", CFG_DIR, CFG_FILENAME),     # etc/jupyter-o2/jupyter-o2.cfg
    os.path.join(os.path.expanduser("~"), "." + CFG_FILENAME),  # ~/.jupyter-o2.cfg
    CFG_FILENAME,                                               # ./jupyter-o2.cfg
]

CFG_LOCATIONS = config.read(CFG_SEARCH_LOCATIONS)


def generate_config(config_dir=None):
    """
    Write the default configuration file. Overwrites any existing config file.
    :param config_dir: The directory to place the config file,
    or None or a boolean to use the default directory.
    :return: The config file location
    """
    if config_dir is None or isinstance(config_dir, bool):
        config_dir = os.path.join(sys.prefix, "etc", CFG_DIR)

    config_path = os.path.join(config_dir, CFG_FILENAME)

    resource_package = __name__
    resource_path = '/'.join((CFG_FILENAME,))

    # os.makedirs(config_dir, exist_ok=True)
    try:  # py27-compatible version
        os.makedirs(config_dir)
    except OSError as e:
        if e.errno != EEXIST:
            raise

    default_config = pkg_resources.resource_string(resource_package, resource_path)

    with open(config_path, 'wb') as config_file:
        config_file.write(default_config)

    return config_path
