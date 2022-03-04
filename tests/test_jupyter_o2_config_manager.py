import os
from configparser import ConfigParser

from jupyter_o2.config_manager import (
    generate_config_file,
    CFG_FILENAME,
    ConfigManager,
    JO2_DEFAULTS,
    CFG_SEARCH_LOCATIONS,
)


class TestConfigManager:
    def test_generate_config(self, tmpdir):
        """
        generate_config_file creates a config file at config_dir
        with file name from CFG_FILENAME
        """
        assert isinstance(generate_config_file(config_dir=tmpdir), str)
        assert os.path.exists(tmpdir / CFG_FILENAME)

    def test_load_config_file(self, tmpdir, monkeypatch):
        generate_config_file(config_dir=tmpdir)
        monkeypatch.chdir(
            tmpdir
        )  # Temporarily change working dir, will change back after test

        # Add a user to the config file by replacing the line
        with open(tmpdir / CFG_FILENAME, "r") as fp:
            filedata = fp.read()

        modified = filedata.replace("DEFAULT_USER =", "DEFAULT_USER = mock")
        # print("tmp", modified)

        with open(tmpdir / CFG_FILENAME, "w") as fp:
            fp.write(modified)

        # load the config file
        config_mgr = ConfigManager()
        config = config_mgr.config

        assert (
            config.get("Defaults", "DEFAULT_USER") == "mock"
        ), f"Config file {tmpdir / CFG_FILENAME} not read in correctly"
