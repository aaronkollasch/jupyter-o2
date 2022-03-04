from unittest import mock

from jupyter_o2 import ConfigManager
from jupyter_o2.jupyter_o2 import JupyterO2
from tests.test_pysectools import MockStringIO


def load_config():
    # load the config file
    config_mgr = ConfigManager()
    cfg_locations = config_mgr.cfg_locations
    config = config_mgr.config
    return config


class TestJupyterO2:
    @mock.patch("os.isatty")
    @mock.patch("sys.stdout", new=MockStringIO())
    def test_jupyter_o2_init(self, isatty):
        """
        We can initialize JupyterO2()
        """
        isatty.return_value = True
        assert isinstance(JupyterO2(), JupyterO2)

    @mock.patch("os.isatty")
    @mock.patch("sys.stdout", new=MockStringIO())
    def test_jupyter_o2_using_pubkey(self, isatty):
        config: ConfigManager = load_config()
        isatty.return_value = True
        config.set("Remote Environment Settings", "USE_PUBLIC_KEY_AUTHENTICATION", "True")
        # Test that a pubkey is used when set
        jupyter_o2 = JupyterO2(config=config)
        assert jupyter_o2.use_pubkey is True, f"JupyterO2 didn't load use_pubkey from config"
        # Check that pubkey was actually used
        assert "PubkeyAuthentication" in jupyter_o2._login_ssh.options, \
            f"JupyterO2's login_ssh didn't use pubkey, options: {jupyter_o2._login_ssh.options}"
        assert jupyter_o2._login_ssh.options["PubkeyAuthentication"] == "yes", \
            f"JupyterO2's login_ssh didn't use pubkey, options: {jupyter_o2._login_ssh.options}"

        assert "PubkeyAuthentication" in jupyter_o2._second_ssh.options, \
            f"JupyterO2's login_ssh didn't use pubkey, options: {jupyter_o2._login_ssh.options}"
        assert jupyter_o2._second_ssh.options["PubkeyAuthentication"] == "yes", \
            f"JupyterO2's login_ssh didn't use pubkey, options: {jupyter_o2._login_ssh.options}"
