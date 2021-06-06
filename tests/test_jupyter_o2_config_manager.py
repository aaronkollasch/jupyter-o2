import os
from jupyter_o2.config_manager import generate_config_file, CFG_FILENAME


class TestConfigManager:
    def test_generate_config(self, tmpdir):
        """
        generate_config_file creates a config file at config_dir
        with file name from CFG_FILENAME
        """
        assert isinstance(generate_config_file(config_dir=tmpdir), str)
        assert os.path.exists(tmpdir / CFG_FILENAME)
