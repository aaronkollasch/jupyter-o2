import os
from jupyter_o2.config_manager import generate_config_file, CFG_FILENAME


class TestConfigManager:
    def test_generate_config(self, tmpdir):
        assert isinstance(generate_config_file(tmpdir), str)
        assert os.path.exists(tmpdir / CFG_FILENAME)
