from jupyter_o2.config_manager import generate_config_file


class TestConfigManager:
    def test_generate_config(self, tmpdir):
        assert isinstance(generate_config_file("/tmp"), str)
