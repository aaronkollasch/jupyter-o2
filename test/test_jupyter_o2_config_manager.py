import unittest

from jupyter_o2.config_manager import generate_config


class TestConfigManager(unittest.TestCase):
    def test_generate_config(self):
        self.assertIsInstance(
            generate_config("/tmp"),
            str
        )
