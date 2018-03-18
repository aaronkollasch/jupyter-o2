import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from jupyter_o2.jupyter_o2 import JupyterO2


class TestJupyterO2(unittest.TestCase):
    @mock.patch('os.isatty')
    @mock.patch('sys.stdout.fileno')
    def test_jupyter_o2_init(self, fileno, isatty):
        isatty.return_value = True
        fileno.return_value = 1
        self.assertIsInstance(JupyterO2(), JupyterO2)
