import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from jupyter_o2.jupyter_o2 import JupyterO2


class TestJupyterO2(unittest.TestCase):
    def test_jupyter_o2_init(self):
        self.assertIsInstance(JupyterO2(), JupyterO2)
