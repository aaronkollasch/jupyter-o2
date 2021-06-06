import unittest
try:
    from unittest import mock
except ImportError:
    import mock
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

from jupyter_o2.jupyter_o2 import JupyterO2
from tests.test_pysectools import MockStringIO


class TestJupyterO2(unittest.TestCase):
    @mock.patch('os.isatty')
    @mock.patch('sys.stdout', new=MockStringIO())
    def test_jupyter_o2_init(self, isatty):
        isatty.return_value = True
        self.assertIsInstance(JupyterO2(), JupyterO2)
