from unittest import mock

from jupyter_o2.jupyter_o2 import JupyterO2
from tests.test_pysectools import MockStringIO


class TestJupyterO2:
    @mock.patch("os.isatty")
    @mock.patch("sys.stdout", new=MockStringIO())
    def test_jupyter_o2_init(self, isatty):
        isatty.return_value = True
        assert isinstance(JupyterO2(), JupyterO2)
