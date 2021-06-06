from unittest import mock
from io import StringIO

from jupyter_o2.pysectools import zero, cmd_exists, Pinentry


class MockStringIO(StringIO):
    def fileno(self, *args, **kwargs):
        return 1


class TestPysectools:
    def test_zero(self):
        """
        zero() replaces string contents with zeros
        """
        s = "This is a test."
        assert zero(s) is True
        assert s == "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    def test_cmd_exists_positive(self):
        """
        cmd_exists() reports that `ls` exists
        """
        assert cmd_exists("ls") is True

    def test_cmd_exists_negative(self):
        """
        cmd_exists() reports that a nonexistent command does not exist
        """
        assert cmd_exists("notacommand_kjnbvc") is False

    @mock.patch("getpass.getpass")
    @mock.patch("os.isatty")
    @mock.patch("sys.stdout", new=MockStringIO())
    def test_ask_with_getpass(self, is_a_tty, get_pass):
        """
        Pinentry returns the getpass return value
        """
        get_pass.return_value = "password"
        is_a_tty.return_value = True
        p = Pinentry(fallback_to_getpass=True, force_getpass=True)
        out = p.ask(
            "This is a test",
            "This is a description",
            "This is an error",
            lambda x: x is not None,
        )
        assert out == "password"
