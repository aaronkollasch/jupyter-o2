import unittest

try:
    from unittest import mock
except ImportError:
    import mock
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

from jupyter_o2.pysectools import zero, cmd_exists, Pinentry


class MockStringIO(StringIO):
    def fileno(self, *args, **kwargs):
        return 1


class TestPysectools(unittest.TestCase):
    def test_zero(self):
        s = "This is a test."
        self.assertTrue(zero(s))
        self.assertEqual(
            s, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )

    def test_cmd_exists_positive(self):
        self.assertTrue(cmd_exists("ls"))

    def test_cmd_exists_negative(self):
        self.assertFalse(cmd_exists("notacommand_kjnbvc"))

    @mock.patch("getpass.getpass")
    @mock.patch("os.isatty")
    @mock.patch("sys.stdout", new=MockStringIO())
    def test_ask_with_getpass(self, is_a_tty, get_pass):
        get_pass.return_value = "password"
        is_a_tty.return_value = True
        p = Pinentry(fallback_to_getpass=True, force_getpass=True)
        out = p.ask(
            "This is a test",
            "This is a description",
            "This is an error",
            lambda x: x is not None,
        )
        self.assertEqual(out, "password")
