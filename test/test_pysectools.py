import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from jupyter_o2.pysectools import zero, cmd_exists, Pinentry


class TestPysectools(unittest.TestCase):
    def test_zero(self):
        s = "This is a test."
        self.assertTrue(zero(s))
        self.assertEqual(s, '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_cmd_exists(self):
        self.assertTrue(cmd_exists('ls'))

    @mock.patch('getpass.getpass')
    @mock.patch('jupyter_o2.cmd_exists')
    @mock.patch('os.isatty')
    @mock.patch('sys.stdout.fileno')
    def test_ask_with_getpass(self, file_no, is_a_tty, cmd_exists_val, get_pass):
        get_pass.return_value = "password"
        cmd_exists_val.return_value = False
        is_a_tty.return_value = True
        file_no.return_value = 1
        p = Pinentry(fallback_to_getpass=True)
        out = p.ask(
            "This is a test",
            "This is a description",
            "This is an error",
            lambda x: x is not None
        )
        self.assertEqual(out, "password")
