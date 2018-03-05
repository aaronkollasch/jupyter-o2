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
    def test_ask_with_getpass(self, getpass):
        p = Pinentry()
        getpass.return_value = "password"
        out = p._ask_with_getpass(
            "This is a test",
            "This is a description",
            "This is an error",
            lambda x: x is not None
        )
        self.assertEqual(out, "password")

