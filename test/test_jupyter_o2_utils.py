from __future__ import print_function
import unittest

from jupyter_o2.utils import (check_dns, check_port_occupied, print, join_cmd, try_quit_xquartz)


class TestUtils(unittest.TestCase):
    def test_check_dns(self):
        self.assertIn(
            check_dns("o2.hms.harvard.edu")[0],
            (0, 1),
            "Could not find O2 in DNS."
        )

    def test_check_port_occupied(self):
        self.assertIsInstance(check_port_occupied(22), Exception)
        self.assertFalse(check_port_occupied(52138), "Port 52138 is occupied.")

    def test_print(self):
        self.assertIsNone(print("", flush=True, end=""))

    def test_join_cmd(self):
        self.assertEqual(
            join_cmd('ls', '-a; rm -rf /'),
            "ls '-a;' rm -rf /"
        )

    def test_try_quit_xquartz(self):
        self.assertIsNone(try_quit_xquartz())
