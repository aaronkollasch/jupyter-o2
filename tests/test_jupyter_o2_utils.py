from jupyter_o2.utils import (
    check_dns,
    check_port_occupied,
    join_cmd,
    try_quit_xquartz,
)


class TestUtils:
    def test_check_dns(self):
        """
        Search for O2 in DNS.
        """
        assert check_dns("o2.hms.harvard.edu")[0] in (0, 1)

    def test_check_port_occupied_rejects_occupied(self):
        """
        Port 22 is "occupied" - unavailable for binding
        """
        check_port_occupied(22)

    def test_check_port_occupied_accepts_unoccupied(self):
        """
        check_port_unoccupied shows 52138 as unoccupied
        (unless it is occupied by coincidence)
        """
        assert check_port_occupied(52138) is False

    def test_join_cmd_rejects_semicolon(self):
        """
        join_cmd escapes the semicolon
        """
        assert join_cmd("ls", "-a; rm -rf /") == "ls '-a;' rm -rf /"

    def test_try_quit_xquartz(self):
        """
        try_quit_xquartz does not return an error
        """
        assert try_quit_xquartz() is None
