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
        assert check_dns("o2.hms.harvard.edu")[0] in (0, 1), "Could not find O2 in DNS."

    def test_check_port_occupied_rejects_occupied(self):
        check_port_occupied(22)

    def test_check_port_occupied_accepts_unoccupied(self):
        assert (
            check_port_occupied(52138) is False
        ), "Port 52138 is occupied, perhaps just by coincidence."

    def test_join_cmd_rejects_semicolon(self):
        assert join_cmd("ls", "-a; rm -rf /") == "ls '-a;' rm -rf /"

    def test_try_quit_xquartz(self):
        assert try_quit_xquartz() is None
