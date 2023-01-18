from dns import resolver
from dns.exception import DNSException

from jupyter_o2.utils import (
    check_dns,
    check_port_occupied,
    join_cmd,
    try_quit_xquartz,
    get_most_recent_version,
    check_for_updates,
)
import jupyter_o2


class TestUtils:
    def test_check_dns(self):
        """
        Search for O2 in DNS.
        """
        assert check_dns("o2.hms.harvard.edu")[0] in (0, 1)

    def test_check_dns_resolver_init_error(self, monkeypatch):
        def resolver_error(*_args, **_kwargs):
            del _args, _kwargs
            raise DNSException

        monkeypatch.setattr(resolver, "Resolver", resolver_error)

        assert check_dns("o2.hms.harvard.edu")[0] == 2

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

    most_recent_version = get_most_recent_version()

    def test_get_most_recent_version(self):
        from pkg_resources import parse_version
        from urllib import request
        import json

        r = request.urlopen("https://pypi.org/pypi/jupyter-o2/json")
        d = json.loads(r.read())
        max_version = max(
            d["releases"].keys(), key=lambda x: parse_version(x), default=None
        )
        assert parse_version(max_version) == parse_version(self.most_recent_version)

    def test_check_version_out_of_date(self, monkeypatch, caplog):
        monkeypatch.setattr(jupyter_o2, "version", "1.0.0")
        most_recent_version = check_for_updates()
        assert most_recent_version is not None

    def test_check_version_up_to_date(self, monkeypatch, caplog):
        monkeypatch.setattr(jupyter_o2, "version", self.most_recent_version)
        most_recent_version = check_for_updates()
        assert most_recent_version is None
