import ipaddress

import pytest
from starlette.requests import Request

from app.core import client_ip
from app.core.config import settings


def request(peer, xff=None):
    headers = [(b"x-forwarded-for", xff.encode())] if xff is not None else []
    return Request({"type": "http", "client": (peer, 1234), "headers": headers})


@pytest.fixture
def trust(monkeypatch):
    def _trust(*cidrs):
        monkeypatch.setitem(settings.__dict__, "trusted_proxy_networks",
                            [ipaddress.ip_network(c) for c in cidrs])
    return _trust


def test_no_trusted_proxies_ignores_forwarded_header(trust):
    trust()
    # Regression guard: otherwise any client could claim a new IP per request.
    assert client_ip.get_client_ip(request("198.51.100.1", "1.2.3.4")) == "198.51.100.1"


def test_untrusted_peer_cannot_spoof(trust):
    trust("10.0.0.0/8")
    assert client_ip.get_client_ip(request("198.51.100.1", "1.2.3.4")) == "198.51.100.1"


def test_trusted_proxy_forwards_client(trust):
    trust("10.0.0.0/8")
    assert client_ip.get_client_ip(request("10.0.0.5", "203.0.113.9")) == "203.0.113.9"


def test_client_prepended_values_are_ignored(trust):
    # The client sent "X-Forwarded-For: 1.1.1.1"; our proxy appended the real address.
    trust("10.0.0.0/8")
    assert client_ip.get_client_ip(request("10.0.0.5", "1.1.1.1, 203.0.113.9")) == "203.0.113.9"


def test_multiple_trusted_hops_are_skipped(trust):
    trust("10.0.0.0/8")
    assert client_ip.get_client_ip(request("10.0.0.5", "203.0.113.9, 10.0.0.7")) == "203.0.113.9"


def test_garbage_in_chain_falls_back_to_peer(trust):
    trust("10.0.0.0/8")
    assert client_ip.get_client_ip(request("10.0.0.5", "not-an-ip")) == "10.0.0.5"


def test_trusted_proxy_without_header_uses_peer(trust):
    trust("10.0.0.0/8")
    assert client_ip.get_client_ip(request("10.0.0.5")) == "10.0.0.5"


def test_ipv6(trust):
    trust("fd00::/8")
    assert client_ip.get_client_ip(request("fd00::1", "2001:db8::42")) == "2001:db8::42"
