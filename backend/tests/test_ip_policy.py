"""The shared SSRF guard (services/ip_policy.py): which addresses may ever be contacted. Used by ownership checks, scans, uptime checks, the
Nuclei egress proxy, the vulnerability database client and the subdomain lookup. Controlled DNS answers; no live traffic."""
import socket

import pytest

from app.services import ip_policy


@pytest.fixture(autouse=True)
def not_this_server(monkeypatch):
    """The fake DNS below must not also answer the guard's look-up of this computer's own addresses."""
    monkeypatch.setattr(ip_policy, "server_addresses", lambda: set())


def dns(ip):
    return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]


PROHIBITED = ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.1", "172.16.0.1", "100.64.0.1", "0.0.0.0", "192.0.0.8", "192.88.99.1",
              "198.18.0.1", "240.0.0.1", "255.255.255.255", "224.0.0.1",
              "fec0::1", "3fff::1", "5f00::1", "::1", "::", "fc00::1", "fe80::1", "ff02::1", "::ffff:8.8.8.8", "::ffff:127.0.0.1", "64:ff9b::a00:1",
              "2002:0808:0808::1", "2001::1", "2001:db8::1"]


@pytest.mark.parametrize("ip", PROHIBITED)
def test_prohibited_addresses_are_never_resolved_to(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: dns(ip))
    with pytest.raises(ip_policy.Blocked) as refused:
        ip_policy.resolve_public("synthetic.example", 443)
    assert refused.value.code in ("private_or_reserved_address", "cloud_metadata_address")   # refused for the address itself, not by accident
    assert ip_policy.refusal_reason(ip, own=set()) in ("private_or_reserved_address", "cloud_metadata_address")


def test_one_bad_answer_refuses_the_whole_host_no_partial_trust(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: dns("8.8.8.8") + dns("127.0.0.1"))
    with pytest.raises(ip_policy.Blocked):
        ip_policy.resolve_public("synthetic.example", 443)


@pytest.mark.parametrize("ip", ["8.8.8.8", "93.184.216.34", "2001:4860:4860::8888", "2606:4700:4700::1111"])
def test_ordinary_public_addresses_are_accepted(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: dns(ip))
    assert ip_policy.resolve_public("synthetic.example", 443) == [ip]
    assert ip_policy.refusal_reason(ip, own=set()) is None


def test_the_cloud_metadata_address_has_its_own_reason():
    assert ip_policy.refusal_reason("169.254.169.254", own=set()) == "cloud_metadata_address"


def test_this_servers_own_address_is_refused(monkeypatch):
    monkeypatch.setattr(ip_policy, "server_addresses", lambda: {__import__("ipaddress").ip_address("93.184.216.34")})
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: dns("93.184.216.34"))
    with pytest.raises(ip_policy.Blocked) as refused:
        ip_policy.resolve_public("synthetic.example", 443)
    assert refused.value.code == "server_own_address"


def test_a_name_that_does_not_resolve_is_a_lookup_failure_not_a_pass(monkeypatch):
    def fail(*a, **k):
        raise socket.gaierror("no such host")
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(ip_policy.Blocked) as refused:
        ip_policy.resolve_public("synthetic.example", 443)
    assert refused.value.code == "dns_lookup_failed"


def test_an_empty_or_huge_dns_answer_is_refused(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])
    with pytest.raises(ip_policy.Blocked):
        ip_policy.resolve_public("synthetic.example", 443)
    many = [dns(f"8.8.{i // 250}.{i % 250 + 1}")[0] for i in range(40)]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: many)
    with pytest.raises(ip_policy.Blocked):
        ip_policy.resolve_public("synthetic.example", 443)
