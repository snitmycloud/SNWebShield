"""The egress proxy: Nuclei's only way out. Policy, pinned-IP connection, logging and limits, against loopback servers."""
import asyncio
import json
import socket

import pytest

from app.services import egress_proxy as ep
from netfixtures import BackgroundServer, HOST, banner_handler, http_handler

DOMAIN = "target.example.com"


async def exchange(proxy, request: bytes, *, read_after=b"", wait=1.0) -> bytes:
    reader, writer = await asyncio.open_connection(HOST, proxy.port)
    writer.write(request)
    await writer.drain()
    data = b""
    try:
        while True:  # read until the proxy closes or nothing more arrives for a moment
            chunk = await asyncio.wait_for(reader.read(65536), wait)
            if not chunk:
                break
            data += chunk
            if read_after:
                writer.write(read_after)
                await writer.drain()
                read_after = b""
    except (asyncio.TimeoutError, ConnectionError):
        pass
    writer.close()
    return data


def with_proxy(coro_factory, *, log_path=None, ip="127.0.0.1", allow_ip=lambda ip: True, port_map=None):
    async def main():
        proxy = ep.EgressProxy(host=DOMAIN, ip=ip, scan_id="scan-1", log_path=log_path, allow_ip=allow_ip, port_map=port_map)
        await proxy.start()
        try:
            return await coro_factory(proxy), proxy
        finally:
            await proxy.stop()
    return asyncio.run(main())


def connect(host, port):
    return f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n".encode()


def get(url, extra=""):
    return f"GET {url} HTTP/1.1\r\nHost: x\r\nProxy-Connection: keep-alive\r\n{extra}\r\n".encode()


def refused(data):
    return data.startswith(b"HTTP/1.1 403")


# --- HTTPS: CONNECT to the verified host on 443 only -----------------------------------------------------------------------------

def test_connect_to_the_verified_host_on_443_is_tunnelled_to_the_pinned_ip():
    with BackgroundServer(banner_handler(b"HELLO-FROM-ORIGIN", then_close=False)) as origin:
        data, proxy = with_proxy(lambda p: exchange(p, connect(DOMAIN, 443)), port_map={443: origin.port})
    assert data.startswith(b"HTTP/1.1 200 Connection Established") and b"HELLO-FROM-ORIGIN" in data
    assert origin.connections == 1
    [entry] = proxy.entries
    assert entry["decision"] == "allowed" and entry["host"] == DOMAIN and entry["port"] == 443 and entry["ip"] == "127.0.0.1"


def test_host_name_matching_ignores_case_and_a_trailing_dot_but_nothing_else():
    with BackgroundServer(banner_handler(b"OK", then_close=False)) as origin:
        data, _ = with_proxy(lambda p: exchange(p, connect("TARGET.Example.COM.", 443)), port_map={443: origin.port})
        assert data.startswith(b"HTTP/1.1 200")
        for sneaky in ("target.example.com.evil.example", "evil.target.example.com", "target.example.org", "targetXexample.com"):
            data, _ = with_proxy(lambda p: exchange(p, connect(sneaky, 443)), port_map={443: origin.port})
            assert refused(data), sneaky


@pytest.mark.parametrize("host, port, reason", [
    ("other.example.org", 443, "other_host"), ("localhost", 443, "other_host"), (DOMAIN, 8443, "port_not_allowed"),
    (DOMAIN, 80, "port_not_allowed"), (DOMAIN, 22, "port_not_allowed"), ("127.0.0.1", 443, "ip_literal_host"),
    ("169.254.169.254", 443, "ip_literal_host"), ("10.0.0.5", 443, "ip_literal_host"), ("[::1]", 443, "ip_literal_host"),
])
def test_connect_anywhere_else_is_refused_logged_and_never_connects(host, port, reason):
    with BackgroundServer(banner_handler(b"SHOULD-NOT-BE-REACHED", then_close=False)) as origin:
        data, proxy = with_proxy(lambda p: exchange(p, connect(host, port)), port_map={443: origin.port, 80: origin.port, 8443: origin.port, 22: origin.port})
    assert refused(data) and origin.connections == 0
    assert [(e["decision"], e["reason"]) for e in proxy.entries] == [("refused", reason)]


# --- HTTP: absolute-form GET/HEAD to the verified host on 80 only ----------------------------------------------------------------------

def test_plain_http_is_forwarded_in_origin_form_with_connection_close():
    page = (200, {"Content-Type": "text/plain"}, b"PAGE-BODY")
    with BackgroundServer(http_handler({"/a/b": page})) as origin:
        data, proxy = with_proxy(lambda p: exchange(p, get(f"http://{DOMAIN}/a/b", "X-Keep: 1\r\n")), port_map={80: origin.port})
    assert b"200" in data.split(b"\r\n", 1)[0] and b"PAGE-BODY" in data
    request = origin.requests[0].decode("latin-1")
    assert request.startswith("GET /a/b HTTP/1.1\r\n") and "X-Keep: 1" in request
    assert "Proxy-Connection" not in request and "Connection: close" in request
    assert proxy.entries[0]["decision"] == "allowed" and proxy.entries[0]["ip"] == "127.0.0.1"


def test_head_is_allowed_too_and_port_80_may_be_written_out():
    with BackgroundServer(http_handler({"/": (200, {}, b"")})) as origin:
        data, _ = with_proxy(lambda p: exchange(p, b"HEAD http://%s:80/ HTTP/1.1\r\nHost: x\r\n\r\n" % DOMAIN.encode()), port_map={80: origin.port})
    assert data.startswith(b"HTTP/1.0 200") or data.startswith(b"HTTP/1.1 200")


@pytest.mark.parametrize("request_bytes, reason", [
    (get("http://other.example.org/"), "other_host"), (get(f"http://{DOMAIN}:8080/"), "port_not_allowed"),
    (get(f"http://{DOMAIN}:443/"), "port_not_allowed"), (get("http://127.0.0.1/"), "ip_literal_host"),
    (get("http://169.254.169.254/latest/meta-data/"), "ip_literal_host"), (get("http://127.0.0.1:9999/leak"), "ip_literal_host"),
])
def test_plain_http_to_anything_else_is_refused(request_bytes, reason):
    with BackgroundServer(http_handler({}, default=(200, {}, b"LEAK"))) as origin:
        data, proxy = with_proxy(lambda p: exchange(p, request_bytes), port_map={80: origin.port, 8080: origin.port, 443: origin.port})
    assert refused(data) and b"LEAK" not in data and origin.connections == 0
    assert proxy.entries[0]["reason"] == reason


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"])
def test_only_get_and_head_are_forwarded(method):
    with BackgroundServer(http_handler({}, default=(200, {}, b"x"))) as origin:
        data, proxy = with_proxy(lambda p: exchange(p, f"{method} http://{DOMAIN}/ HTTP/1.1\r\nHost: x\r\n\r\n".encode()), port_map={80: origin.port})
    assert refused(data) and origin.connections == 0 and proxy.entries[0]["reason"] == "method_or_form_not_allowed"


def test_a_request_that_is_not_proxy_form_is_refused():
    with BackgroundServer(http_handler({}, default=(200, {}, b"x"))) as origin:
        data, _ = with_proxy(lambda p: exchange(p, b"GET /plain HTTP/1.1\r\nHost: target.example.com\r\n\r\n"), port_map={80: origin.port})
    assert refused(data) and origin.connections == 0


@pytest.mark.parametrize("junk", [b"\x00\x01\x02\r\n\r\n", b"NOT HTTP\r\n\r\n", b"GET\r\n\r\n", b"CONNECT\r\n\r\n"])
def test_garbage_is_refused_and_logged_without_crashing(junk):
    data, proxy = with_proxy(lambda p: exchange(p, junk))
    assert refused(data) or data == b""
    assert all(e["decision"] == "refused" for e in proxy.entries)


# --- the pinned IP is the only address ever used; names are never resolved ------------------------------------------------------------

def test_no_name_is_ever_resolved(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("the proxy must never resolve a name")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with BackgroundServer(banner_handler(b"OK", then_close=False)) as origin:
        data, _ = with_proxy(lambda p: exchange(p, connect(DOMAIN, 443)), port_map={443: origin.port})
    assert data.startswith(b"HTTP/1.1 200")


def test_a_pinned_ip_that_is_not_public_is_refused_with_the_real_policy():
    for ip in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.0.10", "::1", "172.16.0.1", "100.64.0.1"):
        data, proxy = with_proxy(lambda p: exchange(p, connect(DOMAIN, 443)), ip=ip, allow_ip=None)
        assert refused(data) or data.startswith(b"HTTP/1.1 502") or data == b"", ip
        assert proxy.entries[0]["decision"] == "refused" and proxy.entries[0]["reason"] == "pinned_ip_not_public", ip


def test_the_connection_is_made_to_the_pinned_ip_not_to_anything_the_client_names(monkeypatch):
    from app.services import netio
    seen = []
    real = netio.open_connection

    async def spy(ip, port, **kwargs):
        seen.append((ip, port))
        return await real(ip, port, **kwargs)
    monkeypatch.setattr(netio, "open_connection", spy)
    with BackgroundServer(banner_handler(b"OK", then_close=False)) as origin:
        with_proxy(lambda p: exchange(p, connect(DOMAIN, 443)), port_map={443: origin.port})
    assert seen == [("127.0.0.1", origin.port)]


# --- logging and summary --------------------------------------------------------------------------------------------------------------

def test_every_allowed_and_refused_attempt_is_logged_to_a_file_and_summarised(tmp_path):
    log = tmp_path / "logs" / "scan-1.jsonl"
    with BackgroundServer(http_handler({"/": (200, {}, b"ok")})) as origin:
        async def scenario(proxy):
            await exchange(proxy, get(f"http://{DOMAIN}/secret-path?token=abc", "Authorization: Bearer topsecret\r\n"))
            await exchange(proxy, get("http://evil.example.org/"))
            await exchange(proxy, connect("127.0.0.1", 443))
        _, proxy = with_proxy(scenario, log_path=log, port_map={80: origin.port})
    lines = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [(x["decision"], x["reason"]) for x in lines] == [("allowed", None), ("refused", "other_host"), ("refused", "ip_literal_host")]
    text = log.read_text(encoding="utf-8")
    assert "secret-path" not in text and "topsecret" not in text and "token=abc" not in text   # paths, headers and secrets are never logged
    assert all(x["scan"] == "scan-1" and x["time"] for x in lines)
    summary = proxy.summary()
    assert summary["allowed"] == 1 and summary["refused"] == 2 and summary["ips_contacted"] == ["127.0.0.1"] and summary["hosts_allowed"] == [DOMAIN]
    assert summary["refused_reasons"] == {"other_host": 1, "ip_literal_host": 1}


def test_only_the_pinned_ip_appears_as_contacted_even_after_many_attempts():
    with BackgroundServer(http_handler({}, default=(200, {}, b"x"))) as origin:
        async def scenario(proxy):
            for url in ("http://a.example.org/", "http://169.254.169.254/", f"http://{DOMAIN}/", "http://10.0.0.1/", f"http://{DOMAIN}:81/"):
                await exchange(proxy, get(url))
        _, proxy = with_proxy(scenario, port_map={80: origin.port})
    assert proxy.summary()["ips_contacted"] == ["127.0.0.1"] and proxy.summary()["allowed"] == 1 and proxy.summary()["refused"] == 4


# --- limits ---------------------------------------------------------------------------------------------------------------------------------

def test_too_many_connections_are_refused(monkeypatch):
    monkeypatch.setattr(ep, "MAX_CONNECTIONS", 2)
    with BackgroundServer(http_handler({}, default=(200, {}, b"x"))) as origin:
        async def scenario(proxy):
            return [await exchange(proxy, get(f"http://{DOMAIN}/")) for _ in range(4)]
        answers, proxy = with_proxy(scenario, port_map={80: origin.port})
    assert [refused(a) for a in answers] == [False, False, True, True]
    assert proxy.summary()["refused_reasons"] == {"too_many_connections": 2}


def test_a_tunnel_stops_after_the_byte_limit(monkeypatch):
    monkeypatch.setattr(ep, "MAX_BYTES_PER_CONNECTION", 1000)

    async def flood(reader, writer, server):
        for _ in range(40):
            writer.write(b"x" * 500)
            await writer.drain()
            await asyncio.sleep(0.03)
        await asyncio.sleep(0.2)

    with BackgroundServer(flood) as origin:
        data, proxy = with_proxy(lambda p: exchange(p, connect(DOMAIN, 443), wait=1.0), port_map={443: origin.port})
    assert 0 < len(data) < 3000 and proxy.bytes_total <= 1000   # cut off after the limit, not the full 20 000 bytes


def test_an_unreachable_pinned_ip_port_is_a_502_and_logged():
    from netfixtures import free_port
    data, proxy = with_proxy(lambda p: exchange(p, connect(DOMAIN, 443), wait=6.0), port_map={443: free_port()})  # Windows reports a refusal after ~2 s
    assert data.startswith(b"HTTP/1.1 502") and proxy.entries[0]["reason"] == "upstream_unreachable"


def test_the_proxy_listens_on_loopback_only_and_stops_cleanly():
    async def main():
        proxy = ep.EgressProxy(host=DOMAIN, ip="127.0.0.1", scan_id="s", allow_ip=lambda ip: True)
        await proxy.start()
        bound = proxy._server.sockets[0].getsockname()[0]
        await proxy.stop()
        with pytest.raises(OSError):
            await asyncio.open_connection(HOST, proxy.port)
        return bound
    assert asyncio.run(main()) == "127.0.0.1"
