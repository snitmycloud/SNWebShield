"""Service and version detection: parsers, local servers (SSH, MySQL, HTTP, TLS), disclosure, limits and hostile servers."""
import asyncio
import time

import pytest

from app.services import detect_versions as dv
from netfixtures import BackgroundServer, banner_handler, http_handler, silent_handler

IP = "127.0.0.1"
DOMAIN = "test.snwebshield.example"


def probe(port, *, timeout=None):
    return asyncio.run(dv.probe_open_port(IP, port, DOMAIN, timeout=timeout))


# --- Parsers --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("OpenSSH_8.2p1", ("OpenSSH", "8.2p1")), ("dropbear_2020.81", ("dropbear", "2020.81")),
    ("nginx/1.18.0", ("nginx", "1.18.0")), ("Apache/2.4.41 (Ubuntu)", ("Apache", "2.4.41")),
    ("Microsoft-IIS/10.0", ("Microsoft-IIS", "10.0")), ("cloudflare", ("cloudflare", None)),
    ("openresty/1.19.3.1", ("openresty", "1.19.3.1")), ("", (None, None)), ("1234", (None, None)),
])
def test_split_software(text, expected):
    assert dv.split_software(text) == expected


@pytest.mark.parametrize("data, port, expected", [
    (b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.13\r\n", 22, ("ssh", "OpenSSH", "8.2p1")),
    (b"SSH-2.0-dropbear_2020.81\r\n", 2222, ("ssh", "dropbear", "2020.81")),
    (b"220 ProFTPD 1.3.5 Server (Debian) [::ffff:1.2.3.4]\r\n", 21, ("ftp", "ProFTPD", "1.3.5")),
    (b"220 (vsFTPd 3.0.3)\r\n", 21, ("ftp", "vsFTPd", "3.0.3")),
    (b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", 25, ("smtp", "Postfix", None)),
    (b"220 mail.example.com ESMTP Exim 4.94.2 Tue\r\n", 25, ("smtp", "Exim", "4.94.2")),
    (b"+OK Dovecot ready.\r\n", 110, ("pop3", "Dovecot", None)),
    (b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n", 143, ("imap", "Dovecot", None)),
    (b"RFB 003.008\n", 5900, ("vnc", None, None)),
    (b"HTTP/1.1 200 OK\r\n\r\n", 8080, ("http", None, None)),
])
def test_banner_parsing(data, port, expected):
    parsed = dv.parse_banner(data, port)
    assert (parsed["service"], parsed["product"], parsed["version"]) == expected


def test_mysql_and_mariadb_greetings():
    greeting = lambda version: len(version).to_bytes(3, "little")[:3] and (
        (len(version) + 1 + 13).to_bytes(3, "little") + b"\x00\x0a" + version + b"\x00" + b"\x01" * 12)
    mysql = dv.parse_banner(greeting(b"8.0.32-0ubuntu0.22.04.2"), 3306)
    assert (mysql["service"], mysql["product"], mysql["version"]) == ("mysql", "MySQL", "8.0.32")
    maria = dv.parse_banner(greeting(b"5.5.5-10.3.34-MariaDB-0ubuntu0.20.04.1"), 3306)
    assert (maria["product"], maria["version"]) == ("MariaDB", "10.3.34")
    assert dv.parse_mysql(b"\x20\x00\x00\x00\xff\x6a\x04Host is not allowed")["service"] == "mysql"
    assert dv.parse_mysql(b"\x01\x02\x03") is None and dv.parse_banner(b"random bytes", 1234) is None


def test_http_response_parsing_and_cookie_privacy():
    parsed = dv.parse_http_response(b"HTTP/1.1 301 Moved\r\nServer: nginx/1.18.0\r\nSet-Cookie: sid=SECRET123; Secure; HttpOnly; SameSite=Lax\r\n"
                                    b"Set-Cookie: pref=1\r\nLocation: https://x/\r\n\r\nbody")
    status, headers, body = parsed
    assert status == 301 and headers["server"] == ["nginx/1.18.0"] and body == b"body"
    cookies = dv.parse_cookies(headers["set-cookie"])
    assert cookies == [{"name": "sid", "secure": True, "httponly": True, "samesite": "Lax"},
                       {"name": "pref", "secure": False, "httponly": False, "samesite": None}]
    assert "SECRET123" not in repr(cookies)  # cookie values are never kept
    assert dv.parse_http_response(b"SSH-2.0-OpenSSH\r\n") is None and dv.parse_http_response(b"HTTP/9 nope\r\n\r\n") is None


def test_only_identifying_headers_are_kept_and_they_are_cleaned():
    headers = {"server": ["nginx\x00/1.0"], "x-secret-internal": ["leak"], "x-powered-by": ["PHP/8.1.2"]}
    kept = dv.kept_headers(headers)
    assert kept == {"server": "nginx/1.0", "x-powered-by": "PHP/8.1.2"}


# --- Local servers ----------------------------------------------------------------------------------------

def test_ssh_banner_and_its_version():
    with BackgroundServer(banner_handler(b"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13\r\n")) as server:
        result = probe(server.port)
    assert (result.service, result.product, result.version) == ("ssh", "OpenSSH", "6.6.1p1")
    assert result.banner.startswith("SSH-2.0-OpenSSH_6.6.1p1") and not result.service_guess
    assert result.tls is None


def test_mysql_greeting_over_a_real_connection():
    greeting = (30).to_bytes(3, "little") + b"\x00\x0a" + b"5.7.40-log\x00" + b"\x02" * 12
    with BackgroundServer(banner_handler(greeting)) as server:
        result = probe(server.port)
    assert (result.service, result.product, result.version) == ("mysql", "MySQL", "5.7.40")


def test_a_web_server_head_get_headers_cookies_and_body():
    page = b"<html><head><meta name='generator' content='WordPress 6.4.2'></head><body>hello</body></html>"
    pages = {"/": (200, {"Server": "nginx/1.18.0 (Ubuntu)", "X-Powered-By": "PHP/7.4.3",
                         "Set-Cookie": ["PHPSESSID=abc123; HttpOnly", "tracker=1; Secure"],
                         "Strict-Transport-Security": "max-age=63072000"}, page)}
    with BackgroundServer(http_handler(pages)) as server:
        result = probe(server.port)
    assert (result.service, result.product, result.version) == ("http", "nginx", "1.18.0")
    assert result.http["status"] == 200 and result.http["headers"]["x-powered-by"] == "PHP/7.4.3"
    assert result.http["headers"]["strict-transport-security"] == "max-age=63072000"
    assert [c["name"] for c in result.http["cookies"]] == ["PHPSESSID", "tracker"]
    assert result.web is not None and b"WordPress 6.4.2" in result.web.body.encode() and not result.web.tls
    methods = [r.split(b" ", 1)[0] for r in server.requests if r.startswith((b"HEAD", b"GET"))]
    assert set(methods) == {b"HEAD", b"GET"}  # both are used


def test_a_server_that_does_not_disclose_its_version():
    with BackgroundServer(http_handler({"/": (200, {"Server": "nginx"}, b"<html></html>")})) as server:
        result = probe(server.port)
    assert result.product == "nginx" and result.version is None  # shown as "not disclosed"


def test_https_tls_details_and_certificate():
    with BackgroundServer(http_handler({"/": (200, {"Server": "Apache/2.4.41"}, b"<html>secure</html>")}), tls=True) as server:
        result = probe(server.port)
    assert result.service == "https" and (result.product, result.version) == ("Apache", "2.4.41")
    assert result.tls["version"].startswith("TLSv1") and result.tls["cipher"]
    certificate = result.tls["certificate"]
    assert certificate["subject_cn"] == DOMAIN and certificate["self_signed"] is True and "alt.snwebshield.example" in certificate["san"]
    assert certificate["not_after"] and result.web.tls and "secure" in result.web.body


def test_the_probes_send_nothing_harmful():
    with BackgroundServer(http_handler({"/": (200, {}, b"ok")})) as server:
        probe(server.port)
    for request in server.requests:
        line = request.split(b"\r\n", 1)[0].decode("latin-1")
        assert line.split(" ")[0] in ("HEAD", "GET") and line.split(" ")[1] == "/"  # only the home page
        assert f"Host: {DOMAIN}".encode() in request and b"SNWebShield" in request
        assert b"Authorization" not in request and b"Cookie" not in request and b"password" not in request.lower()


def test_a_huge_hostile_banner_is_cut_to_1kb_and_stripped_of_control_characters():
    noise = (b"220 " + b"\x1b[31mevil\x00\x07\r" * 2000)
    with BackgroundServer(banner_handler(noise)) as server:
        result = probe(server.port)
    assert len(result.banner) <= 1024 and all(c == "\n" or c == "\t" or ord(c) >= 32 for c in result.banner)
    assert "\x1b" not in result.banner and "\x00" not in result.banner


def test_a_silent_server_is_limited_to_three_seconds_and_never_looks_identified():
    with BackgroundServer(silent_handler) as server:
        started = time.monotonic()
        result = probe(server.port)
        elapsed = time.monotonic() - started
    assert elapsed < 3.6
    assert result.banner == "" and result.version is None and result.http is None and result.tls is None


def test_an_unknown_open_port_falls_back_to_the_port_number_name_as_a_guess(monkeypatch):
    async def refuse(ip, port, **kwargs):
        raise ConnectionRefusedError  # the server says nothing we can learn from

    monkeypatch.setattr(dv.netio, "open_connection", refuse)
    result = asyncio.run(dv.probe_open_port(IP, 22, DOMAIN, timeout=0.5))
    assert result.service == "ssh" and result.service_guess is True and result.version is None
    assert asyncio.run(dv.probe_open_port(IP, 54321, DOMAIN, timeout=0.5)).service is None


def test_probing_many_ports_stores_each_result_as_it_finishes():
    with BackgroundServer(banner_handler(b"SSH-2.0-OpenSSH_7.4\r\n")) as a, BackgroundServer(
            http_handler({"/": (200, {"Server": "nginx/1.20.1"}, b"<html></html>")})) as b:
        stored = []
        done = asyncio.run(dv.probe_ports(IP, [a.port, b.port], DOMAIN, stored.append))
    assert {p.port for p in done} == {a.port, b.port} == {p.port for p in stored}
