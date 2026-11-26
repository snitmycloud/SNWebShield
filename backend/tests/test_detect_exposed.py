"""Exposed files: confirmed by content, soft-404s ignored, contents never kept, only the fixed list is requested."""
import asyncio

import pytest

from app.services import detect_exposed as ex
from netfixtures import BackgroundServer, HOST, http_handler

DOMAIN = "test.snwebshield.example"
HTML = {"Content-Type": "text/html"}
ALLOWED = {path for path, *_ in ex.CHECKS}

EXPOSED_SITE = {
    "/.git/HEAD": (200, {}, b"ref: refs/heads/main\n"),
    "/.env": (200, {"Content-Type": "text/plain"}, b"APP_KEY=base64:SECRETVALUE123\nDB_PASSWORD=hunter2\nDEBUG=true\n"),
    "/backup.zip": (200, {"Content-Type": "application/zip"}, b"PK\x03\x04" + b"\x00" * 40),
    "/wp-config.php.bak": (200, {}, b"<?php define('DB_NAME','w'); define('DB_PASSWORD','topsecret');"),
    "/phpinfo.php": (200, HTML, b"<html><head><title>phpinfo()</title></head><body>PHP Version 8.1</body></html>"),
    "/server-status": (200, HTML, b"<html><body><h1>Apache Server Status for example.com</h1></body></html>"),
    "/.DS_Store": (200, {}, b"\x00\x00\x00\x01Bud1" + b"\x00" * 20),
    "/admin/": (200, HTML, b"<html><form><input type=\"text\" name=\"u\"><input type=\"password\" name=\"p\"></form></html>"),
    "/phpmyadmin/": (200, HTML, b"<html><title>phpMyAdmin</title></html>"),
    "/uploads/": (200, HTML, b"<html><head><title>Index of /uploads</title></head><body><a href=\"a.txt\">a.txt</a></body></html>"),
}


def run(pages, default=(404, {}, b"nothing here")):
    with BackgroundServer(http_handler(pages, default=default)) as server:
        fetch = ex.make_fetcher(HOST, server.port, False, DOMAIN, timeout=2.0)
        result = asyncio.run(ex.check_exposed(fetch))
    return result, server


def keys(result):
    return {o["key"]: o["data"] for o in result.observations}


def test_a_clean_site_has_nothing_exposed_and_every_check_ran():
    result, _ = run({"/": (200, HTML, b"<html><body>Welcome</body></html>")})
    assert result.observations == [] and result.failed == 0 and result.checked == len(ex.CHECKS)


def test_each_exposed_item_is_confirmed_by_its_content():
    result, _ = run(EXPOSED_SITE)
    found = keys(result)
    assert found["/.git/HEAD"]["signature"] == "git-head" and found["/.env"]["signature"] == "env-file"
    assert found["/backup.zip"]["signature"] == "zip-archive" and found["/wp-config.php.bak"]["signature"] == "wp-config-backup"
    assert found["/phpinfo.php"]["signature"] == "phpinfo-page" and found["/server-status"]["signature"] == "apache-server-status"
    assert found["/.DS_Store"]["signature"] == "ds-store"
    assert found["/admin/"]["kind"] == "admin_login" and found["/phpmyadmin/"]["kind"] == "admin_login"
    assert found["/uploads/"]["kind"] == "directory_listing"
    assert result.failed == 0 and all(o["status"] == "exposed" and o["data"]["http_status"] == 200 for o in result.observations)


def test_file_contents_and_secrets_are_never_kept():
    result, _ = run(EXPOSED_SITE)
    dump = repr(result.observations)
    for secret in ("SECRETVALUE123", "hunter2", "topsecret", "DB_PASSWORD", "refs/heads"):
        assert secret not in dump
    for observation in result.observations:
        assert set(observation["data"]) == {"kind", "signature", "http_status"}


def test_a_soft_404_site_does_not_cause_false_alarms():
    soft = (200, HTML, b"<html><body><h1>Oops</h1><form><input type=\"password\"></form></body></html>")
    result, _ = run({}, default=soft)
    assert result.observations == []  # every path answers 200 with a login form: it is the site's own error page


def test_a_status_200_alone_proves_nothing():
    result, _ = run({"/.env": (200, HTML, b"<html>Not found</html>"), "/.git/HEAD": (200, {}, b"<html>hello</html>"),
                     "/backup.zip": (200, HTML, b"<html>PK\x03\x04</html>"), "/phpinfo.php": (200, HTML, b"<html>nope</html>"),
                     "/wp-config.php.bak": (200, {}, b"just text")})
    assert result.observations == []


def test_redirects_and_errors_are_not_exposures():
    result, _ = run({"/.git/HEAD": (302, {"Location": "/"}, b""), "/.env": (403, {}, b"forbidden"),
                     "/admin/": (301, {"Location": "/login"}, b"")})
    assert result.observations == []


def test_only_the_fixed_list_of_paths_is_requested():
    _, server = run(EXPOSED_SITE)
    paths = {r.split(b" ", 2)[1].decode() for r in server.requests}
    unknown = {p for p in paths if p not in ALLOWED}
    assert len(unknown) == 1 and next(iter(unknown)).startswith("/snwebshield-nf-")  # only the not-found baseline
    assert all(r.startswith(b"GET ") for r in server.requests)


def test_requests_that_fail_are_counted_so_the_step_can_say_could_not_check():
    async def broken(reader, writer, server):
        await reader.readuntil(b"\r\n\r\n")
        writer.close()  # no response at all

    with BackgroundServer(broken) as server:
        fetch = ex.make_fetcher(HOST, server.port, False, DOMAIN, timeout=1.0)
        result = asyncio.run(ex.check_exposed(fetch))
    assert result.failed == result.checked == len(ex.CHECKS) and result.observations == []


def test_the_guard_stops_the_check_and_no_more_requests_are_made():
    class Stop(Exception):
        pass

    class Guard:
        def __init__(self):
            self.calls = 0
        def check(self):
            self.calls += 1
            if self.calls > 3:
                raise Stop

    with BackgroundServer(http_handler({})) as server:
        fetch = ex.make_fetcher(HOST, server.port, False, DOMAIN, timeout=1.0)
        with pytest.raises(Stop):
            asyncio.run(ex.check_exposed(fetch, guard=Guard(), concurrency=1))
        count = len(server.requests)
    assert count < len(ex.CHECKS)


def test_large_responses_are_cut_at_64kb():
    async def endless(reader, writer, server):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + b"A=1\n" * 2_000_000)
        try:
            await writer.drain()
        except ConnectionError:
            pass
        writer.close()

    with BackgroundServer(endless) as server:
        fetch = ex.make_fetcher(HOST, server.port, False, DOMAIN, timeout=2.0)
        response = asyncio.run(fetch("/.env"))
    assert response is not None and len(response.body) <= ex.READ_LIMIT


ADMINER = b"<html><title>Login - Adminer</title><form><input name='auth[username]'><input type='password' name='auth[password]'></form></html>"


def test_adminer_is_found_at_its_two_usual_addresses():
    for path in ("/adminer.php", "/adminer/"):
        result, _ = run({path: (200, HTML, ADMINER)})
        assert keys(result)[path] == {"kind": "admin_login", "signature": "login-form", "http_status": 200}, path


def test_adminer_is_not_reported_on_a_site_that_answers_the_same_login_everywhere():
    everywhere = (200, HTML, ADMINER)
    result, _ = run({}, default=everywhere)
    assert not [o for o in result.observations if o["key"].startswith("/adminer")]
