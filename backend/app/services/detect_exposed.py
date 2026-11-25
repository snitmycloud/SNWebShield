"""Exposed files and pages: a FIXED list of paths, each confirmed by what the response contains, not by a 200 status.

A learned "not found" baseline (a random path) shields against sites that answer 200 for everything. At most 64 KB of
a response is read. File CONTENTS ARE NEVER STORED OR LOGGED: only the path, the kind of signature that matched and
the HTTP status are kept, so finding a `.env` never copies its secrets anywhere.
"""
import asyncio
import hashlib
import re
import secrets
from dataclasses import dataclass, field

from app.services import netio
from app.services.detect_versions import USER_AGENT, parse_http_response

READ_LIMIT = 64 * 1024
ENV_LINE = re.compile(rb"^[A-Za-z_][A-Za-z0-9_.]*\s*=", re.M)
PASSWORD_FIELD = re.compile(rb"""<input[^>]+type\s*=\s*["']?password""", re.I)


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes


@dataclass
class ExposedResult:
    observations: list = field(default_factory=list)
    checked: int = 0
    failed: int = 0


def _is_html(response: Response) -> bool:
    return b"<html" in response.body[:2048].lower() or "html" in response.headers.get("content-type", [""])[0].lower()


def _git_head(r, baseline):
    return r.status == 200 and r.body.strip().startswith(b"ref: refs/") and len(r.body) < 200


def _env_file(r, baseline):
    return r.status == 200 and not _is_html(r) and len(ENV_LINE.findall(r.body[:READ_LIMIT])) >= 2


def _zip_archive(r, baseline):
    return r.status == 200 and r.body[:4] in (b"PK\x03\x04", b"PK\x05\x06") and not _is_html(r)


def _wp_config(r, baseline):
    return r.status == 200 and b"DB_NAME" in r.body and b"DB_PASSWORD" in r.body


def _phpinfo(r, baseline):
    return r.status == 200 and (b"<title>phpinfo()" in r.body or (b"PHP Version" in r.body and b"phpinfo" in r.body.lower()))


def _server_status(r, baseline):
    return r.status == 200 and b"Apache Server Status for" in r.body


def _ds_store(r, baseline):
    return r.status == 200 and r.body[:8] == b"\x00\x00\x00\x01Bud1"


def _login_form(r, baseline):
    if r.status != 200 or not _is_html(r):
        return False
    if baseline is not None and (hashlib.sha256(r.body).hexdigest() == baseline["hash"] or baseline["has_password"]):
        return False  # the whole site answers like this: not a real login page
    return bool(PASSWORD_FIELD.search(r.body)) or b"phpMyAdmin" in r.body


def _dir_listing(r, baseline):
    return r.status == 200 and _is_html(r) and (
        b"<title>Index of /" in r.body or (b"Parent Directory" in r.body and b"<a href=" in r.body))


# (path, kind, signature name, matcher)
CHECKS = (
    ("/.git/HEAD", "exposed_file", "git-head", _git_head),
    ("/.env", "exposed_file", "env-file", _env_file),
    ("/backup.zip", "exposed_file", "zip-archive", _zip_archive),
    ("/wp-config.php.bak", "exposed_file", "wp-config-backup", _wp_config),
    ("/phpinfo.php", "exposed_file", "phpinfo-page", _phpinfo),
    ("/server-status", "exposed_file", "apache-server-status", _server_status),
    ("/.DS_Store", "exposed_file", "ds-store", _ds_store),
    ("/wp-login.php", "admin_login", "login-form", _login_form),
    ("/wp-admin/", "admin_login", "login-form", _login_form),
    ("/administrator/", "admin_login", "login-form", _login_form),
    ("/admin/", "admin_login", "login-form", _login_form),
    ("/phpmyadmin/", "admin_login", "login-form", _login_form),
    ("/user/login", "admin_login", "login-form", _login_form),
    ("/", "directory_listing", "index-of", _dir_listing),
    ("/uploads/", "directory_listing", "index-of", _dir_listing),
    ("/images/", "directory_listing", "index-of", _dir_listing),
    ("/backup/", "directory_listing", "index-of", _dir_listing),
    ("/backups/", "directory_listing", "index-of", _dir_listing),
    ("/files/", "directory_listing", "index-of", _dir_listing),
)


def make_fetcher(ip: str, port: int, tls: bool, domain: str, *, timeout: float):
    """A coroutine `fetch(path) -> Response | None` that talks only to the pinned IP."""
    async def fetch(path: str):
        if any(c in path for c in "\r\n "):
            return None
        try:
            reader, writer = await netio.open_connection(ip, port, tls=tls, server_name=domain, timeout=min(timeout, 1.5))
        except (asyncio.TimeoutError, OSError):
            return None
        try:
            writer.write((f"GET {path} HTTP/1.0\r\nHost: {domain}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\n"
                          f"Connection: close\r\n\r\n").encode("ascii"))
            await asyncio.wait_for(writer.drain(), timeout)
            data = await netio.read_until_end(reader, READ_LIMIT + 8192, timeout)
        except (asyncio.TimeoutError, OSError):
            return None
        finally:
            await netio.close(writer)
        parsed = parse_http_response(data)
        if parsed is None:
            return None
        status, headers, body = parsed
        return Response(status, headers, body[:READ_LIMIT])
    return fetch


async def check_exposed(fetch, *, guard=None, concurrency: int = 4, on_progress=None) -> ExposedResult:
    result = ExposedResult()
    probe = await fetch(f"/snwebshield-nf-{secrets.token_hex(6)}")
    baseline = None
    if probe is not None:
        baseline = {"status": probe.status, "hash": hashlib.sha256(probe.body).hexdigest(),
                    "has_password": bool(PASSWORD_FIELD.search(probe.body))}
    limit = asyncio.Semaphore(concurrency)

    async def one(path, kind, signature, matcher) -> None:
        async with limit:
            if guard is not None:
                guard.check()
            response = await fetch(path)
            result.checked += 1
            if response is None:
                result.failed += 1
            elif matcher(response, baseline):
                result.observations.append({"key": path, "status": "exposed",
                                            "data": {"kind": kind, "signature": signature, "http_status": response.status}})
            if on_progress is not None:
                on_progress(result)

    tasks = [asyncio.create_task(one(*check)) for check in CHECKS]
    try:
        await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    return result
