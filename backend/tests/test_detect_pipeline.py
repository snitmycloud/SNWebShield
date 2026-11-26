"""One whole scan through every DETECT step against local servers, and what the results API returns."""
import asyncio
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.time import utc_now
from app.db.session import SessionLocal
from app.main import app
from app.models.scan import Scan, ScanObservation, ScanPort, ScanTechnology
from app.models.website import Website
from app.services import detect_dns, detect_runner, detect_subdomains, netio, scans
from account_helpers import account_headers
from netfixtures import BackgroundServer, banner_handler, free_port, http_handler

W = "/api/v1/websites"
HTML = {"Content-Type": "text/html"}
HOME = (b"<html><head><meta name='generator' content='WordPress 6.4.2'>"
        b"<script src='/js/jquery-3.6.0.min.js'></script></head><body>Hello</body></html>")
SITE = {
    "/": (200, {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3", "Content-Type": "text/html",
                "Set-Cookie": ["PHPSESSID=SECRETSESSION; HttpOnly"]}, HOME),
    "/.git/HEAD": (200, {}, b"ref: refs/heads/main\n"),
}


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def fake_dns(monkeypatch, fail=False):
    async def lookup(name, rdtype):
        if fail:
            raise OSError("down")
        if (name, rdtype) == ("example.com", "TXT"):
            return ["v=spf1 include:_spf.example.net ~all"]
        if (name, rdtype) == ("example.com", "MX"):
            return ["10 mail.example.com."]
        return []
    monkeypatch.setattr(detect_dns, "lookup", lookup)


def fake_crtsh(monkeypatch, ok=True):
    def fetch(domain):
        if not ok:
            raise OSError("crt.sh is down")
        return json.dumps([{"name_value": "shop.example.com\nblog.example.com"}])
    monkeypatch.setattr(detect_subdomains, "fetch", fetch)


def run_scan(client, headers, ports, monkeypatch, domain="example.com"):
    site = client.post(W, headers=headers, json={"domain": domain}).json()
    with SessionLocal() as db:
        row = db.get(Website, site["id"])
        row.verification_status, row.verification_method = "verified", "dns"
        row.verified_at = row.verification_checked_at = utc_now()
        db.query(Scan).filter_by(website_id=row.id).delete()
        scan = scans.request_scan(db, row, "manual")
        db.commit()
        scan_id = scan.id
    with SessionLocal() as db:
        claimed = scans.claim(db)

    async def detect(ctx, state, guard):
        if ports:  # None means: the real standard port list
            ctx.ports = tuple(ports)
        await detect_runner.run(ctx, state, guard)

    status = scans.execute(*claimed, resolve=lambda d: ["127.0.0.1"], verify=lambda db, w: (True, "cached"), detect=detect)
    return site, scan_id, status


def test_a_whole_scan_finds_ports_versions_technologies_dns_files_and_subdomains(client, monkeypatch):
    fake_dns(monkeypatch)
    fake_crtsh(monkeypatch)
    greeting = (30).to_bytes(3, "little") + b"\x00\x0a" + b"8.0.32-0ubuntu0.22.04\x00" + b"\x02" * 12
    with BackgroundServer(banner_handler(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu\r\n")) as ssh, \
            BackgroundServer(banner_handler(greeting)) as mysql, BackgroundServer(http_handler(SITE)) as web:
        closed = free_port()

        real = netio.open_connection

        async def fast_close(ip, port, **kwargs):  # a refusal takes ~2 s to be reported on Windows; simulate it
            if port == closed:
                raise ConnectionRefusedError
            return await real(ip, port, **kwargs)

        monkeypatch.setattr(netio, "open_connection", fast_close)
        _, _, headers = account_headers(client)
        site, scan_id, status = run_scan(client, headers, [ssh.port, mysql.port, web.port, closed], monkeypatch)

    assert status == "completed"
    body = client.get(f"{W}/{site['id']}/scans/{scan_id}", headers=headers).json()
    scan = body["scan"]
    assert scan["status"] == "completed" and scan["resolved_ip"] == "127.0.0.1" and scan["result"]["code"] == "detect_completed"
    assert all(step["state"] == "ok" for name, step in scan["result"]["steps"].items() if name != "nuclei"), scan["result"]["steps"]
    assert scan["result"]["steps"]["nuclei"] == {"state": "skipped", "reason": "disabled"}   # off by default
    assert scan["result"]["ports"]["open"] == 3 and scan["result"]["ports"]["closed"] == 1
    assert "not a security verdict" in scan["message"] and "3 open port" in scan["message"]

    by_service = {p["service"]: p for p in body["ports"]}
    assert (by_service["ssh"]["product"], by_service["ssh"]["version"]) == ("OpenSSH", "8.2p1")
    assert (by_service["mysql"]["product"], by_service["mysql"]["version"]) == ("MySQL", "8.0.32")
    assert (by_service["http"]["product"], by_service["http"]["version"]) == ("nginx", "1.18.0")
    assert by_service["ssh"]["banner"].startswith("SSH-2.0-OpenSSH_8.2p1")
    assert [c["name"] for c in by_service["http"]["http"]["cookies"]] == ["PHPSESSID"]
    assert "SECRETSESSION" not in json.dumps(body)  # cookie values are never stored

    techs = {t["name"]: t["version"] for t in body["technologies"]}
    assert techs["nginx"] == "1.18.0" and techs["PHP"] == "7.4.3" and techs["WordPress"] == "6.4.2" and techs["jQuery"] == "3.6.0"

    dns = {d["key"]: d for d in body["dns"]}
    assert dns["spf"]["status"] == "present" and dns["spf"]["data"]["policy"] == "softfail"
    assert dns["dmarc"]["status"] == "missing" and dns["mx"]["status"] == "present"
    assert [e["path"] for e in body["exposed"]] == ["/.git/HEAD"] and body["exposed"][0]["signature"] == "git-head"
    assert body["subdomains"] == ["blog.example.com", "shop.example.com"]
    assert "refs/heads" not in json.dumps(body)  # exposed file contents are never stored


def test_a_core_step_that_cannot_finish_makes_the_scan_incomplete_never_clean(client, monkeypatch):
    fake_dns(monkeypatch, fail=True)  # DNS is a core step
    fake_crtsh(monkeypatch)
    with BackgroundServer(http_handler({"/": (200, HTML, b"<html></html>")})) as web:
        _, _, headers = account_headers(client)
        site, scan_id, status = run_scan(client, headers, [web.port], monkeypatch)
    assert status == "incomplete"
    body = client.get(f"{W}/{site['id']}/scans/{scan_id}", headers=headers).json()
    assert body["scan"]["status"] == "incomplete" and body["scan"]["result"]["code"] == "some_checks_incomplete"
    assert body["scan"]["result"]["steps"]["dns"]["state"] == "could_not_check"
    assert body["scan"]["result"]["steps"]["ports"]["state"] == "ok"
    assert "email and dns records" in body["scan"]["message"] and "does not mean your website is safe" in body["scan"]["message"]
    assert [p["port"] for p in body["ports"]] == [web.port]  # what was found is kept


def test_the_subdomain_list_is_optional_a_scan_still_completes_with_a_clear_note(client, monkeypatch):
    fake_dns(monkeypatch)
    fake_crtsh(monkeypatch, ok=False)  # crt.sh is down
    with BackgroundServer(http_handler({"/": (200, HTML, b"<html></html>")})) as web:
        _, _, headers = account_headers(client)
        site, scan_id, status = run_scan(client, headers, [web.port], monkeypatch)
    assert status == "completed"
    body = client.get(f"{W}/{site['id']}/scans/{scan_id}", headers=headers).json()
    scan = body["scan"]
    assert scan["status"] == "completed" and scan["result"]["code"] == "detect_completed"
    assert scan["result"]["steps"]["subdomains"]["state"] == "could_not_check"      # still recorded honestly
    assert scan["result"]["optional_unavailable"] == ["subdomains"]
    assert ("Subdomain list unavailable right now (outside service didn't answer). "
            "This does not affect your security results.") in scan["message"]
    assert "not a security verdict" in scan["message"]
    assert [p["port"] for p in body["ports"]] == [web.port] and body["subdomains"] == []


def test_without_a_problem_there_is_no_optional_note(client, monkeypatch):
    fake_dns(monkeypatch)
    fake_crtsh(monkeypatch)
    with BackgroundServer(http_handler({"/": (200, HTML, b"<html></html>")})) as web:
        _, _, headers = account_headers(client)
        site, scan_id, status = run_scan(client, headers, [web.port], monkeypatch)
    scan = client.get(f"{W}/{site['id']}/scans/{scan_id}", headers=headers).json()["scan"]
    assert status == "completed" and "unavailable" not in scan["message"] and scan["result"]["optional_unavailable"] == []


def test_optional_and_core_steps_are_exactly_these():
    assert set(detect_runner.OPTIONAL_STEPS) == {"subdomains", "nuclei"}
    core = {"ports", "versions", "technologies", "exposed", "dns", "configuration", "vulnerabilities", "lifecycle"}
    assert core <= set(detect_runner.STEP_NAMES) and not core & set(detect_runner.OPTIONAL_STEPS)


def test_a_core_failure_together_with_an_optional_one_is_still_incomplete(client, monkeypatch):
    fake_dns(monkeypatch, fail=True)
    fake_crtsh(monkeypatch, ok=False)
    with BackgroundServer(http_handler({"/": (200, HTML, b"<html></html>")})) as web:
        _, _, headers = account_headers(client)
        site, scan_id, status = run_scan(client, headers, [web.port], monkeypatch)
    scan = client.get(f"{W}/{site['id']}/scans/{scan_id}", headers=headers).json()["scan"]
    assert status == "incomplete" and "subdomain" not in scan["message"].lower() and "email and dns records" in scan["message"]


def test_a_failing_vulnerability_database_is_core_so_the_scan_is_incomplete(client, monkeypatch):
    from app.services import vuln_sources
    fake_dns(monkeypatch)
    fake_crtsh(monkeypatch)

    def down(source, method, path, **kwargs):
        raise vuln_sources.SourceError("timeout")
    monkeypatch.setattr(vuln_sources, "http_json", down)
    with BackgroundServer(banner_handler(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu\r\n")) as ssh:
        _, _, headers = account_headers(client)
        _, _, status = run_scan(client, headers, [ssh.port], monkeypatch)
    assert status == "incomplete"


def test_dns_failures_are_could_not_check_not_missing(client, monkeypatch):
    fake_dns(monkeypatch, fail=True)
    fake_crtsh(monkeypatch)
    with BackgroundServer(http_handler({"/": (200, HTML, b"<html></html>")})) as web:
        _, _, headers = account_headers(client)
        site, scan_id, status = run_scan(client, headers, [web.port], monkeypatch)
    assert status == "incomplete"
    body = client.get(f"{W}/{site['id']}/scans/{scan_id}", headers=headers).json()
    assert body["scan"]["result"]["steps"]["dns"]["state"] == "could_not_check"
    assert {d["status"] for d in body["dns"] if d["key"] != "dkim"} == {"could_not_check"}


def test_if_the_port_step_cannot_check_nothing_else_pretends_to(client, monkeypatch):
    fake_dns(monkeypatch)
    fake_crtsh(monkeypatch)

    async def unreachable(ip, port, **kwargs):
        raise OSError(101, "Network is unreachable")

    monkeypatch.setattr(netio, "open_connection", unreachable)
    _, _, headers = account_headers(client)
    site, scan_id, status = run_scan(client, headers, list(range(1000, 1030)), monkeypatch)
    steps = client.get(f"{W}/{site['id']}/scans/{scan_id}", headers=headers).json()["scan"]["result"]["steps"]
    assert status == "incomplete" and steps["ports"]["state"] == "could_not_check"
    assert steps["versions"]["state"] == steps["technologies"]["state"] == steps["exposed"]["state"] == "skipped"


def test_a_host_with_no_open_ports_is_reported_as_such_but_web_steps_are_not_applicable(client, monkeypatch):
    fake_dns(monkeypatch)
    fake_crtsh(monkeypatch)

    async def refuse(ip, port, **kwargs):
        raise ConnectionRefusedError

    monkeypatch.setattr(netio, "open_connection", refuse)
    _, _, headers = account_headers(client)
    site, scan_id, status = run_scan(client, headers, list(range(1000, 1010)), monkeypatch)
    body = client.get(f"{W}/{site['id']}/scans/{scan_id}", headers=headers).json()
    steps = body["scan"]["result"]["steps"]
    assert body["ports"] == [] and steps["ports"]["state"] == "ok" and steps["ports"]["closed"] == 10
    assert steps["versions"]["state"] == "not_applicable" and steps["exposed"]["state"] == "not_applicable"


def test_results_are_visible_only_to_the_owner_and_staff(client, monkeypatch):
    fake_dns(monkeypatch)
    fake_crtsh(monkeypatch)
    with BackgroundServer(http_handler({"/": (200, HTML, b"<html></html>")})) as web:
        _, _, owner = account_headers(client)
        site, scan_id, _ = run_scan(client, owner, [web.port], monkeypatch)
    _, _, other = account_headers(client)
    _, _, staff = account_headers(client, "admin")
    url = f"{W}/{site['id']}/scans/{scan_id}"
    assert client.get(url, headers=owner).status_code == 200 and client.get(url, headers=staff).status_code == 200
    assert client.get(url, headers=other).status_code == 404
    assert client.get(url).status_code == 401
    assert client.get(f"{W}/{site['id']}/scans/no-such-scan", headers=owner).status_code == 404
    _, _, second = account_headers(client)
    other_site = client.post(W, headers=second, json={"domain": "another.example.com"}).json()
    assert client.get(f"{W}/{other_site['id']}/scans/{scan_id}", headers=second).status_code == 404  # wrong website


def test_the_standard_scan_reports_ports_open_like_scanmes_including_31337(client, monkeypatch):
    """scanme.nmap.org has 22, 80, 9929 and 31337 open. The whole standard scan, with its real port list, must report all four."""
    fake_dns(monkeypatch)
    fake_crtsh(monkeypatch)
    with BackgroundServer(banner_handler(b"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu\r\n")) as ssh, \
            BackgroundServer(http_handler({"/": (200, HTML, b"<html></html>")})) as web, \
            BackgroundServer(banner_handler(b"\x00")) as nping, BackgroundServer(banner_handler(b"hello\r\n")) as elite:
        mapping = {22: ssh.port, 80: web.port, 9929: nping.port, 31337: elite.port}
        real = netio.open_connection

        async def fake(ip, port, **kwargs):
            if port in mapping:
                return await real(ip, mapping[port], **kwargs)
            raise ConnectionRefusedError

        monkeypatch.setattr(netio, "open_connection", fake)
        _, _, headers = account_headers(client)
        site, scan_id, status = run_scan(client, headers, None, monkeypatch)
    body = client.get(f"{W}/{site['id']}/scans/{scan_id}", headers=headers).json()
    assert [p["port"] for p in body["ports"]] == [22, 80, 9929, 31337]
    assert body["scan"]["result"]["ports"]["planned"] == 1011 and body["scan"]["result"]["ports"]["open"] == 4
    assert body["scan"]["result"]["steps"]["ports"]["state"] == "ok"