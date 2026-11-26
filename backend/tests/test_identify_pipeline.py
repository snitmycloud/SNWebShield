"""Whole scans through DETECT and IDENTIFY against local servers and fake vulnerability databases."""
import threading
import time

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.db.session import SessionLocal
from app.main import app
from app.models.scan import ScanFinding
from app.services import vuln_sources
from account_helpers import account_headers
from netfixtures import BackgroundServer, banner_handler, http_handler
from test_detect_pipeline import fake_crtsh, fake_dns, run_scan
from test_scan_stops_cleanly import POLL, finished_within, scan_row, start_scan

W = "/api/v1/websites"
PAGE = b"<html><head><script src='/js/jquery-1.12.4.min.js'></script></head><body>hi</body></html>"
WEB = {"/": (200, {"Server": "nginx/1.18.0", "Content-Type": "text/html", "Set-Cookie": ["sid=abc123SECRET"]}, PAGE)}
SSH_UBUNTU = b"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13\r\n"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings, "scan_guard_poll_seconds", POLL)
    with TestClient(app) as test_client:
        yield test_client


def cve(cve_id="CVE-2016-0777", score=9.8, end="7.1"):
    return {"cve": {"id": cve_id, "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "Information leak in the client."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
                    "configurations": [{"operator": "OR", "nodes": [{"operator": "OR", "cpeMatch": [
                        {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionEndExcluding": end}]}]}]}}


def fake_databases(monkeypatch, nvd=None, osv=None, fail=False, log=None):
    def http_json(source, method, path, **kwargs):
        if log is not None:
            log.append((source, kwargs.get("params"), kwargs.get("body")))
        if fail:
            raise vuln_sources.SourceError("timeout")
        if source == "nvd":
            cpe = (kwargs.get("params") or {}).get("cpeName", "")
            return {"totalResults": 1, "vulnerabilities": [nvd]} if nvd and ":openssh:" in cpe else {"totalResults": 0, "vulnerabilities": []}
        return osv or {}
    monkeypatch.setattr(vuln_sources, "http_json", http_json)


def scan_and_read(client, monkeypatch, ports_fn, **kw):
    fake_dns(monkeypatch)
    fake_crtsh(monkeypatch)
    _, _, headers = account_headers(client)
    site, scan_id, status = run_scan(client, headers, ports_fn, monkeypatch)
    body = client.get(f"{W}/{site['id']}/scans/{scan_id}", headers=headers).json()
    return status, body, headers


def test_a_scan_reports_findings_in_the_right_groups_and_never_says_safe(client, monkeypatch):
    log = []
    fake_databases(monkeypatch, nvd=cve(), log=log)
    with BackgroundServer(banner_handler(SSH_UBUNTU)) as ssh, BackgroundServer(http_handler(WEB)) as web:
        status, body, _ = scan_and_read(client, monkeypatch, [ssh.port, web.port])
    assert status == "completed"
    steps = body["scan"]["result"]["steps"]
    assert steps["vulnerabilities"]["state"] == "ok" and steps["lifecycle"]["state"] == "ok"
    findings = body["findings"]
    by_id = {f["check_id"]: f for f in findings}
    # Ubuntu OpenSSH: the CVE is only POSSIBLE (backports) and does not count; the operating system release is confirmed end of life.
    assert by_id["cve:CVE-2016-0777"]["confidence"] == "possible" and by_id["cve:CVE-2016-0777"]["group"] == "needs_checking"
    assert by_id["cve:CVE-2016-0777"]["scored"] is False and "Ubuntu" in by_id["cve:CVE-2016-0777"]["caveat"]
    eol = by_id["eol:distro:ubuntu-14.04"]
    assert eol["severity"] == "high" and eol["scored"] and eol["group"] == "findings" and "no longer receives security updates" in eol["title"]
    # vanilla nginx 1.18.0 has an end-of-life branch and a missing-header set; the server is HTTP-only so no HTTPS
    assert "eol:product:nginx-1.18" in by_id and "http:no-https" in by_id and "cookie:no-httponly" in by_id
    assert body["findings"] == sorted(body["findings"], key=lambda f: ["critical", "high", "medium", "low", "info"].index(f["severity"]) * 10 + (f["group"] != "findings"))
    text = " ".join((f["title"] + " " + (f["why"] or "") + (f["how_to_fix"] or "")).lower() for f in findings)
    assert "is safe" not in text and "clean" not in text.split("cleaning")[0]
    assert "it is not a security verdict" in body["scan"]["message"] or "does not mean your website is safe" in body["scan"]["message"]
    sent = [item for item in log if item[0] == "nvd"]
    assert sent and all(set(item[1]) == {"cpeName", "resultsPerPage"} for item in sent)   # only a name and version were sent
    assert not any("example.com" in str(item) or "127.0.0.1" in str(item) for item in log)


def test_cookie_values_never_reach_the_database_or_the_api(client, monkeypatch):
    fake_databases(monkeypatch)
    with BackgroundServer(http_handler(WEB)) as web:
        _, body, _ = scan_and_read(client, monkeypatch, [web.port])
    assert "abc123SECRET" not in str(body)
    with SessionLocal() as db:
        assert "abc123SECRET" not in str([vars(f) for f in db.query(ScanFinding)])


def test_findings_are_saved_per_scan_and_unique(client, monkeypatch):
    fake_databases(monkeypatch)
    with BackgroundServer(http_handler(WEB)) as web:
        _, body, _ = scan_and_read(client, monkeypatch, [web.port])
    prints = [f["fingerprint"] for f in body["findings"]]
    assert prints and len(prints) == len(set(prints))


def test_when_the_databases_are_down_the_step_is_could_not_check_and_the_scan_is_incomplete(client, monkeypatch):
    fake_databases(monkeypatch, fail=True)
    with BackgroundServer(banner_handler(SSH_UBUNTU)) as ssh:
        status, body, _ = scan_and_read(client, monkeypatch, [ssh.port])
    scan = body["scan"]
    assert status == "incomplete" and scan["result"]["steps"]["vulnerabilities"]["state"] == "could_not_check"
    assert scan["result"]["steps"]["vulnerabilities"]["failed"][0]["reason"] == "timeout"
    assert "known vulnerabilities" in scan["message"] and "does not mean your website is safe" in scan["message"]
    ids = {f["check_id"] for f in body["findings"]}
    assert "eol:distro:ubuntu-14.04" in ids                                # what could be checked is still reported
    assert not any(i.startswith("cve:") for i in ids)                      # and nothing is invented


def test_a_hidden_version_is_an_info_finding_that_says_we_cannot_check(client, monkeypatch):
    fake_databases(monkeypatch)
    with BackgroundServer(banner_handler(b"220 mail ESMTP Postfix\r\n")) as smtp:
        _, body, _ = scan_and_read(client, monkeypatch, [smtp.port])
    hidden = [f for f in body["findings"] if f["check_id"].startswith("disclosure:version-hidden")]
    assert hidden and hidden[0]["severity"] == "info" and hidden[0]["scored"] is False and "cannot check" in hidden[0]["title"]


def test_findings_are_visible_only_to_the_owner(client, monkeypatch):
    fake_databases(monkeypatch)
    with BackgroundServer(http_handler(WEB)) as web:
        _, body, _ = scan_and_read(client, monkeypatch, [web.port])
    site_id, scan_id = body["scan"]["website_id"], body["scan"]["id"]
    _, _, other = account_headers(client)
    assert client.get(f"{W}/{site_id}/scans/{scan_id}", headers=other).status_code == 404


def test_the_scan_stops_cleanly_while_waiting_for_a_slow_database(client, monkeypatch):
    release = threading.Event()
    waiting = threading.Event()

    def slow(source, method, path, **kwargs):
        waiting.set()
        release.wait(30)
        return {"totalResults": 0, "vulnerabilities": []}
    monkeypatch.setattr(vuln_sources, "http_json", slow)
    fake_dns(monkeypatch)
    fake_crtsh(monkeypatch)
    _, _, headers = account_headers(client)
    with BackgroundServer(banner_handler(SSH_UBUNTU)) as ssh, BackgroundServer(http_handler(WEB)) as web:
        site, scan_id, thread, outcome = start_scan(client, headers, ports=[ssh.port, web.port])
        assert waiting.wait(30), "the scan never reached the vulnerability step"
        started = time.monotonic()
        assert client.post(f"{W}/{site['id']}/remove", headers=headers, json={"confirm_domain": site["domain"]}).status_code == 200
        took = finished_within(thread, outcome, started, 10)
    release.set()
    assert took < 6 and outcome["status"] == "incomplete"
    row = scan_row(scan_id)
    assert row.status == "incomplete" and row.result["code"] == "website_removed" and row.result["stopped_step"] == "vulnerabilities"
    with SessionLocal() as db:   # what the configuration step found before the stop is kept
        assert db.query(ScanFinding).filter_by(scan_id=scan_id).count() > 0
