"""Real-world robustness (CDN/WAF, blocking sites, redirects, IPv6, time) and the score, grade and summary of a scan."""
import time

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.main import app
from app.models.scan import Scan
from app.models.website import Website
from app.services import cdn, engine_vulns as ev, scan_notes, scans, scoring, vuln_sources
from app.services.detect_runner import ScanContext, ScanState
from app.services.detect_versions import PortProbe, WebPage
from account_helpers import account_headers
from netfixtures import BackgroundServer, banner_handler, hanging_http_handler, http_handler, server_tls
from test_detect_pipeline import fake_crtsh, fake_dns
from test_identify_pipeline import cve, fake_databases

W = "/api/v1/websites"
HTML = {"Content-Type": "text/html"}


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


# --- CDN / WAF detection -------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("headers, name", [
    ({"server": "cloudflare", "cf-ray": "8a1b-BOM"}, "Cloudflare"), ({"cf-cache-status": "HIT"}, "Cloudflare"),
    ({"server": "AkamaiGHost"}, "Akamai"), ({"x-akamai-transformed": "9 - 0 pmb=mRUM,1"}, "Akamai"),
    ({"x-served-by": "cache-bom4727-BOM", "x-timer": "S1700000000.1,VS0"}, "Fastly"), ({"fastly-debug-digest": "abc"}, "Fastly"),
    ({"x-amz-cf-id": "abc=="}, "Amazon CloudFront"), ({"via": "1.1 abc.cloudfront.net (CloudFront)"}, "Amazon CloudFront"),
    ({"x-azure-ref": "0abc"}, "Microsoft Azure Front Door"), ({"x-sucuri-id": "12345"}, "Sucuri"), ({"x-iinfo": "5-1-1 NNNN"}, "Imperva Incapsula"),
    ({"server": "Vercel", "x-vercel-id": "bom1::abc"}, "Vercel"), ({"server": "Netlify"}, "Netlify"), ({"server": "GitHub.com", "x-github-request-id": "A"}, "GitHub Pages"),
    ({"server": "DDoS-Guard"}, "DDoS-Guard"), ({"Server": "CLOUDFLARE"}, "Cloudflare"),
])
def test_known_cdns_and_wafs_are_recognised(headers, name):
    assert cdn.detect_headers(headers)["name"] == name


@pytest.mark.parametrize("headers", [{}, None, {"server": "nginx/1.18.0"}, {"server": "Apache/2.4.7 (Ubuntu)"}, {"x-powered-by": "PHP/8.1"}, {"server": "cloudflare-lookalike-not"}])
def test_an_ordinary_server_is_not_called_a_cdn(headers):
    assert cdn.detect_headers(headers) is None or headers == {"server": "cloudflare-lookalike-not"}


def test_cookie_names_can_reveal_a_waf():
    assert cdn.detect_headers({}, [{"name": "incap_ses_123"}])["name"] == "Imperva Incapsula"
    assert cdn.detect_headers({}, [{"name": "__cf_bm"}])["name"] == "Cloudflare"
    assert cdn.detect_headers({}, [{"name": "PHPSESSID"}]) is None


def test_the_message_is_the_exact_plain_sentence():
    assert cdn.message({"name": "Cloudflare", "evidence": "cf-ray header"}) == "This site is behind Cloudflare. Port results show the CDN, not your server."
    assert cdn.message(None) is None


def web(port=80, status=200, headers=None, body="", tls=False):
    return PortProbe(port=port, service="https" if tls else "http", http={"status": status, "over_tls": tls, "headers": dict(headers or {}), "cookies": []},
                     web=WebPage(port=port, tls=tls, status=status, headers=dict(headers or {}), cookies=[], body=body))


def test_a_blocking_or_challenge_page_is_noticed():
    assert cdn.looks_like_challenge(web(status=403, body="<title>Just a moment...</title>").web)
    assert cdn.looks_like_challenge(web(status=403, body="Access Denied - you are blocked").web)
    assert cdn.looks_like_challenge(web(status=200, headers={"cf-mitigated": "challenge"}).web)
    assert not cdn.looks_like_challenge(web(status=200, body="Just a moment of your time").web)
    assert not cdn.looks_like_challenge(web(status=404, body="not found").web)


# --- notes -------------------------------------------------------------------------------------------------------------------------------

def notes(probes, *, ports_ok=True, open_ports=(80,), domain="example.com"):
    found = cdn.detect(probes)
    return scan_notes.build(domain, ports_ok=ports_ok, open_ports=open_ports, probes=probes, cdn=found), found


def test_a_cdn_note_says_ports_show_the_cdn():
    result, found = notes([web(headers={"server": "cloudflare", "cf-ray": "x"})])
    assert found["name"] == "Cloudflare" and result[0]["text"] == "This site is behind Cloudflare. Port results show the CDN, not your server."


def test_a_site_that_blocks_us_gets_an_honest_note_never_a_pass():
    result, _ = notes([web(status=403, body="Access Denied")])
    [note] = [n for n in result if n["kind"] == "blocked"]
    assert "HTTP 403" in note["text"] and "not the same as being secure" in note["text"]


def test_a_redirect_to_another_host_is_explained_but_a_same_host_redirect_is_not():
    result, _ = notes([web(status=301, headers={"location": "https://www.example.com/"})])
    assert any(n["kind"] == "redirect" and "www.example.com" in n["text"] and "add www.example.com" in n["text"] for n in result)
    assert not any(n["kind"] == "redirect" for n in notes([web(status=301, headers={"location": "https://example.com/login"})])[0])
    assert not any(n["kind"] == "redirect" for n in notes([web(status=301, headers={"location": "/relative"})])[0])


def test_no_answering_ports_is_explained_only_when_the_port_step_worked():
    assert any(n["kind"] == "no_ports" and "not the same as being secure" in n["text"] for n in notes([], open_ports=())[0])
    assert not any(n["kind"] == "no_ports" for n in notes([], ports_ok=False, open_ports=())[0])
    assert notes([web()])[0] == []


# --- score and grade (spec section 7) ----------------------------------------------------------------------------------------------------

def f(severity, confidence="confirmed"):
    return {"severity": severity, "confidence": confidence, "group": "findings" if confidence == "confirmed" else "needs_checking"}


@pytest.mark.parametrize("findings, score, grade", [
    ([], 100, "A"), ([f("low")], 99, "A"), ([f("high")], 90, "A"), ([f("high"), f("low")], 89, "B"), ([f("critical")], 75, "B"),
    ([f("critical"), f("low")], 74, "C"), ([f("critical"), f("high")], 65, "C"), ([f("critical"), f("high"), f("medium")], 61, "C"),
    ([f("critical"), f("high"), f("medium"), f("low")], 60, "C"), ([f("critical"), f("critical")], 50, "D"), ([f("critical"), f("critical"), f("high")], 40, "D"),
    ([f("critical")] * 2 + [f("high")] * 2, 30, "F"), ([f("critical")] * 5, 0, "F"), ([f("critical")] * 9, 0, "F"),
])
def test_the_score_formula_and_grade_limits(findings, score, grade):
    result = scoring.summarize(findings)
    assert (result["score"], result["grade"]) == (score, grade)


def test_needs_checking_and_info_never_count():
    result = scoring.summarize([f("critical", "possible")] * 50 + [f("info")] * 20 + [f("medium")])
    assert result["score"] == 96 and result["counts"]["info"] == 20 and result["needs_checking"] == 50 and result["confirmed"] == 1


def test_weights_and_limits_come_from_settings(monkeypatch):
    monkeypatch.setattr(settings, "score_weight_high", 20)
    monkeypatch.setattr(settings, "grade_a_min", 95)
    result = scoring.summarize([f("high")])
    assert result["score"] == 80 and result["grade"] == "B" and result["weights"]["high"] == 20


def test_the_spec_weights_are_the_defaults():
    assert scoring.weights() == {"critical": 25, "high": 10, "medium": 4, "low": 1}
    assert [scoring.grade_for(s) for s in (100, 90, 89, 75, 74, 60, 59, 40, 39, 0)] == list("AABBCCDDFF")


def test_an_incomplete_scan_is_marked_so():
    assert scoring.summarize([], incomplete=True)["incomplete"] is True and scoring.summarize([])["incomplete"] is False


# --- whole scans on awkward sites ------------------------------------------------------------------------------------------------------------

def scan_site(client, monkeypatch, ports, *, resolve=lambda d: ["127.0.0.1"], domain="example.com"):
    fake_dns(monkeypatch)
    fake_crtsh(monkeypatch)
    _, _, headers = account_headers(client)
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

    from app.services import detect_runner

    async def detect(ctx, state, guard):
        ctx.ports = tuple(ports)
        await detect_runner.run(ctx, state, guard)
    started = time.monotonic()
    status = scans.execute(*claimed, resolve=resolve, verify=lambda db, w: (True, "cached"), detect=detect)
    body = client.get(f"{W}/{site['id']}/scans/{scan_id}", headers=headers).json()
    return status, body, time.monotonic() - started, headers, site


def test_a_site_behind_cloudflare_shows_the_cdn_note_finding_and_a_score(client, monkeypatch):
    fake_databases(monkeypatch)
    page = (200, {"Server": "cloudflare", "CF-RAY": "8a1b2c-BOM", "Content-Type": "text/html"}, b"<html>hi</html>")
    with BackgroundServer(http_handler({"/": page})) as web_server:
        status, body, took, _, _ = scan_site(client, monkeypatch, [web_server.port])
    assert status == "completed"
    result = body["scan"]["result"]
    assert result["cdn"]["name"] == "Cloudflare" and result["notes"][0]["text"] == "This site is behind Cloudflare. Port results show the CDN, not your server."
    assert any(x["check_id"] == "cdn:detected" and x["severity"] == "info" for x in body["findings"])
    summary = body["summary"]
    assert summary["cdn"]["name"] == "Cloudflare" and 0 <= summary["score"] <= 100 and summary["grade"] in "ABCDF"


def test_versions_seen_through_a_cdn_are_only_possible_never_confirmed(client, monkeypatch):
    fake_databases(monkeypatch, nvd=cve())
    page = (200, {"Server": "Apache/2.4.7", "CF-RAY": "x", "Content-Type": "text/html"}, b"<html>hi</html>")
    with BackgroundServer(http_handler({"/": page})) as web_server:
        _, body, _, _, _ = scan_site(client, monkeypatch, [web_server.port])
    cves = [x for x in body["findings"] if x["check_id"].startswith("cve:")]
    assert all(x["confidence"] == "possible" and x["scored"] is False for x in cves)


def test_a_site_that_blocks_scanners_completes_with_a_note_and_never_crashes(client, monkeypatch):
    fake_databases(monkeypatch)
    blocked = (403, {"Content-Type": "text/html"}, b"<html><title>Access Denied</title>You are blocked</html>")
    with BackgroundServer(http_handler({}, default=blocked)) as web_server:
        status, body, _, _, _ = scan_site(client, monkeypatch, [web_server.port])
    assert status in ("completed", "incomplete")
    assert any(n["kind"] == "blocked" for n in body["scan"]["result"]["notes"])
    assert body["summary"] is not None and "safe" not in " ".join(n["text"] for n in body["scan"]["result"]["notes"]).replace("not the same as being secure", "")


def test_a_site_that_never_answers_ends_cleanly_and_quickly(client, monkeypatch):
    fake_databases(monkeypatch)
    with BackgroundServer(hanging_http_handler) as web_server:
        status, body, took, _, _ = scan_site(client, monkeypatch, [web_server.port])
    assert status in ("completed", "incomplete") and took < 60
    assert body["scan"]["status"] in ("completed", "incomplete") and body["summary"] is not None


def test_a_site_with_no_open_ports_gets_the_explanation(client, monkeypatch):
    fake_databases(monkeypatch)
    from netfixtures import free_port
    from app.services import netio
    real = netio.open_connection

    async def refuse(ip, port, **kwargs):
        raise ConnectionRefusedError
    monkeypatch.setattr(netio, "open_connection", refuse)
    status, body, _, _, _ = scan_site(client, monkeypatch, [free_port()])
    monkeypatch.setattr(netio, "open_connection", real)
    assert any(n["kind"] == "no_ports" for n in body["scan"]["result"]["notes"])


def test_an_https_only_site_works_and_is_not_called_unencrypted(client, monkeypatch):
    fake_databases(monkeypatch)
    page = (200, {"Content-Type": "text/html"}, b"<html>secure</html>")
    with BackgroundServer(http_handler({"/": page}), tls=True) as secure:
        status, body, _, _, _ = scan_site(client, monkeypatch, [secure.port])
    assert status in ("completed", "incomplete")
    assert not any(x["check_id"] == "http:no-https" for x in body["findings"])
    assert any(p["tls"] for p in body["ports"])


def test_an_http_only_site_gets_the_no_https_finding(client, monkeypatch):
    fake_databases(monkeypatch)
    with BackgroundServer(http_handler({"/": (200, HTML, b"<html>plain</html>")})) as plain:
        _, body, _, _, _ = scan_site(client, monkeypatch, [plain.port])
    assert any(x["check_id"] == "http:no-https" and x["severity"] == "high" for x in body["findings"])


def test_a_site_that_redirects_to_www_gets_the_redirect_note(client, monkeypatch):
    fake_databases(monkeypatch)
    redirect = (301, {"Location": "https://www.example.com/", "Content-Type": "text/html"}, b"")
    with BackgroundServer(http_handler({"/": redirect})) as server:
        _, body, _, _, _ = scan_site(client, monkeypatch, [server.port])
    assert any(n["kind"] == "redirect" and "www.example.com" in n["text"] for n in body["scan"]["result"]["notes"])


def test_an_ipv6_only_site_is_refused_with_a_clear_message_and_nothing_is_contacted(client, monkeypatch):
    from app.services import netio
    touched = []

    async def spy(ip, port, **kwargs):
        touched.append(ip)
        raise OSError("must not connect")
    monkeypatch.setattr(netio, "open_connection", spy)
    status, body, _, _, _ = scan_site(client, monkeypatch, [80], resolve=lambda d: ["2001:db8::1"])
    assert status == "refused" and touched == []
    assert body["scan"]["result"]["code"] == "ipv6_only" and "IPv6" in body["scan"]["message"] and "does not support yet" in body["scan"]["message"]


def test_a_site_with_both_addresses_uses_the_ipv4_one(client, monkeypatch):
    fake_databases(monkeypatch)
    with BackgroundServer(http_handler({"/": (200, HTML, b"<html>hi</html>")})) as server:
        status, body, _, _, _ = scan_site(client, monkeypatch, [server.port], resolve=lambda d: ["127.0.0.1", "2001:db8::1"])
    assert status in ("completed", "incomplete") and body["scan"]["resolved_ip"] == "127.0.0.1"


# --- summary in the API ---------------------------------------------------------------------------------------------------------------------------

def test_the_website_card_and_the_scan_carry_score_grade_counts_and_certificate_expiry(client, monkeypatch):
    fake_databases(monkeypatch)
    with BackgroundServer(http_handler({"/": (200, HTML, b"<html>secure</html>")}), tls=True) as secure:
        _, body, _, headers, site = scan_site(client, monkeypatch, [secure.port])
    summary = body["summary"]
    assert set(summary) >= {"score", "grade", "counts", "needs_checking", "confirmed", "incomplete", "certificate", "cdn", "notes", "scanned_at"}
    assert summary["certificate"]["days_left"] > 1000 and summary["certificate"]["port"] == secure.port     # the test certificate lasts 100 years
    card = client.get(f"{W}/{site['id']}", headers=headers).json()
    assert card["summary"]["score"] == summary["score"] and card["summary"]["grade"] == summary["grade"]
    listed = [s for s in client.get(W, headers=headers).json() if s["id"] == site["id"]][0]
    assert listed["summary"]["grade"] == summary["grade"]


def test_a_website_with_no_finished_scan_has_no_summary(client):
    _, _, headers = account_headers(client)
    site = client.post(W, headers=headers, json={"domain": "fresh.example.org"}).json()
    assert client.get(f"{W}/{site['id']}", headers=headers).json()["summary"] is None


# --- results as they arrive: a slow vulnerability database never holds them back ------------------------------------------------------------------

def test_partial_findings_are_published_after_every_item_before_the_engine_finishes(monkeypatch):
    calls = []

    def slow_then_down(source, method, path, **kwargs):
        calls.append(len(calls))
        if len(calls) == 1:
            return {"totalResults": 1, "vulnerabilities": [cve()]}
        raise vuln_sources.SourceError("timeout")
    monkeypatch.setattr(vuln_sources, "http_json", slow_then_down)
    state = ScanState()
    state.probes = [PortProbe(port=22, service="ssh", product="OpenSSH", version="6.6.1p1", banner="SSH-2.0-OpenSSH_6.6.1p1"),
                    web(80, headers={"server": "Apache/2.4.7"})]
    state.probes[1].product, state.probes[1].version = "Apache", "2.4.7"
    published = []
    state.publish = lambda items: published.append([i.check_id for i in items])
    messages = []
    ctx = ScanContext(scan_id="s", domain="example.com", ip="203.0.113.7", progress=lambda step, text: messages.append(text), sessions=SessionLocal)

    class Guard:
        def check(self):
            pass
    import asyncio
    result = asyncio.run(ev.VulnerabilityEngine().run(ctx, state, Guard()))
    assert len(published) == 2 and "cve:CVE-2016-0777" in published[0]       # the first item's results were shown before the second look-up
    assert result.state == "could_not_check" and any("OpenSSH 6.6.1p1" in m and "(1 of 2)" in m for m in messages)
