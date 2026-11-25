"""Extra passive checks: HTTPS use, certificate lifetime, cookie flags. Synthetic data; no target traffic."""
import json
import socket
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.assessment import AssessmentReport
from app.models.vulnerability import Vulnerability
from app.services import assessment_broker as broker, assessments as service
from app.services import local_assessment_runtime as runtime, passive_checks as pc, vulnerabilities as vulns
from app.services.header_analyzer import analyze
from test_authorization_correctness import api  # noqa: F401
from test_assessments import assessed  # noqa: F401
from test_local_assessment import network  # noqa: F401

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


def openssl(moment):
    return moment.strftime("%b %d %H:%M:%S %Y GMT")


def by_check(items):
    return {o["check"]: o for o in items}


def run_checks(*, https=True, expires_in_days=None, cookies=None):
    transport = {"tls_verified": https,
                 "certificate_not_after": None if expires_in_days is None else openssl(NOW + timedelta(days=expires_in_days))}
    facts = {"https": https} | ({"cookies": cookies} if cookies is not None else {})
    return by_check(pc.extra_observations(transport, facts, NOW))


# --- HTTPS in use --------------------------------------------------------------------------------

def test_https_site_passes_and_http_site_is_flagged():
    assert run_checks(https=True)["https_in_use"]["observed"] is True
    flagged = run_checks(https=False)["https_in_use"]
    assert flagged["observed"] is False and flagged["severity_suggestion"] == "medium"


# --- Certificate expiry --------------------------------------------------------------------------

@pytest.mark.parametrize("days,observed,severity", [
    (365, True, "informational"), (31, True, "informational"),
    (29, False, "low"), (8, False, "low"), (6, False, "medium"), (0.5, False, "medium"), (-3, False, "medium")])
def test_certificate_expiry_thresholds(days, observed, severity):
    item = run_checks(expires_in_days=days)["certificate_expiry"]
    assert item["observed"] is observed and item["severity_suggestion"] == severity


@pytest.mark.parametrize("not_after", [None, "", "not a date", "x" * 200, 12345, {"a": 1}])
def test_unusable_certificate_dates_are_not_applicable_never_a_false_alarm(not_after):
    items = by_check(pc.extra_observations({"tls_verified": True, "certificate_not_after": not_after}, {}, NOW))
    assert items["certificate_expiry"]["observed"] is None


def test_plain_http_has_no_certificate_to_judge():
    assert run_checks(https=False, expires_in_days=1)["certificate_expiry"]["observed"] is None


def test_iso_dates_are_accepted_too():
    soon = (NOW + timedelta(days=3)).isoformat()
    item = by_check(pc.extra_observations({"tls_verified": True, "certificate_not_after": soon}, {}, NOW))["certificate_expiry"]
    assert item["observed"] is False


# --- Cookie flags --------------------------------------------------------------------------------

def test_cookie_flags_cases():
    assert run_checks()["cookie_flags"]["observed"] is None  # no cookies seen: not applicable
    assert run_checks(cookies={"count": 0, "secure_missing": 0, "httponly_missing": 0, "samesite_missing": 0})["cookie_flags"]["observed"] is None
    good = {"count": 2, "secure_missing": 0, "httponly_missing": 0, "samesite_missing": 0}
    assert run_checks(cookies=good)["cookie_flags"]["observed"] is True
    for flag in ("secure_missing", "httponly_missing", "samesite_missing"):
        item = run_checks(cookies={**good, flag: 1})["cookie_flags"]
        assert item["observed"] is False and item["severity_suggestion"] == "low"


@pytest.mark.parametrize("facts", [None, {}, {"cookies": None}, {"cookies": "x"}, {"cookies": {"count": "2"}},
                                   {"cookies": {"count": 2, "secure_missing": "no"}}, {"cookies": {"count": True}}])
def test_malformed_facts_never_raise_or_alarm(facts):
    items = by_check(pc.extra_observations({"tls_verified": True}, facts, NOW))
    assert items["cookie_flags"]["observed"] is None


# --- Contract with the rest of the platform --------------------------------------------------------

def test_every_extra_observation_is_a_valid_unconfirmed_observation_and_a_known_check():
    for item in pc.extra_observations({"tls_verified": False}, {"https": False}, NOW):
        assert item["check"] in vulns.CHECKS
        assert item["requires_human_validation"] is True and item["confirmed_vulnerability"] is False
        assert item["severity_suggestion"] in vulns.SEVERITIES
    parsed = vulns.parse_observation(run_checks(https=False)["https_in_use"])
    assert parsed == ("https_in_use", "detected", "medium")
    assert vulns.parse_observation(run_checks()["https_in_use"]) == ("https_in_use", "not_detected", "informational")
    assert vulns.parse_observation(run_checks()["cookie_flags"]) is None  # not applicable: no record


def test_merge_does_not_touch_the_container_analysis_and_adds_only_applicable_observations():
    base = analyze({"https": True, "status": 200, "headers": {}})
    snapshot = json.dumps(base, sort_keys=True)
    merged = pc.merge(base, {"tls_verified": True}, {}, NOW)
    assert json.dumps(base, sort_keys=True) == snapshot  # the validated original is unchanged
    assert [o["check"] for o in merged["observations"]][:8] == [o["check"] for o in base["observations"]]
    # No certificate date and no cookies: only HTTPS use applies, so analysts are not asked to review the rest.
    assert [o["check"] for o in merged["observations"][8:]] == ["https_in_use"]
    assert "cookie_names_and_values_never_retained" in merged["limitations"]
    full = pc.merge(base, {"tls_verified": True, "certificate_not_after": openssl(NOW + timedelta(days=90))},
                    {"cookies": {"count": 1, "secure_missing": 0, "httponly_missing": 0, "samesite_missing": 0}}, NOW)
    assert [o["check"] for o in full["observations"][8:]] == ["https_in_use", "certificate_expiry", "cookie_flags"]


def test_analyze_itself_is_unchanged_so_the_vm_image_stays_compatible():
    assert [o["check"] for o in analyze({"https": True, "status": 200, "headers": {}})["observations"]] == [
        "csp", "hsts", "x_frame_options", "csp_frame_ancestors", "x_content_type_options",
        "referrer_policy", "permissions_policy", "server_disclosure"]


# --- The broker counts cookie attributes only ------------------------------------------------------

def test_broker_counts_cookie_flags_and_never_returns_names_or_values(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_HEAD(self):
            self.send_response(200)
            self.send_header("Set-Cookie", "SESSIONID=SECRETVALUE1; Path=/; Secure; HttpOnly; SameSite=Lax")
            self.send_header("Set-Cookie", "tracker=SECRETVALUE2; Path=/")
            self.send_header("Set-Cookie", "pref=SECRETVALUE3; httponly; SAMESITE=None")
            self.end_headers()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    monkeypatch.setattr(broker.policy, "resolve", lambda host, port: [(socket.AF_INET, ("127.0.0.1", server.server_port))])
    try: result = broker.collect("http://synthetic.example/", lambda: True)
    finally: server.shutdown(); server.server_close(); thread.join()
    assert result["facts"]["cookies"] == {"count": 3, "secure_missing": 2, "httponly_missing": 1, "samesite_missing": 1}
    blob = json.dumps(result)
    assert "SECRETVALUE" not in blob and "SESSIONID" not in blob and "tracker" not in blob
    assert "set-cookie" not in result["selected_headers"]
    assert by_check(pc.extra_observations({"tls_verified": False}, result["facts"], NOW))["cookie_flags"]["observed"] is False


# --- Full path: worker run -> report -> unconfirmed vulnerability ----------------------------------

def pipeline(network, monkeypatch, *, facts, cert, tls=True):
    api, _, body = network
    def broker_stub(script, payload, permitted, seconds):
        assert permitted()
        if script == "assessment_broker.py":
            return {"result": {"status": 200, "tls_verified": tls, "tls_version": "TLSv1.3" if tls else None,
                               "connected_ip": "8.8.8.8", "dns_addresses": ["8.8.8.8"], "response_ms": 3.5, "header_bytes": 200,
                               "headers_sha256": "f" * 64, "certificate_not_after": cert, "redirect_followed": False,
                               "redirect": {"is_redirect": False, "location": None, "followed": False},
                               "selected_headers": {"content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                                                    "strict-transport-security": "max-age=31536000", "x-frame-options": "DENY",
                                                    "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
                                                    "permissions-policy": "camera=()"},
                               "facts": facts}}
        return analyze(payload)
    monkeypatch.setattr(runtime, "invoke", broker_stub)
    response = api.post("/api/v1/assessments", json={**body, "idempotency_key": str(uuid4())})
    assert response.status_code == 201, response.text
    service.worker_tick()
    return api, response.json()


def test_insecure_cookies_and_expiring_certificate_become_unconfirmed_findings(network, monkeypatch):
    soon = openssl(datetime.now(UTC) + timedelta(days=5))
    api, row = pipeline(network, monkeypatch, cert=soon, facts={
        "https": True, "cookies": {"count": 1, "secure_missing": 1, "httponly_missing": 1, "samesite_missing": 1}})
    with SessionLocal() as db:
        found = {v.check_id: v for v in db.scalars(select(Vulnerability))}
        report = db.scalar(select(AssessmentReport))
    assert set(found) == {"cookie_flags", "certificate_expiry"}  # secure headers pass; https passes
    assert all(v.validation_state == "unconfirmed" and v.analyst_severity is None for v in found.values())
    assert found["certificate_expiry"].scanner_severity == "medium" and found["cookie_flags"].scanner_severity == "low"
    stored = json.dumps(report.content)
    assert "facts" not in report.content["transport"] and "cookies" not in report.content["transport"]
    assert "cookie_flags" in stored and "cookie_names_and_values_never_retained" in stored


def test_clean_site_creates_no_findings(network, monkeypatch):
    far = openssl(datetime.now(UTC) + timedelta(days=200))
    pipeline(network, monkeypatch, cert=far, facts={
        "https": True, "cookies": {"count": 2, "secure_missing": 0, "httponly_missing": 0, "samesite_missing": 0}})
    with SessionLocal() as db:
        assert list(db.scalars(select(Vulnerability))) == []
