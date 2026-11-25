"""Module H: remediation tracking, scoped retests and assessment closure. Synthetic scanner output only."""
import json
import sqlite3
from datetime import timedelta
from uuid import uuid4

import jwt
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.core import rbac
from app.core.config import settings
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.models.admin import Admin
from app.models.assessment import AssessmentRequest
from app.models.authorization import WebsiteAuthorization
from app.models.remediation import (AssessmentClosure, RemediationEvent, RetestRequest, VulnerabilityRemediation)
from app.models.vulnerability import VulnerabilityOccurrence
from app.services import assessments as assess_service, job_engine as engine
from app.services import local_assessment_runtime as runtime, remote_assessment_runtime as remote
from app.services import vulnerabilities as vulns
from app.services.header_analyzer import analyze
from test_assessments import assessed  # noqa: F401 - fixture
from test_authorization_correctness import api, NOW  # noqa: F401 - fixture
from test_local_assessment import network  # noqa: F401 - fixture
from test_migrations import migrate
from test_vulnerabilities import ONLY_DISCLOSURE, assess, one, run
from test_workbench import signoff

REM = "/api/v1/remediation"
AS = "/api/v1/assessments"
NIL = "00000000-0000-4000-8000-000000000000"
NOTE = "Engineering deployed the header change at the CDN edge on the production site."
FIXED = {**ONLY_DISCLOSURE, "content-security-policy": "default-src 'self'; frame-ancestors 'none'"}
FIXED_ALL = {**FIXED, "strict-transport-security": "max-age=31536000"}


def confirm(client, check):
    item = one(client, check)
    assert assess(client, item).status_code == 201
    assert signoff(client, item).status_code == 200
    return item


def patch_scanner(monkeypatch, headers, minutes):
    """Synthetic scanner at NOW + minutes (same broker shape as test_vulnerabilities.run)."""
    at = NOW + timedelta(minutes=minutes)
    monkeypatch.setattr(assess_service, "utc_now", lambda: at)
    monkeypatch.setattr(engine, "utc_now", lambda: at)

    def broker(script, payload, permitted, seconds):
        assert permitted()
        if script == "assessment_broker.py":
            return {"result": {"status": 200, "tls_verified": True, "tls_version": "TLSv1.3", "connected_ip": "8.8.8.8",
                               "dns_addresses": ["8.8.8.8"], "response_ms": 3.5, "header_bytes": 200,
                               "headers_sha256": "f" * 64, "certificate_not_after": None, "redirect_followed": False,
                               "redirect": {"is_redirect": False, "location": None, "followed": False},
                               "selected_headers": dict(headers), "facts": {}}}
        return analyze(payload)
    monkeypatch.setattr(runtime, "invoke", broker)
    monkeypatch.setattr(remote, "invoke", broker)


def update(client, vid, status, version, **changes):
    body = {"expected_version": version, "status": status, "note": NOTE} | changes
    return client.post(f"{REM}/{vid}/update", json=body)


def get(client, vid):
    response = client.get(f"{REM}/{vid}")
    assert response.status_code == 200, response.text
    return response.json()


def request_retest(client, vid, version, **changes):
    body = {"expected_version": version, "authorization_id": client.auth_id, "explicitly_requested": True,
            "network_permission_confirmed": True, "note": "Verify the CDN header change on the exact target."} | changes
    return client.post(f"{REM}/{vid}/retests", json=body)


def reopen(client, vid, version, **changes):
    return client.post(f"{REM}/{vid}/reopen", json={"expected_version": version,
                                                    "reason": "The fix was rolled back during the release."} | changes)


def run_worker():
    assess_service.worker_tick()


@pytest.fixture
def tracked(network, monkeypatch):
    row = run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    client = network[0]
    client.assessment_id, client.auth_id, client.monkeypatch = row["id"], network[1], monkeypatch
    client.vid = confirm(client, "csp")["id"]
    return client


@pytest.fixture
def submitted(tracked):
    assert update(tracked, tracked.vid, "fix_submitted", 0).status_code == 200
    return tracked


def retest_cycle(client, headers, minutes):
    """Request a retest and let the worker execute and ingest it."""
    patch_scanner(client.monkeypatch, headers, minutes)
    version = get(client, client.vid)["version"]
    response = request_retest(client, client.vid, version)
    assert response.status_code == 201, response.text
    run_worker()
    return get(client, client.vid)


# --- Remediation lifecycle and client updates ---------------------------------------------

def test_confirmed_findings_start_open_and_status_changes_record_client_updates(tracked):
    first = get(tracked, tracked.vid)
    assert first["status"] == "open" and first["version"] == 0 and first["events"] == []
    target = (utc_now() + timedelta(days=14)).date().isoformat()
    progress = update(tracked, tracked.vid, "in_progress", 0, note="Ticket OPS-12 opened with the platform team.\x00",
                      target_date=target)
    assert progress.status_code == 200, progress.text
    body = progress.json()
    assert body["status"] == "in_progress" and body["version"] == 1 and body["target_date"] == target
    assert body["client_note"] == "Ticket OPS-12 opened with the platform team."  # control characters removed
    assert update(tracked, tracked.vid, "fix_submitted", 1, note="Fix deployed to production; ready for verification.").status_code == 200
    final = get(tracked, tracked.vid)
    assert final["status"] == "fix_submitted" and final["target_date"] == target  # kept when omitted
    history = list(reversed(final["events"]))
    assert [(e["from_status"], e["to_status"], e["action"]) for e in history] == [
        ("open", "in_progress", "status_updated"), ("in_progress", "fix_submitted", "status_updated")]
    assert all(e["actor_id"] == tracked.admin_id and e["actor_name"] and e["occurred_at"].endswith("+00:00") for e in history)
    assert final["can_request_retest"] is True and final["allowed_statuses"] == ["in_progress", "risk_accepted"]


def test_illegal_transitions_stale_versions_and_unconfirmed_findings_are_refused(tracked):
    assert update(tracked, tracked.vid, "open", 0).status_code == 409  # open -> open
    assert update(tracked, tracked.vid, "verified_fixed", 0).status_code == 422  # only a retest can verify
    assert update(tracked, tracked.vid, "retest_requested", 0).status_code == 422  # only a retest request can
    assert update(tracked, tracked.vid, "in_progress", 5).status_code == 409  # stale version
    assert update(tracked, tracked.vid, "in_progress", 0).status_code == 200
    assert update(tracked, tracked.vid, "in_progress", 0).status_code == 409  # concurrent duplicate
    assert update(tracked, tracked.vid, "fix_submitted", 1).status_code == 200
    assert update(tracked, tracked.vid, "open", 2).status_code == 409  # cannot walk back after submitting
    unconfirmed = one(tracked, "hsts")
    for call in (lambda: update(tracked, unconfirmed["id"], "in_progress", 0), lambda: tracked.get(f"{REM}/{unconfirmed['id']}"),
                 lambda: reopen(tracked, unconfirmed["id"], 0), lambda: request_retest(tracked, unconfirmed["id"], 0)):
        assert call().status_code == 409
    with SessionLocal() as db:
        assert db.query(VulnerabilityRemediation).count() == 1


@pytest.mark.parametrize("bad", [
    {"note": "short"}, {"target_date": "2020-01-01"}, {"target_date": "2099-01-01"}, {"target_date": "not-a-date"},
    {"unexpected": 1}, {"expected_version": "0"}, {"expected_version": -1}, {"note": " " * 30}, {"note": "\x00" * 30}])
def test_invalid_updates_are_rejected_without_writes(tracked, bad):
    assert update(tracked, tracked.vid, "in_progress", 0, **bad).status_code in (409, 422)
    with SessionLocal() as db:
        assert db.query(VulnerabilityRemediation).count() == 0 and db.query(RemediationEvent).count() == 0


def test_risk_acceptance_needs_attestation_and_a_real_justification(tracked):
    assert update(tracked, tracked.vid, "risk_accepted", 0).status_code == 422  # no attestation
    assert update(tracked, tracked.vid, "risk_accepted", 0, human_validation_confirmed=True, note="Accepted.......").status_code == 422
    accepted = update(tracked, tracked.vid, "risk_accepted", 0, human_validation_confirmed=True,
                      note="Business owner accepts the residual risk until the platform migration in Q2.")
    assert accepted.status_code == 200 and accepted.json()["status"] == "risk_accepted"
    assert accepted.json()["risk_acceptance_reason"].startswith("Business owner") and accepted.json()["risk_accepted_at"]
    assert get(tracked, tracked.vid)["events"][0]["action"] == "risk_accepted"
    assert update(tracked, tracked.vid, "in_progress", 1).status_code == 409  # only a reopen leaves risk acceptance


# --- Authorisation-gated retests -----------------------------------------------------------

def test_retest_needs_a_submitted_fix_and_explicit_confirmation(tracked):
    assert request_retest(tracked, tracked.vid, 0).status_code == 409  # still open
    assert update(tracked, tracked.vid, "fix_submitted", 0).status_code == 200
    for bad in ({"explicitly_requested": False}, {"network_permission_confirmed": False}, {"note": "short"},
                {"authorization_id": 0}, {"unexpected": 1}, {"expected_version": "1"}):
        assert request_retest(tracked, tracked.vid, 1, **bad).status_code == 422
    assert request_retest(tracked, tracked.vid, 0).status_code == 409  # stale version
    with SessionLocal() as db:
        assert db.query(RetestRequest).count() == 0 and db.query(AssessmentRequest).count() == 1


@pytest.mark.parametrize("change", ["revoked", "expired", "scope", "method", "unknown_authorization"])
def test_retest_requests_revalidate_authorisation_scope_and_methods(submitted, monkeypatch, change):
    patch_scanner(monkeypatch, FIXED, 10)
    changes = {}
    if change == "revoked":
        assert submitted.post(f"/api/v1/authorizations/{submitted.auth_id}/revoke",
                              json={"reason": "Synthetic withdrawal of written permission."}).status_code == 200
    elif change == "expired":
        monkeypatch.setattr(assess_service, "utc_now", lambda: NOW + timedelta(hours=2))
    elif change == "unknown_authorization":
        changes["authorization_id"] = 999999
    else:
        with SessionLocal() as db:
            record = db.get(WebsiteAuthorization, submitted.auth_id)
            if change == "scope": record.authorized_domains = ["other.example.com"]
            else: record.permitted_methods = ["passive_reconnaissance"]
            db.commit()
    response = request_retest(submitted, submitted.vid, 1, **changes)
    assert response.status_code == 409 and "Assessment blocked" in response.json()["detail"], response.text
    after = get(submitted, submitted.vid)
    assert after["status"] == "fix_submitted" and after["retests"] == []
    with SessionLocal() as db:
        assert db.query(RetestRequest).count() == 0 and db.query(AssessmentRequest).count() == 1
        assert db.query(RemediationEvent).count() == 1  # only the submission


def test_retest_is_refused_when_the_website_target_no_longer_matches_the_finding(submitted):
    with SessionLocal() as db:
        db.execute(text("UPDATE websites SET url = 'https://moved.example.com/'"))
        db.commit()
    assert request_retest(submitted, submitted.vid, 1).status_code == 409


def test_revocation_after_a_retest_request_fails_the_retest_closed(submitted, monkeypatch):
    patch_scanner(monkeypatch, FIXED, 10)
    assert request_retest(submitted, submitted.vid, 1).status_code == 201
    assert get(submitted, submitted.vid)["status"] == "retest_requested"
    monkeypatch.setattr(runtime, "invoke", lambda *a: pytest.fail("No target traffic after revocation"))
    monkeypatch.setattr(remote, "invoke", lambda *a: pytest.fail("No target traffic after revocation"))
    assert submitted.post(f"/api/v1/authorizations/{submitted.auth_id}/revoke",
                          json={"reason": "Synthetic withdrawal of written permission."}).status_code == 200
    run_worker()
    after = get(submitted, submitted.vid)
    assert after["status"] == "fix_submitted" and after["retests"][0]["status"] == "failed"
    assert after["retests"][0]["failure_code"] == "job_cancelled" and after["retests"][0]["assessment_status"] == "cancelled"
    assert after["events"][0]["action"] == "retest_failed" and after["events"][0]["actor_name"] == "system"
    assert after["retest_attempts"] == 0  # a failed run is not a conclusive attempt
    with SessionLocal() as db:
        assert db.query(VulnerabilityOccurrence).filter_by(assessment_id=after["retests"][0]["assessment_id"]).count() == 0


def test_one_retest_at_a_time_and_a_retest_cannot_be_reopened_mid_flight(submitted, monkeypatch):
    patch_scanner(monkeypatch, FIXED, 10)
    assert request_retest(submitted, submitted.vid, 1).status_code == 201
    pending = get(submitted, submitted.vid)
    assert pending["can_request_retest"] is False and pending["active_retest_id"] and pending["allowed_statuses"] == []
    assert request_retest(submitted, submitted.vid, pending["version"]).status_code == 409
    assert reopen(submitted, submitted.vid, pending["version"]).status_code == 409
    assert update(submitted, submitted.vid, "in_progress", pending["version"]).status_code == 409


# --- Fix verification and automatic reopening -----------------------------------------------

def test_a_retest_that_no_longer_detects_the_weakness_verifies_the_fix(submitted):
    done = retest_cycle(submitted, FIXED, 10)
    assert done["status"] == "verified_fixed" and done["retest_attempts"] == 1
    retest = done["retests"][0]
    assert retest["status"] == "completed" and retest["outcome"] == "verified_fixed" and retest["attempt"] == 1
    assert retest["assessment_status"] == "completed" and retest["evidence_sha256"] and retest["occurrence_id"]
    with SessionLocal() as db:
        occurrence = db.get(VulnerabilityOccurrence, retest["occurrence_id"])
        assert occurrence.result == "not_detected" and occurrence.assessment_id == retest["assessment_id"]
        assert occurrence.evidence_sha256 == retest["evidence_sha256"]
    assert [e["action"] for e in done["events"][:2]] == ["retest_verified_fixed", "retest_requested"]
    assert done["events"][0]["actor_name"] == "system" and done["events"][1]["actor_name"] != "system"


def test_a_retest_that_still_reproduces_reopens_with_fresh_evidence_and_counts_the_attempt(submitted):
    first = retest_cycle(submitted, ONLY_DISCLOSURE, 10)
    assert first["status"] == "reopened" and first["retest_attempts"] == 1
    retest = first["retests"][0]
    assert retest["outcome"] == "still_present"
    with SessionLocal() as db:
        occurrence = db.get(VulnerabilityOccurrence, retest["occurrence_id"])
        assert occurrence.result == "detected" and occurrence.assessment_id == retest["assessment_id"]
    assert first["events"][0]["action"] == "retest_still_present" and first["events"][0]["detail"]["occurrence_id"] == retest["occurrence_id"]
    # Second cycle: reopened -> fix submitted -> retest passes.
    assert update(submitted, submitted.vid, "fix_submitted", first["version"], note="Second fix deployed after the rollback.").status_code == 200
    second = retest_cycle(submitted, FIXED, 20)
    assert second["status"] == "verified_fixed" and second["retest_attempts"] == 2
    assert [r["attempt"] for r in second["retests"]] == [2, 1] and second["retests"][1]["outcome"] == "still_present"


def test_retest_waits_for_ingestion_then_resolves_through_the_worker_hook(submitted, monkeypatch):
    patch_scanner(monkeypatch, FIXED, 10)
    monkeypatch.setattr(vulns, "ingest_after_assessment", lambda assessment_id: None)
    assert request_retest(submitted, submitted.vid, 1).status_code == 201
    run_worker()
    waiting = get(submitted, submitted.vid)
    assert waiting["status"] == "retest_requested" and waiting["retests"][0]["status"] == "requested"
    monkeypatch.undo()
    vulns.ingest_after_assessment(waiting["retests"][0]["assessment_id"])
    with SessionLocal() as db:
        assert db.query(RetestRequest).one().outcome == "verified_fixed"
    assert get(submitted, submitted.vid)["status"] == "verified_fixed"


def test_a_retest_without_an_applicable_observation_is_inconclusive(submitted, monkeypatch):
    patch_scanner(monkeypatch, FIXED, 10)
    monkeypatch.setattr(vulns, "ingest_after_assessment", lambda assessment_id: None)
    assert request_retest(submitted, submitted.vid, 1).status_code == 201
    run_worker()
    with SessionLocal() as db:
        vulns.ingest_pending(db)
        db.execute(text("DELETE FROM vulnerability_occurrences WHERE assessment_id IN (SELECT assessment_id FROM retest_requests)"))
        db.commit()
    after = get(submitted, submitted.vid)
    assert after["status"] == "fix_submitted" and after["retests"][0]["outcome"] == "inconclusive"
    assert after["retest_attempts"] == 0 and after["events"][0]["action"] == "retest_inconclusive"
    assert after["can_request_retest"] is True


def test_retest_evidence_that_fails_its_hash_check_is_inconclusive_not_verified(submitted, monkeypatch):
    patch_scanner(monkeypatch, FIXED, 10)
    monkeypatch.setattr(vulns, "ingest_after_assessment", lambda assessment_id: None)
    assert request_retest(submitted, submitted.vid, 1).status_code == 201
    run_worker()
    with SessionLocal() as db:
        vulns.ingest_pending(db)
        db.execute(text("UPDATE vulnerability_occurrences SET evidence = '{\"forged\": true}' WHERE assessment_id IN "
                        "(SELECT assessment_id FROM retest_requests)"))
        db.commit()
    assert get(submitted, submitted.vid)["retests"][0]["outcome"] == "inconclusive"
    assert get(submitted, submitted.vid)["status"] == "fix_submitted"


# --- Manual reopening --------------------------------------------------------------------

def test_analysts_can_reopen_verified_accepted_and_submitted_findings_with_a_reason(submitted):
    done = retest_cycle(submitted, FIXED, 10)
    assert reopen(submitted, submitted.vid, done["version"], reason="too short").status_code == 422
    reopened = reopen(submitted, submitted.vid, done["version"])
    assert reopened.status_code == 200 and reopened.json()["status"] == "reopened"
    assert reopened.json()["events"][0]["action"] == "reopened" and reopened.json()["events"][0]["detail"]["reopened_from"] == "verified_fixed"
    assert reopen(submitted, submitted.vid, reopened.json()["version"]).status_code == 409  # already reopened
    version = reopened.json()["version"]
    accepted = update(submitted, submitted.vid, "risk_accepted", version, human_validation_confirmed=True,
                      note="Risk accepted by the business owner until the next release train.")
    assert accepted.status_code == 200
    again = reopen(submitted, submitted.vid, accepted.json()["version"])
    assert again.status_code == 200 and again.json()["risk_acceptance_reason"] is None and again.json()["risk_accepted_at"] is None
    assert reopen(submitted, submitted.vid, 99).status_code == 409  # stale version


def test_open_findings_cannot_be_reopened(tracked):
    assert reopen(tracked, tracked.vid, 0).status_code == 409
    assert update(tracked, tracked.vid, "in_progress", 0).status_code == 200
    assert reopen(tracked, tracked.vid, 1).status_code == 409


# --- Assessment closure ------------------------------------------------------------------

def close(client, **changes):
    body = {"human_validation_confirmed": True, "justification": "All confirmed findings are verified or formally accepted."} | changes
    return client.post(f"{AS}/{client.assessment_id}/close", json=body)


def test_closure_is_blocked_while_confirmed_findings_are_unresolved(tracked):
    state = tracked.get(f"{AS}/{tracked.assessment_id}/closure").json()
    assert state["closed"] is False and state["can_close"] is False and state["confirmed_count"] == 1
    assert state["blockers"][0]["status"] == "open" and state["unreviewed_count"] == 7
    assert "1 open" in state["blocking_reasons"][0]
    for status, version in (("in_progress", 0), ("fix_submitted", 1)):
        assert update(tracked, tracked.vid, status, version).status_code == 200
        blocked = close(tracked)
        assert blocked.status_code == 409 and "unresolved" in blocked.json()["detail"], blocked.text
    reopened = retest_cycle(tracked, ONLY_DISCLOSURE, 10)
    assert reopened["status"] == "reopened"
    assert close(tracked).status_code == 409
    pending = update(tracked, tracked.vid, "fix_submitted", reopened["version"])
    patch_scanner(tracked.monkeypatch, FIXED, 20)
    assert request_retest(tracked, tracked.vid, pending.json()["version"]).status_code == 201
    assert close(tracked).status_code == 409  # a pending retest also blocks
    with SessionLocal() as db:
        assert db.query(AssessmentClosure).count() == 0


def test_assessment_closes_once_every_confirmed_finding_is_verified_or_formally_accepted(tracked):
    hsts = confirm(tracked, "hsts")
    assert update(tracked, tracked.vid, "fix_submitted", 0).status_code == 200
    assert close(tracked).status_code == 409
    assert retest_cycle(tracked, FIXED, 10)["status"] == "verified_fixed"
    assert close(tracked).status_code == 409  # hsts is still open
    accepted = update(tracked, hsts["id"], "risk_accepted", 0, human_validation_confirmed=True,
                      note="HSTS deferred: the legacy payment gateway still needs plain HTTP until June.")
    assert accepted.status_code == 200
    ready = tracked.get(f"{AS}/{tracked.assessment_id}/closure").json()
    assert ready["can_close"] is True and ready["status_counts"] == {"verified_fixed": 1, "risk_accepted": 1}
    assert close(tracked, justification="short").status_code == 422
    assert close(tracked, human_validation_confirmed=False).status_code == 422
    assert close(tracked, unexpected=1).status_code == 422
    closed = close(tracked)
    assert closed.status_code == 200, closed.text
    body = closed.json()
    assert body["closed"] is True and body["can_close"] is False and body["closure"]["closed_by"] == tracked.admin_id
    summary = {f["check_id"]: f for f in body["closure"]["summary"]["findings"]}
    assert summary["csp"]["status"] == "verified_fixed" and summary["hsts"]["risk_acceptance_reason"].startswith("HSTS deferred")
    assert len(body["closure"]["content_sha256"]) == 64 and body["closure"]["closed_at"].endswith("+00:00")
    assert close(tracked).status_code == 409  # cannot close twice
    assert tracked.get(f"{AS}/{tracked.assessment_id}/closure").json()["closure"]["id"] == body["closure"]["id"]


def test_closure_of_unknown_assessments_and_assessments_without_confirmed_findings(network, monkeypatch):
    client = network[0]
    client.assessment_id = NIL
    assert close(client).status_code == 404 and client.get(f"{AS}/{NIL}/closure").status_code == 404
    row = run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    client.assessment_id = row["id"]
    state = client.get(f"{AS}/{row['id']}/closure").json()
    assert state["confirmed_count"] == 0 and state["can_close"] is True and state["unreviewed_count"] == 8
    assert close(client).status_code == 200


# --- Authentication, RBAC and sanitisation ------------------------------------------------

def endpoints(tracked):
    vid, aid = tracked.vid, tracked.assessment_id
    return [("get", REM), ("get", f"{REM}/{vid}"), ("post", f"{REM}/{vid}/update"), ("post", f"{REM}/{vid}/reopen"),
            ("get", f"{REM}/{vid}/retests"), ("post", f"{REM}/{vid}/retests"), ("get", f"{AS}/{aid}/closure"),
            ("post", f"{AS}/{aid}/close")]


def call(client, method, path):
    return getattr(client, method)(path, **({"json": {}} if method == "post" else {}))


def test_every_remediation_and_closure_route_rejects_unauthenticated_callers(tracked):
    token = tracked.headers.pop("Authorization")
    try:
        for method, path in endpoints(tracked):
            assert call(tracked, method, path).status_code == 401, path
        tracked.headers["Authorization"] = "Bearer not.a.jwt"
        for method, path in endpoints(tracked):
            assert call(tracked, method, path).status_code == 401, path
    finally:
        tracked.headers["Authorization"] = token
    assert tracked.get(REM).status_code == 200


def test_forged_role_tokens_and_deactivated_admins_are_rejected_without_writes(tracked):
    original = tracked.headers["Authorization"]
    key = settings.jwt_secret_key.get_secret_value()
    claims = jwt.decode(original.split()[1], key, algorithms=["HS256"], audience=settings.jwt_audience)
    try:
        tracked.headers["Authorization"] = "Bearer " + jwt.encode({**claims, "role": "viewer"}, key, algorithm="HS256")
        for method, path in endpoints(tracked):
            assert call(tracked, method, path).status_code == 401, path
    finally:
        tracked.headers["Authorization"] = original
    with SessionLocal() as db:
        db.get(Admin, tracked.admin_id).is_active = False
        db.commit()
    for method, path in endpoints(tracked):
        assert call(tracked, method, path).status_code == 401, path
    with SessionLocal() as db:
        assert db.query(VulnerabilityRemediation).count() == 0 and db.query(AssessmentClosure).count() == 0


def test_role_allow_lists_gate_remediation_risk_acceptance_and_closure_separately(tracked, monkeypatch):
    accept = {"human_validation_confirmed": True, "note": "Risk accepted by the business owner for this quarter."}
    monkeypatch.setattr(rbac, "RISK_ACCEPTANCE_ROLES", frozenset())
    assert update(tracked, tracked.vid, "risk_accepted", 0, **accept).status_code == 403
    assert update(tracked, tracked.vid, "in_progress", 0).status_code == 200  # other updates still allowed
    monkeypatch.undo()
    monkeypatch.setattr(rbac, "CLOSURE_ROLES", frozenset())
    assert close(tracked).status_code == 403 and tracked.get(f"{AS}/{tracked.assessment_id}/closure").status_code == 200
    monkeypatch.undo()
    monkeypatch.setattr(rbac, "REMEDIATION_ROLES", frozenset())
    for method, path in endpoints(tracked):
        if "/close" in path and method == "post":
            continue  # gated by the closure allow-list, checked above
        assert call(tracked, method, path).status_code == 403, path
    monkeypatch.undo()
    with SessionLocal() as db:
        assert db.query(VulnerabilityRemediation).one().status == "in_progress" and db.query(AssessmentClosure).count() == 0


def test_unknown_findings_and_malformed_ids_and_filters(tracked):
    for path in (f"{REM}/{NIL}", f"{REM}/{NIL}/retests"):
        assert tracked.get(path).status_code == 404
    assert update(tracked, NIL, "in_progress", 0).status_code == 404 and request_retest(tracked, NIL, 0).status_code == 404
    assert tracked.get(f"{REM}/not-a-uuid").status_code == 422
    for bad in ({"status": "done"}, {"limit": 0}, {"limit": 101}, {"offset": -1}, {"website_id": 0}, {"assessment_id": "x"},
                {"search": "x" * 201}):
        assert tracked.get(REM, params=bad).status_code == 422


def test_listing_filters_counts_search_and_pagination(tracked):
    hsts = confirm(tracked, "hsts")
    assert update(tracked, tracked.vid, "fix_submitted", 0).status_code == 200
    listing = tracked.get(REM).json()
    assert {i["check_id"] for i in listing["items"]} == {"csp", "hsts"}  # only confirmed findings
    assert listing["summary"]["open"] == 1 and listing["summary"]["fix_submitted"] == 1 and listing["summary"]["verified_fixed"] == 0
    assert [i["check_id"] for i in tracked.get(REM, params={"status": "open"}).json()["items"]] == ["hsts"]
    assert [i["check_id"] for i in tracked.get(REM, params={"status": "fix_submitted"}).json()["items"]] == ["csp"]
    assert tracked.get(REM, params={"status": "reopened"}).json()["items"] == []
    assert [i["check_id"] for i in tracked.get(REM, params={"search": "hsts"}).json()["items"]] == ["hsts"]
    assert len(tracked.get(REM, params={"assessment_id": tracked.assessment_id}).json()["items"]) == 2
    assert tracked.get(REM, params={"assessment_id": NIL}).json()["items"] == []
    assert len(tracked.get(REM, params={"limit": 1, "offset": 1}).json()["items"]) == 1
    assert hsts["id"] in {i["vulnerability_id"] for i in listing["items"]}


def test_hostile_notes_are_stored_as_inert_bounded_text(tracked):
    hostile = "<script>steal()</script> ${jndi:ldap://x} ‮evil‬ {{7*7}} \x1b[31m end of the note"
    response = update(tracked, tracked.vid, "in_progress", 0, note=hostile)
    assert response.status_code == 200 and response.headers["content-type"].startswith("application/json")
    stored = response.json()["client_note"]
    assert "<script>steal()</script>" in stored and "‮" not in stored and "\x1b" not in stored


# --- Immutability and migration --------------------------------------------------------

def test_orm_and_database_block_rewriting_history_closures_and_finished_retests(submitted):
    done = retest_cycle(submitted, FIXED, 10)
    confirm(submitted, "hsts")
    assert update(submitted, one(submitted, "hsts")["id"], "risk_accepted", 0, human_validation_confirmed=True,
                  note="Accepted by the business owner until the platform migration completes.").status_code == 200
    assert close(submitted).status_code == 200
    with SessionLocal() as db:
        db.get(RetestRequest, done["retests"][0]["id"]).note = "changed"
        with pytest.raises(ValueError, match="frozen"):
            db.flush()
        db.rollback()
        for model in (RemediationEvent, AssessmentClosure):
            db.delete(db.query(model).first())
            with pytest.raises(ValueError, match="append-only"):
                db.flush()
            db.rollback()
        db.delete(db.query(VulnerabilityRemediation).first())
        with pytest.raises(ValueError, match="never be deleted"):
            db.flush()
        db.rollback()
        db.delete(db.query(RetestRequest).first())
        with pytest.raises(ValueError, match="never be deleted"):
            db.flush()
        db.rollback()
    statements = [
        ("UPDATE remediation_events SET note = 'x'", "append-only"), ("DELETE FROM remediation_events", "append-only"),
        ("UPDATE assessment_closures SET justification = 'x'", "append-only"), ("DELETE FROM assessment_closures", "append-only"),
        ("DELETE FROM vulnerability_remediations", "cannot be deleted"), ("DELETE FROM retest_requests", "cannot be deleted"),
        ("UPDATE retest_requests SET note = 'x'", "frozen"), ("UPDATE retest_requests SET assessment_id = 'x'", "frozen"),
        ("UPDATE retest_requests SET outcome = 'still_present'", "final"), ("UPDATE retest_requests SET status = 'failed'", "final")]
    for sql, message in statements:
        with SessionLocal() as db:
            with pytest.raises(DBAPIError, match=message):
                db.execute(text(sql))
            db.rollback()
    with SessionLocal() as db:
        assert db.query(RetestRequest).one().outcome == "verified_fixed" and db.query(AssessmentClosure).count() == 1


def test_migration_installs_remediation_tables_and_triggers_preserving_data(tmp_path):
    path = tmp_path / "remediation.db"
    migrate(path, "0011_vapt_reports")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO admins (id,email,full_name,password_hash,role,is_active) VALUES (7,'a@example.com','Synthetic','preserved-hash','admin',1)")
    migrate(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0015_port_watch"
        assert db.execute("SELECT password_hash FROM admins WHERE id = 7").fetchone()[0] == "preserved-hash"
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert {"vulnerability_remediations", "remediation_events", "retest_requests", "assessment_closures"} <= tables
        triggers = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}
        assert {"trg_remediation_events_no_update", "trg_remediation_events_no_delete", "trg_assessment_closures_no_update",
                "trg_assessment_closures_no_delete", "trg_retest_requests_frozen", "trg_retest_requests_final",
                "trg_retest_requests_no_delete", "trg_vulnerability_remediations_no_delete"} <= triggers
