"""Module E: normalised vulnerabilities. Synthetic scanner output only; no target traffic."""
import json
from datetime import timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.models.assessment import AssessmentReport, AssessmentRequest
from app.models.jobs import ExecutionEvent, Job
from app.models.vulnerability import (Vulnerability, VulnerabilityEvent, VulnerabilityIngestion,
                                      VulnerabilityOccurrence, VulnerabilitySuppression)
from app.services import assessments as service, job_engine as engine
from app.services import local_assessment_runtime as runtime, remote_assessment_runtime as remote
from app.services import vulnerabilities as vulns
from app.services.header_analyzer import analyze
from test_authorization_correctness import api, NOW
from test_assessments import assessed
from test_local_assessment import network

SECURE = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'",
          "strict-transport-security": "max-age=31536000", "x-frame-options": "DENY",
          "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin",
          "permissions-policy": "camera=()"}
ONLY_DISCLOSURE = {"server": "PRIVATE-server-1.2.3"}  # Only a disclosure header: all 8 checks fail.
API = "/api/v1/vulnerabilities"


def run(network, monkeypatch, headers, minutes, profile=None):
    """Queue and execute one synthetic assessment at NOW + minutes."""
    at = NOW + timedelta(minutes=minutes)
    monkeypatch.setattr(service, "utc_now", lambda: at)
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
    api_client, _, body = network
    body = {**body, "idempotency_key": str(uuid4())}
    if profile == service.REMOTE_PROFILE_ID:
        image = "sha256:" + "c" * 64
        monkeypatch.setattr(settings, "assessment_remote_docker_enabled", True)
        monkeypatch.setattr(settings, "assessment_remote_image_id", image)

        def exchange(operation, payload, permitted, seconds):
            if operation == "check":
                return {"runner": remote.VERSION, "image_id": image}
            return {"analysis": analyze(payload["data"]), "execution": {
                "id": payload["id"], "image_id": image, "limits": remote.LIMITS, "cleanup_confirmed": True,
                "isolation_verified": True, "duration_ms": 1, "container_duration_ms": 1, "analyzer_cpu_seconds": 0,
                "analyzer_peak_rss_bytes": 1, "analyzer_duration_ms": 1}}
        monkeypatch.setattr(remote, "ssh_exchange", exchange)
        body["profile_id"] = profile
    response = api_client.post("/api/v1/assessments", json=body)
    assert response.status_code == 201, response.text
    service.worker_tick()
    with SessionLocal() as db:
        assert db.get(Job, response.json()["job_id"]).status == "completed"
    return response.json()


def records(**where):
    with SessionLocal() as db:
        statement = select(Vulnerability)
        for key, value in where.items():
            statement = statement.where(getattr(Vulnerability, key) == value)
        return {row.check_id: row for row in db.scalars(statement)}


def decide(client, vulnerability, **changes):
    body = {"expected_revision": vulnerability["revision"], "human_validation_confirmed": True,
            "justification": "Analyst inspected the stored evidence and target scope."} | changes
    return client.post(f"{API}/{vulnerability['id']}/validation", json=body)


def assess(client, vulnerability, **changes):
    """Save the human risk assessment that the sign-off gate requires (default: medium risk)."""
    body = {"expected_revision": vulnerability["revision"], "likelihood": "possible", "business_impact": "moderate",
            "business_context": "Public marketing site; no customer data is processed on this host.",
            "risk_rating": "medium", "remediation": "Add the header at the CDN edge and verify with a HEAD request.",
            "remediation_priority": "planned"} | changes
    return client.post(f"/api/v1/workbench/{vulnerability['id']}/assessment", json=body)


def confirm(client, vulnerability, **changes):
    severity = changes.get("severity", "medium")
    if severity in ("informational", "low", "medium", "high", "critical") and vulnerability["validation_state"] == "unconfirmed":
        # Assess with the same rating (override reason when it differs from the matrix) so the gate passes.
        calculated = vulns.calculate_rating("possible", "moderate")
        extra = {} if severity == calculated else {"override_reason": "Analyst judgement differs from the matrix for this target."}
        assess(client, vulnerability, risk_rating=severity, **extra)  # stale revisions are rejected, as in decide
    values = {"decision": "confirmed", "severity": "medium",
              "reproduction_steps": "curl -sI the authorised URL and observe the header is absent."} | changes
    return decide(client, vulnerability, **values)


def one(client, check="csp"):
    item = next(i for i in client.get(API, params={"search": check}).json()["items"] if i["check_id"] == check)
    return client.get(f"{API}/{item['id']}").json()


def without_auto_ingest(monkeypatch):
    monkeypatch.setattr(vulns, "ingest_after_assessment", lambda assessment_id: None)


# --- Ingestion and normalisation ---------------------------------------------------------

def test_completed_assessment_ingests_unconfirmed_normalised_records(network, monkeypatch):
    client = network[0]
    row = run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    found = records()
    assert set(found) == set(vulns.CHECKS)  # every failed check, nothing for passing ones
    for record in found.values():
        assert record.validation_state == "unconfirmed" and record.analyst_severity is None
        assert record.detection_count == 1 and record.last_result == "detected" and record.revision == 1
        assert record.fingerprint == vulns.fingerprint(record.website_id, record.target_url, vulns.FAMILY, record.check_id)
    assert found["csp"].scanner_severity == "medium" and found["hsts"].scanner_severity == "low"
    with SessionLocal() as db:
        occurrence = db.scalar(select(VulnerabilityOccurrence).where(VulnerabilityOccurrence.vulnerability_id == found["csp"].id))
        assert occurrence.assessment_id == row["id"] and occurrence.result == "detected"
        assert occurrence.evidence["observation"]["check"] == "csp"
        assert occurrence.evidence["transport"]["tls_version"] == "TLSv1.3"
        assert sha256(service.report_bytes(occurrence.evidence)).hexdigest() == occurrence.evidence_sha256
        assert "PRIVATE" not in json.dumps(occurrence.evidence)  # raw header values never retained
        assert db.get(VulnerabilityIngestion, occurrence.report_id).outcome["created"] == 8
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "vulnerabilities_ingested"))
    events = client.get(f"{API}/{found['csp'].id}/events").json()
    assert [e["action"] for e in events] == ["occurrence_recorded", "detected_new"]
    assert all(e["actor_id"] is None for e in events)


def test_secure_response_creates_no_records(network, monkeypatch):
    run(network, monkeypatch, SECURE, 0)
    assert records() == {}


def test_deduplicates_across_assessments_and_profiles(network, monkeypatch):
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    first = records()
    run(network, monkeypatch, ONLY_DISCLOSURE, 2, profile=service.REMOTE_PROFILE_ID)
    second = records()
    assert set(second) == set(first) and {r.id for r in second.values()} == {r.id for r in first.values()}
    assert second["csp"].detection_count == 2
    assert second["csp"].confidence_score == first["csp"].confidence_score + 5
    assert any(f["factor"] == "repeated_detection" for f in second["csp"].confidence_factors)
    with SessionLocal() as db:
        assert db.query(VulnerabilityOccurrence).filter_by(vulnerability_id=second["csp"].id).count() == 2


def test_later_pass_is_recorded_lowers_confidence_and_never_auto_closes(network, monkeypatch):
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    before = records()["x_content_type_options"]
    run(network, monkeypatch, {"x-content-type-options": "nosniff"}, 2)
    after = records()["x_content_type_options"]
    assert after.validation_state == "unconfirmed" and after.last_result == "not_detected"
    assert after.not_detected_count == 1 and after.confidence_score < before.confidence_score
    assert {f["factor"] for f in after.confidence_factors} >= {"inconsistent_results", "not_detected_in_latest_assessment"}


def test_confidence_scoring_is_deterministic_and_bounded():
    assert vulns.score("hsts", ["detected"]) == (80, "high", [{"factor": "check_reliability", "effect": 80}])
    assert vulns.score("csp_frame_ancestors", ["detected"])[1] == "medium"
    assert vulns.score("hsts", ["detected"] * 10)[0] == 95
    low = vulns.score("permissions_policy", ["detected", "not_detected", "detected", "not_detected"])
    assert low[0] == 5 and low[1] == "low"


@pytest.mark.parametrize("item", [
    None, [], "csp", {"check": "unknown_check", "observed": False, "severity_suggestion": "low",
                       "requires_human_validation": True, "confirmed_vulnerability": False},
    {"check": "csp", "observed": 0, "severity_suggestion": "low", "requires_human_validation": True, "confirmed_vulnerability": False},
    {"check": "csp", "observed": "false", "severity_suggestion": "low", "requires_human_validation": True, "confirmed_vulnerability": False},
    {"check": "csp", "observed": False, "severity_suggestion": "urgent", "requires_human_validation": True, "confirmed_vulnerability": False},
    {"check": "csp", "observed": False, "severity_suggestion": "low", "requires_human_validation": False, "confirmed_vulnerability": False},
    {"check": "csp", "observed": False, "severity_suggestion": "low", "requires_human_validation": True, "confirmed_vulnerability": True},
    {"check": "csp", "observed": None, "severity_suggestion": "low", "requires_human_validation": True, "confirmed_vulnerability": False},
])
def test_untrusted_or_non_applicable_observations_are_not_ingested(item):
    assert vulns.parse_observation(item) is None


def rewrite_report(mutate):
    """Change a stored report while keeping its hash consistent (an internally valid hostile report)."""
    with SessionLocal() as db:
        report = db.scalar(select(AssessmentReport))
        content = json.loads(json.dumps(report.content))
        mutate(content)
        data = service.report_bytes(content)
        report.content, report.sha256, report.size = content, sha256(data).hexdigest(), len(data)
        db.commit()
        return report.id


def test_hostile_report_cannot_confirm_or_inject_checks(network, monkeypatch):
    without_auto_ingest(monkeypatch)
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)

    def hostile(content):
        observations = content["analysis"]["observations"]
        observations[0] = {**observations[0], "confirmed_vulnerability": True}  # scanner claims confirmation
        observations.append({**observations[1]})  # duplicate check
        observations.append({"check": "rce<script>", "observed": False, "severity_suggestion": "critical",
                             "requires_human_validation": True, "confirmed_vulnerability": False})
    report_id = rewrite_report(hostile)
    result = network[0].post(f"{API}/ingest", json={}).json()
    assert result["results"][0]["status"] == "ingested" and result["results"][0]["skipped"] == 3
    found = records()
    assert "rce<script>" not in found and len(found) == 7
    assert all(r.validation_state == "unconfirmed" for r in found.values())
    with SessionLocal() as db:
        assert db.get(VulnerabilityIngestion, report_id)


def test_oversized_observation_list_rejected(network, monkeypatch):
    without_auto_ingest(monkeypatch)
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    rewrite_report(lambda content: content["analysis"].update(observations=content["analysis"]["observations"] * 9))
    result = network[0].post(f"{API}/ingest", json={}).json()
    assert result["results"][0] == {"report_id": result["results"][0]["report_id"], "status": "rejected",
                                    "reason": "report_schema_invalid"}
    assert records() == {}


def test_tampered_report_is_rejected_audited_and_left_pending(network, monkeypatch):
    without_auto_ingest(monkeypatch)
    row = run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    with SessionLocal() as db:
        report = db.scalar(select(AssessmentReport))
        report.content = {**report.content, "analysis": {**report.content["analysis"], "confirmed_findings": 99}}
        db.commit()
    client = network[0]
    result = client.post(f"{API}/ingest", json={"assessment_id": row["id"]}).json()
    assert result["results"][0]["status"] == "rejected" and result["results"][0]["reason"] == "report_integrity_failed"
    assert records() == {} and client.get(API).json()["pending_ingestion"] == 1
    with SessionLocal() as db:
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "vulnerability_ingestion_rejected"))


def test_backfill_is_idempotent(network, monkeypatch):
    without_auto_ingest(monkeypatch)
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    client = network[0]
    assert client.get(API).json()["pending_ingestion"] == 1
    first = client.post(f"{API}/ingest", json={}).json()
    assert first["processed"] == 1 and first["remaining"] == 0
    assert client.post(f"{API}/ingest", json={}).json()["processed"] == 0
    with SessionLocal() as db:
        report_id = db.scalar(select(AssessmentReport.id))
        assert vulns.ingest_one(db, report_id)["status"] == "already_ingested"
        assert db.query(VulnerabilityOccurrence).count() == 8


def test_ingestion_failure_never_loses_scanner_result(network, monkeypatch):
    def broken(*args, **kwargs): raise RuntimeError("synthetic ingestion fault")
    monkeypatch.setattr(vulns, "ingest_report", broken)
    row = run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    with SessionLocal() as db:
        assert db.get(Job, row["job_id"]).status == "completed" and db.scalar(select(AssessmentReport))
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "vulnerability_ingestion_failed"))
    monkeypatch.undo()
    assert records() == {}


def test_port_inventory_reports_are_marked_but_not_ingested(network, monkeypatch):
    without_auto_ingest(monkeypatch)
    row = run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    with SessionLocal() as db:
        db.get(AssessmentRequest, row["id"]).profile_id = service.NMAP_PROFILE_ID
        db.commit()
    result = network[0].post(f"{API}/ingest", json={}).json()["results"][0]
    assert result["status"] == "ingested" and result["reason"] == "profile_not_ingested_inventory_only"
    assert records() == {} and network[0].get(API).json()["pending_ingestion"] == 0


@pytest.mark.parametrize("path", ["/a'b", "/x';touch /tmp/p;'", "/$(id)", "/`id`", "/a b?q='1'&r=$HOME"])
def test_reproduction_command_is_shell_inert(path):
    steps = vulns.reproduction("csp", "https://example.com" + path)
    command = steps[1]
    assert command.count("'") == 2 and command.endswith("'")
    quoted = command.split("'")[1]
    assert not any(c in quoted for c in "'`$ ;\"\\")
    assert quoted.startswith("https://example.com/")


# --- Validation state machine ------------------------------------------------------------

def test_confirmation_requires_attested_analyst_decision(network, monkeypatch):
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    client = network[0]
    item = one(client)
    assert item["allowed_decisions"] == ["confirmed", "false_positive", "not_applicable"]
    for bad in ({"human_validation_confirmed": False}, {"severity": None}, {"reproduction_steps": None},
                {"justification": "too short"}, {"suppress_until": (utc_now() + timedelta(days=1)).isoformat()},
                {"severity": "catastrophic"}, {"unexpected": True}):
        assert confirm(client, item, **bad).status_code == 422, bad
    assert one(client)["validation_state"] == "unconfirmed"
    response = confirm(client, item, severity="high")
    assert response.status_code == 200, response.text
    confirmed = response.json()
    assert confirmed["validation_state"] == "confirmed" and confirmed["effective_severity"] == "high"
    assert confirmed["scanner_severity"] == "medium" and confirmed["revision"] == 2
    assert confirmed["reproduction_steps"].startswith("curl")
    event = client.get(f"{API}/{item['id']}/events").json()[0]
    assert (event["action"], event["from_state"], event["to_state"], event["actor_id"]) == (
        "validation_changed", "unconfirmed", "confirmed", client.admin_id)
    assert event["detail"]["human_validation_confirmed"] is True and event["detail"]["evidence_report_sha256"]
    assert confirm(client, item).status_code == 409  # stale revision
    assert confirm(client, confirmed).status_code == 409  # confirmed -> confirmed is not a transition


def test_confirmation_requires_intact_source_evidence(network, monkeypatch):
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    client = network[0]
    item = one(client)
    with SessionLocal() as db:
        report = db.scalar(select(AssessmentReport))
        report.content = {**report.content, "recorded_at": "tampered"}
        db.commit()
    response = confirm(client, item)
    assert response.status_code == 409 and "integrity" in response.json()["detail"]
    assert one(client)["validation_state"] == "unconfirmed"


def test_false_positive_suppression_carries_forward_then_expires(network, monkeypatch):
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    client = network[0]
    item = one(client)
    response = decide(client, item, decision="false_positive",
                      suppress_until=(utc_now() + timedelta(days=30)).isoformat())
    assert response.status_code == 200, response.text
    assert response.json()["suppression"]["status"] == "active"
    run(network, monkeypatch, ONLY_DISCLOSURE, 2)
    held = one(client)
    assert held["validation_state"] == "false_positive" and held["detection_count"] == 2
    assert client.get(f"{API}/{item['id']}/occurrences").json()[0]["suppressed"] is True
    assert client.get(API, params={"suppressed": "true"}).json()["summary"]["total"] == 1
    later = utc_now() + timedelta(days=31)
    monkeypatch.setattr(vulns, "utc_now", lambda: later)
    run(network, monkeypatch, ONLY_DISCLOSURE, 4)
    reopened = one(client)
    assert reopened["validation_state"] == "unconfirmed" and reopened["revision"] == 3
    assert reopened["suppression"]["status"] == "expired"
    assert client.get(f"{API}/{item['id']}/events").json()[0]["action"] == "reopened_redetected"


@pytest.mark.parametrize("offset", [timedelta(minutes=-1), timedelta(days=366)])
def test_suppression_expiry_must_be_future_and_bounded(network, monkeypatch, offset):
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    client = network[0]
    response = decide(client, one(client), decision="not_applicable", suppress_until=(utc_now() + offset).isoformat())
    assert response.status_code == 422
    with SessionLocal() as db:
        assert db.query(VulnerabilitySuppression).count() == 0


def test_dismissal_needs_timezone_aware_expiry(network, monkeypatch):
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    client = network[0]
    naive = (utc_now() + timedelta(days=5)).replace(tzinfo=None).isoformat()
    assert decide(client, one(client), decision="false_positive", suppress_until=naive).status_code == 422
    assert decide(client, one(client), decision="false_positive").status_code == 422


def test_reopen_revokes_suppression(network, monkeypatch):
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    client = network[0]
    item = decide(client, one(client), decision="not_applicable",
                  suppress_until=(utc_now() + timedelta(days=10)).isoformat()).json()
    assert item["allowed_decisions"] == ["unconfirmed"]
    assert decide(client, item, decision="confirmed", severity="low",
                  reproduction_steps="Not allowed directly from not applicable.").status_code == 409
    reopened = decide(client, item, decision="unconfirmed")
    assert reopened.status_code == 200, reopened.text
    body = reopened.json()
    assert body["validation_state"] == "unconfirmed" and body["suppression"]["status"] == "revoked"
    assert body["suppression"]["revoked_by"] == client.admin_id
    assert client.get(API, params={"suppressed": "true"}).json()["summary"]["total"] == 0


def test_comments_and_history_are_append_only(network, monkeypatch):
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    client = network[0]
    item = one(client)
    assert client.post(f"{API}/{item['id']}/comments", json={"comment": "Owner says a CDN strips the header."}).status_code == 201
    assert client.post(f"{API}/{item['id']}/comments", json={"comment": "x"}).status_code == 422
    latest = client.get(f"{API}/{item['id']}/events").json()[0]
    assert latest["action"] == "comment" and latest["actor_id"] == client.admin_id
    assert one(client)["revision"] == item["revision"]  # comments never change validation state
    with SessionLocal() as db:
        event = db.get(VulnerabilityEvent, latest["id"])
        event.comment = "rewritten"
        with pytest.raises(ValueError, match="append-only"):
            db.commit()
        db.rollback()
        occurrence = db.scalar(select(VulnerabilityOccurrence))
        db.delete(occurrence)
        with pytest.raises(ValueError, match="append-only"):
            db.commit()


def test_listing_filters_counts_and_ordering(network, monkeypatch):
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    client = network[0]
    confirm(client, one(client, "hsts"), severity="critical")
    data = client.get(API).json()
    assert data["summary"] == {"total": 8, "unconfirmed": 7, "confirmed": 1, "false_positive": 0, "not_applicable": 0}
    assert data["items"][0]["check_id"] == "hsts"  # effective severity ordering
    assert client.get(API, params={"severity": "critical"}).json()["summary"]["total"] == 1
    assert client.get(API, params={"state": "confirmed"}).json()["items"][0]["check_id"] == "hsts"
    assert client.get(API, params={"confidence": "high"}).json()["summary"]["total"] == 2  # hsts, nosniff
    assert client.get(API, params={"website_id": data["items"][0]["website_id"]}).json()["summary"]["total"] == 8
    assert client.get(API, params={"search": "referrer"}).json()["summary"]["total"] == 1
    page = client.get(API, params={"limit": 3, "offset": 3}).json()
    assert len(page["items"]) == 3 and page["summary"]["total"] == 8
    for bad in ({"state": "fixed"}, {"severity": "urgent"}, {"limit": 101}, {"offset": -1}):
        assert client.get(API, params=bad).status_code == 422


def test_authentication_and_unknown_records(network, monkeypatch):
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    client = network[0]
    item_id = one(client)["id"]
    token = client.headers.pop("Authorization")
    try:
        for method, path in (("get", API), ("get", f"{API}/{item_id}"), ("get", f"{API}/{item_id}/events"),
                             ("get", f"{API}/{item_id}/occurrences"), ("post", f"{API}/ingest"),
                             ("post", f"{API}/{item_id}/comments"), ("post", f"{API}/{item_id}/validation")):
            assert getattr(client, method)(path, **({"json": {}} if method == "post" else {})).status_code == 401
    finally:
        client.headers["Authorization"] = token
    assert client.get(f"{API}/{uuid4()}").status_code == 404
    assert client.get(f"{API}/not-a-uuid").status_code == 422
