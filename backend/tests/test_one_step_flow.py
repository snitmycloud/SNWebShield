"""One-step assessment flow: server-side readiness, strict authorisation selection, worker re-check
and hand-off to Vulnerability Management. Synthetic data only; no target traffic."""
from datetime import timedelta
from uuid import uuid4
import pytest
from sqlalchemy import select, func
from app.core.config import settings
from app.db.session import SessionLocal
from app.models import WebsiteAuthorization
from app.models.assessment import AssessmentRequest
from app.models.jobs import ExecutionEvent, Job, JobResult
from app.services import assessments as service
from app.services import local_assessment_runtime as runtime
from test_authorization_correctness import NOW, api  # noqa: F401
from test_assessments import assessed  # noqa: F401
from test_local_assessment import network  # noqa: F401
from test_vulnerabilities import run, one, confirm, ONLY_DISCLOSURE, API

URL = "/api/v1/assessments/readiness"


def ready(api, site):
    r = api.get(URL, params={"website_id": site})
    assert r.status_code == 200, r.text
    return {p["profile_id"]: p for p in r.json()}


def test_readiness_selects_the_valid_authorisation_and_is_read_only(assessed):
    api, auth, site, _, _ = assessed
    with SessionLocal() as db:
        before = (db.scalar(select(func.count()).select_from(ExecutionEvent)), db.scalar(select(func.count()).select_from(Job)))
    item = ready(api, site)[service.PROFILE_ID]
    assert item["ready"] is True and item["authorization_id"] == auth and item["reason"] is None
    with SessionLocal() as db:  # network-free and writes nothing: no job, no audit event, no request
        assert before == (db.scalar(select(func.count()).select_from(ExecutionEvent)), db.scalar(select(func.count()).select_from(Job)))
        assert not list(db.scalars(select(AssessmentRequest)))


@pytest.mark.parametrize("field,value,code", [
    ("status", "pending", "no_approved_authorization"), ("status", "revoked", "no_approved_authorization"),
    ("status", "rejected", "no_approved_authorization"),
    ("valid_until", NOW, "authorization_outside_validity_window"),
    ("valid_from", NOW + timedelta(seconds=1), "authorization_outside_validity_window"),
    ("authorized_domains", ["other.example.com"], "exact_domain_not_authorized"),
    ("authorized_domains", ["*.example.com"], "exact_domain_not_authorized"),
    ("permitted_methods", ["passive_reconnaissance"], "profile_methods_not_authorized"),
    ("timestamps_verified", False, "authorization_not_currently_approved")])
def test_invalid_authorisation_is_never_selected_and_reason_is_exact(assessed, field, value, code):
    api, auth, site, _, body = assessed
    with SessionLocal() as db:
        setattr(db.get(WebsiteAuthorization, auth), field, value); db.commit()
    item = ready(api, site)[service.PROFILE_ID]
    assert item["ready"] is False and item["authorization_id"] is None
    assert item["reason_code"] == code and item["reason"] and item["reason"] != code
    # The server refuses the same request even if a client ignores the gate.
    assert api.post("/api/v1/assessments", json=body).status_code == 409


def test_evidence_not_accepted_blocks_readiness(assessed):
    api, auth, site, _, _ = assessed
    with SessionLocal() as db:
        db.get(WebsiteAuthorization, auth).evidence_revision += 1; db.commit()
    item = ready(api, site)[service.PROFILE_ID]
    assert item["ready"] is False and item["reason_code"] == "current_accepted_evidence_required"


def test_profile_methods_are_checked_per_profile(assessed, monkeypatch):
    api, auth, site, _, _ = assessed
    monkeypatch.setattr(settings, "assessment_local_http_enabled", True)
    monkeypatch.setattr(service, "profile_available", lambda selected: True)
    items = ready(api, site)
    assert items[service.HTTP_PROFILE_ID]["ready"] is True
    # Nmap needs tcp_port_discovery and an approved public IPv4 literal in scope; the seed has neither.
    assert items[service.NMAP_PROFILE_ID]["ready"] is False
    assert items[service.NMAP_PROFILE_ID]["reason_code"] == "profile_methods_not_authorized"


def test_disabled_network_profile_reports_why(assessed, monkeypatch):
    api, _, site, _, _ = assessed
    monkeypatch.setattr(settings, "assessment_local_http_enabled", False)
    item = ready(api, site)[service.HTTP_PROFILE_ID]
    assert item["ready"] is False and item["reason_code"] == "profile_disabled"


def test_unknown_website_and_bad_id(assessed):
    api, _, _, _, _ = assessed
    assert api.get(URL, params={"website_id": 99999}).status_code == 404
    assert api.get(URL, params={"website_id": 0}).status_code == 422


def test_readiness_requires_authentication(assessed):
    api, _, site, _, _ = assessed
    from fastapi.testclient import TestClient
    from app.main import app
    assert TestClient(app).get(URL, params={"website_id": site}).status_code == 401


def test_one_step_request_uses_the_server_chosen_authorisation_then_blocks_a_second(assessed):
    api, auth, site, _, body = assessed
    chosen = ready(api, site)[service.PROFILE_ID]["authorization_id"]
    r = api.post("/api/v1/assessments", json={**body, "authorization_id": chosen, "idempotency_key": str(uuid4())})
    assert r.status_code == 201, r.text
    again = ready(api, site)[service.PROFILE_ID]
    assert again["ready"] is False and again["reason_code"] == "assessment_already_active"


def test_worker_still_rechecks_after_one_step_request(network, monkeypatch):
    """Revoking between request and execution must stop the run before any network call (TOCTOU)."""
    api, auth, body = network
    monkeypatch.setattr(runtime, "invoke", lambda *a, **k: pytest.fail("network adapter ran after revocation"))
    row = api.post("/api/v1/assessments", json=body).json()
    with SessionLocal() as db:
        db.get(WebsiteAuthorization, auth).status = "revoked"; db.commit()
    service.worker_tick()
    with SessionLocal() as db:
        assert db.get(Job, row["job_id"]).status == "cancelled"
        assert db.get(JobResult, row["job_id"]).payload["state"] == "cancelled"
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.job_id == row["job_id"],
                                                      ExecutionEvent.action == "assessment_permission_denied"))


def test_observations_flow_to_vulnerability_management_for_human_validation(network, monkeypatch):
    api, auth, body = network
    assert ready(api, body["website_id"])[service.HTTP_PROFILE_ID]["authorization_id"] == auth
    row = run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    item = one(api, "csp")
    # Ingested as an unconfirmed scanner observation, linked to this assessment, never auto-confirmed.
    assert item["validation_state"] == "unconfirmed" and item["effective_severity"] == item["scanner_severity"]
    assert item["analyst_severity"] is None
    events = api.get(f"{API}/{item['id']}/events").json()
    assert [e["action"] for e in events][:1] == ["occurrence_recorded"]
    # Only an explicit human decision confirms it.
    assert confirm(api, item).status_code == 200
    assert one(api, "csp")["validation_state"] == "confirmed"
