"""Analyst review lifecycle: synthetic jobs only, no VM or website requests."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import select, func

from app.db.session import SessionLocal
from app.models.assessment import AssessmentReport, ObservationReview, ReviewedAssessmentExport
from app.models.jobs import ExecutionEvent
from app.services import assessments, job_engine
from test_authorization_correctness import api, NOW
from test_assessments import assessed
from test_local_assessment import network, create, fake_broker


@pytest.fixture
def completed(network, monkeypatch):
    fake_broker(monkeypatch)
    row = create(network)
    assessments.worker_tick()
    client, _, _ = network
    assert client.get(f"/api/v1/assessments/{row['id']}").json()["job"]["status"] == "completed"
    return client, row, network


def body(**changes):
    return {"expected_revision": 0, "human_validation_confirmed": True,
            "disposition": "dismissed", "severity": "informational",
            "notes": "Analyst inspected the synthetic policy and dismissed this observation.",
            "supporting_evidence": "Synthetic review evidence, report checksum and inspected staging configuration.",
            "recommendation": "", "owner": "", "remediation_status": "not_applicable", **changes}


def save(client, row, check="csp", **changes):
    return client.post(f"/api/v1/assessments/{row['id']}/reviews/{check}", json=body(**changes))


def test_dispositions_revision_history_and_original_report_preserved(completed):
    client, row, _ = completed
    path = f"/api/v1/assessments/{row['id']}"
    original = client.get(path + "/report/download").content
    summary = client.get(path + "/reviews").json()
    assert summary["reviewed"] == 0 and summary["total"] == 9  # 8 header checks + HTTPS use
    first = save(client, row)
    assert first.status_code == 201, first.text
    assert first.json()["revision"] == 1 and first.json()["reviewer_id"] == client.admin_id
    assert save(client, row).status_code == 409
    second = save(client, row, expected_revision=1, disposition="not_applicable")
    assert second.status_code == 201
    history = client.get(path + "/reviews/csp/history?limit=1&offset=0").json()
    assert [r["revision"] for r in history] == [2]
    assert client.get(path + "/reviews/csp/history?limit=1&offset=1").json()[0]["disposition"] == "dismissed"
    summary = client.get(path + "/reviews").json()
    assert summary["reviewed"] == 1
    assert next(item for item in summary["observations"] if item["observation"]["check"] == "csp")["review"]["revision"] == 2
    assert client.get(path + "/report/download").content == original
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(ObservationReview)) == 2
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "observation_review_recorded"))


@pytest.mark.parametrize("changes", [
    {"human_validation_confirmed": False}, {"expected_revision": -1}, {"expected_revision": "0"},
    {"notes": " " * 30}, {"supporting_evidence": "too short"}, {"reviewer_id": 999},
    {"disposition": "pending"}, {"severity": "critical"}, {"remediation_status": "resolved"},
    {"disposition": "confirmed", "remediation_status": "open"},
    {"disposition": "confirmed", "remediation_status": "resolved", "owner": "Ops",
     "recommendation": "Review and fix the controlled staging security configuration."},
])
def test_invalid_or_unattested_reviews_rejected(completed, changes):
    client, row, _ = completed
    assert save(client, row, **changes).status_code == 422
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(ObservationReview)) == 0


def test_unknown_observation_failed_assessment_and_authentication(completed):
    client, row, data = completed
    assert save(client, row, check="arbitrary-finding").status_code == 404
    assert client.get(f"/api/v1/assessments/{row['id']}/reviews/arbitrary/history").status_code == 404
    client.headers.pop("Authorization")
    assert save(client, row).status_code == 401
    assert client.get(f"/api/v1/assessments/{row['id']}/reviews").status_code == 401
    assert client.post(f"/api/v1/assessments/{row['id']}/reviewed-reports", json={}).status_code == 401


def test_report_integrity_required_for_review_and_export(completed):
    client, row, _ = completed
    with SessionLocal() as db:
        db.scalar(select(AssessmentReport)).sha256 = "0" * 64
        db.commit()
    assert save(client, row).status_code == 409
    assert client.post(f"/api/v1/assessments/{row['id']}/reviewed-reports").status_code == 409


def test_reviewed_export_is_complete_private_immutable_and_hash_checked(completed):
    client, row, _ = completed
    path = f"/api/v1/assessments/{row['id']}"
    assert client.post(path + "/reviewed-reports").status_code == 409
    checks = [item["observation"]["check"] for item in client.get(path + "/reviews").json()["observations"]]
    for check in checks:
        assert save(client, row, check).status_code == 201
    response = client.post(path + "/reviewed-reports")
    assert response.status_code == 201, response.text
    export_id = response.json()["id"]
    url = path + f"/reviewed-reports/{export_id}/download"
    downloaded = client.get(url)
    assert downloaded.status_code == 200
    assert downloaded.headers["cache-control"] == "no-store, private"
    assert "attachment" in downloaded.headers["content-disposition"]
    snapshot = downloaded.json()
    assert snapshot["summary"] == {"total": 9, "reviewed": 9, "analyst_confirmed": 0, "unresolved_confirmed": 0, "resolved": 0}
    assert snapshot["source_report"]["content"]["analysis"]["confirmed_findings"] == 0
    assert save(client, row, expected_revision=1, disposition="confirmed", severity="medium",
                owner="Security team", remediation_status="in_progress",
                recommendation="Prepare and validate a policy for the owned staging site.").status_code == 201
    assert client.get(url).content == downloaded.content
    newer = client.post(path + "/reviewed-reports").json()["id"]
    new_snapshot = client.get(path + f"/reviewed-reports/{newer}/download").json()
    assert new_snapshot["summary"]["analyst_confirmed"] == 1
    assert new_snapshot["summary"]["unresolved_confirmed"] == 1
    assert len(client.get(path + "/reviews").json()["exports"]) == 2
    _, _, payload = completed[2]
    preflight = client.post("/api/v1/assessments", json={**payload, "profile_id": assessments.PROFILE_ID,
        "network_permission_confirmed": False, "idempotency_key": str(uuid4())}).json()
    assert client.get(f"/api/v1/assessments/{preflight['id']}/reviewed-reports/{export_id}/download").status_code == 404
    with SessionLocal() as db:
        export = db.get(ReviewedAssessmentExport, export_id)
        export.sha256 = "0" * 64
        db.commit()
    assert client.get(url).status_code == 409
    assert client.get(path + f"/reviewed-reports/{uuid4()}/download").status_code == 404


def test_resolution_requires_later_same_target_retest(completed, monkeypatch):
    client, row, network = completed
    confirmed = dict(disposition="confirmed", severity="medium", owner="Staging owner", remediation_status="resolved",
        recommendation="Deploy a reviewed policy appropriate for the controlled staging application.",
        resolution_notes="Analyst inspected the later retest and verified the compensating controls.")
    assert save(client, row, **confirmed, retest_assessment_id=row["id"]).status_code == 422
    later = NOW + timedelta(minutes=2)
    monkeypatch.setattr(assessments, "utc_now", lambda: later)
    monkeypatch.setattr(job_engine, "utc_now", lambda: later)
    _, _, payload = network
    response = client.post("/api/v1/assessments", json={**payload, "idempotency_key": str(uuid4())})
    assert response.status_code == 201, response.text
    retest = response.json()
    # Queued retests cannot close a finding.
    assert save(client, row, **confirmed, retest_assessment_id=retest["id"]).status_code == 409
    assessments.worker_tick()
    from app.models.assessment import AssessmentRequest
    with SessionLocal() as db:
        intent = db.get(AssessmentRequest, retest["id"])
        actual_target = intent.target_url
        intent.target_url = "https://different.example/"
        db.commit()
    assert save(client, row, **confirmed, retest_assessment_id=retest["id"]).status_code == 422
    with SessionLocal() as db:
        db.get(AssessmentRequest, retest["id"]).target_url = actual_target
        db.commit()
    response = save(client, row, **confirmed, retest_assessment_id=retest["id"])
    assert response.status_code == 201, response.text
    assert response.json()["remediation_status"] == "resolved"
    # Reopen through a new revision; historical resolution remains available.
    assert save(client, row, expected_revision=1, **{**confirmed, "remediation_status": "open"}).status_code == 201
    history = client.get(f"/api/v1/assessments/{row['id']}/reviews/csp/history").json()
    assert [r["remediation_status"] for r in history] == ["open", "resolved"]


def test_policy_only_assessment_cannot_receive_observation_review(assessed):
    client, _, _, _, payload = assessed
    row = client.post("/api/v1/assessments", json=payload).json()
    assessments.worker_tick()
    assert save(client, row).status_code == 409


def test_reviewing_history_does_not_require_new_network_authorisation(completed):
    client, row, data = completed
    _, auth, _ = data
    assert client.post(f"/api/v1/authorizations/{auth}/revoke", json={"reason": "Revoke synthetic future network permission."}).status_code == 200
    assert save(client, row).status_code == 201


def test_concurrent_reviews_do_not_overwrite_each_other(completed, monkeypatch):
    from app.api.routes.assessments import ObservationDecision
    from app.services import observation_reviews
    from fastapi import HTTPException
    client, row, _ = completed
    barrier = Barrier(2)
    original = observation_reviews.validate_retest
    def synchronise(*args):
        original(*args)
        barrier.wait(timeout=10)
    monkeypatch.setattr(observation_reviews, "validate_retest", synchronise)
    def submit(_):
        with SessionLocal() as db:
            try:
                return observation_reviews.save(db, row["id"], "csp", client.admin_id, ObservationDecision(**body()))["revision"]
            except HTTPException as error:
                return error.status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(submit, range(2)))
    assert sorted(outcomes) == [1, 409]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(ObservationReview)) == 1
