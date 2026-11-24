"""Central findings queue: latest analyst decisions, filters and deadline audit."""
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import select, func

from app.db.session import SessionLocal
from app.models.assessment import FindingDueDate
from app.models.jobs import ExecutionEvent
from app.services import findings
from test_authorization_correctness import api, NOW
from test_assessments import assessed
from test_local_assessment import network
from test_observation_reviews import completed, save as save_review


@pytest.fixture
def confirmed(completed):
    client, row, _ = completed
    response = save_review(client, row, disposition="confirmed", severity="high", owner="Operations Alpha",
        remediation_status="open", recommendation="Deploy a reviewed policy for this synthetic owned staging application.")
    assert response.status_code == 201, response.text
    return client, row


def deadline(client, row, **changes):
    data = {"expected_revision": 0, "expected_review_revision": 1,
            "due_date": "2026-11-23", "note": "Set a synthetic remediation deadline.", **changes}
    return client.post(f"/api/v1/findings/{row['id']}/csp/deadline", json=data)


def test_only_current_confirmations_enter_queue(completed):
    client, row, _ = completed
    assert client.get("/api/v1/findings").json()["summary"]["total"] == 0
    assert save_review(client, row, disposition="confirmed", severity="medium", owner="Team A", remediation_status="open",
        recommendation="Prepare a reviewed staging configuration and validate it.").status_code == 201
    first = client.get("/api/v1/findings").json()
    assert first["summary"]["total"] == 1 and first["summary"]["open"] == 1
    assert first["items"][0]["review"]["revision"] == 1
    assert save_review(client, row, expected_revision=1, disposition="dismissed").status_code == 201
    assert client.get("/api/v1/findings").json()["summary"]["total"] == 0
    assert client.get(f"/api/v1/findings/{row['id']}/csp").status_code == 409


def test_filters_counts_pagination_and_source_context(confirmed):
    client, row = confirmed
    assert save_review(client, row, "hsts", disposition="confirmed", severity="low", owner="Team Beta",
        remediation_status="in_progress", recommendation="Validate a suitable staging policy and deploy the reviewed change.").status_code == 201
    first = client.get("/api/v1/findings?limit=1").json()
    assert first["summary"]["total"] == 2 and len(first["items"]) == 1
    assert first["summary"]["open"] == 1 and first["summary"]["in_progress"] == 1
    assert first["items"][0]["check_id"] == "csp"  # Severity order is deterministic.
    assert client.get("/api/v1/findings?limit=1&offset=1").json()["items"][0]["check_id"] == "hsts"
    assert client.get("/api/v1/findings?owner=ALPHA&severity=high&status=open").json()["summary"]["total"] == 1
    assert client.get("/api/v1/findings?owner=%25").json()["summary"]["total"] == 0  # Literal wildcard, not LIKE injection.
    assert client.get("/api/v1/findings?severity=critical").json()["summary"]["total"] == 0
    item = first["items"][0]
    assert client.get(f"/api/v1/findings?client_id={item['client_id']}&website_id={item['website_id']}").json()["summary"]["total"] == 2
    assert client.get("/api/v1/findings?client_id=999999").json()["summary"]["total"] == 0
    assert client.get("/api/v1/findings?search=CSP").json()["summary"]["total"] == 1
    detail = client.get(f"/api/v1/findings/{row['id']}/csp").json()
    assert detail["review"]["supporting_evidence"] and len(detail["source_report_sha256"]) == 64
    assert detail["observation"]["check"] == "csp"


def test_deadline_overdue_boundary_clearing_history_and_conflicts(confirmed, monkeypatch):
    client, row = confirmed
    # UTC is still November 23; the business date in India is November 24.
    monkeypatch.setattr(findings, "utc_now", lambda: datetime(2026, 11, 23, 20, tzinfo=timezone.utc))
    original = client.get(f"/api/v1/assessments/{row['id']}/report/download").content
    assert deadline(client, row).status_code == 201
    result = client.get("/api/v1/findings?overdue_only=true").json()
    assert result["today"] == "2026-11-24" and result["timezone"] == "Asia/Kolkata"
    assert result["summary"]["overdue"] == 1 and result["items"][0]["overdue"]
    assert deadline(client, row).status_code == 409
    assert deadline(client, row, expected_revision=1, expected_review_revision=99).status_code == 409
    assert deadline(client, row, expected_revision=1, due_date="2026-11-24").status_code == 201
    assert client.get("/api/v1/findings?overdue_only=true").json()["summary"]["total"] == 0
    assert deadline(client, row, expected_revision=2, due_date=None).status_code == 201
    history_path = f"/api/v1/findings/{row['id']}/csp/deadline-history"
    history = client.get(history_path + "?limit=1&offset=0").json()
    assert history[0]["revision"] == 3 and history[0]["due_date"] is None
    assert client.get(history_path + "?limit=1&offset=1").json()[0]["due_date"] == "2026-11-24"
    assert client.get(f"/api/v1/assessments/{row['id']}/report/download").content == original
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(FindingDueDate)) == 3
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "finding_deadline_recorded"))


@pytest.mark.parametrize("changes", [{"note": "short"}, {"due_date": "not-a-date"}, {"expected_revision": -1},
    {"expected_review_revision": 0}, {"updated_by": 999}, {"expected_revision": "0"}])
def test_invalid_deadline_payload_rejected(confirmed, changes):
    client, row = confirmed
    assert deadline(client, row, **changes).status_code == 422


def test_authentication_and_unconfirmed_unknown_observations(confirmed):
    client, row = confirmed
    assert client.get(f"/api/v1/findings/{row['id']}/not-a-check").status_code == 404
    assert client.get(f"/api/v1/findings/{row['id']}/hsts").status_code == 409
    assert client.post(f"/api/v1/findings/{row['id']}/hsts/deadline", json={"expected_revision": 0,
        "expected_review_revision": 1, "due_date": None, "note": "Synthetic deadline note."}).status_code == 409
    client.headers.pop("Authorization")
    assert client.get("/api/v1/findings").status_code == 401
    assert deadline(client, row).status_code == 401
    assert client.get(f"/api/v1/findings/{row['id']}/csp/deadline-history").status_code == 401


def test_resolved_not_overdue_and_reopened_uses_same_deadline(confirmed, monkeypatch, network):
    from app.services import assessments, job_engine
    client, row = confirmed
    assert deadline(client, row, due_date="2020-01-01").status_code == 201
    later = NOW + timedelta(minutes=2)
    monkeypatch.setattr(assessments, "utc_now", lambda: later)
    monkeypatch.setattr(job_engine, "utc_now", lambda: later)
    _, _, payload = network
    retest = client.post("/api/v1/assessments", json={**payload, "idempotency_key": str(uuid4())})
    assert retest.status_code == 201, retest.text
    assessments.worker_tick()
    confirmed_body = dict(expected_revision=1, disposition="confirmed", severity="high", owner="Operations Alpha",
        remediation_status="resolved", recommendation="Validate the reviewed staging policy and deploy the approved change.",
        retest_assessment_id=retest.json()["id"], resolution_notes="Analyst inspected the later retest and accepted the applied remediation.")
    assert save_review(client, row, **confirmed_body).status_code == 201
    resolved = client.get("/api/v1/findings?status=resolved").json()
    assert resolved["summary"]["resolved"] == 1 and resolved["summary"]["overdue"] == 0
    assert save_review(client, retest.json(), disposition="confirmed", severity="low", owner="Retest owner",
        remediation_status="open", recommendation="Review this separate retest observation and plan the appropriate action.").status_code == 201
    assert client.get("/api/v1/findings").json()["summary"]["total"] == 2  # Same check, separate assessments.
    assert save_review(client, row, **{**confirmed_body, "expected_revision": 2, "remediation_status": "open"}).status_code == 201
    assert client.get("/api/v1/findings?overdue_only=true").json()["summary"]["total"] == 1


def test_dashboard_filters_validate_query_values(confirmed):
    client, _ = confirmed
    for query in ("limit=101", "offset=-1", "status=discarded", "severity=extreme", "client_id=0"):
        assert client.get("/api/v1/findings?" + query).status_code == 422


def test_concurrent_deadline_edits_preserve_one_revision(confirmed, monkeypatch):
    from app.api.routes.findings import Deadline
    from fastapi import HTTPException
    client, row = confirmed
    original = findings.current
    barrier = Barrier(2)
    def synchronise(*args):
        result = original(*args)
        barrier.wait(timeout=10)
        return result
    monkeypatch.setattr(findings, "current", synchronise)
    payload = Deadline(expected_revision=0, expected_review_revision=1, due_date=None, note="Synthetic deadline concurrency test.")
    def submit(_):
        with SessionLocal() as db:
            try:
                return findings.save_deadline(db, row["id"], "csp", client.admin_id, payload)["revision"]
            except HTTPException as error:
                return error.status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(submit, range(2)))
    assert sorted(results) == [1, 409]
