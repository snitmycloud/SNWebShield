from evidence_helpers import attach_review
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from threading import Barrier

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import event, select

from app.db.session import SessionLocal
from app.main import app
from app.models import Admin, AuthorizationAuditEvent, Client, Website, WebsiteAuthorization
from app.services import authorizations as service
from test_auth import create_admin_and_login, create_pending_authorization


NOW = datetime(2026, 11, 22, 10, 0, tzinfo=UTC)
APPROVAL = {"evidence_reviewed": True, "review_note": "Reviewed synthetic permission and verified the exact domain scope."}


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setattr("app.api.routes.authorizations.utc_now", lambda: NOW)
    monkeypatch.setattr("app.api.routes.websites.utc_now", lambda: NOW)
    monkeypatch.setattr(service, "utc_now", lambda: NOW)
    with TestClient(app) as client:
        admin, headers = create_admin_and_login(client)
        client.headers.update(headers)
        client.admin_id = admin.id
        yield client


def seed_record(**changes):
    record_id = create_pending_authorization()
    with SessionLocal() as db:
        record = db.get(WebsiteAuthorization, record_id)
        record.valid_from = NOW - timedelta(hours=1)
        record.valid_until = NOW + timedelta(hours=1)
        for key, value in changes.items():
            setattr(record, key, value)
        db.commit()
        return record_id, record.website_id


@pytest.mark.parametrize("offset", [0, 330, -420])
@pytest.mark.parametrize("expired", [True, False])
def test_offsets_round_trip_and_approval(api, offset, expired):
    seed_id, website_id = seed_record()
    tz = timezone(timedelta(minutes=offset))
    end = NOW + timedelta(minutes=-10 if expired else 10)
    response = api.post("/api/v1/authorizations", json={
        "website_id": website_id, "authorization_reference": "TZ-ROUND-TRIP",
        "authorized_by": "Synthetic Signatory",
        "authorized_domains": api.get(f"/api/v1/authorizations/{seed_id}").json()["authorized_domains"],
        "permitted_methods": ["passive_reconnaissance"],
        "valid_from": (NOW - timedelta(days=1)).astimezone(tz).isoformat(),
        "valid_until": end.astimezone(tz).isoformat(),
    })
    assert response.status_code == 201, response.text
    record = response.json()
    assert record["timestamps_verified"] is True
    assert datetime.fromisoformat(record["valid_until"].replace("Z", "+00:00")) == end
    assert record["valid_until"].endswith(("Z", "+00:00"))
    if not expired: attach_review(api, record["id"])
    result = api.post(f"/api/v1/authorizations/{record['id']}/approve", json=APPROVAL)
    assert result.status_code == (409 if expired else 200), result.text


@pytest.mark.parametrize("status,verified,start_delta,end_delta,expected", [
    ("approved", True, -1, 1, "active"),
    ("approved", True, 0, 1, "active"),
    ("approved", True, 1, 2, "scheduled"),
    ("approved", True, -1, 0, "expired"),
    ("pending", True, -1, 0, "expired"),
    ("pending", True, 1, 2, "pending"),
    ("approved", False, -1, 1, "needs_date_review"),
    ("rejected", False, -1, 1, "rejected"),
    ("revoked", False, -1, 1, "revoked"),
])
def test_effective_state_boundaries_and_filter(api, status, verified, start_delta, end_delta, expected):
    record_id, website_id = seed_record(
        status=status, timestamps_verified=verified,
        valid_from=NOW + timedelta(hours=start_delta),
        valid_until=NOW + timedelta(hours=end_delta),
    )
    result = api.get(f"/api/v1/authorizations/{record_id}").json()
    assert result["status"] == status  # Decision history is not overwritten.
    assert result["effective_status"] == expected
    rows = api.get(f"/api/v1/authorizations?effective_status={expected}").json()
    assert [row["id"] for row in rows] == [record_id]
    assert api.get(f"/api/v1/websites/{website_id}").json()["effective_authorisation_status"] == expected


def test_legacy_approval_blocked_without_changing_dates_or_decisions(api):
    record_id, _ = seed_record(timestamps_verified=False)
    before = api.get(f"/api/v1/authorizations/{record_id}").json()
    response = api.post(f"/api/v1/authorizations/{record_id}/approve", json=APPROVAL)
    assert response.status_code == 409
    after = api.get(f"/api/v1/authorizations/{record_id}").json()
    assert after == before
    assert api.get(f"/api/v1/authorizations/{record_id}/events").json() == []
    # Rejection remains available for an unverified or expired pending request.
    assert api.post(f"/api/v1/authorizations/{record_id}/reject", json={"reason": "Legacy dates cannot be established."}).status_code == 200


def test_summary_counts_full_dataset_not_websites_or_first_page(api):
    record_id, website_id = seed_record()
    with SessionLocal() as db:
        original = db.get(WebsiteAuthorization, record_id)
        for i in range(105):
            db.add(WebsiteAuthorization(
                website_id=website_id, authorization_reference=f"COUNT-{i}",
                authorized_by="Synthetic Signatory", authorized_domains=original.authorized_domains,
                permitted_methods=["passive_reconnaissance"], status="approved",
                valid_from=NOW - timedelta(days=1), valid_until=NOW - timedelta(hours=1),
                timestamps_verified=True,
            ))
        db.add(Website(client_id=db.get(Website, website_id).client_id, name="No request",
                       url="https://no-request.example.com", environment="staging"))
        db.commit()
    summary = api.get("/api/v1/authorizations/summary").json()
    assert summary["total"] == 106
    assert summary["decision_counts"]["approved"] == 105
    assert summary["effective_counts"]["pending"] == 1
    assert summary["effective_counts"]["expired"] == 105
    assert summary["effective_counts"]["active"] == 0
    assert len(api.get("/api/v1/authorizations?effective_status=expired&limit=100").json()) == 100
    assert len(api.get("/api/v1/authorizations?effective_status=expired&limit=100&offset=100").json()) == 5
    sites = api.get("/api/v1/websites").json()
    assert next(s for s in sites if s["name"] == "No request")["effective_authorisation_status"] == "not_requested"


def test_revoking_one_approval_uses_another_current_approval(api):
    record_id, website_id = seed_record(status="approved")
    with SessionLocal() as db:
        original = db.get(WebsiteAuthorization, record_id)
        db.add(WebsiteAuthorization(
            website_id=website_id, authorization_reference="SECOND-APPROVAL",
            authorized_by="Synthetic Signatory", authorized_domains=original.authorized_domains,
            permitted_methods=["passive_reconnaissance"], status="approved",
            valid_from=NOW - timedelta(hours=1), valid_until=NOW + timedelta(hours=1),
            timestamps_verified=True,
        ))
        db.commit()
    assert api.post(f"/api/v1/authorizations/{record_id}/revoke", json={"reason": "Withdraw only the first written permission."}).status_code == 200
    assert api.get(f"/api/v1/websites/{website_id}").json()["effective_authorisation_status"] == "active"


@pytest.mark.parametrize("actions", [("approved", "rejected"), ("approved", "approved")])
def test_competing_decisions_have_one_winner_and_one_event(api, monkeypatch, actions):
    record_id, _ = seed_record()
    attach_review(api, record_id)
    barrier = Barrier(2)
    original_get = service.get_authorization

    def synchronized_get(db, key):
        record = original_get(db, key)
        barrier.wait(timeout=10)  # Both transactions have read the pending state.
        return record

    monkeypatch.setattr(service, "get_authorization", synchronized_get)

    def decide(action):
        with SessionLocal() as db:
            try:
                service.decide_authorization(db, record_id, api.admin_id, action, APPROVAL["review_note"], now=NOW)
                return 200
            except HTTPException as exc:
                return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(decide, actions))
    assert sorted(results) == [200, 409]
    with SessionLocal() as db:
        events = list(db.scalars(select(AuthorizationAuditEvent).where(AuthorizationAuditEvent.authorization_id == record_id)))
        assert len(events) == 1
        assert db.get(WebsiteAuthorization, record_id).status == events[0].new_status


def test_audit_write_failure_rolls_back_decision(api):
    record_id, _ = seed_record()
    attach_review(api, record_id)
    with SessionLocal() as db:
        def reject_event(session, context, instances):
            if any(isinstance(item, AuthorizationAuditEvent) for item in session.new):
                raise RuntimeError("Synthetic audit-storage failure")

        event.listen(db, "before_flush", reject_event)
        with pytest.raises(RuntimeError, match="Synthetic audit"):
            service.decide_authorization(db, record_id, api.admin_id, "approved", APPROVAL["review_note"], now=NOW)
        event.remove(db, "before_flush", reject_event)
    with SessionLocal() as db:
        assert db.get(WebsiteAuthorization, record_id).status == "pending"
        assert list(db.scalars(select(AuthorizationAuditEvent))) == []


def test_repeated_and_invalid_decisions_do_not_add_audit_events(api):
    record_id, _ = seed_record()
    attach_review(api, record_id)
    endpoint = f"/api/v1/authorizations/{record_id}"
    assert api.post(endpoint + "/approve", json={**APPROVAL, "evidence_reviewed": False}).status_code == 422
    assert api.post(endpoint + "/approve", json={**APPROVAL, "review_note": " " * 30}).status_code == 422
    assert api.get(endpoint + "/events").json() == []
    assert api.post(endpoint + "/approve", json=APPROVAL).status_code == 200
    assert api.post(endpoint + "/approve", json=APPROVAL).status_code == 409
    assert api.post(endpoint + "/reject", json={"reason": "Too late for rejection now."}).status_code == 409
    assert len(api.get(endpoint + "/events").json()) == 1


def test_summary_and_mutations_require_authentication(api):
    api.headers.pop("Authorization")
    assert api.get("/api/v1/authorizations/summary").status_code == 401
    assert api.post("/api/v1/authorizations/1/approve", json=APPROVAL).status_code == 401
