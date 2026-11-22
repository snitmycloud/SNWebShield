from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_password
from app.db.session import SessionLocal
from app.main import app
from app.models.admin import Admin
from app.models.authorization import WebsiteAuthorization
from app.models.client import Client
from app.models.website import Website

TEST_PASSWORD = "A-strong-test-password-123!"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def create_admin_and_login(client: TestClient, *, active: bool = True) -> tuple[Admin, dict[str, str]]:
    email = f"admin-{uuid4().hex}@example.com"
    with SessionLocal() as db:
        admin = Admin(
            email=email,
            full_name="Unit Test Admin",
            password_hash=hash_password(TEST_PASSWORD),
            role="admin",
            is_active=active,
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)
        admin_id = admin.id

    login = client.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
    if not active:
        assert login.status_code == 403
        return admin, {}
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    return admin, {"Authorization": f"Bearer {token}"}


def create_pending_authorization() -> int:
    unique = uuid4().hex[:8]
    with SessionLocal() as db:
        client_record = Client(
            company_name=f"Test Client {unique}",
            primary_contact_name="Test Signatory",
            email=f"client-{unique}@example.com",
            industry="Testing",
        )
        db.add(client_record)
        db.flush()
        website = Website(
            client_id=client_record.id,
            name=f"Test site {unique}",
            url=f"https://{unique}.example.com",
            environment="staging",
            authorisation_status="pending",
        )
        db.add(website)
        db.flush()
        now = datetime.now(UTC)
        authorization = WebsiteAuthorization(
            website_id=website.id,
            authorization_reference=f"TEST-AUTH-{unique}",
            authorized_by="Test Signatory",
            authorized_domains=[f"{unique}.example.com"],
            permitted_methods=["passive_reconnaissance"],
            valid_from=now - timedelta(hours=1),
            valid_until=now + timedelta(days=2),
            status="pending",
            timestamps_verified=True,
        )
        db.add(authorization)
        db.commit()
        db.refresh(authorization)
        return authorization.id


def test_login_and_admin_profile(client):
    admin, headers = create_admin_and_login(client)
    me = client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["id"] == admin.id
    assert me.json()["role"] == "admin"
    assert "password_hash" not in me.json()


def test_login_rejects_wrong_password(client):
    admin, _ = create_admin_and_login(client)
    response = client.post(
        "/api/v1/auth/login", json={"email": admin.email, "password": "wrong-password"}
    )
    assert response.status_code == 401


def test_inactive_admin_cannot_login(client):
    create_admin_and_login(client, active=False)


def test_authorization_apis_require_admin_token(client):
    assert client.get("/api/v1/authorizations").status_code == 401
    assert client.get("/api/v1/authorizations/1").status_code == 401


def test_approval_requires_evidence_attestation(client):
    _, headers = create_admin_and_login(client)
    authorization_id = create_pending_authorization()
    response = client.post(
        f"/api/v1/authorizations/{authorization_id}/approve",
        json={"evidence_reviewed": False, "review_note": "This should not be accepted."},
        headers=headers,
    )
    assert response.status_code == 422


def test_admin_can_approve_and_audit_event_is_recorded(client):
    _, headers = create_admin_and_login(client)
    authorization_id = create_pending_authorization()
    response = client.post(
        f"/api/v1/authorizations/{authorization_id}/approve",
        json={
            "evidence_reviewed": True,
            "review_note": "Reviewed the signed authorization and verified the listed domain scope.",
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "approved"

    events = client.get(f"/api/v1/authorizations/{authorization_id}/events", headers=headers)
    assert events.status_code == 200
    assert len(events.json()) == 1
    assert events.json()[0]["action"] == "approved"
    assert events.json()[0]["evidence_reviewed"] is True


def test_admin_can_reject_pending_authorization(client):
    _, headers = create_admin_and_login(client)
    authorization_id = create_pending_authorization()
    response = client.post(
        f"/api/v1/authorizations/{authorization_id}/reject",
        json={"reason": "The submitted scope document is incomplete."},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "rejected"


def test_admin_can_revoke_approved_authorization(client):
    _, headers = create_admin_and_login(client)
    authorization_id = create_pending_authorization()
    approved = client.post(
        f"/api/v1/authorizations/{authorization_id}/approve",
        json={
            "evidence_reviewed": True,
            "review_note": "Reviewed the signed authorization and verified the listed domain scope.",
        },
        headers=headers,
    )
    assert approved.status_code == 200, approved.text

    revoked = client.post(
        f"/api/v1/authorizations/{authorization_id}/revoke",
        json={"reason": "Client requested withdrawal of testing permission."},
        headers=headers,
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"


def test_expired_authorization_cannot_be_approved(client):
    _, headers = create_admin_and_login(client)
    authorization_id = create_pending_authorization()
    with SessionLocal() as db:
        record = db.get(WebsiteAuthorization, authorization_id)
        now = datetime.now(UTC)
        record.valid_from = now - timedelta(days=3)
        record.valid_until = now - timedelta(minutes=1)
        db.commit()

    response = client.post(
        f"/api/v1/authorizations/{authorization_id}/approve",
        json={
            "evidence_reviewed": True,
            "review_note": "Reviewed the signed authorization and verified the listed domain scope.",
        },
        headers=headers,
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "Authorization validity period has expired"
