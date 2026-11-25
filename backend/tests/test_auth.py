"""Login, profile and the staff/customer boundary."""
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.security import hash_password
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.main import app
from app.models.admin import Admin

TEST_PASSWORD = "A-strong-test-password-123!"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def create_admin_and_login(client: TestClient, *, active: bool = True, role: str = "admin") -> tuple[Admin, dict[str, str]]:
    email = f"{role}-{uuid4().hex}@example.com"
    with SessionLocal() as db:
        admin = Admin(email=email, full_name="Unit Test Account", password_hash=hash_password(TEST_PASSWORD),
                      role=role, is_active=active, email_verified_at=utc_now())
        db.add(admin)
        db.commit()
        db.refresh(admin)

    login = client.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
    if not active:
        assert login.status_code == 403
        return admin, {}
    assert login.status_code == 200, login.text
    return admin, {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_login_and_profile(client):
    admin, headers = create_admin_and_login(client)
    me = client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["id"] == admin.id and me.json()["role"] == "admin" and me.json()["plan"] == "free"
    assert "password_hash" not in me.json()


def test_login_rejects_wrong_password(client):
    admin, _ = create_admin_and_login(client)
    response = client.post("/api/v1/auth/login", json={"email": admin.email, "password": "wrong-password"})
    assert response.status_code == 401


def test_inactive_account_cannot_login(client):
    create_admin_and_login(client, active=False)


def test_customer_is_refused_by_every_staff_route(client):
    _, headers = create_admin_and_login(client, role="user")
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    for path in ("/api/v1/clients", "/api/v1/assessments", "/api/v1/vulnerabilities", "/api/v1/workbench/queue",
                 "/api/v1/reports", "/api/v1/remediation", "/api/v1/monitoring/overview", "/api/v1/admin/users"):
        assert client.get(path, headers=headers).status_code == 403, path


def test_staff_routes_still_require_a_token(client):
    assert client.get("/api/v1/assessments").status_code == 401
    assert client.get("/api/v1/websites").status_code == 401


def test_the_written_permission_api_is_gone(client):
    _, headers = create_admin_and_login(client)
    for method, path in (("get", "/api/v1/authorizations"), ("post", "/api/v1/authorizations"),
                         ("post", "/api/v1/authorizations/1/approve"), ("get", "/api/v1/authorizations/1/evidence"),
                         ("post", "/api/v1/evidence/x/purge"), ("get", "/api/v1/assessments/readiness?website_id=1")):
        response = getattr(client, method)(path, headers=headers, **({"json": {}} if method == "post" else {}))
        assert response.status_code in (404, 405, 422), (path, response.status_code)
    paths = client.get("/openapi.json").json()["paths"]
    assert not any("authorization" in p or "evidence" in p for p in paths)
