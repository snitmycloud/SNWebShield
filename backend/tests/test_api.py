
import os
from pathlib import Path
from uuid import uuid4

import pytest

# Ensure tests use an isolated SQLite database before importing the app.
TEST_DB = Path(__file__).with_name("test_snwebshield.db")
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"
os.environ["JWT_SECRET_KEY"] = (
    "test-only-secret-key-not-for-any-real-environment-123456789"
)

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.security import hash_password  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models.admin import Admin  # noqa: E402


@pytest.fixture
def api_client():
    # Entering the context manager runs FastAPI's lifespan and creates test tables.
    with TestClient(app) as test_client:
        email = f"test-admin-{uuid4().hex}@example.com"
        password = "TestAdminPassword!234"

        with SessionLocal() as db:
            db.add(
                Admin(
                    email=email,
                    full_name="Test Administrator",
                    password_hash=hash_password(password),
                    role="admin",
                    is_active=True,
                )
            )
            db.commit()

        # Authenticate the test administrator and obtain a real JWT token.
        login = test_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert login.status_code == 200, login.text

        test_client.test_admin_headers = {
            "Authorization": f"Bearer {login.json()['access_token']}"
        }

        yield test_client


def create_website(api_client: TestClient, email: str | None = None) -> int:
    email = email or f"asha-{uuid4().hex}@example.com"

    # Create client using authenticated admin credentials.
    client_response = api_client.post(
        "/api/v1/clients",
        json={
            "company_name": "Example Client Pvt Ltd",
            "primary_contact_name": "Asha Rao",
            "email": email,
            "industry": "E-commerce",
        },
        headers=api_client.test_admin_headers,
    )

    assert client_response.status_code == 201, client_response.text
    client_id = client_response.json()["id"]

    # Create website using authenticated admin credentials.
    website_response = api_client.post(
        "/api/v1/websites",
        json={
            "client_id": client_id,
            "name": "Example public website",
            "url": "https://example.com",
            "platform": "WordPress",
            "environment": "staging",
        },
        headers=api_client.test_admin_headers,
    )

    assert website_response.status_code == 201, website_response.text

    return website_response.json()["id"]


def valid_authorization_payload(website_id: int) -> dict:
    return {
        "website_id": website_id,
        "authorization_reference": f"AUTH-EXAMPLE-{uuid4().hex[:8]}",
        "authorized_by": "Asha Rao",
        "authorized_domains": ["example.com", "staging.example.com"],
        "permitted_methods": [
            "passive_reconnaissance",
            "configuration_review",
            "automated_non_intrusive_scanning",
            "manual_web_application_testing",
        ],
        "valid_from": "2026-11-20T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
    }


def test_health_endpoint(api_client):
    response = api_client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_create_client_and_website(api_client):
    website_id = create_website(api_client)

    website_response = api_client.get(
        f"/api/v1/websites/{website_id}",
        headers=api_client.test_admin_headers,
    )

    assert website_response.status_code == 200
    assert website_response.json()["authorisation_status"] == "pending"


def test_create_authorization_stays_pending(api_client):
    website_id = create_website(api_client)

    response = api_client.post(
        "/api/v1/authorizations",
        json=valid_authorization_payload(website_id),
        headers=api_client.test_admin_headers,
    )

    assert response.status_code == 201, response.text

    data = response.json()
    assert data["website_id"] == website_id
    assert data["status"] == "pending"
    assert data["authorized_domains"] == [
        "example.com",
        "staging.example.com",
    ]


def test_authorization_requires_admin_authentication(api_client):
    response = api_client.get("/api/v1/authorizations")

    assert response.status_code == 401


def test_authorization_requires_existing_website(api_client):
    response = api_client.post(
        "/api/v1/authorizations",
        json=valid_authorization_payload(99999),
        headers=api_client.test_admin_headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Website not found"


def test_authorized_domains_must_include_registered_hostname(api_client):
    website_id = create_website(api_client)
    payload = valid_authorization_payload(website_id)
    payload["authorized_domains"] = ["other-example.com"]

    response = api_client.post(
        "/api/v1/authorizations",
        json=payload,
        headers=api_client.test_admin_headers,
    )

    assert response.status_code == 422
    assert "must explicitly include" in response.json()["detail"]


def test_invalid_testing_method_is_rejected(api_client):
    website_id = create_website(api_client)
    payload = valid_authorization_payload(website_id)
    payload["permitted_methods"] = ["denial_of_service"]

    response = api_client.post(
        "/api/v1/authorizations",
        json=payload,
        headers=api_client.test_admin_headers,
    )

    assert response.status_code == 422


def test_authorization_requires_timezone_and_valid_date_order(api_client):
    website_id = create_website(api_client)

    payload = valid_authorization_payload(website_id)
    payload["valid_from"] = "2026-11-20T00:00:00"

    response = api_client.post(
        "/api/v1/authorizations",
        json=payload,
        headers=api_client.test_admin_headers,
    )

    assert response.status_code == 422

    payload = valid_authorization_payload(website_id)
    payload["valid_until"] = "2026-11-19T23:59:59Z"

    response = api_client.post(
        "/api/v1/authorizations",
        json=payload,
        headers=api_client.test_admin_headers,
    )

    assert response.status_code == 422


def test_client_cannot_set_authorization_status_on_create(api_client):
    website_id = create_website(api_client)
    payload = valid_authorization_payload(website_id)
    payload["status"] = "approved"

    response = api_client.post(
        "/api/v1/authorizations",
        json=payload,
        headers=api_client.test_admin_headers,
    )

    assert response.status_code == 422


def test_list_authorizations_can_filter_by_website(api_client):
    website_id = create_website(api_client)

    create_response = api_client.post(
        "/api/v1/authorizations",
        json=valid_authorization_payload(website_id),
        headers=api_client.test_admin_headers,
    )

    assert create_response.status_code == 201

    response = api_client.get(
        "/api/v1/authorizations",
        params={"website_id": website_id},
        headers=api_client.test_admin_headers,
    )

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["status"] == "pending"


def teardown_module():
    engine.dispose()

    if TEST_DB.exists():
        TEST_DB.unlink()
