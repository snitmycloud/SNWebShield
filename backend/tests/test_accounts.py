"""Phase 1 accounts: sign-up, email verification, password reset/change, logout, throttling, admin controls."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.main import app
from app.models.admin import AccountToken, Admin
from app.models.security import AuthEvent
from account_helpers import PASSWORD, account_headers, latest_link_token, login, make_account, outbox_messages

A = "/api/v1/auth"
NEW_PASSWORD = "Another-strong-pass-456?"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def sign_up(client, email, password=PASSWORD):
    return client.post(f"{A}/signup", json={"email": email, "password": password, "full_name": "Asha Rao"})


def test_sign_up_verify_email_then_log_in(client):
    email = "Owner.One@Example.com"
    response = sign_up(client, email)
    assert response.status_code == 202 and response.json()["status"] == "check_email"
    with SessionLocal() as db:
        account = db.scalar(select(Admin).where(Admin.email == "owner.one@example.com"))
        assert account.role == "user" and account.plan == "free" and account.email_verified_at is None
        assert account.password_hash != PASSWORD and account.password_hash.startswith("$argon2")
        # Only a hash of the emailed token is stored.
        stored = db.scalar(select(AccountToken).where(AccountToken.account_id == account.id))
        token = latest_link_token("owner.one@example.com", "verify-email")
        assert stored.token_sha256 != token and token not in stored.token_sha256

    refused = client.post(f"{A}/login", json={"email": email, "password": PASSWORD})
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "email_not_verified"

    assert client.post(f"{A}/verify-email", json={"token": token}).status_code == 200
    assert client.post(f"{A}/verify-email", json={"token": token}).status_code == 400  # single use
    headers = login(client, "owner.one@example.com")
    me = client.get(f"{A}/me", headers=headers).json()
    assert me["role"] == "user" and me["email_verified_at"]
    plan = client.get(f"{A}/me/plan", headers=headers).json()
    assert plan["name"] == "free" and plan["max_websites"] == 5 and plan["websites_used"] == 0


def test_sign_up_rejects_a_weak_password_and_does_not_create_an_account(client):
    response = sign_up(client, "weak@example.com", "password")
    assert response.status_code == 422
    with SessionLocal() as db:
        assert db.scalar(select(Admin).where(Admin.email == "weak@example.com")) is None


def test_existing_email_gets_the_same_answer_and_no_new_account(client):
    _, email = make_account()
    response = sign_up(client, email)
    assert response.status_code == 202 and response.json()["status"] == "check_email"
    with SessionLocal() as db:
        assert len(db.scalars(select(Admin).where(Admin.email == email)).all()) == 1
    assert outbox_messages(email) == []  # a verified account is not sent anything


def test_expired_or_wrong_verification_link_is_refused(client):
    sign_up(client, "late@example.com")
    token = latest_link_token("late@example.com", "verify-email")
    with SessionLocal() as db:
        for row in db.scalars(select(AccountToken)):
            row.expires_at = utc_now() - timedelta(seconds=1)
        db.commit()
    assert client.post(f"{A}/verify-email", json={"token": token}).status_code == 400
    assert client.post(f"{A}/verify-email", json={"token": "x" * 43}).status_code == 400


def test_resending_verification_invalidates_the_previous_link(client):
    sign_up(client, "again@example.com")
    first = latest_link_token("again@example.com", "verify-email")
    assert client.post(f"{A}/resend-verification", json={"email": "again@example.com"}).status_code == 202
    second = latest_link_token("again@example.com", "verify-email")
    assert first != second
    assert client.post(f"{A}/verify-email", json={"token": first}).status_code == 400
    assert client.post(f"{A}/verify-email", json={"token": second}).status_code == 200


def test_sign_up_is_rate_limited_per_address(client, monkeypatch):
    monkeypatch.setattr(settings, "signup_max_per_ip", 3)
    for n in range(3):
        assert sign_up(client, f"burst{n}@example.com").status_code == 202
    assert sign_up(client, "burst-last@example.com").status_code == 429
    with SessionLocal() as db:
        assert db.scalar(select(Admin).where(Admin.email == "burst-last@example.com")) is None
        assert db.scalar(select(AuthEvent).where(AuthEvent.event_type == "signup_throttled")) is not None


def test_login_is_rate_limited(client, monkeypatch):
    monkeypatch.setattr(settings, "login_max_failures", 3)
    _, email = make_account()
    for _ in range(3):
        assert client.post(f"{A}/login", json={"email": email, "password": "wrong-password-1A!"}).status_code == 401
    assert client.post(f"{A}/login", json={"email": email, "password": PASSWORD}).status_code == 429


def test_forgot_and_reset_password(client):
    _, email, old_headers = account_headers(client)
    assert client.post(f"{A}/forgot-password", json={"email": email}).status_code == 202
    token = latest_link_token(email, "reset-password")
    weak = client.post(f"{A}/reset-password", json={"token": token, "new_password": "short"})
    assert weak.status_code == 422
    sign_up(client, "other@example.com")  # an unrelated token must not help
    assert client.post(f"{A}/forgot-password", json={"email": email}).status_code == 202
    token = latest_link_token(email, "reset-password")
    assert client.post(f"{A}/reset-password", json={"token": token, "new_password": NEW_PASSWORD}).status_code == 200
    assert client.post(f"{A}/reset-password", json={"token": token, "new_password": NEW_PASSWORD}).status_code == 400
    assert client.post(f"{A}/login", json={"email": email, "password": PASSWORD}).status_code == 401
    login(client, email, NEW_PASSWORD)


def test_forgot_password_never_reveals_whether_an_account_exists(client):
    unknown = client.post(f"{A}/forgot-password", json={"email": "nobody@example.com"})
    _, email = make_account()
    known = client.post(f"{A}/forgot-password", json={"email": email})
    assert unknown.status_code == known.status_code == 202 and unknown.json() == known.json()
    assert outbox_messages("nobody@example.com") == []


def test_disabled_account_gets_no_reset_link(client):
    _, email = make_account(active=False)
    client.post(f"{A}/forgot-password", json={"email": email})
    assert outbox_messages(email) == []


def test_change_password_returns_a_new_session_and_ends_old_ones(client):
    import time
    _, email, old = account_headers(client)
    time.sleep(1.1)  # token issue times have one-second precision
    wrong = client.post(f"{A}/change-password", headers=old, json={"current_password": "nope", "new_password": NEW_PASSWORD})
    assert wrong.status_code == 400
    changed = client.post(f"{A}/change-password", headers=old, json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    assert changed.status_code == 200, changed.text
    fresh = {"Authorization": "Bearer " + changed.json()["access_token"]}
    assert client.get(f"{A}/me", headers=old).status_code == 401
    assert client.get(f"{A}/me", headers=fresh).status_code == 200
    login(client, email, NEW_PASSWORD)


def test_logout_revokes_the_token(client):
    _, _, headers = account_headers(client)
    assert client.post(f"{A}/logout", headers=headers).status_code == 204
    assert client.get(f"{A}/me", headers=headers).status_code == 401


def test_audit_log_never_stores_passwords_tokens_or_raw_emails(client):
    sign_up(client, "audit@example.com")
    token = latest_link_token("audit@example.com", "verify-email")
    client.post(f"{A}/verify-email", json={"token": token})
    client.post(f"{A}/login", json={"email": "audit@example.com", "password": PASSWORD})
    with SessionLocal() as db:
        dump = repr([(e.event_type, e.email_sha256, e.reason, e.detail) for e in db.scalars(select(AuthEvent))])
    for event in ("signup", "email_verified", "login_success"):
        assert event in dump
    assert "audit@example.com" not in dump and PASSWORD not in dump and token not in dump


# --- Admin ---------------------------------------------------------------------------------------

def test_admin_lists_users_changes_plans_and_disables_accounts(client):
    admin_id, _, admin = account_headers(client, "admin")
    user_id, user_email, user = account_headers(client)
    listing = client.get("/api/v1/admin/users", headers=admin).json()
    assert {"free", "pro", "business"} <= set(listing["plans"])
    assert any(u["id"] == user_id and u["plan"] == "free" for u in listing["users"])

    assert client.post(f"/api/v1/admin/users/{user_id}/plan", headers=admin, json={"plan": "gold"}).status_code == 422
    changed = client.post(f"/api/v1/admin/users/{user_id}/plan", headers=admin, json={"plan": "pro"})
    assert changed.status_code == 200 and changed.json()["plan"] == "pro"

    assert client.post(f"/api/v1/admin/users/{user_id}/disable", headers=admin).status_code == 200
    assert client.get(f"{A}/me", headers=user).status_code == 401  # existing session ends
    assert client.post(f"{A}/login", json={"email": user_email, "password": PASSWORD}).status_code == 403
    assert client.post(f"/api/v1/admin/users/{admin_id}/disable", headers=admin).status_code == 409
    assert client.post(f"/api/v1/admin/users/{user_id}/enable", headers=admin).status_code == 200
    login(client, user_email)


@pytest.mark.parametrize("role", ["user", "analyst", "lead_analyst"])
def test_only_the_admin_role_manages_users(client, role):
    target, _ = make_account()
    _, _, headers = account_headers(client, role)
    assert client.get("/api/v1/admin/users", headers=headers).status_code == 403
    assert client.post(f"/api/v1/admin/users/{target}/plan", headers=headers, json={"plan": "business"}).status_code == 403


def test_email_links_open_the_app_under_app_and_plans_carry_prices():
    sign_up_client = TestClient(app)
    with sign_up_client as c:
        assert sign_up(c, "links.owner@example.com").status_code == 202
    token = latest_link_token("links.owner@example.com", "verify-email")
    assert token
    from app.services import accounts as accounts_service, plans
    assert accounts_service._link("verify-email", "T") == f"{settings.frontend_base_url.rstrip('/')}/app/verify-email?token=T"
    assert settings.public_app_url.rstrip("/").endswith("/app")
    data = plans.load()
    assert data["currency"] == "INR" and data["plans"]["free"]["price"] == {"monthly": 0, "yearly": 0}
    for name in ("pro", "business"):
        price = data["plans"][name]["price"]
        assert 0 < price["monthly"] < price["yearly"] <= price["monthly"] * 12
