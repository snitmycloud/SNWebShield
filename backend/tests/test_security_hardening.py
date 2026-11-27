"""Security hardening that still applies to the self-service product (ported from the retired production-hardening and authorization suites):
authentication audit log, login throttling, logout revocation, forged tokens, password rules, security headers, CORS, role storage,
users cannot reach each other's data, admin-only routes, and error messages that do not leak details."""
import json
from datetime import timedelta
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.core.config import Settings, settings
from app.core.security import hash_password, password_hasher, validate_password_policy
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.main import app
from app.models.admin import Admin
from app.models.scan import Scan
from app.models.security import AuthEvent, RevokedToken
from app.models.website import Website
from app.services import auth_audit
from account_helpers import PASSWORD, account_headers, login, make_account

LOGIN = "/api/v1/auth/login"
LOGOUT = "/api/v1/auth/logout"
W = "/api/v1/websites"
BAD = "wrong-password-value-1!"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def attempt(client, email, password=PASSWORD):
    return client.post(LOGIN, json={"email": email, "password": password})


# --- authentication audit log --------------------------------------------------------------------------------------------------------------------

def test_login_outcomes_are_audited_without_passwords_tokens_or_raw_emails(client):
    admin_id, email = make_account("admin")
    inactive_id, inactive = make_account("user", active=False)
    assert attempt(client, email, BAD).status_code == 401
    assert attempt(client, "nobody@example.com", "wrong-password-value-2!").status_code == 401
    assert attempt(client, inactive).status_code == 403
    ok = attempt(client, email)
    assert ok.status_code == 200
    with SessionLocal() as db:
        rows = list(db.scalars(select(AuthEvent).order_by(AuthEvent.id)))
        assert [r.event_type for r in rows] == ["login_failure", "login_failure", "login_inactive", "login_success"]
        assert [r.reason for r in rows][:2] == ["bad_password", "unknown_account"]
        assert rows[0].admin_id == admin_id and rows[1].admin_id is None and rows[2].admin_id == inactive_id
        assert all(r.occurred_at and r.client_ip for r in rows)
        dump = json.dumps([[r.email_sha256, r.client_ip, r.reason, r.detail] for r in rows])
        for secret in (PASSWORD, "wrong-password-value", ok.json()["access_token"], email, "nobody@example.com"):
            assert secret not in dump
        assert rows[3].email_sha256 == auth_audit.email_digest(email)


def test_auth_events_are_append_only_in_orm_and_database(client):
    _, email = make_account("admin")
    attempt(client, email)
    with SessionLocal() as db:
        row = db.query(AuthEvent).first()
        row.reason = "changed"
        with pytest.raises(ValueError, match="append-only"):
            db.flush()
        db.rollback()
        db.delete(db.query(AuthEvent).first())
        with pytest.raises(ValueError, match="append-only"):
            db.flush()
        db.rollback()
        for sql in ("UPDATE auth_events SET reason = 'x'", "DELETE FROM auth_events"):
            with pytest.raises(DBAPIError, match="append-only"):
                db.execute(text(sql))
            db.rollback()
        assert db.query(AuthEvent).count() == 1


# --- login throttling ----------------------------------------------------------------------------------------------------------------------------

def test_repeated_failures_lock_the_login_even_for_the_correct_password(client):
    _, email = make_account("user")
    for _ in range(settings.login_max_failures):
        assert attempt(client, email, BAD).status_code == 401
    locked = attempt(client, email)   # correct password, but throttled
    assert locked.status_code == 429 and int(locked.headers["Retry-After"]) > 0 and "token" not in locked.text
    assert attempt(client, email, BAD).status_code == 429
    with SessionLocal() as db:
        kinds = [r.event_type for r in db.scalars(select(AuthEvent).order_by(AuthEvent.id))]
        assert kinds.count("login_failure") == settings.login_max_failures and kinds.count("login_throttled") == 2 and "login_success" not in kinds


def test_the_lock_lifts_after_the_window_and_other_accounts_are_unaffected(client, monkeypatch):
    _, victim = make_account("user")
    _, other = make_account("user")
    for _ in range(settings.login_max_failures):
        attempt(client, victim, BAD)
    assert attempt(client, victim).status_code == 429
    assert attempt(client, other).status_code == 200   # same address, different account
    later = utc_now() + timedelta(minutes=settings.login_window_minutes, seconds=5)
    monkeypatch.setattr(auth_audit, "utc_now", lambda: later)
    assert attempt(client, victim).status_code == 200


def test_a_successful_login_resets_the_failure_count(client):
    _, email = make_account("user")
    for _ in range(settings.login_max_failures - 1):
        attempt(client, email, BAD)
    assert attempt(client, email).status_code == 200
    for _ in range(settings.login_max_failures - 1):
        assert attempt(client, email, BAD).status_code == 401
    assert attempt(client, email).status_code == 200


def test_credential_stuffing_from_one_address_is_throttled(client):
    for index in range(settings.login_max_failures * 4):
        assert attempt(client, f"stuff-{index}@example.com", BAD).status_code == 401
    assert attempt(client, "another@example.com", BAD).status_code == 429


# --- logout and tokens ----------------------------------------------------------------------------------------------------------------------------

def test_logout_revokes_only_the_presented_token_and_is_audited(client):
    admin_id, email = make_account("user")
    first, second = login(client, email), login(client, email)
    assert client.get("/api/v1/auth/me", headers=first).status_code == 200
    assert client.post(LOGOUT, headers=first).status_code == 204
    assert client.get("/api/v1/auth/me", headers=first).status_code == 401
    assert client.get(W, headers=first).status_code == 401
    assert client.post(LOGOUT, headers=first).status_code == 401   # a revoked token cannot do anything
    assert client.get("/api/v1/auth/me", headers=second).status_code == 200
    with SessionLocal() as db:
        assert db.query(RevokedToken).count() == 1
        assert db.scalar(select(AuthEvent).where(AuthEvent.event_type == "logout")).admin_id == admin_id
    assert client.post(LOGOUT).status_code == 401


def test_a_token_with_a_stale_role_is_rejected_and_old_revocation_entries_are_cleaned(client):
    account_id, email = make_account("user")
    headers = login(client, email)
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    with SessionLocal() as db:
        db.get(Admin, account_id).role = "admin"   # promoted after the token was issued
        db.commit()
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert client.get("/api/v1/admin/users", headers=headers).status_code == 401
    with SessionLocal() as db:
        db.add(RevokedToken(jti="old", admin_id=account_id, revoked_at=utc_now() - timedelta(hours=3), expires_at=utc_now() - timedelta(hours=2)))
        db.commit()
    assert client.post(LOGOUT, headers=login(client, email)).status_code == 204
    with SessionLocal() as db:
        assert db.get(RevokedToken, "old") is None


def test_forged_unknown_role_and_wrong_signature_tokens_are_rejected(client):
    _, email = make_account("user")
    original = login(client, email)["Authorization"].split()[1]
    key = settings.jwt_secret_key.get_secret_value()
    claims = jwt.decode(original, key, algorithms=["HS256"], audience=settings.jwt_audience)
    for forged in (jwt.encode({**claims, "role": "root"}, key, algorithm="HS256"),
                   jwt.encode({**claims, "role": "admin"}, key, algorithm="HS256"),   # claims more than the account has
                   jwt.encode(claims, "x" * 40, algorithm="HS256"),
                   jwt.encode({**claims, "aud": "someone-else"}, key, algorithm="HS256"),
                   jwt.encode({k: v for k, v in claims.items() if k != "exp"}, key, algorithm="HS256"),
                   jwt.encode({**claims, "exp": 1}, key, algorithm="HS256"),
                   original + "tamper", "not.a.token", ""):
        assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


# --- passwords -----------------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("password,email,ok", [
    ("A-strong-test-password-123!", "a@example.com", True), ("Short1!", "a@example.com", False), ("alllowercaseletters", "a@example.com", False),
    ("1234567890123456", "a@example.com", False), ("aaaaaaaaaaaaaaaaAA1", "a@example.com", False), ("Password1234", "a@example.com", False),
    ("Janedoe-Secure-99", "janedoe@example.com", False), ("x" * 129 + "A1!", "a@example.com", False)])
def test_password_policy(password, email, ok):
    assert (validate_password_policy(password, email) == []) is ok


def test_password_hash_uses_argon2id_and_old_hashes_are_upgraded_on_login(client):
    assert password_hasher.hash("x").startswith("$argon2id$")
    from argon2 import PasswordHasher
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
    account_id, email = make_account("user")
    with SessionLocal() as db:
        db.get(Admin, account_id).password_hash = weak
        db.commit()
    assert attempt(client, email).status_code == 200
    with SessionLocal() as db:
        assert db.get(Admin, account_id).password_hash != weak and not password_hasher.check_needs_rehash(db.get(Admin, account_id).password_hash)
    assert attempt(client, email).status_code == 200


# --- security headers and CORS -------------------------------------------------------------------------------------------------------------------

def test_security_headers_on_success_error_and_preflight_responses(client):
    for response in (client.get("/api/v1/health"), client.get(W),
                     client.options(W, headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})):
        h = response.headers
        assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff" and h["referrer-policy"] == "no-referrer"
        assert "default-src 'none'" in h["content-security-policy"] and "frame-ancestors 'none'" in h["content-security-policy"]
        assert h["cache-control"] == "no-store" and "permissions-policy" in h
        assert "strict-transport-security" not in h   # plain HTTP never gets HSTS


def test_hsts_only_over_https_and_never_from_a_forwarded_header():
    with TestClient(app, base_url="https://testserver") as secure:
        assert "max-age=" in secure.get("/api/v1/health").headers["strict-transport-security"]
    with TestClient(app) as plain:
        assert "strict-transport-security" not in plain.get("/api/v1/health", headers={"X-Forwarded-Proto": "https"}).headers


def test_cors_only_trusts_configured_origins_and_rejects_unsafe_configuration(client):
    allowed = client.options(W, headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"})
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    denied = client.options(W, headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in denied.headers
    assert "DELETE" not in allowed.headers["access-control-allow-methods"]
    for bad in ("*", "http://a.example/path", "javascript:alert(1)", "http://a.example,*", "localhost:5173"):
        with pytest.raises(ValidationError):
            Settings(cors_origins=bad, _env_file=None)
    assert Settings(cors_origins="https://app.example.com, http://localhost:5173", _env_file=None).cors_origin_list == [
        "https://app.example.com", "http://localhost:5173"]


# --- roles ---------------------------------------------------------------------------------------------------------------------------------------

def test_unknown_roles_cannot_be_stored(client):
    with SessionLocal() as db:
        db.add(Admin(email="v@example.com", full_name="Viewer", password_hash="x", role="viewer"))
        with pytest.raises(Exception, match="ck_admins_role|CHECK"):
            db.commit()
        db.rollback()


# --- users cannot reach each other's data ---------------------------------------------------------------------------------------------------------

def test_another_users_website_scans_findings_and_actions_are_not_reachable(client):
    _, _, owner = account_headers(client)
    _, _, stranger = account_headers(client)
    site = client.post(W, headers=owner, json={"domain": f"mine-{uuid4().hex[:8]}.example.com"}).json()
    with SessionLocal() as db:
        row = db.get(Website, site["id"])
        scan = Scan(id=str(uuid4()), website_id=row.id, owner_id=row.owner_id, scan_type="standard", trigger="manual", status="completed",
                    requested_at=utc_now(), result={})
        db.add(scan)
        db.commit()
        scan_id = scan.id
    fp, base = "0" * 64, f"{W}/{site['id']}"
    reads = [base, f"{base}/scans", f"{base}/scans/{scan_id}", f"{base}/scans/{scan_id}/comparison", f"{base}/trend", f"{base}/audit"]
    writes = [(f"{base}/scan", {"scan_type": "standard"}), (f"{base}/verify", {"method": "dns"}), (f"{base}/findings/{fp}/accept", {"reason": "x" * 30, "days": 90}),
              (f"{base}/findings/{fp}/unaccept", {}), (f"{base}/findings/{fp}/recheck", {}), (f"{base}/remove", {"confirm_domain": "x"}),
              (f"{base}/verify-manual", {"owner_name": "Asha Rao", "consent_method": "email", "reason": "Asha emailed her consent for the scan"})]
    assert all(client.get(url, headers=owner).status_code == 200 for url in reads[:2])
    for url in reads:
        assert client.get(url, headers=stranger).status_code in (403, 404), url
        assert client.get(url).status_code in (401, 403), url
    for url, body in writes:
        assert client.post(url, headers=stranger, json=body).status_code in (403, 404), url
        assert client.post(url, json=body).status_code in (401, 403), url
    listed = client.get(W, headers=stranger).json()
    assert site["id"] not in [item["id"] for item in (listed if isinstance(listed, list) else listed.get("items", []))]


# --- admin-only routes ---------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("role", ["user", "analyst", "lead_analyst"])
def test_only_the_admin_role_reaches_admin_routes(client, role):
    _, _, headers = account_headers(client, role=role)
    _, _, admin = account_headers(client, role="admin")
    target = client.get("/api/v1/admin/users", headers=admin).json()["users"][0]["id"]
    for method, url, body in (("get", "/api/v1/admin/users", None), ("get", "/api/v1/admin/workers", None),
                              ("post", f"/api/v1/admin/users/{target}/plan", {"plan": "pro"}), ("post", f"/api/v1/admin/users/{target}/disable", {}),
                              ("post", f"{W}/1/verify-manual", {"owner_name": "Asha Rao", "consent_method": "email", "reason": "Asha emailed her consent"})):
        response = client.request(method.upper(), url, headers=headers, **({"json": body} if body is not None else {}))
        assert response.status_code in (403, 404), (role, url, response.status_code)
    assert client.get("/api/v1/admin/workers", headers=admin).status_code == 200


# --- error messages do not leak details --------------------------------------------------------------------------------------------------------

def test_an_unexpected_error_returns_a_generic_message_without_details(monkeypatch):
    from app.api.routes import websites
    with TestClient(app, raise_server_exceptions=False) as quiet:
        _, _, headers = account_headers(quiet)
        site = quiet.post(W, headers=headers, json={"domain": f"boom-{uuid4().hex[:8]}.example.com"}).json()
        monkeypatch.setattr(websites, "read_website", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("SECRET-connection-string C:\\Users\\x\\.env")))
        response = quiet.get(f"{W}/{site['id']}", headers=headers)
    assert response.status_code == 500
    assert "SECRET" not in response.text and "Traceback" not in response.text and ".env" not in response.text and "RuntimeError" not in response.text


def test_wrong_password_and_unknown_account_get_the_same_answer(client):
    _, email = make_account("user")
    wrong, unknown = attempt(client, email, BAD), attempt(client, "nobody-here@example.com", BAD)
    assert wrong.status_code == unknown.status_code == 401 and wrong.json() == unknown.json()


def test_validation_errors_do_not_echo_secrets(client):
    response = client.post(LOGIN, json={"email": "not-an-email", "password": "My-Secret-Password-9!"})
    assert response.status_code == 422 and "My-Secret-Password-9!" not in response.text
    response = client.post("/api/v1/auth/signup", json={"email": "a@example.com", "full_name": "A", "password": "weak"})
    assert response.status_code in (400, 422) and "weak" not in json.dumps(response.json().get("detail", "")).replace("weak password", "")
