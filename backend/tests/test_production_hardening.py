"""Milestone 6: production hardening (R1-R3, R14, R15, closed-assessment lock, evidence retention)."""
import json
import sqlite3
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.core import rbac
from app.core.config import Settings, settings
from app.core.security import hash_password, password_hasher, validate_password_policy
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.main import app
from app.models.admin import Admin
from app.models.evidence import AuthorizationEvidence, EvidenceEvent
from app.models.authorization import WebsiteAuthorization
from app.models.remediation import AssessmentClosure
from app.models.security import AuthEvent, ClosureReopening, RevokedToken
from app.services import auth_audit, evidence as evidence_service
from evidence_helpers import attach_review, png
from test_auth import TEST_PASSWORD
from test_authorization_correctness import APPROVAL, NOW, api, seed_record  # noqa: F401 - fixture
from test_local_assessment import network  # noqa: F401 - fixture
from test_assessments import assessed  # noqa: F401 - fixture
from test_migrations import migrate
from test_remediation import AS, NIL, REM, close, confirm, get, patch_scanner, reopen, tracked, update  # noqa: F401
from test_remediation import request_retest
from test_reports import R, decide as decide_report, generate as generate_report
from test_vulnerabilities import ONLY_DISCLOSURE, assess, one, run
from test_workbench import signoff

LOGIN = "/api/v1/auth/login"
LOGOUT = "/api/v1/auth/logout"
RISK = "Business owner accepts the residual risk until the platform migration in Q2."


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def make_user(role="analyst", *, active=True, password=TEST_PASSWORD):
    email = f"{role}-{uuid4().hex[:10]}@example.com"
    with SessionLocal() as db:
        admin = Admin(email=email, full_name=f"Test {role}", password_hash=hash_password(password), role=role, is_active=active)
        db.add(admin)
        db.commit()
        return email, admin.id


def login(client, email, password=TEST_PASSWORD):
    return client.post(LOGIN, json={"email": email, "password": password})


def token_for(client, role):
    email, admin_id = make_user(role)
    response = login(client, email)
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}, admin_id


class As:
    """Temporarily act as another account on a shared TestClient."""
    def __init__(self, client, headers):
        self.client, self.headers = client, headers

    def __enter__(self):
        self.saved = self.client.headers.get("Authorization")
        self.client.headers["Authorization"] = self.headers["Authorization"]
        return self.client

    def __exit__(self, *exc):
        self.client.headers["Authorization"] = self.saved


# --- R1: authentication audit log ------------------------------------------------------------

def test_login_outcomes_are_audited_without_passwords_tokens_or_raw_emails(client):
    email, admin_id = make_user("admin")
    inactive, inactive_id = make_user("analyst", active=False)
    assert login(client, email, "wrong-password-value-1!").status_code == 401
    assert login(client, "nobody@example.com", "wrong-password-value-2!").status_code == 401
    assert login(client, inactive).status_code == 403
    ok = login(client, email)
    assert ok.status_code == 200
    with SessionLocal() as db:
        rows = list(db.scalars(select(AuthEvent).order_by(AuthEvent.id)))
        assert [r.event_type for r in rows] == ["login_failure", "login_failure", "login_inactive", "login_success"]
        assert [r.reason for r in rows][:2] == ["bad_password", "unknown_account"]
        assert rows[0].admin_id == admin_id and rows[1].admin_id is None and rows[2].admin_id == inactive_id
        assert all(r.occurred_at and r.client_ip for r in rows)
        dump = json.dumps([[r.email_sha256, r.client_ip, r.reason, r.detail] for r in rows])
        for secret in (TEST_PASSWORD, "wrong-password-value", ok.json()["access_token"], email, "nobody@example.com"):
            assert secret not in dump
        assert rows[3].email_sha256 == auth_audit.email_digest(email)


def test_auth_events_are_append_only_in_orm_and_database(client):
    email, _ = make_user("admin")
    login(client, email)
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


# --- R2: login throttling ----------------------------------------------------------------------

def test_repeated_failures_lock_the_login_even_for_the_correct_password(client):
    email, _ = make_user("admin")
    for _ in range(settings.login_max_failures):
        assert login(client, email, "wrong-password-value-1!").status_code == 401
    locked = login(client, email)  # correct password, but throttled
    assert locked.status_code == 429 and int(locked.headers["Retry-After"]) > 0
    assert "token" not in locked.text
    assert login(client, email, "wrong-password-value-1!").status_code == 429
    with SessionLocal() as db:
        kinds = [r.event_type for r in db.scalars(select(AuthEvent).order_by(AuthEvent.id))]
        assert kinds.count("login_failure") == settings.login_max_failures
        assert kinds.count("login_throttled") == 2 and "login_success" not in kinds


def test_lock_lifts_after_the_window_and_other_accounts_are_unaffected(client, monkeypatch):
    victim, _ = make_user("admin")
    other, _ = make_user("admin")
    for _ in range(settings.login_max_failures):
        login(client, victim, "wrong-password-value-1!")
    assert login(client, victim).status_code == 429
    assert login(client, other).status_code == 200  # same address, different account
    later = utc_now() + timedelta(minutes=settings.login_window_minutes, seconds=5)
    monkeypatch.setattr(auth_audit, "utc_now", lambda: later)
    assert login(client, victim).status_code == 200


def test_a_successful_login_resets_the_failure_count(client):
    email, _ = make_user("admin")
    for _ in range(settings.login_max_failures - 1):
        login(client, email, "wrong-password-value-1!")
    assert login(client, email).status_code == 200
    for _ in range(settings.login_max_failures - 1):
        assert login(client, email, "wrong-password-value-1!").status_code == 401
    assert login(client, email).status_code == 200


def test_credential_stuffing_from_one_address_is_throttled(client):
    for index in range(settings.login_max_failures * 4):
        assert login(client, f"stuff-{index}@example.com", "wrong-password-value-1!").status_code == 401
    assert login(client, "another@example.com", "wrong-password-value-1!").status_code == 429


# --- R3: server-side logout --------------------------------------------------------------------

def test_logout_revokes_only_the_presented_token_and_is_audited(client):
    email, admin_id = make_user("admin")
    first = {"Authorization": "Bearer " + login(client, email).json()["access_token"]}
    second = {"Authorization": "Bearer " + login(client, email).json()["access_token"]}
    assert client.get("/api/v1/auth/me", headers=first).status_code == 200
    assert client.post(LOGOUT, headers=first).status_code == 204
    assert client.get("/api/v1/auth/me", headers=first).status_code == 401
    assert client.get("/api/v1/clients", headers=first).status_code == 401
    assert client.post(LOGOUT, headers=first).status_code == 401  # a revoked token cannot do anything
    assert client.get("/api/v1/auth/me", headers=second).status_code == 200
    with SessionLocal() as db:
        assert db.query(RevokedToken).count() == 1
        assert db.scalar(select(AuthEvent).where(AuthEvent.event_type == "logout")).admin_id == admin_id
    assert client.post(LOGOUT).status_code == 401


def test_revoked_entries_expire_and_a_stale_role_claim_is_rejected(client):
    email, admin_id = make_user("analyst")
    headers = {"Authorization": "Bearer " + login(client, email).json()["access_token"]}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    with SessionLocal() as db:
        db.get(Admin, admin_id).role = "lead_analyst"  # promoted after the token was issued
        db.commit()
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    with SessionLocal() as db:
        db.add(RevokedToken(jti="old", admin_id=admin_id, revoked_at=utc_now() - timedelta(hours=3),
                            expires_at=utc_now() - timedelta(hours=2)))
        db.commit()
    fresh = {"Authorization": "Bearer " + login(client, email).json()["access_token"]}
    assert client.post(LOGOUT, headers=fresh).status_code == 204
    with SessionLocal() as db:
        assert {r.jti for r in db.query(RevokedToken)} != {"old"} and db.get(RevokedToken, "old") is None


def test_forged_unknown_role_and_wrong_signature_tokens_are_rejected(client):
    email, _ = make_user("analyst")
    original = login(client, email).json()["access_token"]
    key = settings.jwt_secret_key.get_secret_value()
    claims = jwt.decode(original, key, algorithms=["HS256"], audience=settings.jwt_audience)
    for forged in (jwt.encode({**claims, "role": "root"}, key, algorithm="HS256"),
                   jwt.encode({**claims, "role": "admin"}, key, algorithm="HS256"),  # claims more than the account has
                   jwt.encode(claims, "x" * 40, algorithm="HS256"),
                   original + "tamper"):
        assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


# --- Password policy -----------------------------------------------------------------------------

@pytest.mark.parametrize("password,email,ok", [
    ("A-strong-test-password-123!", "a@example.com", True),
    ("Short1!", "a@example.com", False),
    ("alllowercaseletters", "a@example.com", False),
    ("1234567890123456", "a@example.com", False),
    ("aaaaaaaaaaaaaaaaAA1", "a@example.com", False),
    ("Password1234", "a@example.com", False),
    ("Janedoe-Secure-99", "janedoe@example.com", False),
    ("x" * 129 + "A1!", "a@example.com", False),
])
def test_password_policy(password, email, ok):
    assert (validate_password_policy(password, email) == []) is ok


def test_password_hash_uses_argon2id_and_old_hashes_are_upgraded_on_login(client):
    assert password_hasher.hash("x").startswith("$argon2id$")
    from argon2 import PasswordHasher
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(TEST_PASSWORD)
    email, admin_id = make_user("admin")
    with SessionLocal() as db:
        db.get(Admin, admin_id).password_hash = weak
        db.commit()
    assert login(client, email).status_code == 200
    with SessionLocal() as db:
        assert db.get(Admin, admin_id).password_hash != weak and not password_hasher.check_needs_rehash(db.get(Admin, admin_id).password_hash)
    assert login(client, email).status_code == 200


# --- Security headers and CORS -------------------------------------------------------------------

def test_security_headers_on_success_error_and_preflight_responses(client):
    for response in (client.get("/api/v1/health"), client.get("/api/v1/clients"),
                     client.options("/api/v1/clients", headers={"Origin": "http://localhost:5173",
                                                                "Access-Control-Request-Method": "GET"})):
        h = response.headers
        assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"
        assert h["referrer-policy"] == "no-referrer"
        assert "default-src 'none'" in h["content-security-policy"] and "frame-ancestors 'none'" in h["content-security-policy"]
        assert h["cache-control"] == "no-store" and "permissions-policy" in h
        assert "strict-transport-security" not in h  # plain HTTP never gets HSTS


def test_hsts_only_over_https_and_never_from_a_forwarded_header():
    with TestClient(app, base_url="https://testserver") as secure:
        assert "max-age=" in secure.get("/api/v1/health").headers["strict-transport-security"]
    with TestClient(app) as plain:
        assert "strict-transport-security" not in plain.get("/api/v1/health", headers={"X-Forwarded-Proto": "https"}).headers


def test_evidence_downloads_keep_their_stricter_route_headers(api):
    authorization, _ = seed_record()
    key = attach_review(api, authorization)
    response = api.get(f"/api/v1/evidence/{key}/download")
    assert response.headers["content-security-policy"] == "default-src 'none'; sandbox"
    assert response.headers["cache-control"] == "no-store, private" and response.headers["x-frame-options"] == "DENY"


def test_cors_only_trusts_configured_origins_and_rejects_unsafe_configuration(client):
    allowed = client.options("/api/v1/clients", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"})
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    denied = client.options("/api/v1/clients", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in denied.headers
    assert "DELETE" not in allowed.headers["access-control-allow-methods"]
    for bad in ("*", "http://a.example/path", "javascript:alert(1)", "http://a.example,*", "localhost:5173"):
        with pytest.raises(ValidationError):
            Settings(cors_origins=bad, _env_file=None)
    assert Settings(cors_origins="https://app.example.com, http://localhost:5173", _env_file=None).cors_origin_list == [
        "https://app.example.com", "http://localhost:5173"]


# --- Roles (R14) ----------------------------------------------------------------------------------

def test_role_matrix_on_routes_that_need_a_senior_role(client):
    analyst, _ = token_for(client, "analyst")
    lead, _ = token_for(client, "lead_analyst")
    admin, _ = token_for(client, "admin")
    body = {"human_validation_confirmed": True, "justification": "x" * 30}
    for headers, expected in ((analyst, 403), (lead, 404), (admin, 404)):
        assert client.post(f"/api/v1/reports/{NIL}/approve", json=body, headers=headers).status_code == expected
        assert client.post(f"/api/v1/reports/{NIL}/reject", json=body, headers=headers).status_code == expected
        assert client.post(f"{AS}/{NIL}/close", json=body, headers=headers).status_code == expected
        assert client.post(f"{AS}/{NIL}/reopen-closure", json=body, headers=headers).status_code == expected
    # Everyday analyst work is open to all three roles.
    for headers in (analyst, lead, admin):
        assert client.get("/api/v1/workbench/queue", headers=headers).status_code == 200
        assert client.get("/api/v1/reports", headers=headers).status_code == 200
        assert client.get(REM, headers=headers).status_code == 200
    assert not (set(rbac.REPORT_APPROVER_ROLES) | set(rbac.CLOSURE_ROLES) | set(rbac.RISK_ACCEPTANCE_ROLES)) & {"analyst"}


def test_unknown_roles_cannot_be_stored(client):
    _, _ = make_user("admin")
    with SessionLocal() as db:
        db.add(Admin(email="v@example.com", full_name="Viewer", password_hash="x", role="viewer"))
        with pytest.raises(Exception, match="ck_admins_role|CHECK"):
            db.commit()
        db.rollback()


def test_analyst_cannot_accept_risk_but_lead_can(tracked):
    analyst, _ = token_for(tracked, "analyst")
    lead, _ = token_for(tracked, "lead_analyst")
    payload = dict(human_validation_confirmed=True, note=RISK)
    with As(tracked, analyst) as c:
        assert update(c, c.vid, "risk_accepted", 0, **payload).status_code == 403
        assert update(c, c.vid, "in_progress", 0).status_code == 200  # ordinary updates are fine
    with As(tracked, lead) as c:
        assert update(c, c.vid, "risk_accepted", 1, **payload).status_code == 200
    with SessionLocal() as db:
        assert db.get(__import__("app.models.remediation", fromlist=["x"]).VulnerabilityRemediation, tracked.vid).status == "risk_accepted"


# --- Separation of duties (R14, R15) ---------------------------------------------------------------

@pytest.fixture
def seeded(network, monkeypatch):
    row = run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    network[0].assessment_id, network[0].auth_id, network[0].monkeypatch = row["id"], network[1], monkeypatch
    return network[0]


def test_single_admin_bootstrap_still_runs_the_whole_workflow_by_default(seeded):
    assert settings.separation_of_duties_enabled is False
    item = one(seeded, "csp")
    assert assess(seeded, item).status_code == 201 and signoff(seeded, item).status_code == 200
    report = generate_report(seeded)
    assert decide_report(seeded, report).status_code == 200


def test_dual_signoff_blocks_self_approval_of_findings_reports_and_closure(seeded, monkeypatch):
    monkeypatch.setattr(settings, "separation_of_duties_enabled", True)
    analyst, analyst_id = token_for(seeded, "analyst")
    lead, lead_id = token_for(seeded, "lead_analyst")
    item = one(seeded, "csp")
    with As(seeded, analyst) as c:
        assert assess(c, item).status_code == 201
        refused = signoff(c, item)
        assert refused.status_code == 403 and "Separation of duties" in refused.json()["detail"]
    assert one(seeded, "csp")["validation_state"] == "unconfirmed"
    with As(seeded, lead) as c:
        assert signoff(c, item).status_code == 200  # a second person approves
    # Report: the creator cannot approve their own, even holding an approver role.
    with As(seeded, lead) as c:
        report = generate_report(c)
        assert decide_report(c, report).status_code == 403
        assert decide_report(c, report, "reject").status_code == 200  # rejecting is not self-approval
    with As(seeded, analyst) as c:
        report = generate_report(c)
        assert decide_report(c, report).status_code == 403  # role gate
    with As(seeded, lead) as c:
        assert decide_report(c, report).status_code == 200
    # Closure: whoever handled remediation cannot close.
    with As(seeded, lead) as c:
        assert update(c, item["id"], "risk_accepted", 0, human_validation_confirmed=True, note=RISK).status_code == 200
        assert close(seeded).status_code == 403
    second_lead, _ = token_for(seeded, "lead_analyst")
    with As(seeded, second_lead) as c:
        assert close(seeded).status_code == 200
    with SessionLocal() as db:
        assert db.query(AssessmentClosure).count() == 1


def test_separation_rule_is_a_runtime_switch_read_at_call_time(seeded, monkeypatch):
    item = one(seeded, "csp")
    assert assess(seeded, item).status_code == 201
    monkeypatch.setattr(settings, "separation_of_duties_enabled", True)
    assert signoff(seeded, item).status_code == 403
    monkeypatch.setattr(settings, "separation_of_duties_enabled", False)
    assert signoff(seeded, item).status_code == 200


# --- Closed-assessment lock ---------------------------------------------------------------------------

@pytest.fixture
def closed(tracked):
    assert update(tracked, tracked.vid, "risk_accepted", 0, human_validation_confirmed=True, note=RISK).status_code == 200
    assert close(tracked).status_code == 200
    return tracked


def locked_calls(c):
    item = c.get(f"/api/v1/vulnerabilities/{c.vid}").json()
    return {
        "remediation update": lambda: update(c, c.vid, "in_progress", 2),
        "finding reopen": lambda: reopen(c, c.vid, 1),
        "retest": lambda: request_retest(c, c.vid, 1),
        "sign-off reopen": lambda: signoff(c, item, "reopen"),
        "legacy validation": lambda: c.post(f"/api/v1/vulnerabilities/{c.vid}/validation", json={
            "expected_revision": item["revision"], "decision": "unconfirmed", "human_validation_confirmed": True,
            "justification": "Analyst inspected the stored evidence and target scope."}),
        "risk assessment": lambda: assess(c, item),
    }


def test_confirmed_findings_and_remediation_are_immutable_after_closure(closed):
    before = get(closed, closed.vid)
    for name, call in locked_calls(closed).items():
        response = call()
        assert response.status_code == 409 and "closed assessment" in response.json()["detail"], name
    after = get(closed, closed.vid)
    assert after["status"] == before["status"] == "risk_accepted" and after["version"] == before["version"]
    assert len(after["events"]) == len(before["events"])
    state = closed.get(f"{AS}/{closed.assessment_id}/closure").json()
    assert state["closed"] is True and state["can_close"] is False
    # Reading and append-only comments remain possible.
    assert closed.get(f"/api/v1/vulnerabilities/{closed.vid}").status_code == 200
    assert closed.post(f"/api/v1/vulnerabilities/{closed.vid}/comments", json={"comment": "Post-closure observation noted."}).status_code in (200, 201)


def test_closure_reopening_is_role_gated_attested_audited_and_unlocks_edits(closed):
    analyst, _ = token_for(closed, "analyst")
    lead, lead_id = token_for(closed, "lead_analyst")
    path = f"{AS}/{closed.assessment_id}/reopen-closure"
    body = {"human_validation_confirmed": True, "justification": "Client supplied new information about the fix."}
    with As(closed, analyst) as c:
        assert c.post(path, json=body).status_code == 403
    for bad in ({"justification": "too short"}, {"human_validation_confirmed": False}, {"extra": 1}):
        assert closed.post(path, json=body | bad).status_code == 422
    with As(closed, lead) as c:
        reopened = c.post(path, json=body)
    assert reopened.status_code == 200, reopened.text
    state = reopened.json()
    assert state["closed"] is False and len(state["reopenings"]) == 1
    assert state["reopenings"][0]["reopened_by"] == lead_id and state["reopenings"][0]["reason"] == body["justification"]
    with SessionLocal() as db:
        assert db.query(AssessmentClosure).count() == 1  # the original closure record is never edited
    assert closed.post(path, json=body).status_code == 409  # nothing left to reopen
    assert reopen(closed, closed.vid, 1).status_code == 200  # edits are possible again
    again = closed.get(f"{AS}/{closed.assessment_id}/closure").json()
    assert again["can_close"] is False and "unresolved" in " ".join(again["blocking_reasons"])


def test_an_assessment_can_be_closed_again_as_a_new_generation(closed):
    path = f"{AS}/{closed.assessment_id}/reopen-closure"
    body = {"human_validation_confirmed": True, "justification": "Client supplied new information about the fix."}
    assert closed.post(path, json=body).status_code == 200
    assert reopen(closed, closed.vid, 1).status_code == 200
    assert update(closed, closed.vid, "risk_accepted", 2, human_validation_confirmed=True, note=RISK + " Reviewed again.").status_code == 200
    final = close(closed)
    assert final.status_code == 200 and final.json()["closure"]["generation"] == 2
    assert update(closed, closed.vid, "in_progress", 3).status_code == 409  # locked again
    with SessionLocal() as db:
        assert [c.generation for c in db.scalars(select(AssessmentClosure).order_by(AssessmentClosure.generation))] == [1, 2]
        assert db.query(ClosureReopening).count() == 1


def test_closures_and_reopenings_cannot_be_rewritten(closed):
    path = f"{AS}/{closed.assessment_id}/reopen-closure"
    assert closed.post(path, json={"human_validation_confirmed": True, "justification": "Client supplied new information."}).status_code == 200
    with SessionLocal() as db:
        db.get(ClosureReopening, db.query(ClosureReopening).one().id).reason = "x"
        with pytest.raises(ValueError, match="append-only"):
            db.flush()
        db.rollback()
        for sql, message in (("UPDATE assessment_closure_reopenings SET reason = 'x'", "append-only"),
                             ("DELETE FROM assessment_closure_reopenings", "append-only"),
                             ("UPDATE assessment_closures SET justification = 'x'", "append-only"),
                             ("DELETE FROM assessment_closures", "append-only")):
            with pytest.raises(DBAPIError, match=message):
                db.execute(text(sql))
            db.rollback()


def test_unreviewed_findings_detected_in_the_closed_assessment_are_locked_too(closed):
    other = one(closed, "hsts")  # detected in the same assessment but never confirmed
    assert other["validation_state"] == "unconfirmed"
    assert assess(closed, other).status_code == 409 and signoff(closed, other).status_code == 409


# --- Evidence retention and secure deletion (R9) ---------------------------------------------------------

def expire(key, **changes):
    with SessionLocal() as db:
        row = db.get(AuthorizationEvidence, key)
        row.retain_until = utc_now() - timedelta(days=1)
        for name, value in changes.items():
            setattr(row, name, value)
        db.commit()


def purge(client, key):
    return client.post(f"/api/v1/evidence/{key}/purge", json={"reason": "Retention period ended; approved for deletion."})


def withdraw(client, key):
    return client.post(f"/api/v1/evidence/{key}/withdraw", json={"reason": "Superseded by a newer document."})


@pytest.fixture
def document(api):
    authorization, _ = seed_record()
    key = attach_review(api, authorization)
    return api, authorization, key


def test_purge_overwrites_the_file_then_unlinks_and_keeps_the_audit_hash(document, monkeypatch):
    api, authorization, key = document
    path = evidence_service.stored_path(key)
    original = path.read_bytes()
    with SessionLocal() as db:
        digest = db.get(AuthorizationEvidence, key).sha256
    expire(key)
    assert withdraw(api, key).status_code == 200
    seen = {}
    real_unlink = Path.unlink

    def spy(self, *args, **kwargs):
        if self == path:
            seen["content"] = self.read_bytes()
        return real_unlink(self, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", spy)
    response = purge(api, key)
    assert response.status_code == 200, response.text
    assert len(seen["content"]) == len(original) and seen["content"] != original  # overwritten before removal
    assert not path.exists()
    body = response.json()
    assert body["state"] == "purged" and body["sha256"] == digest and body["purge_method"] == evidence_service.OVERWRITE_METHOD
    assert body["purged_at"].endswith("+00:00")
    with SessionLocal() as db:
        last = db.scalars(select(EvidenceEvent).where(EvidenceEvent.evidence_id == key).order_by(EvidenceEvent.occurred_at)).all()[-1]
        assert last.action == "purged" and digest in last.comment
    assert purge(api, key).status_code == 200  # idempotent
    assert api.get(f"/api/v1/evidence/{key}/download").status_code == 410


def test_purge_is_refused_during_retention_legal_hold_or_active_approval(document):
    api, authorization, key = document
    assert withdraw(api, key).status_code == 200
    assert purge(api, key).status_code == 409  # retention period still running
    expire(key)
    assert api.post(f"/api/v1/evidence/{key}/hold", json={"reason": "Dispute with the client is open.", "legal_hold": True}).status_code == 200
    assert purge(api, key).status_code == 409
    assert api.post(f"/api/v1/evidence/{key}/hold", json={"reason": "Dispute with the client is resolved.", "legal_hold": False}).status_code == 200
    assert evidence_service.stored_path(key).exists()
    # Un-withdrawn documents need an explicit withdrawal first.
    other, _ = seed_record()
    live = attach_review(api, other)
    expire(live)
    assert purge(api, live).status_code == 409 and evidence_service.stored_path(live).exists()
    approved, _ = seed_record()
    approved_key = attach_review(api, approved)
    assert api.post(f"/api/v1/authorizations/{approved}/approve", json=APPROVAL).status_code == 200
    expire(approved_key)
    assert purge(api, approved_key).status_code == 409 and evidence_service.stored_path(approved_key).exists()


def test_retention_report_lists_expired_documents_with_blockers_and_deletes_nothing(document):
    api, authorization, key = document
    fresh, _ = seed_record()
    attach_review(api, fresh)
    expire(key, legal_hold=True)
    with SessionLocal() as db:
        rows = evidence_service.retention_report(db)
    assert [r["evidence_id"] for r in rows] == [key]
    assert set(rows[0]["blockers"]) == {"legal_hold", "not_withdrawn"} and rows[0]["sha256"]
    assert evidence_service.stored_path(key).exists()
    with SessionLocal() as db:
        assert evidence_service.retention_report(db, now=utc_now() + timedelta(days=4000))  # everything expires eventually
        assert len(evidence_service.retention_report(db, now=utc_now() + timedelta(days=4000))) == 2


def test_secure_erase_handles_missing_and_special_files(tmp_path):
    target = tmp_path / "doc"
    target.write_bytes(b"A" * 3_000_000)
    assert evidence_service.secure_erase(target) == evidence_service.OVERWRITE_METHOD and not target.exists()
    assert evidence_service.secure_erase(target) == "already_absent"
    with pytest.raises(Exception, match="Storage integrity"):
        evidence_service.secure_erase(tmp_path)  # a directory is never touched


def test_evidence_identity_hash_and_history_are_immutable_in_orm_and_database(document):
    api, authorization, key = document
    expire(key)
    assert withdraw(api, key).status_code == 200 and purge(api, key).status_code == 200
    with SessionLocal() as db:
        row = db.get(AuthorizationEvidence, key)
        row.sha256 = "0" * 64
        with pytest.raises(ValueError, match="immutable"):
            db.flush()
        db.rollback()
        db.delete(db.get(AuthorizationEvidence, key))
        with pytest.raises(ValueError, match="never be deleted"):
            db.flush()
        db.rollback()
        db.get(AuthorizationEvidence, key).state = "available"
        with pytest.raises(ValueError, match="restored"):
            db.flush()
        db.rollback()
        for sql, message in ((f"UPDATE authorization_evidence SET sha256 = 'x' WHERE id = '{key}'", "immutable"),
                             (f"UPDATE authorization_evidence SET size = 1 WHERE id = '{key}'", "immutable"),
                             (f"UPDATE authorization_evidence SET state = 'available' WHERE id = '{key}'", "restored"),
                             ("DELETE FROM authorization_evidence", "cannot be deleted"),
                             ("UPDATE evidence_events SET comment = 'x'", "append-only"),
                             ("DELETE FROM evidence_events", "append-only")):
            with pytest.raises(DBAPIError, match=message):
                db.execute(text(sql))
            db.rollback()


# --- Migration 0013 --------------------------------------------------------------------------------------

def test_migration_0013_preserves_data_swaps_constraints_and_keeps_triggers(tmp_path):
    path = tmp_path / "hardening.db"
    migrate(path, "0012_remediation_retesting")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO admins (id,email,full_name,password_hash,role,is_active) VALUES (7,'a@example.com','Synthetic','preserved-hash','admin',1)")
    migrate(path)
    migrate(path)  # idempotent
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0014_fix_verification_signoff"
        assert db.execute("SELECT password_hash, role FROM admins WHERE id = 7").fetchone() == ("preserved-hash", "admin")
        for role in ("lead_analyst", "analyst"):
            db.execute("INSERT INTO admins (email,full_name,password_hash,role,is_active) VALUES (?, 'N', 'h', ?, 1)", (f"{role}@example.com", role))
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO admins (email,full_name,password_hash,role,is_active) VALUES ('v@example.com','N','h','viewer',1)")
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert {"auth_events", "revoked_tokens", "assessment_closure_reopenings"} <= tables
        columns = {r[1] for r in db.execute("PRAGMA table_info(authorization_evidence)")}
        assert {"purged_at", "purge_method"} <= columns
        assert "generation" in {r[1] for r in db.execute("PRAGMA table_info(assessment_closures)")}
        triggers = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}
        assert {"trg_assessment_closures_no_update", "trg_assessment_closures_no_delete", "trg_auth_events_no_update",
                "trg_assessment_closure_reopenings_no_delete", "trg_authorization_evidence_frozen",
                "trg_authorization_evidence_purged_final", "trg_evidence_events_no_update"} <= triggers
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
