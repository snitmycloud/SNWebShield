"""Second-person sign-off on a scanner-verified fix. Synthetic scanner output only."""
import sqlite3

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.remediation import FixVerificationSignoff, RemediationEvent
from test_remediation import (AS, FIXED, NIL, REM, close, get, retest_cycle, submitted, tracked, update)  # noqa: F401
from test_assessments import assessed  # noqa: F401 - fixture
from test_authorization_correctness import api  # noqa: F401 - fixture
from test_local_assessment import network  # noqa: F401 - fixture
from test_production_hardening import login, make_user
from test_migrations import migrate

NOTE = "I reviewed the stored retest evidence and the header is now present on the exact target."


def second_person(client, role="analyst"):
    email, admin_id = make_user(role)
    token = login(client, email).json()["access_token"]
    return {"Authorization": "Bearer " + token}, admin_id


def verify(client, vid, decision="confirmed", headers=None, **changes):
    version = changes.pop("expected_version", None)
    if version is None: version = get(client, vid)["version"]
    body = {"expected_version": version, "decision": decision, "note": NOTE, "human_validation_confirmed": True} | changes
    return client.post(f"{REM}/{vid}/verify-fix", json=body, headers=headers or {})


@pytest.fixture
def verified(submitted):
    """A finding the scanner verified as fixed by a retest the (first) administrator requested."""
    done = retest_cycle(submitted, FIXED, 10)
    assert done["status"] == "verified_fixed"
    return submitted


@pytest.fixture
def dual(verified, monkeypatch):
    monkeypatch.setattr(settings, "separation_of_duties_enabled", True)
    return verified


def closure(client):
    return client.get(f"{AS}/{client.assessment_id}/closure").json()


# --- Default (dual sign-off off): behaviour unchanged, sign-off optional ---------------------------------

def test_without_dual_signoff_closure_is_not_blocked_and_signoff_is_optional(verified):
    state = get(verified, verified.vid)["fix_verification"]
    assert state["applicable"] is True and state["required"] is False and state["state"] == "pending"
    ready = closure(verified)
    assert ready["can_close"] is True and ready["signoff_pending"] == []
    response = verify(verified, verified.vid)  # a single administrator may still record it
    assert response.status_code == 200, response.text
    assert response.json()["fix_verification"]["state"] == "confirmed"


def test_other_statuses_report_not_applicable(submitted):
    assert get(submitted, submitted.vid)["fix_verification"] == {"applicable": False, "required": False, "state": "not_applicable"}


# --- Dual sign-off on ---------------------------------------------------------------------------------

def test_closure_waits_for_an_independent_signoff_and_the_requester_cannot_provide_it(dual):
    state = closure(dual)
    assert state["can_close"] is False and state["signoff_pending"][0]["check_id"] == "csp"
    assert any("independent sign-off" in reason for reason in state["blocking_reasons"])
    assert get(dual, dual.vid)["fix_verification"]["required"] is True
    own = verify(dual, dual.vid)  # same administrator who requested the retest
    assert own.status_code == 403 and "Separation of duties" in own.text
    with SessionLocal() as db:
        assert list(db.scalars(select(FixVerificationSignoff))) == []
    assert closure(dual)["can_close"] is False


def test_a_second_analyst_confirms_and_closure_opens(dual):
    headers, other = second_person(dual)
    response = verify(dual, dual.vid, headers=headers)
    assert response.status_code == 200, response.text
    state = response.json()["fix_verification"]
    assert state["state"] == "confirmed" and state["signed_by"] == other and state["signed_by_name"]
    assert state["note"] == NOTE and len(state["evidence_sha256"]) == 64
    with SessionLocal() as db:
        row = db.scalar(select(FixVerificationSignoff))
        assert row.decision == "confirmed" and row.signed_by == other and row.evidence_sha256 == state["evidence_sha256"]
    ready = closure(dual)
    assert ready["signoff_pending"] == [] and ready["can_close"] is True


def test_rejection_by_a_second_analyst_reopens_the_finding_and_keeps_the_record(dual):
    headers, other = second_person(dual)
    response = verify(dual, dual.vid, "rejected", headers=headers, note="The retest evidence does not show the CSP header on the exact page.")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "reopened" and body["events"][0]["action"] == "reopened"
    assert body["events"][0]["detail"]["signoff"] == "rejected" and body["events"][0]["actor_id"] == other
    with SessionLocal() as db:
        assert db.scalar(select(FixVerificationSignoff.decision)) == "rejected"
    assert closure(dual)["can_close"] is False  # reopened is an unresolved blocker


def test_a_new_verified_retest_needs_a_fresh_signoff(dual):
    headers, _ = second_person(dual)
    assert verify(dual, dual.vid, "rejected", headers=headers).status_code == 200
    version = get(dual, dual.vid)["version"]
    assert update(dual, dual.vid, "fix_submitted", version).status_code == 200
    again = retest_cycle(dual, FIXED, 20)
    assert again["status"] == "verified_fixed" and again["fix_verification"]["state"] == "pending"
    assert again["fix_verification"]["retest_id"] != again["retests"][-1]["id"]  # a different (newest) retest
    assert verify(dual, dual.vid, headers=headers).status_code == 200  # the earlier rejection did not consume it


def test_anyone_who_handled_the_remediation_cannot_be_the_second_person(dual):
    with SessionLocal() as db:
        handler = db.scalar(select(RemediationEvent.actor_id).where(RemediationEvent.actor_id.is_not(None)))
    assert handler is not None  # the administrator updated remediation and requested the retest
    assert verify(dual, dual.vid).status_code == 403


# --- Validation and refusals ---------------------------------------------------------------------------

def test_only_a_verified_fix_can_be_signed_off_and_only_once(submitted, monkeypatch):
    headers, _ = second_person(submitted)
    assert verify(submitted, submitted.vid, headers=headers).status_code == 409  # fix_submitted, not verified_fixed
    retest_cycle(submitted, FIXED, 10)
    assert verify(submitted, submitted.vid, headers=headers).status_code == 200
    assert verify(submitted, submitted.vid, headers=headers).status_code == 409  # already signed off


def test_stale_version_and_bad_payloads_are_rejected_without_writes(verified):
    headers, _ = second_person(verified)
    assert verify(verified, verified.vid, headers=headers, expected_version=999).status_code == 409
    for bad in (dict(note="too short"), dict(decision="maybe"), dict(human_validation_confirmed=False),
                dict(unexpected=1), dict(expected_version=-1), dict(expected_version="1")):
        assert verify(verified, verified.vid, headers=headers, **bad).status_code == 422, bad
    with SessionLocal() as db:
        assert list(db.scalars(select(FixVerificationSignoff))) == []


def test_unknown_finding_and_missing_login(verified):
    headers, _ = second_person(verified)
    assert verify(verified, NIL, headers=headers, expected_version=0).status_code == 404
    from fastapi.testclient import TestClient
    from app.main import app
    anonymous = TestClient(app).post(f"{REM}/{verified.vid}/verify-fix", json={})
    assert anonymous.status_code == 401


def test_a_retest_without_stored_evidence_cannot_be_confirmed(verified):
    headers, _ = second_person(verified)
    with SessionLocal() as db:
        db.execute(text("DROP TRIGGER IF EXISTS trg_retest_requests_final"))
        db.execute(text("UPDATE retest_requests SET evidence_sha256 = NULL"))
        db.commit()
    assert verify(verified, verified.vid, headers=headers).status_code == 409
    assert verify(verified, verified.vid, "rejected", headers=headers).status_code == 200  # rejecting is still possible


# --- History cannot be rewritten ------------------------------------------------------------------------

def test_signoffs_are_append_only_in_the_orm_and_the_database(verified):
    headers, _ = second_person(verified)
    assert verify(verified, verified.vid, headers=headers).status_code == 200
    with SessionLocal() as db:
        row = db.scalar(select(FixVerificationSignoff))
        row.decision = "rejected"
        with pytest.raises(ValueError, match="append-only"): db.flush()
        db.rollback()
        row = db.scalar(select(FixVerificationSignoff))
        db.delete(row)
        with pytest.raises(ValueError, match="append-only"): db.flush()
        db.rollback()
    with SessionLocal() as db:
        for statement in ("UPDATE fix_verification_signoffs SET decision = 'rejected'", "DELETE FROM fix_verification_signoffs"):
            with pytest.raises(DBAPIError, match="append-only"):
                db.execute(text(statement))
            db.rollback()


def test_migration_adds_the_table_and_triggers_without_touching_existing_data(tmp_path):
    path = tmp_path / "pre-signoff.db"
    migrate(path, "0013_production_hardening")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO admins (id,email,full_name,password_hash,role,is_active) VALUES (1,'s@example.com','Test','kept-hash','admin',1)")
        before = db.execute("SELECT * FROM admins").fetchall()
        assert db.execute("SELECT name FROM sqlite_master WHERE name = 'fix_verification_signoffs'").fetchone() is None
    migrate(path)
    migrate(path)  # idempotent
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0015_port_watch"
        assert db.execute("SELECT * FROM admins").fetchall() == before
        assert db.execute("SELECT COUNT(*) FROM fix_verification_signoffs").fetchone() == (0,)
        triggers = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'fix_verification_signoffs'")}
        assert triggers == {"trg_fix_verification_signoffs_no_update", "trg_fix_verification_signoffs_no_delete"}
