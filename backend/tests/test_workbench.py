"""Module F: human security analyst workbench. Synthetic scanner output only; no target traffic."""
import sqlite3
from datetime import timedelta

import jwt
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.core import rbac
from app.core.config import settings
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.models.admin import Admin
from app.models.vulnerability import (Vulnerability, VulnerabilityEvent, VulnerabilityRiskAssessment,
                                      VulnerabilitySignoff)
from app.services import vulnerabilities as vulns
from test_assessments import assessed  # noqa: F401 - fixture
from test_authorization_correctness import api  # noqa: F401 - fixture
from test_local_assessment import network  # noqa: F401 - fixture
from test_migrations import migrate
from test_vulnerabilities import ONLY_DISCLOSURE, assess, decide, one, records, run

WB = "/api/v1/workbench"
STEPS = "curl -sI the authorised URL and observe that the header is absent."


def signoff(client, item, decision="approve", **changes):
    body = {"expected_revision": item["revision"], "decision": decision, "human_validation_confirmed": True,
            "justification": "Analyst inspected the stored evidence and target scope."}
    if decision == "approve":
        body["reproduction_steps"] = STEPS
    elif decision == "reject":
        body.update(rejection_outcome="false_positive", suppress_until=(utc_now() + timedelta(days=30)).isoformat())
    return client.post(f"{WB}/{item['id']}/signoff", json=body | changes)


def detail(client, item):
    return client.get(f"{WB}/{item['id']}").json()


@pytest.fixture
def seeded(network, monkeypatch):
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    return network[0]


# --- Risk matrix and assessment authoring -------------------------------------------------

@pytest.mark.parametrize("likelihood,impact,rating", [
    ("rare", "negligible", "informational"), ("rare", "minor", "informational"), ("unlikely", "minor", "low"),
    ("possible", "moderate", "medium"), ("likely", "moderate", "medium"), ("likely", "major", "high"),
    ("almost_certain", "major", "critical"), ("almost_certain", "severe", "critical"), ("possible", "severe", "high")])
def test_risk_matrix_is_deterministic(likelihood, impact, rating):
    assert vulns.calculate_rating(likelihood, impact) == rating


def test_assessment_records_business_impact_and_remediation(seeded):
    item = one(seeded)
    response = assess(seeded, item, likelihood="likely", business_impact="major", risk_rating="high",
                      remediation_priority="immediate")
    assert response.status_code == 201, response.text
    body = response.json()
    current = body["current_assessment"]
    assert current["version"] == 1 and current["calculated_rating"] == "high" and current["risk_rating"] == "high"
    assert current["author_id"] == seeded.admin_id and current["author_name"] and current["created_at"].endswith("+00:00")
    assert body["can_approve"] is True and body["validation_state"] == "unconfirmed"
    assert body["revision"] == item["revision"]  # assessing is not a state change
    assert assess(seeded, item, remediation="Different, longer remediation guidance for version two.").status_code == 201
    versions = detail(seeded, item)["assessments"]
    assert [a["version"] for a in versions] == [2, 1] and [a["current"] for a in versions] == [True, False]


def test_override_needs_reason_and_reason_needs_override(seeded):
    item = one(seeded)
    assert assess(seeded, item, risk_rating="critical").status_code == 422  # differs from matrix, no reason
    assert assess(seeded, item, risk_rating="medium",
                  override_reason="Not needed because the rating matches the matrix.").status_code == 422
    ok = assess(seeded, item, risk_rating="critical", override_reason="Regulated data is served from this host.")
    assert ok.status_code == 201 and ok.json()["current_assessment"]["calculated_rating"] == "medium"
    assert ok.json()["current_assessment"]["override_reason"].startswith("Regulated")


@pytest.mark.parametrize("bad", [
    {"likelihood": "certain"}, {"business_impact": "catastrophic"}, {"risk_rating": "urgent"},
    {"remediation_priority": "asap"}, {"business_context": "short"}, {"remediation": "short"},
    {"expected_revision": "1"}, {"expected_revision": 0}, {"unexpected": True}])
def test_invalid_assessments_rejected_without_writes(seeded, bad):
    item = one(seeded)
    assert assess(seeded, item, **bad).status_code == 422
    with SessionLocal() as db:
        assert db.query(VulnerabilityRiskAssessment).count() == 0


def test_assessment_rejects_stale_revision_and_decided_records(seeded):
    item = one(seeded)
    assert assess(seeded, item, expected_revision=item["revision"] + 1).status_code == 409
    assert assess(seeded, item).status_code == 201
    assert signoff(seeded, item).status_code == 200
    assert assess(seeded, item).status_code == 409  # stale revision
    assert assess(seeded, detail(seeded, item)).status_code == 409  # confirmed records cannot be re-assessed


# --- Review queue ------------------------------------------------------------------------

def test_review_queue_stages_filters_and_counts(seeded):
    summary = seeded.get(f"{WB}/queue").json()["summary"]
    assert summary == {"needs_assessment": 8, "ready_for_signoff": 0, "report_eligible": 0, "dismissed": 0}
    hsts, csp, nosniff = one(seeded, "hsts"), one(seeded, "csp"), one(seeded, "x_content_type_options")
    assert assess(seeded, hsts).status_code == 201
    assert assess(seeded, csp).status_code == 201 and signoff(seeded, csp).status_code == 200
    assert signoff(seeded, nosniff, "reject").status_code == 200
    queue = seeded.get(f"{WB}/queue").json()
    assert queue["stage"] == "needs_assessment" and queue["summary"] == {
        "needs_assessment": 5, "ready_for_signoff": 1, "report_eligible": 1, "dismissed": 1}
    assert len(queue["items"]) == 5 and all(i["stage"] == "needs_assessment" for i in queue["items"])
    ready = seeded.get(f"{WB}/queue", params={"stage": "ready_for_signoff"}).json()["items"]
    assert [i["check_id"] for i in ready] == ["hsts"]
    eligible = seeded.get(f"{WB}/queue", params={"stage": "report_eligible"}).json()["items"]
    assert [(i["check_id"], i["report_eligible"], i["stage"]) for i in eligible] == [("csp", True, "report_eligible")]
    assert [i["check_id"] for i in seeded.get(f"{WB}/queue", params={"stage": "dismissed"}).json()["items"]] == ["x_content_type_options"]
    assert len(seeded.get(f"{WB}/queue", params={"stage": "all"}).json()["items"]) == 8
    assert len(seeded.get(f"{WB}/queue", params={"stage": "all", "limit": 3, "offset": 3}).json()["items"]) == 3
    assert seeded.get(f"{WB}/queue", params={"stage": "all", "search": "referrer"}).json()["items"][0]["check_id"] == "referrer_policy"
    for bad in ({"stage": "done"}, {"severity": "urgent"}, {"limit": 101}, {"limit": 0}, {"offset": -1}, {"website_id": 0}):
        assert seeded.get(f"{WB}/queue", params=bad).status_code == 422


# --- Sign-off gating and state transitions ---------------------------------------------

def test_approval_is_impossible_without_a_current_assessment(seeded):
    item = one(seeded)
    response = signoff(seeded, item)
    assert response.status_code == 409 and "risk assessment" in response.json()["detail"]
    legacy = decide(seeded, item, decision="confirmed", severity="medium", reproduction_steps=STEPS)
    assert legacy.status_code == 409 and "risk assessment" in legacy.json()["detail"]
    after = one(seeded)
    assert after["validation_state"] == "unconfirmed" and after["report_eligible"] is False
    with SessionLocal() as db:
        assert db.query(VulnerabilitySignoff).count() == 0


def test_legacy_validation_cannot_bypass_the_assessed_rating(seeded):
    item = one(seeded)
    assert assess(seeded, item, risk_rating="medium").status_code == 201
    mismatch = decide(seeded, item, decision="confirmed", severity="critical", reproduction_steps=STEPS)
    assert mismatch.status_code == 409 and "rating" in mismatch.json()["detail"]
    assert one(seeded)["validation_state"] == "unconfirmed"


def test_attested_approval_confirms_and_makes_report_eligible(seeded):
    item = one(seeded)
    assert one(seeded)["report_eligible"] is False
    assert assess(seeded, item, likelihood="likely", business_impact="major", risk_rating="high").status_code == 201
    for bad in ({"human_validation_confirmed": False}, {"justification": "too short"}, {"reproduction_steps": None},
                {"rejection_outcome": "false_positive"}, {"decision": "delete"}, {"unexpected": True}):
        assert signoff(seeded, item, **bad).status_code == 422, bad
    assert one(seeded)["validation_state"] == "unconfirmed"
    response = signoff(seeded, item)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["validation_state"] == "confirmed" and body["effective_severity"] == "high"  # the assessed rating
    assert body["analyst_severity"] == "high" and body["scanner_severity"] == "medium"
    assert body["report_eligible"] is True and body["revision"] == item["revision"] + 1
    with SessionLocal() as db:
        row = db.scalar(select(VulnerabilitySignoff))
        assert (row.decision, row.from_state, row.to_state, row.analyst_id, row.sequence) == (
            "approved", "unconfirmed", "confirmed", seeded.admin_id, 1)
        assert row.vulnerability_revision == body["revision"] and row.risk_assessment_id == body["current_assessment"]["id"]
        assert row.justification.startswith("Analyst inspected") and row.occurred_at is not None
    assert signoff(seeded, item).status_code == 409  # stale revision
    assert signoff(seeded, body).status_code == 409  # confirmed -> confirmed is not a transition


def test_rejection_dismisses_with_suppression_and_is_never_report_eligible(seeded):
    item = one(seeded)
    for bad in ({"suppress_until": None}, {"rejection_outcome": None}, {"reproduction_steps": STEPS},
                {"rejection_outcome": "confirmed"},
                {"suppress_until": (utc_now() + timedelta(days=400)).isoformat()}):
        assert signoff(seeded, item, "reject", **bad).status_code == 422, bad
    response = signoff(seeded, item, "reject", rejection_outcome="not_applicable")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["validation_state"] == "not_applicable" and body["report_eligible"] is False
    assert body["suppression"]["status"] == "active"
    ledger = seeded.get(f"{WB}/{item['id']}/signoffs").json()
    assert [(r["decision"], r["to_state"]) for r in ledger] == [("rejected", "not_applicable")]


def test_reopening_revokes_eligibility_and_stales_the_assessment(seeded):
    item = one(seeded)
    assert assess(seeded, item).status_code == 201
    confirmed = signoff(seeded, item).json()
    assert confirmed["report_eligible"] is True
    for bad in ({"reproduction_steps": STEPS}, {"justification": "short"}):
        assert signoff(seeded, confirmed, "reopen", **bad).status_code == 422
    reopened = signoff(seeded, confirmed, "reopen",
                       justification="New evidence shows the header is set by the CDN after all.").json()
    assert reopened["validation_state"] == "unconfirmed" and reopened["report_eligible"] is False
    assert reopened["analyst_severity"] is None and reopened["current_assessment"] is None
    assert reopened["can_approve"] is False and reopened["assessments"][0]["current"] is False
    assert signoff(seeded, reopened).status_code == 409  # old assessment is stale: assess again first
    assert assess(seeded, reopened).status_code == 201
    assert signoff(seeded, detail(seeded, reopened)).json()["report_eligible"] is True
    ledger = seeded.get(f"{WB}/{item['id']}/signoffs").json()
    assert [r["decision"] for r in ledger] == ["approved", "reopened", "approved"]
    assert [r["sequence"] for r in ledger] == [3, 2, 1]


def test_eligibility_requires_the_signoff_to_match_the_current_revision(seeded):
    item = one(seeded)
    assert assess(seeded, item).status_code == 201
    confirmed = signoff(seeded, item).json()
    with SessionLocal() as db:
        vulnerability = db.get(Vulnerability, item["id"])
        assert vulns.report_eligible(db, vulnerability) is True
        # A state change without a matching approval (for example a database edit) voids eligibility.
        db.execute(text("UPDATE vulnerabilities SET revision = revision + 1 WHERE id = :id"), {"id": item["id"]})
        db.commit()
        db.refresh(vulnerability)
        assert vulns.report_eligible(db, vulnerability) is False
    assert seeded.get(f"{WB}/queue", params={"stage": "report_eligible"}).json()["items"] == []
    assert confirmed["report_eligible"] is True


def test_concurrent_signoffs_only_one_wins(seeded):
    item = one(seeded)
    assert assess(seeded, item).status_code == 201
    first = signoff(seeded, item)
    second = signoff(seeded, item, "reject")
    assert (first.status_code, second.status_code) == (200, 409)
    with SessionLocal() as db:
        assert db.query(VulnerabilitySignoff).count() == 1


def test_untrusted_text_is_stored_and_returned_as_inert_data(seeded):
    item = one(seeded)
    hostile = "<img src=x onerror=alert(1)> <script>steal()</script> {{7*7}} ${jndi:ldap://x}"
    response = assess(seeded, item, business_context=hostile + " padding", remediation=hostile + " padding")
    assert response.status_code == 201
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["current_assessment"]["business_context"] == hostile + " padding"


# --- Audit trail and immutability --------------------------------------------------------

def test_audit_trail_records_analyst_identity_time_states_and_justification(seeded):
    item = one(seeded)
    assert assess(seeded, item).status_code == 201
    assert signoff(seeded, item).status_code == 200
    audit = seeded.get(f"{WB}/{item['id']}/audit").json()
    actions = [e["action"] for e in audit["events"]]
    assert actions[:2] == ["validation_changed", "risk_assessment_saved"] and "detected_new" in actions
    decision = audit["events"][0]
    assert (decision["actor_id"], decision["from_state"], decision["to_state"]) == (seeded.admin_id, "unconfirmed", "confirmed")
    assert decision["actor_name"] and decision["comment"].startswith("Analyst inspected")
    assert decision["occurred_at"].endswith("+00:00") and decision["detail"]["signoff_id"] == audit["signoffs"][0]["id"]
    assert decision["detail"]["risk_assessment_version"] == 1
    entry = audit["signoffs"][0]
    assert entry["analyst_id"] == seeded.admin_id and entry["analyst_name"] and entry["occurred_at"].endswith("+00:00")
    assert (entry["from_state"], entry["to_state"], entry["decision"]) == ("unconfirmed", "confirmed", "approved")
    assert seeded.get(f"{WB}/{item['id']}/audit", params={"limit": 101}).status_code == 422


def test_orm_blocks_rewriting_assessments_signoffs_and_events(seeded):
    item = one(seeded)
    assert assess(seeded, item).status_code == 201 and signoff(seeded, item).status_code == 200
    with SessionLocal() as db:
        for model, field in ((VulnerabilityRiskAssessment, "remediation"), (VulnerabilitySignoff, "justification"),
                             (VulnerabilityEvent, "comment")):
            row = db.scalar(select(model))
            setattr(row, field, "rewritten history")
            with pytest.raises(ValueError, match="append-only"):
                db.commit()
            db.rollback()
            db.delete(db.scalar(select(model)))
            with pytest.raises(ValueError, match="append-only"):
                db.commit()
            db.rollback()


@pytest.mark.parametrize("table,column", [("vulnerability_signoffs", "justification"),
                                          ("vulnerability_risk_assessments", "remediation"),
                                          ("vulnerability_events", "comment")])
def test_database_triggers_block_raw_sql_rewrites(seeded, table, column):
    item = one(seeded)
    assert assess(seeded, item).status_code == 201 and signoff(seeded, item).status_code == 200
    with SessionLocal() as db:
        with pytest.raises(DBAPIError, match="append-only"):
            db.execute(text(f"UPDATE {table} SET {column} = 'tampered'"))
        db.rollback()
        with pytest.raises(DBAPIError, match="append-only"):
            db.execute(text(f"DELETE FROM {table}"))
        db.rollback()
        assert db.execute(text(f"SELECT COUNT(*) FROM {table} WHERE {column} = 'tampered'")).scalar() == 0


def test_migration_installs_tables_and_immutability_triggers_preserving_data(tmp_path):
    path = tmp_path / "workbench.db"
    migrate(path, "0009_vulnerabilities")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO admins (id,email,full_name,password_hash,role,is_active) VALUES (7,'a@example.com','Synthetic','preserved-hash','admin',1)")
    migrate(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0013_production_hardening"
        assert db.execute("SELECT password_hash FROM admins WHERE id = 7").fetchone()[0] == "preserved-hash"
        triggers = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}
        for table in ("vulnerability_events", "vulnerability_risk_assessments", "vulnerability_signoffs"):
            assert {f"trg_{table}_no_update", f"trg_{table}_no_delete"} <= triggers
        assert {r[1] for r in db.execute("PRAGMA table_info(vulnerability_signoffs)")} >= {
            "analyst_id", "from_state", "to_state", "justification", "occurred_at", "vulnerability_revision"}


# --- Authentication, RBAC and session protection ----------------------------------------

def endpoints(item_id):
    return [("get", f"{WB}/queue"), ("get", f"{WB}/{item_id}"), ("post", f"{WB}/{item_id}/assessment"),
            ("post", f"{WB}/{item_id}/signoff"), ("get", f"{WB}/{item_id}/signoffs"), ("get", f"{WB}/{item_id}/audit")]


def call(client, method, path):
    return getattr(client, method)(path, **({"json": {}} if method == "post" else {}))


def test_every_workbench_route_rejects_unauthenticated_callers(seeded):
    item_id = one(seeded)["id"]
    token = seeded.headers.pop("Authorization")
    try:
        for method, path in endpoints(item_id):
            assert call(seeded, method, path).status_code == 401, path
        seeded.headers["Authorization"] = "Bearer not.a.jwt"
        for method, path in endpoints(item_id):
            assert call(seeded, method, path).status_code == 401, path
    finally:
        seeded.headers["Authorization"] = token


def test_workbench_rejects_tokens_for_other_roles_and_deactivated_analysts(seeded):
    item = one(seeded)
    token = seeded.headers["Authorization"].split()[1]
    key = settings.jwt_secret_key.get_secret_value()
    claims = jwt.decode(token, key, algorithms=["HS256"], audience=settings.jwt_audience)
    forged = jwt.encode({**claims, "role": "viewer"}, key, algorithm="HS256")
    original = seeded.headers["Authorization"]
    try:
        seeded.headers["Authorization"] = f"Bearer {forged}"
        for method, path in endpoints(item["id"]):
            assert call(seeded, method, path).status_code == 401, path
    finally:
        seeded.headers["Authorization"] = original
    with SessionLocal() as db:
        db.get(Admin, seeded.admin_id).is_active = False
        db.commit()
    for method, path in endpoints(item["id"]):
        assert call(seeded, method, path).status_code == 401, path
    with SessionLocal() as db:
        assert db.query(VulnerabilityRiskAssessment).count() == 0 and db.query(VulnerabilitySignoff).count() == 0


def test_role_allow_list_gates_every_workbench_route_and_writes_nothing(seeded, monkeypatch):
    item = one(seeded)
    assert assess(seeded, item).status_code == 201
    monkeypatch.setattr(rbac, "ANALYST_ROLES", frozenset())
    for method, path in endpoints(item["id"]):
        assert call(seeded, method, path).status_code == 403, path
    body = {"expected_revision": item["revision"], "decision": "approve", "human_validation_confirmed": True,
            "justification": "Analyst inspected the stored evidence and target scope.", "reproduction_steps": STEPS}
    assert seeded.post(f"{WB}/{item['id']}/signoff", json=body).status_code == 403
    monkeypatch.undo()
    assert one(seeded)["validation_state"] == "unconfirmed"
    with SessionLocal() as db:
        assert db.query(VulnerabilitySignoff).count() == 0 and db.query(VulnerabilityRiskAssessment).count() == 1


def test_unknown_records_and_malformed_ids(seeded):
    from uuid import uuid4
    for method, path in endpoints(uuid4()):
        if path.endswith("/queue"):
            continue
        assert call(seeded, method, path).status_code in (404, 422), path
    assert seeded.get(f"{WB}/{uuid4()}").status_code == 404
    assert seeded.get(f"{WB}/not-a-uuid").status_code == 422
