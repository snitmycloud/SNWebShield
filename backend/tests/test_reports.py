"""Module G: VAPT reports. Synthetic scanner output only; no target traffic."""
import io
import json
import sqlite3
from hashlib import sha256

import jwt
import pytest
from pypdf import PdfReader
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core import rbac
from app.core.config import settings
from app.db.session import SessionLocal
from app.models.admin import Admin
from app.models.report import VaptReport, VaptReportApproval, VaptReportArtifact, VaptReportEvent
from app.services import assessments, reports as service
from test_assessments import assessed  # noqa: F401 - fixture
from test_authorization_correctness import api  # noqa: F401 - fixture
from test_local_assessment import network  # noqa: F401 - fixture
from test_migrations import migrate
from test_vulnerabilities import ONLY_DISCLOSURE, assess, one, run
from test_workbench import signoff

R = "/api/v1/reports"
REASON = "Reviewed every finding, the evidence and the scope; approved for client release."
NIL = "00000000-0000-4000-8000-000000000000"


@pytest.fixture
def seeded(network, monkeypatch):
    row = run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    network[0].assessment_id = row["id"]
    return network[0]


def approve_finding(client, check, **assessment):
    item = one(client, check)
    assert assess(client, item, **assessment).status_code == 201
    assert signoff(client, item).status_code == 200
    return item


def generate(client, status=201):
    response = client.post(R, json={"assessment_id": client.assessment_id})
    assert response.status_code == status, response.text
    return response.json()


def decide(client, report, verb="approve", **changes):
    body = {"human_validation_confirmed": True, "justification": REASON} | changes
    return client.post(f"{R}/{report['id']}/{verb}", json=body)


def pdf_text(data):
    return "\n".join(page.extract_text() for page in PdfReader(io.BytesIO(data)).pages)


@pytest.fixture
def eligible(seeded):
    approve_finding(seeded, "csp", likelihood="likely", business_impact="major", risk_rating="high",
                    remediation_priority="immediate")
    approve_finding(seeded, "hsts")
    return seeded


# --- Strict eligibility -------------------------------------------------------------------

def test_only_report_eligible_findings_are_included_and_the_rest_counted(seeded):
    approve_finding(seeded, "csp")
    approve_finding(seeded, "hsts")
    assert assess(seeded, one(seeded, "referrer_policy")).status_code == 201  # assessed, not signed off
    assert signoff(seeded, one(seeded, "x_content_type_options"), "reject").status_code == 200  # dismissed
    stale = approve_finding(seeded, "permissions_policy")
    with SessionLocal() as db:  # confirmed, but the approval no longer matches the current revision
        db.execute(text("UPDATE vulnerabilities SET revision = revision + 1 WHERE id = :id"), {"id": stale["id"]})
        db.commit()
    check = seeded.get(f"{R}/eligibility", params={"assessment_id": seeded.assessment_id}).json()
    assert check["eligible_count"] == 2 and check["excluded_count"] == 6 and check["can_generate"] is True
    assert check["excluded_reasons"] == {"unassessed": 3, "unconfirmed": 1, "dismissed": 1, "stale_or_missing_signoff": 1}
    report = generate(seeded)
    assert {f["check_id"] for f in report["findings"]} == {"csp", "hsts"}
    assert report["eligible_count"] == 2 and report["excluded_count"] == 6 and report["status"] == "draft"
    assert sum(report["severity_counts"].values()) == 2
    reasons = {e["check_id"]: e["reason"] for e in report["excluded"]}
    assert reasons["permissions_policy"] == "stale_or_missing_signoff" and reasons["referrer_policy"] == "unconfirmed"
    assert reasons["x_content_type_options"] == "dismissed" and reasons["server_disclosure"] == "unassessed"
    assert report["findings"][0]["signoff_analyst"] and report["findings"][0]["reproduction_steps"]


def test_report_needs_an_eligible_finding_and_a_known_completed_assessment(seeded):
    assert assess(seeded, one(seeded)).status_code == 201  # assessed only
    generate(seeded, 409)
    assert seeded.get(f"{R}/eligibility", params={"assessment_id": seeded.assessment_id}).json()["can_generate"] is False
    assert seeded.post(R, json={"assessment_id": NIL}).status_code == 404
    assert seeded.post(R, json={"assessment_id": "not-a-uuid"}).status_code == 422
    assert seeded.post(R, json={"assessment_id": NIL, "status": "approved"}).status_code == 422
    with SessionLocal() as db:
        assert db.query(VaptReport).count() == 0


def test_tampered_evidence_is_excluded_from_the_report(eligible):
    with SessionLocal() as db:
        db.execute(text("UPDATE vulnerability_occurrences SET evidence = '{\"forged\": true}' WHERE vulnerability_id = "
                        "(SELECT id FROM vulnerabilities WHERE check_id = 'csp')"))
        db.commit()
    report = generate(eligible)
    assert [f["check_id"] for f in report["findings"]] == ["hsts"]
    assert {e["check_id"]: e["reason"] for e in report["excluded"]}["csp"] == "evidence_integrity_failed"


# --- Human approval gate -----------------------------------------------------------------

def test_official_download_is_impossible_before_human_approval(eligible):
    report = generate(eligible)
    assert report["can_download_official"] is False and report["official_pdf_sha256"] is None
    denied = eligible.get(f"{R}/{report['id']}/pdf")
    assert denied.status_code == 409 and denied.headers["content-type"].startswith("application/json")
    preview = eligible.get(f"{R}/{report['id']}/preview")
    assert preview.status_code == 200 and preview.headers["x-report-release"] == "draft-not-for-release"
    assert "DRAFT" in pdf_text(preview.content) and "must not be released" in pdf_text(preview.content)
    with SessionLocal() as db:
        assert db.query(VaptReportArtifact).filter_by(kind="official").count() == 0


def test_approval_publishes_an_official_pdf_with_matching_sha256(eligible):
    report = generate(eligible)
    approved = decide(eligible, report)
    assert approved.status_code == 200, approved.text
    body = approved.json()
    assert body["status"] == "approved" and body["can_download_official"] is True and body["can_decide"] is False
    assert body["approval"]["decision"] == "approved" and body["approval"]["analyst_id"] == eligible.admin_id
    assert body["approval"]["justification"] == REASON and body["decided_by_name"]
    official = eligible.get(f"{R}/{report['id']}/pdf")
    assert official.status_code == 200 and official.headers["content-type"] == "application/pdf"
    assert official.headers["x-content-type-options"] == "nosniff" and official.headers["cache-control"] == "no-store"
    assert official.content.startswith(b"%PDF-") and len(official.content) > 2000
    digest = sha256(official.content).hexdigest()
    assert digest == body["official_pdf_sha256"] == official.headers["x-report-sha256"] == body["approval"]["pdf_sha256"]
    assert body["draft_pdf_sha256"] != digest
    rendered = pdf_text(official.content)
    for heading in ("Executive summary", "Client and domain scope", "Assessment methodology and isolation attestation",
                    "Severity breakdown", "Validated technical findings", "Remediation recommendations",
                    "Analyst approval and sign-off", "Approved for release", "Reproduction steps"):
        assert heading in rendered, heading
    assert "DRAFT" not in rendered and "OFFICIAL - APPROVED" in rendered and REASON[:40] in rendered
    with SessionLocal() as db:
        stored = db.query(VaptReportArtifact).filter_by(report_id=report["id"], kind="official").one()
        assert stored.sha256 == digest and stored.size == len(official.content)
        assert db.query(VaptReportApproval).one().content_sha256 == body["content_sha256"]


def test_rejection_is_final_and_never_releases_a_pdf(eligible):
    report = generate(eligible)
    rejected = decide(eligible, report, "reject")
    assert rejected.status_code == 200 and rejected.json()["status"] == "rejected"
    assert eligible.get(f"{R}/{report['id']}/pdf").status_code == 409
    assert decide(eligible, report).status_code == 409 and decide(eligible, report, "reject").status_code == 409
    assert eligible.get(f"{R}/{report['id']}").json()["status"] == "rejected"


@pytest.mark.parametrize("bad", [{"justification": "too short"}, {"human_validation_confirmed": False},
                                 {"human_validation_confirmed": "true"}, {"unexpected": 1}, {"justification": " " * 30}])
def test_decision_requires_attested_justification(eligible, bad):
    report = generate(eligible)
    for verb in ("approve", "reject"):
        assert decide(eligible, report, verb, **bad).status_code == 422
    assert eligible.get(f"{R}/{report['id']}").json()["status"] == "draft"
    with SessionLocal() as db:
        assert db.query(VaptReportApproval).count() == 0


def test_approval_is_refused_when_a_finding_changed_after_generation(eligible):
    report = generate(eligible)
    assert signoff(eligible, one(eligible, "csp"), "reopen").status_code == 200  # the approval is withdrawn
    refused = decide(eligible, report)
    assert refused.status_code == 409 and "csp" in refused.json()["detail"]
    assert eligible.get(f"{R}/{report['id']}").json()["status"] == "draft"
    assert eligible.get(f"{R}/{report['id']}/pdf").status_code == 409


def test_approval_is_refused_when_the_snapshot_was_tampered_with(eligible):
    report = generate(eligible)
    with SessionLocal() as db:
        db.execute(text("DROP TRIGGER trg_vapt_reports_frozen"))
        db.execute(text("UPDATE vapt_reports SET executive_summary = 'Everything is fine.' WHERE id = :id"), {"id": report["id"]})
        db.commit()
    refused = decide(eligible, report)
    assert refused.status_code == 409 and "integrity" in refused.json()["detail"]


def test_new_revision_supersedes_older_drafts_and_a_new_approval_supersedes_the_old_one(eligible):
    first, second = generate(eligible), generate(eligible)
    assert (first["revision"], second["revision"]) == (1, 2)
    assert eligible.get(f"{R}/{first['id']}").json()["status"] == "superseded"
    assert decide(eligible, first).status_code == 409
    assert decide(eligible, second).status_code == 200
    third = generate(eligible)
    assert decide(eligible, third).status_code == 200
    assert {r["revision"]: r["status"] for r in eligible.get(R).json()["items"]} == {1: "superseded", 2: "superseded", 3: "approved"}
    assert eligible.get(f"{R}/{second['id']}/pdf").status_code == 409  # superseded is not official
    assert eligible.get(f"{R}/{third['id']}/pdf").status_code == 200


def test_downloads_verify_the_stored_pdf_hash(eligible):
    report = generate(eligible)
    decide(eligible, report)
    with SessionLocal() as db:
        db.execute(text("DROP TRIGGER trg_vapt_report_artifacts_no_update"))
        db.execute(text("UPDATE vapt_report_artifacts SET content = :c WHERE kind = 'official'"), {"c": b"%PDF-1.4 forged"})
        db.commit()
    assert eligible.get(f"{R}/{report['id']}/pdf").status_code == 409


# --- Generated PDF safety ----------------------------------------------------------------

HOSTILE = ("<b>bold</b> </para><para>x</para> <font color='red' size=99>big</font> <img src='http://evil.example/x.png'/> "
           "<a href='javascript:alert(1)'>link</a> &lt;&amp; \x00\x07\x1b[31m ‮evil‬ "
           "株式会社 " + "A" * 5000)


def test_hostile_evidence_and_names_render_as_inert_text(eligible):
    evidence = {"observation": {"check": "csp", "note": HOSTILE}, "transport": {"status": 200, "x": ["<script>1</script>"]}}
    with SessionLocal() as db:
        db.execute(text("UPDATE clients SET company_name = :n"), {"n": "<para><b>Acme</b></para> & Co \x00‮"})
        db.execute(text("UPDATE vulnerability_occurrences SET evidence = :e, evidence_sha256 = :h"),
                   {"e": json.dumps(evidence), "h": sha256(assessments.report_bytes(evidence)).hexdigest()})
        db.commit()
    report = generate(eligible)
    assert report["scope"]["client_name"] == "<para><b>Acme</b></para> & Co"  # control and bidi characters removed
    body = eligible.get(f"{R}/{report['id']}/preview")
    assert body.status_code == 200 and body.content.startswith(b"%PDF-")
    rendered = pdf_text(body.content)
    assert "<b>bold</b>" in rendered and "</para>" in rendered and "<script>1</script>" in rendered  # shown, not interpreted
    assert "<para><b>Acme</b></para>" in rendered
    assert "\x00" not in rendered and "\x1b" not in rendered and "‮" not in rendered
    for marker in (b"/JavaScript", b"/JS ", b"/URI", b"/Launch", b"/OpenAction", b"/EmbeddedFile"):
        assert marker not in body.content
    assert decide(eligible, report).status_code == 200
    assert eligible.get(f"{R}/{report['id']}/pdf").content.startswith(b"%PDF-")


@pytest.mark.parametrize("value,expected", [
    ("a<b>&c", "a&lt;b&gt;&amp;c"), ("x\x00y\x1bz", "xyz"), ("l1\nl2", "l1<br/>l2"), ("‮abc⁦", "abc"),
    ("café 株", "café ?"), (None, "")])
def test_pdf_text_escapes_markup_and_removes_control_characters(value, expected):
    assert service.pdf_text(value, multiline=True) == expected


def test_strip_controls_bounds_length_and_flattens_single_line_fields():
    assert service.strip_controls("a\r\nb\tc") == "a  b c" and len(service.strip_controls("x" * 9000, 100)) == 100
    assert service.strip_controls("a\nb", multiline=True) == "a\nb"


# --- Authentication, RBAC and audit -------------------------------------------------------

def endpoints(report_id):
    return [("get", R), ("get", f"{R}/eligibility?assessment_id={report_id}"), ("post", R), ("get", f"{R}/{report_id}"),
            ("get", f"{R}/{report_id}/events"), ("get", f"{R}/{report_id}/preview"), ("get", f"{R}/{report_id}/pdf"),
            ("post", f"{R}/{report_id}/approve"), ("post", f"{R}/{report_id}/reject")]


def call(client, method, path):
    return getattr(client, method)(path, **({"json": {}} if method == "post" else {}))


def test_every_report_route_rejects_unauthenticated_callers(eligible):
    report = generate(eligible)
    token = eligible.headers.pop("Authorization")
    try:
        for method, path in endpoints(report["id"]):
            assert call(eligible, method, path).status_code == 401, path
        eligible.headers["Authorization"] = "Bearer not.a.jwt"
        for method, path in endpoints(report["id"]):
            assert call(eligible, method, path).status_code == 401, path
    finally:
        eligible.headers["Authorization"] = token
    assert eligible.get(f"{R}/{report['id']}").status_code == 200


def test_forged_role_tokens_and_deactivated_admins_are_rejected(eligible):
    report = generate(eligible)
    original = eligible.headers["Authorization"]
    key = settings.jwt_secret_key.get_secret_value()
    claims = jwt.decode(original.split()[1], key, algorithms=["HS256"], audience=settings.jwt_audience)
    try:
        eligible.headers["Authorization"] = "Bearer " + jwt.encode({**claims, "role": "viewer"}, key, algorithm="HS256")
        for method, path in endpoints(report["id"]):
            assert call(eligible, method, path).status_code == 401, path
    finally:
        eligible.headers["Authorization"] = original
    with SessionLocal() as db:
        db.get(Admin, eligible.admin_id).is_active = False
        db.commit()
    for method, path in endpoints(report["id"]):
        assert call(eligible, method, path).status_code == 401, path
    with SessionLocal() as db:
        assert db.query(VaptReport).one().status == "draft" and db.query(VaptReportApproval).count() == 0


def test_role_allow_lists_gate_reporting_and_approval_separately(eligible, monkeypatch):
    report = generate(eligible)
    monkeypatch.setattr(rbac, "REPORT_APPROVER_ROLES", frozenset())
    assert decide(eligible, report).status_code == 403 and decide(eligible, report, "reject").status_code == 403
    assert eligible.get(f"{R}/{report['id']}").status_code == 200  # may still read and preview
    monkeypatch.setattr(rbac, "REPORT_ROLES", frozenset())
    for method, path in endpoints(report["id"]):
        assert call(eligible, method, path).status_code == 403, path
    monkeypatch.undo()
    with SessionLocal() as db:
        assert db.query(VaptReport).one().status == "draft" and db.query(VaptReportApproval).count() == 0


def test_unknown_reports_and_malformed_ids(eligible):
    for suffix in ("", "/events", "/preview", "/pdf"):
        assert eligible.get(f"{R}/{NIL}{suffix}").status_code == 404
    assert decide(eligible, {"id": NIL}).status_code == 404
    assert eligible.get(f"{R}/not-a-uuid").status_code == 422
    for bad in ({"status": "published"}, {"limit": 0}, {"limit": 101}, {"offset": -1}, {"assessment_id": "x"}):
        assert eligible.get(R, params=bad).status_code == 422


def test_listing_filters_and_pagination(eligible):
    first, second = generate(eligible), generate(eligible)
    decide(eligible, second)
    assert eligible.get(R, params={"status": "approved"}).json()["total"] == 1
    assert eligible.get(R, params={"status": "superseded"}).json()["items"][0]["id"] == first["id"]
    listing = eligible.get(R, params={"limit": 1}).json()
    assert listing["total"] == 2 and len(listing["items"]) == 1 and "findings" not in listing["items"][0]
    assert eligible.get(R, params={"assessment_id": eligible.assessment_id}).json()["total"] == 2


def test_audit_trail_records_generation_decisions_and_downloads(eligible):
    report = generate(eligible)
    eligible.get(f"{R}/{report['id']}/preview")
    decide(eligible, report)
    eligible.get(f"{R}/{report['id']}/pdf")
    events = eligible.get(f"{R}/{report['id']}/events").json()
    assert [e["action"] for e in reversed(events)] == ["generated", "preview_downloaded", "approved", "official_downloaded"]
    assert all(e["actor_id"] == eligible.admin_id and e["actor_name"] and e["occurred_at"].endswith("+00:00") for e in events)
    assert events[1]["detail"]["content_sha256"] == report["content_sha256"]


# --- Immutability and migration --------------------------------------------------------

def test_orm_and_database_block_rewriting_snapshots_history_and_final_states(eligible):
    report = generate(eligible)
    decide(eligible, report)
    with SessionLocal() as db:
        db.get(VaptReport, report["id"]).executive_summary = "changed"
        with pytest.raises(ValueError, match="frozen"):
            db.flush()
        db.rollback()
        db.delete(db.get(VaptReport, report["id"]))
        with pytest.raises(ValueError, match="never be deleted"):
            db.flush()
        db.rollback()
        for model in (VaptReportApproval, VaptReportArtifact, VaptReportEvent):
            db.delete(db.query(model).first())
            with pytest.raises(ValueError, match="append-only"):
                db.flush()
            db.rollback()
    statements = [("UPDATE vapt_reports SET findings = '[]'", "frozen"), ("UPDATE vapt_reports SET content_sha256 = 'x'", "frozen"),
                  ("DELETE FROM vapt_reports", "cannot be deleted"), ("UPDATE vapt_reports SET status = 'draft'", "final"),
                  ("UPDATE vapt_reports SET status = 'rejected'", "final"),
                  ("UPDATE vapt_reports SET official_pdf_sha256 = 'x'", "write-once"),
                  ("UPDATE vapt_report_artifacts SET sha256 = 'x'", "append-only"), ("DELETE FROM vapt_report_artifacts", "append-only"),
                  ("UPDATE vapt_report_approvals SET decision = 'rejected'", "append-only"),
                  ("DELETE FROM vapt_report_approvals", "append-only"), ("UPDATE vapt_report_events SET action = 'x'", "append-only"),
                  ("DELETE FROM vapt_report_events", "append-only")]
    for sql, message in statements:
        with SessionLocal() as db:
            with pytest.raises(DBAPIError, match=message):
                db.execute(text(sql))
            db.rollback()
    with SessionLocal() as db:
        assert db.get(VaptReport, report["id"]).status == "approved"


def test_migration_installs_report_tables_and_triggers_preserving_data(tmp_path):
    path = tmp_path / "reports.db"
    migrate(path, "0010_analyst_workbench")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO admins (id,email,full_name,password_hash,role,is_active) VALUES (7,'a@example.com','Synthetic','preserved-hash','admin',1)")
    migrate(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0011_vapt_reports"
        assert db.execute("SELECT password_hash FROM admins WHERE id = 7").fetchone()[0] == "preserved-hash"
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert {"vapt_reports", "vapt_report_artifacts", "vapt_report_approvals", "vapt_report_events"} <= tables
        triggers = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}
        assert {"trg_vapt_reports_frozen", "trg_vapt_reports_no_delete", "trg_vapt_reports_status", "trg_vapt_reports_official_once",
                "trg_vapt_report_artifacts_no_update", "trg_vapt_report_approvals_no_delete",
                "trg_vapt_report_events_no_update"} <= triggers
