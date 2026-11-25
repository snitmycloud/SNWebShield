"""End-to-end SNWebShield lifecycle with separation of duties switched on.

client -> website -> written authorisation (upload, human review, approval) -> monitoring check ->
explicit assessment request -> permission/scope revalidation -> scanner run and JSON ingestion ->
findings -> analyst risk assessment and sign-off -> VAPT PDF and approval -> remediation ->
scoped retest and fix verification -> closure -> post-closure lock. Synthetic scanner output only:
no network, DNS, SSH or Docker is used.
"""
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import func, select

from app.core.config import settings
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.models import AuthorizationAuditEvent
from app.models.assessment import AssessmentReport, AssessmentRequest
from app.models.evidence import EvidenceEvent
from app.models.jobs import ExecutionEvent, Job
from app.models.remediation import AssessmentClosure, RemediationEvent, RetestRequest
from app.models.report import VaptReportApproval, VaptReportEvent
from app.models.security import AuthEvent
from app.models.vulnerability import Vulnerability, VulnerabilityEvent, VulnerabilitySignoff
from app.services import assessments as assess_service, job_engine as engine
from evidence_helpers import attach_review
from test_authorization_correctness import NOW, api  # noqa: F401 - fixture
from test_monitoring import complete, enable, schedule
from test_production_hardening import As, token_for
from test_remediation import AS, FIXED, REM, close, get, reopen, request_retest, retest_cycle, update
from test_reports import R, decide as decide_report, generate as generate_report
from test_vulnerabilities import ONLY_DISCLOSURE, assess, one, run
from test_workbench import signoff

API = "/api/v1"
HOST = "e2e-lifecycle.example.org"


def authorization_body(website_id, methods, reference):
    return {"website_id": website_id, "authorization_reference": reference, "authorized_by": "Synthetic Signatory",
            "authorized_domains": [HOST], "permitted_methods": methods,
            "valid_from": (NOW - timedelta(hours=1)).isoformat(), "valid_until": (NOW + timedelta(hours=1)).isoformat()}


def count(db, model, *where):
    return db.scalar(select(func.count()).select_from(model).where(*where))


def test_full_lifecycle_from_registration_to_closure_with_audit_trail(api, monkeypatch):
    monkeypatch.setattr(settings, "assessment_local_http_enabled", True)
    monkeypatch.setattr(settings, "separation_of_duties_enabled", True)
    analyst, analyst_id = token_for(api, "analyst")
    lead, lead_id = token_for(api, "lead_analyst")
    admin_id = api.admin_id

    # --- 1. Client and website registration (bootstrap admin) -------------------------------
    client_row = api.post(f"{API}/clients", json={"company_name": "E2E Lifecycle Pvt Ltd", "primary_contact_name": "Asha Rao",
                                                  "email": f"e2e-{uuid4().hex[:8]}@example.com", "industry": "Testing"})
    assert client_row.status_code == 201, client_row.text
    site = api.post(f"{API}/websites", json={"client_id": client_row.json()["id"], "name": "E2E public site",
                                             "url": f"https://{HOST}", "environment": "staging"})
    assert site.status_code == 201, site.text
    website_id = site.json()["id"]
    assert site.json()["effective_authorisation_status"] == "not_requested"

    # --- 2. Written authorisation: upload, human review, approval ------------------------------
    created = api.post(f"{API}/authorizations", json=authorization_body(website_id, ["automated_non_intrusive_scanning"], "E2E-LIFECYCLE-001"))
    assert created.status_code == 201, created.text
    auth_id = created.json()["id"]
    approval = {"evidence_reviewed": True, "review_note": "Reviewed the signed permission and verified the exact domain scope."}
    assert api.post(f"{API}/authorizations/{auth_id}/approve", json=approval).status_code == 409  # no document yet
    evidence_key = attach_review(api, auth_id)
    approved = api.post(f"{API}/authorizations/{auth_id}/approve", json=approval)
    assert approved.status_code == 200 and approved.json()["status"] == "approved"
    assert api.get(f"{API}/websites/{website_id}").json()["effective_authorisation_status"] == "active"

    # --- 3. Monitoring check (needs its own consent) -----------------------------------------------
    configured = api.post(f"{API}/websites/{website_id}/monitoring/configure", json={
        "evidence_id": evidence_key, "consent_reference": "E2E-MONITORING-CONSENT", "monitoring_permission_reviewed": True,
        "expires_at": (utc_now() + timedelta(days=7)).isoformat(), "interval_seconds": 60, "failure_threshold": 1})
    assert configured.status_code == 200, configured.text
    enable(api, website_id)
    started = utc_now()
    schedule(website_id, started)
    complete("up", started)
    results = api.get(f"{API}/websites/{website_id}/monitoring/results").json()
    assert len(results) == 1 and results[0]["payload"]["state"] == "up"

    # --- 4. Nothing scans by itself; an explicit request is required ----------------------------------
    with SessionLocal() as db:
        engine.scheduler_tick(db)
        assert count(db, AssessmentRequest) == 0 and count(db, Job, Job.job_type == "assessment") == 0

    request_body = {"website_id": website_id, "authorization_id": auth_id, "profile_id": assess_service.HTTP_PROFILE_ID,
                    "explicitly_requested": True, "network_permission_confirmed": True,
                    "note": "Explicit end-to-end header assessment request.", "idempotency_key": str(uuid4())}

    # --- 5. Authorisation and scope revalidation: every unauthorised request is refused ---------------------
    other_site = api.post(f"{API}/websites", json={"client_id": client_row.json()["id"], "name": "Other site",
                                                   "url": "https://other-e2e.example.net", "environment": "staging"}).json()["id"]
    narrow = api.post(f"{API}/authorizations", json=authorization_body(website_id, ["passive_reconnaissance"], "E2E-LIFECYCLE-002")).json()["id"]
    attach_review(api, narrow)
    assert api.post(f"{API}/authorizations/{narrow}/approve", json=approval).status_code == 200
    revoked = api.post(f"{API}/authorizations", json=authorization_body(website_id, ["automated_non_intrusive_scanning"], "E2E-LIFECYCLE-003")).json()["id"]
    attach_review(api, revoked)
    assert api.post(f"{API}/authorizations/{revoked}/approve", json=approval).status_code == 200
    assert api.post(f"{API}/authorizations/{revoked}/revoke", json={"reason": "Client withdrew permission in writing."}).status_code == 200
    denied = {
        "method not permitted": {**request_body, "authorization_id": narrow},
        "revoked authorisation": {**request_body, "authorization_id": revoked},
        "different website (out of scope)": {**request_body, "website_id": other_site},
        "no explicit network confirmation": {**request_body, "network_permission_confirmed": False},
    }
    with As(api, analyst) as c:
        for name, body in denied.items():
            response = c.post(f"{API}/assessments", json={**body, "idempotency_key": str(uuid4())})
            assert response.status_code in (403, 409, 422), (name, response.text)
    with SessionLocal() as db:
        assert count(db, AssessmentRequest) == 0 and count(db, Job, Job.job_type == "assessment") == 0

    # --- 6. Permitted request -> scanner execution -> structured JSON ingestion ------------------------------
    with As(api, analyst) as c:
        row = run((c, auth_id, request_body), monkeypatch, ONLY_DISCLOSURE, 0)
    assessment_id = row["id"]
    api.assessment_id, api.auth_id, api.monkeypatch = assessment_id, auth_id, monkeypatch
    detail = api.get(f"{API}/assessments/{assessment_id}").json()
    assert detail["job"]["status"] == "completed" and detail["requested_by"] == analyst_id
    assert detail["result"]["payload"]["state"] == "completed" or detail["result"]["payload"].get("outcome")
    stored = api.get(f"{API}/assessments/{assessment_id}/report/download")
    assert stored.status_code == 200 and stored.json()["evidence"] and "PRIVATE" not in stored.text

    # --- 7. Findings exist, unconfirmed, and are never auto-confirmed ------------------------------------------
    listed = api.get(f"{API}/vulnerabilities", params={"limit": 100}).json()
    assert len(listed["items"]) == 8 and listed["pending_ingestion"] == 0 and {i["validation_state"] for i in listed["items"]} == {"unconfirmed"}
    finding = one(api, "csp")
    assert finding["validation_state"] == "unconfirmed"
    with SessionLocal() as db:
        assert count(db, Vulnerability, Vulnerability.validation_state == "confirmed") == 0

    # --- 8. Analyst risk assessment and a second person's sign-off ---------------------------------------------
    with As(api, analyst) as c:
        assert assess(c, finding, likelihood="likely", business_impact="major", risk_rating="high",
                      remediation_priority="immediate").status_code == 201
        assert signoff(c, finding).status_code == 403  # cannot approve own assessment
    with As(api, lead) as c:
        assert signoff(c, finding).status_code == 200
    confirmed = one(api, "csp")
    assert confirmed["validation_state"] == "confirmed" and confirmed["analyst_severity"] == "high"
    vid = confirmed["id"]
    api.vid = vid

    # --- 9. VAPT PDF: generated by the analyst, approved by the lead --------------------------------------------
    with As(api, analyst) as c:
        report = generate_report(c)
        assert decide_report(c, report).status_code == 403  # analysts cannot approve
        assert c.get(f"{R}/{report['id']}/pdf").status_code == 409  # no official PDF before approval
    with As(api, lead) as c:
        decided = decide_report(c, report)
        assert decided.status_code == 200, decided.text
        pdf = c.get(f"{R}/{report['id']}/pdf")
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-")

    # --- 10. Remediation updates, then a scoped retest verifies the fix ------------------------------------------------
    with As(api, analyst) as c:
        assert update(c, vid, "verified_fixed", 0).status_code == 422  # only a retest can verify
        assert update(c, vid, "in_progress", 0).status_code == 200
        assert update(c, vid, "fix_submitted", 1).status_code == 200
        done = retest_cycle(c, FIXED, 10)
    assert done["status"] == "verified_fixed" and done["retests"][0]["outcome"] == "verified_fixed"
    with SessionLocal() as db:
        retest = db.scalar(select(RetestRequest))
        retest_assessment = db.get(AssessmentRequest, retest.assessment_id)
        assert retest.requested_by == analyst_id and retest_assessment.authorization_id == auth_id

    # --- 10b. The scanner's verified-fixed result needs a second person before the assessment can close --------------------
    waiting = api.get(f"{AS}/{assessment_id}/closure").json()
    assert waiting["can_close"] is False and any("independent sign-off" in reason for reason in waiting["blocking_reasons"])
    fix_review = lambda: {"expected_version": get(api, vid)["version"], "decision": "confirmed", "human_validation_confirmed": True,
                          "note": "Second analyst reviewed the stored retest evidence: the header is present on the exact target."}
    with As(api, analyst) as c:
        assert c.post(f"{REM}/{vid}/verify-fix", json=fix_review()).status_code == 403  # they requested the retest
    with As(api, lead) as c:
        signed = c.post(f"{REM}/{vid}/verify-fix", json=fix_review())
        assert signed.status_code == 200, signed.text
        assert signed.json()["fix_verification"]["state"] == "confirmed" and signed.json()["fix_verification"]["signed_by"] == lead_id

    # --- 11. Closure: senior role, and not by whoever handled remediation ----------------------------------------------------
    state = api.get(f"{AS}/{assessment_id}/closure").json()
    assert state["can_close"] is True and state["status_counts"] == {"verified_fixed": 1} and state["unreviewed_count"] >= 1
    with As(api, analyst) as c:
        assert close(c).status_code == 403
    closed = None
    with As(api, lead) as c:
        closed = close(c)
    assert closed.status_code == 200, closed.text
    assert closed.json()["closed"] is True and closed.json()["closure"]["closed_by"] == lead_id
    assert len(closed.json()["closure"]["content_sha256"]) == 64

    # --- 12. After closure every mutation is blocked and nothing changed --------------------------------------------------------
    before = get(api, vid)
    item = api.get(f"{API}/vulnerabilities/{vid}").json()
    with As(api, lead) as c:
        attempts = [update(c, vid, "in_progress", before["version"]), reopen(c, vid, before["version"]),
                    request_retest(c, vid, before["version"]), signoff(c, item, "reopen"), assess(c, item),
                    close(c)]
    assert [a.status_code for a in attempts] == [409] * len(attempts), [a.text for a in attempts]
    after = get(api, vid)
    assert after["status"] == "verified_fixed" and after["version"] == before["version"] and len(after["events"]) == len(before["events"])

    # --- 13. Audit trail exists for every stage -----------------------------------------------------------------------------------
    with SessionLocal() as db:
        logins = list(db.scalars(select(AuthEvent).where(AuthEvent.event_type == "login_success")))
        assert {e.admin_id for e in logins} >= {admin_id, analyst_id, lead_id}
        assert count(db, AuthEvent, AuthEvent.event_type == "login_failure") == 0

        actions = {a for (a,) in db.execute(select(AuthorizationAuditEvent.action).where(AuthorizationAuditEvent.authorization_id == auth_id))}
        assert "approved" in actions
        assert {"uploaded", "opened", "review_accepted"} <= {a for (a,) in db.execute(
            select(EvidenceEvent.action).where(EvidenceEvent.authorization_id == auth_id))}

        assert count(db, ExecutionEvent, ExecutionEvent.resource_id == website_id) >= 1  # monitoring and assessment events
        assert count(db, AssessmentReport) >= 1 and count(db, AssessmentReport, AssessmentReport.sha256 == "") == 0

        vuln_events = list(db.scalars(select(VulnerabilityEvent).where(VulnerabilityEvent.vulnerability_id == vid)))
        assert {"risk_assessment_saved", "validation_changed"} <= {e.action for e in vuln_events}
        signoffs = list(db.scalars(select(VulnerabilitySignoff).where(VulnerabilitySignoff.vulnerability_id == vid)))
        assert [(s.analyst_id, s.to_state) for s in signoffs] == [(lead_id, "confirmed")]

        assert {"generated", "approved"} <= {e.action for e in db.scalars(select(VaptReportEvent))}
        approvals = list(db.scalars(select(VaptReportApproval)))
        assert [(a.analyst_id, a.decision) for a in approvals] == [(lead_id, "approved")]

        remediation = list(db.scalars(select(RemediationEvent).where(RemediationEvent.vulnerability_id == vid).order_by(RemediationEvent.sequence)))
        assert [e.to_status for e in remediation] == ["in_progress", "fix_submitted", "retest_requested", "verified_fixed"]
        assert [e.actor_id for e in remediation] == [analyst_id, analyst_id, analyst_id, None]  # None = scanner reconciliation

        closure = db.scalar(select(AssessmentClosure))
        assert closure.closed_by == lead_id and closure.assessment_id == assessment_id
        # Exactly two scans ran, both explicitly requested by a person: the assessment and its retest.
        assert count(db, AssessmentRequest) == 2 and {r.requested_by for r in db.scalars(select(AssessmentRequest))} == {analyst_id}
