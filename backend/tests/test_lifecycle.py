"""Per-website lifecycle view: monitor, detect, validate, protect and the single next step. Read-only."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.config import settings
from app.db.session import SessionLocal
from app.main import app
from app.models import WebsiteAuthorization
from app.models.jobs import ExecutionEvent, Job
from app.services import assessments as service, lifecycle
from test_assessments import assessed, create  # noqa: F401 - fixtures
from test_authorization_correctness import api  # noqa: F401 - fixture
from test_fix_signoff import FIXED, dual, get, retest_cycle, second_person, verified, verify  # noqa: F401
from test_local_assessment import network  # noqa: F401 - fixture
from test_remediation import submitted, tracked  # noqa: F401 - fixtures
from test_vulnerabilities import ONLY_DISCLOSURE, run


def view(client, website_id):
    response = client.get(f"/api/v1/websites/{website_id}/lifecycle")
    assert response.status_code == 200, response.text
    return response.json()


def monitored(monkeypatch, state="healthy"):
    """Monitoring needs consent evidence to configure; the monitoring suites cover that. Pin a healthy monitor here."""
    monkeypatch.setattr(lifecycle, "_monitor", lambda db, website, now: {
        "state": state, "enabled": True, "interval_seconds": 300, "last_checked_at": None, "last_result": "up"})


# --- The next-step rules, in priority order ---------------------------------------------------------------

MON = {"state": "healthy"}
DET = {"latest": {"status": "completed"}, "can_run": True, "blocked_reason": None}
VAL = {"awaiting_review": 0}
PRO = {"status_counts": {}, "confirmed": 0, "unresolved": 0, "awaiting_signoff": 0, "approved_reports": 0}


def step(monitor=None, detect=None, validate=None, protect=None):
    return lifecycle.next_step({**MON, **(monitor or {})}, {**DET, **(detect or {})}, {**VAL, **(validate or {})}, {**PRO, **(protect or {})})["code"]


@pytest.mark.parametrize("kwargs,expected", [
    (dict(monitor={"state": "not_configured"}), "set_up_monitoring"),
    (dict(monitor={"state": "not_configured"}, detect={"latest": None}), "set_up_monitoring"),  # monitoring comes first
    (dict(detect={"latest": None}), "run_assessment"),
    (dict(detect={"latest": None, "can_run": False, "blocked_reason": "The authorisation is expired."}), "fix_permission"),
    (dict(detect={"latest": {"status": "queued"}}), "wait_for_assessment"),
    (dict(detect={"latest": {"status": "running"}}, validate={"awaiting_review": 3}), "wait_for_assessment"),
    (dict(monitor={"port_watch": {"enabled": True, "last_outcome": "changed",
                                  "latest_change": {"changes": [{"port": "443", "from": "closed", "to": "open"}]}}}), "review_port_change"),
    (dict(monitor={"port_watch": {"enabled": False, "last_outcome": "changed"}}), "all_clear"),  # a paused watch raises nothing
    (dict(monitor={"port_watch": {"enabled": True, "last_outcome": "unchanged"}}), "all_clear"),
    (dict(monitor={"port_watch": {"enabled": True, "last_outcome": "changed", "latest_change": {"changes": []}}},
          detect={"latest": {"status": "running"}}), "wait_for_assessment"),  # an assessment in progress comes first
    (dict(monitor={"port_watch": {"enabled": True, "last_outcome": "changed"}}, validate={"awaiting_review": 3}), "review_port_change"),
    (dict(validate={"awaiting_review": 2}), "review_findings"),
    (dict(validate={"awaiting_review": 2}, protect={"awaiting_signoff": 1}), "review_findings"),
    (dict(protect={"awaiting_signoff": 1, "status_counts": {"verified_fixed": 1}, "confirmed": 1}), "sign_off_fix"),
    (dict(protect={"status_counts": {"retest_requested": 1}, "confirmed": 1, "unresolved": 1}), "wait_for_retest"),
    (dict(protect={"status_counts": {"fix_submitted": 1}, "confirmed": 1, "unresolved": 1}), "request_retest"),
    (dict(protect={"status_counts": {"open": 1}, "confirmed": 1, "unresolved": 1}), "track_remediation"),
    (dict(protect={"status_counts": {"reopened": 1}, "confirmed": 1, "unresolved": 1}), "track_remediation"),
    (dict(protect={"status_counts": {"verified_fixed": 1}, "confirmed": 1}), "generate_report"),
    (dict(protect={"status_counts": {"verified_fixed": 1}, "confirmed": 1, "approved_reports": 1}), "all_clear"),
    (dict(detect={"latest": {"status": "failed"}}), "run_assessment"),
    (dict(detect={"latest": {"status": "failed"}, "can_run": False, "blocked_reason": "Expired."}), "fix_permission"),
    (dict(detect={"latest": {"status": "cancelled"}, "can_run": False}), "fix_permission"),
    (dict(), "all_clear"),
])
def test_next_step_rules(kwargs, expected):
    assert step(**kwargs) == expected


def test_every_next_step_has_a_message():
    for kwargs in (dict(monitor={"state": "not_configured"}), dict(detect={"latest": None}), dict(), dict(validate={"awaiting_review": 1})):
        result = lifecycle.next_step({**MON, **kwargs.get("monitor", {})}, {**DET, **kwargs.get("detect", {})},
                                     {**VAL, **kwargs.get("validate", {})}, PRO)
        assert result["message"] and result["code"]


# --- Against real data -------------------------------------------------------------------------------------

def test_unmonitored_website_starts_with_monitoring(assessed):
    api, auth, site, _, _ = assessed
    body = view(api, site)
    assert body["monitor"]["state"] == "not_configured" and body["next_step"]["code"] == "set_up_monitoring"
    assert body["website"]["id"] == site and body["website"]["client"]
    assert body["detect"]["total_assessments"] == 0 and body["detect"]["latest"] is None and body["detect"]["can_run"] is True
    assert body["validate"]["total"] == 0 and body["protect"]["confirmed"] == 0


def test_a_permitted_website_is_told_to_run_the_first_assessment(assessed, monkeypatch):
    api, _, site, _, _ = assessed
    monitored(monkeypatch)
    body = view(api, site)
    assert body["next_step"]["code"] == "run_assessment" and "preflight" not in body["next_step"]["message"].lower()
    assert service.PROFILE_ID in body["detect"]["ready_profiles"]


def test_a_blocked_website_reports_the_exact_reason(assessed, monkeypatch):
    api, auth, site, _, _ = assessed
    monitored(monkeypatch)
    with SessionLocal() as db:
        db.get(WebsiteAuthorization, auth).status = "revoked"; db.commit()
    body = view(api, site)
    assert body["next_step"]["code"] == "fix_permission" and body["detect"]["can_run"] is False
    assert body["next_step"]["message"] == body["detect"]["blocked_reason"] and "no approved authorisation" in body["next_step"]["message"]


def test_progress_through_a_queued_and_completed_assessment(assessed, monkeypatch):
    api, _, site, _, _ = assessed
    monitored(monkeypatch)
    row = create(assessed)
    queued = view(api, site)
    assert queued["detect"]["latest"]["id"] == row["id"] and queued["detect"]["latest"]["status"] == "queued"
    assert queued["next_step"]["code"] == "wait_for_assessment"
    service.worker_tick()
    done = view(api, site)
    assert done["detect"]["latest"]["status"] == "completed" and done["detect"]["total_assessments"] == 1
    assert done["next_step"]["code"] == "all_clear"  # a permission preflight raises no observations


def test_findings_and_remediation_counts_come_from_the_existing_records(tracked, monkeypatch):
    monitored(monkeypatch)
    site = tracked.get(f"/api/v1/assessments/{tracked.assessment_id}").json()["website_id"]
    body = view(tracked, site)
    assert body["validate"]["confirmed"] == 1 and body["validate"]["unconfirmed"] == 7 and body["validate"]["awaiting_review"] == 7
    assert body["protect"]["confirmed"] == 1 and body["protect"]["status_counts"] == {"open": 1} and body["protect"]["unresolved"] == 1
    assert body["next_step"]["code"] == "review_findings"  # unreviewed observations come before remediation


def test_verified_fix_awaiting_second_person_is_counted_when_dual_signoff_is_on(dual, monkeypatch):
    monitored(monkeypatch)
    site = dual.get(f"/api/v1/assessments/{dual.assessment_id}").json()["website_id"]
    assert view(dual, site)["protect"]["awaiting_signoff"] == 1
    headers, _ = second_person(dual)
    assert verify(dual, dual.vid, headers=headers).status_code == 200
    body = view(dual, site)
    assert body["protect"]["awaiting_signoff"] == 0 and body["protect"]["status_counts"] == {"verified_fixed": 1}


def test_without_dual_signoff_nothing_awaits_a_second_person(verified, monkeypatch):
    monitored(monkeypatch)
    site = verified.get(f"/api/v1/assessments/{verified.assessment_id}").json()["website_id"]
    assert view(verified, site)["protect"]["awaiting_signoff"] == 0


# --- Read-only, authenticated ------------------------------------------------------------------------------

def test_the_view_writes_nothing_and_needs_no_worker(assessed, monkeypatch):
    api, _, site, _, _ = assessed
    monitored(monkeypatch)
    def counts():
        with SessionLocal() as db:
            return (db.scalar(select(func.count()).select_from(ExecutionEvent)), db.scalar(select(func.count()).select_from(Job)))
    before = counts()
    view(api, site); view(api, site)
    assert counts() == before


def test_unknown_website_and_unauthenticated_callers(assessed):
    api, _, site, _, _ = assessed
    assert api.get("/api/v1/websites/999999/lifecycle").status_code == 404
    assert api.get("/api/v1/websites/0/lifecycle").status_code == 404
    assert TestClient(app).get(f"/api/v1/websites/{site}/lifecycle").status_code == 401
    assert api.get("/api/v1/websites/abc/lifecycle").status_code == 422
