"""The analyst-era pipeline is read-only: staff can read it, nothing can start new work, stop actions still work."""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import assessments, port_watch
from account_helpers import account_headers


@pytest.fixture
def staff():
    with TestClient(app) as client:
        _, _, headers = account_headers(client, "admin")
        client.headers.update(headers)
        yield client


@pytest.mark.parametrize("path", ["/api/v1/assessments", "/api/v1/vulnerabilities", "/api/v1/reports",
                                  "/api/v1/monitoring/overview", "/api/v1/clients", "/api/v1/assessments/worker-status"])
def test_staff_can_still_read_past_data(staff, path):
    assert staff.get(path).status_code == 200, path


@pytest.mark.parametrize("path, body", [
    ("/api/v1/clients", {"company_name": "X", "primary_contact_name": "Y", "email": "x@example.com"}),
    ("/api/v1/vulnerabilities/ingest", {}),
    ("/api/v1/reports", {}),
    ("/api/v1/port-watch/1/enable", {"interval_seconds": 3600}),
    ("/api/v1/websites/1/monitoring/enable", {}),
    ("/api/v1/websites/1/monitoring/check-now", {}),
    ("/api/v1/remediation/00000000-0000-0000-0000-000000000000/retests", {}),
    ("/api/v1/workbench/00000000-0000-0000-0000-000000000000/signoff", {}),
    ("/api/v1/assessments/00000000-0000-0000-0000-000000000000/reviewed-reports", {}),
])
def test_nothing_can_start_new_legacy_work(staff, path, body):
    response = staff.post(path, json=body)
    assert response.status_code == 410, (path, response.status_code, response.text)
    assert "read-only" in response.json()["detail"]


def test_creating_a_legacy_assessment_is_gone(staff):
    assert staff.post("/api/v1/assessments", json={}).status_code == 405


def test_stop_actions_are_still_allowed(staff):
    assert staff.post("/api/v1/monitoring/stop").status_code == 200
    # Allowed through (then answered by the route itself, not refused as retired).
    assert staff.post("/api/v1/assessments/00000000-0000-0000-0000-000000000000/cancel",
                      json={"reason": "Stopping a leftover run."}).status_code == 404
    assert staff.post("/api/v1/port-watch/1/disable", json={"reason": "No longer needed."}).status_code != 410


def test_legacy_runs_can_never_be_eligible_and_port_watch_never_schedules():
    from types import SimpleNamespace
    events = []
    db = SimpleNamespace(add=events.append)
    assert assessments.AssessmentHandler.eligible(db, SimpleNamespace(id="j", resource_id=1)) is False
    assert port_watch.schedule(None) is None
    assert port_watch._nmap_readiness(None, 1, 1)["ready"] is False
