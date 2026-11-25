"""A database that has not yet received migrations 0014/0015 must not break existing pages or monitoring."""
import pytest
from sqlalchemy import text

from app.db.session import SessionLocal
from app.services import job_engine as engine
from test_assessments import assessed  # noqa: F401 - fixture
from test_authorization_correctness import api  # noqa: F401 - fixture
from test_fix_signoff import get, verified  # noqa: F401 - fixtures
from test_local_assessment import network  # noqa: F401 - fixture
from test_remediation import AS, REM, submitted, tracked  # noqa: F401 - fixtures


def drop(*tables):
    with SessionLocal() as db:
        for table in tables:
            db.execute(text(f"DROP TABLE IF EXISTS {table}"))
        db.commit()


def test_lifecycle_still_works_without_the_port_watch_tables(assessed):
    api, _, site, _, _ = assessed
    drop("port_watch_changes", "port_watches")
    response = api.get(f"/api/v1/websites/{site}/lifecycle")
    assert response.status_code == 200, response.text
    assert response.json()["monitor"]["port_watch"] is None and response.json()["next_step"]["code"]


def test_port_watch_endpoints_say_what_to_do_instead_of_a_server_error(assessed):
    api, _, site, _, _ = assessed
    drop("port_watch_changes", "port_watches")
    body = {"interval_seconds": 3600, "network_permission_confirmed": True, "human_validation_confirmed": True}
    for response in (api.get(f"/api/v1/port-watch/{site}"), api.post(f"/api/v1/port-watch/{site}/enable", json=body),
                     api.post(f"/api/v1/port-watch/{site}/disable", json={"reason": "No longer needed here."})):
        assert response.status_code in (503, 409), response.text  # disable says 'not enabled' before touching the table
    assert api.get(f"/api/v1/port-watch/{site}").json()["detail"].endswith("alembic upgrade head from backend")


def test_the_scheduler_keeps_running_monitoring_without_the_port_watch_tables(api, capsys):
    drop("port_watch_changes", "port_watches")
    with SessionLocal() as db:
        engine.scheduler_tick(db)  # must not raise
    assert "scheduling failed" in capsys.readouterr().out


def test_remediation_pages_still_load_a_verified_fix_without_the_signoff_table(verified):
    drop("fix_verification_signoffs")
    detail = get(verified, verified.vid)
    assert detail["status"] == "verified_fixed"
    assert detail["fix_verification"]["state"] == "pending" and detail["fix_verification"]["required"] is False
    closure = verified.get(f"{AS}/{verified.assessment_id}/closure")
    assert closure.status_code == 200 and closure.json()["can_close"] is True  # dual sign-off is off, so nothing is blocked
