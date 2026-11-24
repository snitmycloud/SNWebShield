"""Assessment worker health is computed from the server clock, never the browser's."""
from datetime import timedelta
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.models.jobs import WorkerHeartbeat
from app.api.routes.assessments import WORKER_STALE_SECONDS
from test_authorization_correctness import api  # noqa: F401  (authenticated client fixture)


def set_beat(age_seconds):
    with SessionLocal() as db:
        row = db.get(WorkerHeartbeat, "assessment-worker")
        if age_seconds is None:
            if row: db.delete(row)
        else:
            stamp = utc_now() - timedelta(seconds=age_seconds)
            if row: row.seen_at = stamp
            else: db.add(WorkerHeartbeat(name="assessment-worker", seen_at=stamp))
        db.commit()


def status(api):
    r = api.get("/api/v1/assessments/worker-status")
    assert r.status_code == 200, r.text
    return r.json()


def test_not_started_running_and_stale(api):
    set_beat(None)
    assert status(api)["state"] == "not_started" and status(api)["worker"] is None
    set_beat(3)
    body = status(api)
    assert body["state"] == "running" and body["age_seconds"] < WORKER_STALE_SECONDS
    assert "assessment-worker" in body["start_command"]
    set_beat(WORKER_STALE_SECONDS + 60)
    assert status(api)["state"] == "stale"


def test_worker_tick_records_a_heartbeat(api):
    from app.services import assessments
    set_beat(500)
    assessments.worker_tick()
    assert status(api)["state"] == "running"
