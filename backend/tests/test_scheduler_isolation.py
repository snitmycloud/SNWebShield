"""One failing job type must not stop the other schedulers (monitoring in particular)."""
from types import SimpleNamespace

from app.db.session import SessionLocal
from app.services import job_engine as engine
from test_authorization_correctness import api  # noqa: F401 - fixture (creates the database)


def test_a_failing_handler_does_not_stop_the_others_and_prints_no_detail(api, monkeypatch, capsys):
    ran = []
    def boom(db): raise RuntimeError("SECRET-connection-string should never be printed")
    monkeypatch.setitem(engine.HANDLERS, "zz_boom", SimpleNamespace(schedule=boom))
    monkeypatch.setitem(engine.HANDLERS, "zz_after", SimpleNamespace(schedule=lambda db: ran.append("after")))
    with SessionLocal() as db:
        engine.scheduler_tick(db)  # must not raise
    assert ran == ["after"]
    out = capsys.readouterr().out
    assert "zz_boom scheduling failed" in out and "SECRET" not in out and "Traceback" not in out


def test_the_scheduler_heartbeat_is_still_recorded_when_a_handler_fails(api, monkeypatch):
    from sqlalchemy import select
    from app.models.jobs import WorkerHeartbeat
    monkeypatch.setitem(engine.HANDLERS, "zz_boom", SimpleNamespace(schedule=lambda db: 1 / 0))
    with SessionLocal() as db:
        engine.scheduler_tick(db)
        assert db.scalar(select(WorkerHeartbeat).where(WorkerHeartbeat.name == "scheduler")) is not None


def test_handlers_without_a_schedule_are_skipped(api, monkeypatch):
    monkeypatch.setitem(engine.HANDLERS, "zz_plain", SimpleNamespace())
    with SessionLocal() as db:
        engine.scheduler_tick(db)
