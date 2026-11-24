"""Stuck-job recovery: what happens after a worker dies, hangs or restarts. Synthetic data, no target traffic.

A killed process leaves nothing but database state, so a crash is simulated by claiming a job and never
finishing it, and a restart by moving the clock past the lease and running a fresh worker tick.
"""
import threading
import time
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.cli import operations
from app.db.session import SessionLocal
from app.models.assessment import AssessmentReport
from app.models.jobs import ExecutionEvent, Job, JobAttempt, JobResult
from app.models.vulnerability import VulnerabilityIngestion, VulnerabilityOccurrence
from app.services import assessments as service, job_engine as engine, vulnerabilities as vulns
from app.services import local_assessment_runtime as runtime
from test_authorization_correctness import NOW, api  # noqa: F401
from test_assessments import assessed, create  # noqa: F401
from test_local_assessment import network  # noqa: F401
from test_vulnerabilities import run, records, ONLY_DISCLOSURE

LEASE = service.AssessmentHandler.lease_seconds


def at(monkeypatch, seconds):
    moment = NOW + timedelta(seconds=seconds)
    monkeypatch.setattr(service, "utc_now", lambda: moment)
    monkeypatch.setattr(engine, "utc_now", lambda: moment)


def crash_after_claim(assessed):
    """The worker claims the job, then its process is killed: no finish, no cleanup."""
    row = create(assessed)
    with SessionLocal() as db:
        claimed = engine.claim(db, "assessment")
        assert claimed and claimed[0] == row["job_id"]
    return row


def events(job_id, action):
    with SessionLocal() as db:
        return list(db.scalars(select(ExecutionEvent).where(ExecutionEvent.job_id == job_id, ExecutionEvent.action == action)))


def test_restarted_worker_fails_the_dead_run_once_and_never_repeats_it(assessed, monkeypatch):
    api, *_ = assessed
    row = crash_after_claim(assessed)
    at(monkeypatch, LEASE + 180)
    monkeypatch.setattr(runtime, "invoke", lambda *a, **k: pytest.fail("a dead run must never be executed again"))
    service.worker_tick()  # the restarted worker's first tick
    with SessionLocal() as db:
        job = db.get(Job, row["job_id"])
        assert job.status == "failed" and job.attempts == 1 and job.claim_token is None
        assert db.get(JobResult, row["job_id"]) is None  # no result is invented for a run nobody finished
        assert [a.outcome for a in db.scalars(select(JobAttempt).where(JobAttempt.job_id == row["job_id"]))] == ["lease_expired"]
    assert len(events(row["job_id"], "lease_expired")) == 1
    service.worker_tick(); service.worker_tick()  # further ticks change nothing
    assert len(events(row["job_id"], "lease_expired")) == 1
    assert api.get(f"/api/v1/assessments/{row['id']}").json()["job"]["status"] == "failed"


def test_website_is_usable_again_after_recovery(assessed, monkeypatch):
    api, _, _, _, body = assessed
    crash_after_claim(assessed)
    assert api.post("/api/v1/assessments", json={**body, "idempotency_key": str(uuid4())}).status_code == 409  # blocked while stuck
    at(monkeypatch, LEASE + 180)
    service.worker_tick()
    fresh = api.post("/api/v1/assessments", json={**body, "idempotency_key": str(uuid4())})
    assert fresh.status_code == 201, fresh.text
    service.worker_tick()  # the slot was released, so the new run completes normally
    assert api.get(f"/api/v1/assessments/{fresh.json()['id']}").json()["job"]["status"] == "completed"


def test_lease_not_yet_expired_is_left_alone(assessed, monkeypatch):
    row = crash_after_claim(assessed)
    at(monkeypatch, LEASE - 5)
    service.worker_tick()
    with SessionLocal() as db:
        assert db.get(Job, row["job_id"]).status == "running"  # the original worker may still be alive


def test_api_explains_a_stuck_run_before_and_after_recovery(assessed, monkeypatch):
    api, *_ = assessed
    row = crash_after_claim(assessed)
    get = lambda: api.get(f"/api/v1/assessments/{row['id']}").json()
    assert get()["recovery"] is None  # lease still valid
    at(monkeypatch, LEASE + 30)
    stuck = get()["recovery"]
    assert stuck["state"] == "lease_expired" and "cancel" in stuck["message"].lower()
    service.worker_tick()
    assert get()["recovery"] is None and get()["job"]["status"] == "failed"


def test_queued_job_with_no_worker_is_flagged_and_can_be_cancelled(assessed, monkeypatch):
    api, *_ = assessed
    row = create(assessed)
    assert api.get(f"/api/v1/assessments/{row['id']}").json()["recovery"] is None
    at(monkeypatch, 200)
    assert api.get(f"/api/v1/assessments/{row['id']}").json()["recovery"]["state"] == "waiting_for_worker"
    r = api.post(f"/api/v1/assessments/{row['id']}/cancel", json={"reason": "Worker is down, cancelling this request."})
    assert r.status_code == 200, r.text
    assert api.get(f"/api/v1/assessments/{row['id']}").json()["job"]["status"] == "cancelled"


def test_stuck_running_job_can_be_cancelled_without_a_worker(assessed, monkeypatch):
    api, *_ = assessed
    row = crash_after_claim(assessed)
    at(monkeypatch, LEASE + 30)
    r = api.post(f"/api/v1/assessments/{row['id']}/cancel", json={"reason": "Worker crashed; clearing the stuck request."})
    assert r.status_code == 200, r.text
    final = api.get(f"/api/v1/assessments/{row['id']}").json()
    assert final["job"]["status"] == "cancelled" and final["recovery"] is None


# --- Crash between a committed result and its ingestion ---------------------------------------------

def test_startup_recovery_ingests_a_result_the_crashed_worker_never_ingested(network, monkeypatch):
    api = network[0]
    original = vulns.ingest_after_assessment
    monkeypatch.setattr(vulns, "ingest_after_assessment", lambda assessment_id: None)  # process dies right here
    row = run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    assert records() == {}
    with SessionLocal() as db:
        assert vulns.pending_reports(db)  # completed, report stored, nothing ingested
    monkeypatch.setattr(vulns, "ingest_after_assessment", original)  # the restarted worker
    assert service.recover_on_start() == 1
    found = records()
    assert set(found) == set(vulns.CHECKS)
    assert all(v.validation_state == "unconfirmed" and v.detection_count == 1 for v in found.values())  # never auto-confirmed
    with SessionLocal() as db:
        assert not vulns.pending_reports(db)
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "worker_startup_recovery"))
    assert service.recover_on_start() == 0  # idempotent: nothing left, no duplicate occurrences
    with SessionLocal() as db:
        assert len(list(db.scalars(select(VulnerabilityOccurrence)))) == len(vulns.CHECKS)
        assert len(list(db.scalars(select(VulnerabilityIngestion)))) == 1
    assert row["id"]


def test_startup_recovery_survives_a_poison_report_and_audits_it(network, monkeypatch):
    original = vulns.ingest_after_assessment
    monkeypatch.setattr(vulns, "ingest_after_assessment", lambda assessment_id: None)
    run(network, monkeypatch, ONLY_DISCLOSURE, 0)
    with SessionLocal() as db:
        report = db.scalar(select(AssessmentReport)); report.sha256 = "0" * 64; db.commit()  # integrity failure
    monkeypatch.setattr(vulns, "ingest_after_assessment", original)
    assert service.recover_on_start() == 1  # does not raise and does not loop
    assert records() == {}  # a tampered report is never ingested
    with SessionLocal() as db:
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "vulnerability_ingestion_rejected"))
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "worker_startup_recovery"))


def test_startup_recovery_with_nothing_to_do_is_harmless(api):
    assert service.recover_on_start() == 0


# --- Heartbeat must reflect progress, not just a live process -------------------------------------------

def test_should_beat_only_while_the_main_loop_is_progressing():
    assert operations.should_beat(100.0, 110.0, 135) is True
    assert operations.should_beat(100.0, 235.0, 135) is True   # exactly at the limit
    assert operations.should_beat(100.0, 236.0, 135) is False  # hung beyond any legitimate job


def run_loop(monkeypatch, progress_age, limit=135):
    beats = []
    class FakeSession:
        def __enter__(self): return SimpleNamespace(commit=lambda: None)
        def __exit__(self, *exc): return False
    monkeypatch.setattr(operations, "SessionLocal", FakeSession)
    monkeypatch.setattr(operations.engine, "heartbeat", lambda db, name: beats.append(name))
    stop = threading.Event()
    progress = {"at": time.monotonic() - progress_age}
    worker = threading.Thread(target=operations._heartbeat_loop, args=("assessment-worker", stop, progress, limit, 0.01))
    worker.start(); time.sleep(0.15); stop.set(); worker.join(2)
    return beats


def test_heartbeat_thread_beats_while_the_worker_progresses(monkeypatch):
    assert run_loop(monkeypatch, progress_age=1)  # healthy, even mid-scan


def test_heartbeat_thread_goes_silent_when_the_worker_is_hung(monkeypatch):
    assert run_loop(monkeypatch, progress_age=1000) == []  # the dashboard will show stale, not a false "running"


def test_heartbeat_limit_exceeds_the_lease_so_a_legitimate_scan_never_looks_hung():
    limit = engine.lease_seconds("assessment") + 15
    assert limit > service.AssessmentHandler.lease_seconds
    from app.services import nmap_runtime, remote_assessment_runtime as remote
    assert max(nmap_runtime.WORST_CASE_SECONDS, remote.WORST_CASE_SECONDS) < service.AssessmentHandler.lease_seconds
