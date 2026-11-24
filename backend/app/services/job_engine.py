"""Shared durable execution kernel. Handlers register policy/result processing."""
from datetime import timedelta
from uuid import uuid4
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from app.core.time import as_utc, utc_now
from app.models.jobs import Job, JobAttempt, JobResult, ExecutionEvent, WorkerHeartbeat, ExecutionSlot


def event(db, action, job=None, resource_id=None, actor_id=None, detail=None):
    db.add(ExecutionEvent(id=str(uuid4()), job_id=job.id if job else None,
        resource_id=job.resource_id if job else resource_id, actor_id=actor_id,
        action=action, detail=detail or {}, occurred_at=utc_now()))


def heartbeat(db, name):
    # Savepoint isolates a concurrent first heartbeat without losing queued jobs.
    changed = db.execute(update(WorkerHeartbeat).where(WorkerHeartbeat.name == name).values(seen_at=utc_now()))
    if changed.rowcount == 0:
        try:
            with db.begin_nested():
                db.add(WorkerHeartbeat(name=name, seen_at=utc_now())); db.flush()
        except IntegrityError:
            db.execute(update(WorkerHeartbeat).where(WorkerHeartbeat.name == name).values(seen_at=utc_now()))


def enqueue(db, kind, resource_id, revision, key, now=None):
    now = now or utc_now()
    if kind not in HANDLERS: raise ValueError("Unregistered job type")
    job = Job(id=str(uuid4()), job_type=kind, resource_id=resource_id, revision=revision,
        idempotency_key=key, status="queued", due_at=now, created_at=now, attempts=0, max_attempts=2)
    db.add(job); db.flush(); event(db, "queued", job)
    return job


def claim(db, kind, now=None):
    now = now or utc_now()
    if kind not in HANDLERS: raise ValueError("Unregistered job type")
    # Lease expiration is an execution failure, not evidence of website downtime.
    expired = list(db.scalars(select(Job).where(Job.job_type == kind, Job.status == "running", Job.lease_until <= now)))
    for job in expired:
        changed = db.execute(update(Job).where(Job.id == job.id, Job.status == "running", Job.claim_token == job.claim_token,
            Job.lease_until <= now).values(status="failed", completed_at=now, claim_token=None).execution_options(synchronize_session=False))
        if changed.rowcount:
            db.execute(update(JobAttempt).where(JobAttempt.job_id == job.id, JobAttempt.outcome == "running").values(outcome="lease_expired", ended_at=now))
            event(db, "lease_expired", job)
    db.commit()
    candidate = db.scalar(select(Job).where(Job.job_type == kind, Job.status == "queued", Job.due_at <= now).order_by(Job.due_at, Job.id).limit(1))
    if candidate is None: return None
    token = str(uuid4())
    lease = timedelta(seconds=lease_seconds(kind))
    # Initial execution policy: one active job per handler pool and at least
    # five seconds between completed probes, enforced across worker processes.
    if db.get(ExecutionSlot, kind) is None:
        try:
            db.add(ExecutionSlot(job_type=kind, available_at=now)); db.flush()
        except IntegrityError:
            db.rollback(); return None
    acquired = db.execute(update(ExecutionSlot).where(ExecutionSlot.job_type == kind,
        ExecutionSlot.available_at <= now).values(token=token, available_at=now + lease).execution_options(synchronize_session=False))
    if acquired.rowcount != 1: db.rollback(); return None
    changed = db.execute(update(Job).where(Job.id == candidate.id, Job.status == "queued", Job.due_at <= now).values(
        status="running", claim_token=token, lease_until=now + lease, attempts=Job.attempts + 1
    ).execution_options(synchronize_session=False))
    if changed.rowcount != 1: db.rollback(); return None
    db.refresh(candidate)
    db.add(JobAttempt(id=str(uuid4()), job_id=candidate.id, number=candidate.attempts,
        claim_token=token, started_at=now, outcome="running"))
    event(db, "claimed", candidate, detail={"attempt": candidate.attempts})
    db.commit(); return candidate.id, token


def release(db, kind, token, now=None):
    db.execute(update(ExecutionSlot).where(ExecutionSlot.job_type == kind, ExecutionSlot.token == token).values(
        token=None, available_at=(now or utc_now()) + timedelta(seconds=5)).execution_options(synchronize_session=False))


def finish(db, job_id, token, payload, now=None):
    provided_now = now
    now = now or utc_now(); db.expire_all()
    job = db.get(Job, job_id)
    if not job or job.status != "running" or job.claim_token != token or as_utc(job.lease_until) <= now:
        if job: release(db, job.job_type, token, now)
        db.commit(); return False
    handler = HANDLERS[job.job_type]
    if not handler.eligible(db, job, lock=True): payload = {"state": "cancelled", "error": "permission_or_configuration_changed"}
    now = provided_now or utc_now()
    if as_utc(job.lease_until) <= now:
        release(db, job.job_type, token, now); db.commit(); return False
    retry = payload["state"] == "down" and job.attempts < job.max_attempts
    status = "queued" if retry else "cancelled" if payload["state"] == "cancelled" else "failed" if payload["state"] == "failed" else "completed"
    changed = db.execute(update(Job).where(Job.id == job_id, Job.status == "running", Job.claim_token == token,
        Job.lease_until > now).values(status=status, claim_token=None, lease_until=None,
        due_at=now + timedelta(seconds=5) if retry else job.due_at,
        completed_at=None if retry else now).execution_options(synchronize_session=False))
    if changed.rowcount != 1: db.rollback(); return False
    db.execute(update(JobAttempt).where(JobAttempt.job_id == job_id, JobAttempt.claim_token == token).values(
        ended_at=now, outcome="retry_scheduled" if retry else payload["state"]))
    event(db, "retry_scheduled" if retry else status, job, detail=payload)
    if not retry:
        db.add(JobResult(job_id=job.id, recorded_at=now, payload=payload))
        if payload["state"] != "cancelled": handler.process(db, job, payload, now)
    release(db, job.job_type, token, now)
    db.commit(); return True


HANDLERS = {}
DEFAULT_LEASE_SECONDS = 60


def lease_seconds(kind):
    # Handlers with longer bounded execution budgets declare a longer lease.
    return int(getattr(HANDLERS[kind], "lease_seconds", DEFAULT_LEASE_SECONDS))


def scheduler_tick(db):
    heartbeat(db, "scheduler"); db.commit()
    for handler in HANDLERS.values():
        schedule = getattr(handler, "schedule", None)
        if schedule is not None: schedule(db)


def register(name, handler):
    if name in HANDLERS and HANDLERS[name] is not handler: raise ValueError("Handler already registered")
    HANDLERS[name] = handler
