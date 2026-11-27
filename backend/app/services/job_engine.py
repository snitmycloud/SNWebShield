"""Audit events and worker heartbeats shared by the scan worker, the monitor, the supervisor and the API.

(The earlier durable job queue of the removed analyst pipeline lived here too; its tables are kept, unused, in the database.)
"""
from uuid import uuid4

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from app.core.time import utc_now
from app.models.jobs import ExecutionEvent, WorkerHeartbeat


def event(db, action, job=None, resource_id=None, actor_id=None, detail=None):
    db.add(ExecutionEvent(id=str(uuid4()), job_id=job.id if job else None,
        resource_id=job.resource_id if job else resource_id, actor_id=actor_id,
        action=action, detail=detail or {}, occurred_at=utc_now()))


def heartbeat(db, name, detail=None):
    # Savepoint isolates a concurrent first heartbeat without losing queued work.
    values = {"seen_at": utc_now(), **({"detail": detail} if detail is not None else {})}
    changed = db.execute(update(WorkerHeartbeat).where(WorkerHeartbeat.name == name).values(**values))
    if changed.rowcount == 0:
        try:
            with db.begin_nested():
                db.add(WorkerHeartbeat(name=name, seen_at=utc_now(), detail=detail)); db.flush()
        except IntegrityError:
            db.execute(update(WorkerHeartbeat).where(WorkerHeartbeat.name == name).values(**values))
