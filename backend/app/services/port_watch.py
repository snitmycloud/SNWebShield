"""Port watch (Option A): explicitly enabled, recurring TCP 80/443 state checks.

Nothing here scans by itself. An administrator or lead analyst enables port watch for one website, with a
written-permission attestation. From then on the scheduler asks for an ordinary Nmap assessment through
`assessments.create_request`, exactly as a person would, so live authorisation, evidence, UTC dates, exact
domain, `tcp_port_discovery`, the approved public IPv4 and the explicit-confirmation record are all
re-checked at request time, again at claim, and again immediately before execution by the worker, which runs
the scan on the VM under the existing isolation. A failed check blocks the watch and writes an audit event;
it never falls back or scans anyway. Results are compared with the last known state and every change is
stored append-only, audited and queued for notification. A change is an observation, not a vulnerability.
"""
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, OperationalError

from app.core.config import settings
from app.core.time import as_utc, utc_now
from app.models.assessment import AssessmentReport, AssessmentRequest
from app.models.jobs import Job
from app.models.monitoring import NotificationDelivery
from app.models.port_watch import PortWatch, PortWatchChange
from app.models.website import Website
from app.services import assessments, job_engine as engine

MIN_INTERVAL_SECONDS, DEFAULT_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS = 3600, 21600, 604800
RETRY_SECONDS = 600  # when a run is postponed (another assessment is active, or rate-limited)
PORTS = ("80", "443")
STATES = {"open", "closed", "filtered"}
BATCH = 10


def states_of(content):
    """Extract {"80": state, "443": state} from a stored Nmap report, or None when it is not exactly that."""
    try:
        found = {item["check"].removeprefix("tcp_port_"): item["port_state"]
                 for item in content["analysis"]["observations"] if item["check"] in ("tcp_port_80", "tcp_port_443")}
    except (KeyError, TypeError, AttributeError):
        return None
    return found if set(found) == set(PORTS) and all(v in STATES for v in found.values()) else None


def diff(previous, current):
    return [{"port": port, "from": previous.get(port), "to": current[port]} for port in PORTS if previous.get(port) != current[port]]


def _nmap_readiness(db, actor_id, website_id):
    return next(p for p in assessments.readiness(db, actor_id, website_id) if p["profile_id"] == assessments.NMAP_PROFILE_ID)


def _watch_or_none(db, website_id):
    return db.get(PortWatch, website_id)


def _serial_change(change):
    return {"id": change.id, "assessment_id": change.assessment_id, "detected_at": as_utc(change.detected_at).isoformat(),
            "previous": change.previous, "current": change.current, "changes": change.changes}


def describe(db, website_id, actor_id):
    """Everything the page needs for one website. Read-only and network-free."""
    if db.get(Website, website_id) is None:
        raise HTTPException(404, "Website not found")
    watch = _watch_or_none(db, website_id)
    ready = _nmap_readiness(db, actor_id, website_id)
    changes = list(db.scalars(select(PortWatchChange).where(PortWatchChange.website_id == website_id)
                              .order_by(PortWatchChange.detected_at.desc()).limit(20)))
    iso = lambda v: as_utc(v).isoformat() if v is not None else None
    return {"website_id": website_id, "configured": watch is not None, "enabled": bool(watch and watch.enabled),
            "state": watch.state if watch else None,
            "blocked_reason": watch.blocked_reason if watch else None,
            "blocked_reason_text": assessments.DENIAL_TEXT.get(watch.blocked_reason, watch.blocked_reason) if watch and watch.blocked_reason else None,
            "interval_seconds": watch.interval_seconds if watch else DEFAULT_INTERVAL_SECONDS,
            "next_due": iso(watch.next_due) if watch else None, "last_requested_at": iso(watch.last_requested_at) if watch else None,
            "last_checked_at": iso(watch.last_checked_at) if watch else None, "last_outcome": watch.last_outcome if watch else None,
            "last_assessment_id": watch.last_assessment_id if watch else None, "baseline": watch.baseline if watch else None,
            "enabled_by": watch.enabled_by if watch else None, "enabled_at": iso(watch.enabled_at) if watch else None,
            "can_enable": ready["ready"], "cannot_enable_reason": None if ready["ready"] else ready["reason"],
            "min_interval_seconds": MIN_INTERVAL_SECONDS, "max_interval_seconds": MAX_INTERVAL_SECONDS,
            "changes": [_serial_change(c) for c in changes]}


def enable(db, actor_id, website_id, interval_seconds):
    """The explicit act that permits recurring checks. Refused unless a real Nmap assessment would be allowed now."""
    if db.get(Website, website_id) is None:
        raise HTTPException(404, "Website not found")
    if not MIN_INTERVAL_SECONDS <= interval_seconds <= MAX_INTERVAL_SECONDS:
        raise HTTPException(422, f"Interval must be between {MIN_INTERVAL_SECONDS} and {MAX_INTERVAL_SECONDS} seconds")
    ready = _nmap_readiness(db, actor_id, website_id)
    if not ready["ready"]:
        raise HTTPException(409, "Port watch cannot be enabled: " + (ready["reason"] or "permission is not valid"))
    now = utc_now()
    watch = _watch_or_none(db, website_id)
    if watch is None:
        db.add(PortWatch(website_id=website_id, enabled=True, interval_seconds=interval_seconds, enabled_by=actor_id,
                         enabled_at=now, state="active", blocked_reason=None, next_due=now, revision=1))
    else:
        # Re-enabling starts a fresh baseline: the first run only records the state, it never alerts.
        watch.enabled, watch.interval_seconds, watch.enabled_by, watch.enabled_at = True, interval_seconds, actor_id, now
        watch.state, watch.blocked_reason, watch.next_due, watch.revision = "active", None, now, watch.revision + 1
        watch.baseline = watch.last_outcome = watch.last_assessment_id = watch.last_recorded_assessment_id = None
    engine.event(db, "port_watch_enabled", resource_id=website_id, actor_id=actor_id,
                 detail={"interval_seconds": interval_seconds, "authorization_id": ready["authorization_id"]})
    try:
        db.commit()
    except (IntegrityError, OperationalError) as error:
        db.rollback()
        raise HTTPException(409, "Port watch changed concurrently; refresh") from error
    return describe(db, website_id, actor_id)


def disable(db, actor_id, website_id, reason):
    watch = _watch_or_none(db, website_id)
    if watch is None or not watch.enabled:
        raise HTTPException(409, "Port watch is not enabled for this website")
    watch.enabled, watch.state, watch.blocked_reason = False, "paused", None
    engine.event(db, "port_watch_disabled", resource_id=website_id, actor_id=actor_id, detail={"reason": reason[:500]})
    db.commit()
    return describe(db, website_id, actor_id)


# --- Scheduling ------------------------------------------------------------------------------------

def _active_assessment(db, website_id):
    return db.scalar(select(Job.id).join(AssessmentRequest, AssessmentRequest.job_id == Job.id).where(
        AssessmentRequest.website_id == website_id, Job.job_type == "assessment",
        Job.status.in_(["queued", "running"])).limit(1)) is not None


def _block(db, watch, code, now):
    changed = watch.state != "blocked" or watch.blocked_reason != code
    watch.state, watch.blocked_reason = "blocked", code
    watch.next_due = now + timedelta(seconds=watch.interval_seconds)  # re-checked, network-free, at the next slot
    if changed:
        engine.event(db, "port_watch_blocked", resource_id=watch.website_id, actor_id=watch.enabled_by, detail={"reason": code})
    db.commit()


def _request(db, watch, now):
    reconcile_one(db, watch)
    if _active_assessment(db, watch.website_id):
        watch.next_due = now + timedelta(seconds=RETRY_SECONDS)
        db.commit()
        return
    ready = _nmap_readiness(db, watch.enabled_by, watch.website_id)
    if not ready["ready"]:
        _block(db, watch, ready["reason_code"] or "permission_not_valid", now)
        return
    # Stable across a crash and retry: the same slot can never queue two scans.
    key = f"portwatch:{watch.website_id}:{watch.revision}:{as_utc(watch.next_due).isoformat()}"
    website_id, interval, actor = watch.website_id, watch.interval_seconds, watch.enabled_by
    try:
        row = assessments.create_request(db, actor, SimpleNamespace(
            website_id=website_id, authorization_id=ready["authorization_id"], profile_id=assessments.NMAP_PROFILE_ID,
            idempotency_key=key, note="Scheduled port watch of TCP 80 and 443 (explicitly enabled).",
            network_permission_confirmed=True))
    except HTTPException as error:
        db.rollback()
        watch = db.get(PortWatch, website_id)
        detail = str(error.detail)
        if error.status_code == 429 or "already has a pending" in detail or "concurrently" in detail:
            watch.next_due = now + timedelta(seconds=RETRY_SECONDS)
            db.commit()
        else:
            _block(db, watch, detail.removeprefix("Assessment blocked: ")[:80], now)
        return
    watch = db.get(PortWatch, website_id)
    watch.last_requested_at, watch.last_assessment_id = now, row.id
    watch.state, watch.blocked_reason = "active", None
    watch.next_due = now + timedelta(seconds=interval)
    engine.event(db, "port_watch_requested", resource_id=website_id, actor_id=actor, detail={"assessment_id": row.id})
    db.commit()


def schedule(db, now=None):
    """Scheduler hook (every tick): request the next run for each due watch. Cheap when nothing is due."""
    now = now or utc_now()
    due = list(db.scalars(select(PortWatch.website_id).where(PortWatch.enabled.is_(True), PortWatch.next_due <= now)
                          .order_by(PortWatch.next_due).limit(BATCH)))
    for website_id in due:
        try:
            watch = db.get(PortWatch, website_id)
            if watch is not None and watch.enabled:
                _request(db, watch, now)
        except Exception:
            db.rollback()  # one website's failure must not stop the others; the next tick retries
            engine.event(db, "port_watch_schedule_failed", resource_id=website_id)
            db.commit()


# --- Results ---------------------------------------------------------------------------------------

def record_result(db, assessment_id):
    """Compare a completed run with the last known state. Idempotent and safe to repeat after a crash."""
    watch = db.scalar(select(PortWatch).where(PortWatch.last_assessment_id == assessment_id))
    if watch is None or watch.last_recorded_assessment_id == assessment_id:
        return None
    request = db.get(AssessmentRequest, assessment_id)
    job = db.get(Job, request.job_id) if request else None
    if job is None or job.status != "completed":
        return None
    report = db.scalar(select(AssessmentReport).where(AssessmentReport.assessment_id == assessment_id))
    current = states_of(report.content) if report else None
    now = utc_now()
    website_id = watch.website_id
    if current is None:
        outcome = "invalid_report"
    elif watch.baseline is None:
        outcome = "baseline"
    else:
        changes = diff(watch.baseline, current)
        outcome = "changed" if changes else "unchanged"
        if changes:
            db.add(PortWatchChange(id=str(uuid4()), website_id=website_id, assessment_id=assessment_id, detected_at=now,
                                   previous=watch.baseline, current=current, changes=changes))
            db.add(NotificationDelivery(id=str(uuid4()), dedupe_key=f"port_state_changed:{assessment_id}", website_id=website_id,
                                        event="port_state_changed", created_at=now, next_due=now, status="pending", attempts=0))
            engine.event(db, "port_state_changed", job, actor_id=None,
                         detail={"assessment_id": assessment_id, "changes": changes})
    if current is not None:
        watch.baseline = current
    watch.last_recorded_assessment_id, watch.last_outcome = assessment_id, outcome
    watch.last_checked_at = as_utc(job.completed_at) if job.completed_at else now
    engine.event(db, "port_watch_recorded", job, detail={"assessment_id": assessment_id, "outcome": outcome})
    try:
        db.commit()
    except (IntegrityError, OperationalError):
        db.rollback()  # another process recorded it first
        return None
    return outcome


def reconcile_one(db, watch):
    """Settle the previous run: record a completed one, note a failed one. Idempotent."""
    last = watch.last_assessment_id
    if not last or watch.last_recorded_assessment_id == last:
        return
    request = db.get(AssessmentRequest, last)
    job = db.get(Job, request.job_id) if request else None
    if job is None:
        return
    if job.status == "completed":
        record_result(db, last)
    elif job.status in ("failed", "cancelled"):
        watch.last_recorded_assessment_id, watch.last_outcome = last, "failed"
        watch.last_checked_at = as_utc(job.completed_at) if job.completed_at else utc_now()
        engine.event(db, "port_watch_run_failed", job, detail={"assessment_id": last, "status": job.status})
        db.commit()


def record_after_assessment(assessment_id):
    """Worker hook after a Nmap run completes. Failure never affects the stored scanner result."""
    from app.db.session import SessionLocal
    with SessionLocal() as db:
        try:
            record_result(db, assessment_id)
        except Exception:
            db.rollback()
            engine.event(db, "port_watch_record_failed", detail={"assessment_id": assessment_id})
            db.commit()


def reconcile_pending(limit=50):
    """Worker startup: settle runs whose result was stored but not compared because the worker died first."""
    from app.db.session import SessionLocal
    with SessionLocal() as db:
        for website_id in list(db.scalars(select(PortWatch.website_id).where(PortWatch.last_assessment_id.is_not(None)).limit(limit))):
            watch = db.get(PortWatch, website_id)
            try:
                reconcile_one(db, watch)
            except Exception:
                db.rollback()
