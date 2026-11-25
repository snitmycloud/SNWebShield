from datetime import timedelta
from uuid import uuid4
from fastapi import HTTPException
from sqlalchemy import select, update
from app.core.time import as_utc, utc_now
from app.models.website import Website
from app.models.jobs import Job, JobAttempt
from app.models.monitoring import MonitoringConfig, MonitoringConsent, MonitoringIncident, NotificationDelivery
from app.services import job_engine as engine


def permission(db, config, now=None, verify_file=False):
    """Legacy monitoring may keep running only while the website's ownership is verified (Phase 1).

    The written-permission evidence it used to require was removed; `verify_file` is ignored. New monitoring
    cannot be configured (the legacy routes are read-only); Phase 5 replaces this.
    """
    now = now or utc_now()
    if not config: return False
    consent = db.get(MonitoringConsent, config.consent_id)
    website = db.get(Website, config.website_id)
    if not consent or not website or consent.website_id != website.id or consent.revoked_at or as_utc(consent.expires_at) <= now or consent.url != website.url:
        return False
    return website.verification_status == "verified"


def cancel_pending(db, website_id, actor_id=None):
    rows = list(db.scalars(select(Job).where(Job.job_type == "monitoring", Job.resource_id == website_id,
        Job.status.in_(["queued", "running"]))))
    for job in rows:
        db.execute(update(Job).where(Job.id == job.id, Job.status.in_(["queued", "running"])).values(
            status="cancelled", claim_token=None, completed_at=utc_now()))
        db.execute(update(JobAttempt).where(JobAttempt.job_id == job.id, JobAttempt.outcome == "running").values(outcome="cancelled", ended_at=utc_now()))
        engine.event(db, "cancellation_requested", job, actor_id=actor_id)


def enqueue_due(db, config, *, manual=False, actor_id=None, now=None):
    now = now or utc_now()
    if not config.enabled or not permission(db, config, now): return None
    if config.last_enqueued_at and as_utc(config.last_enqueued_at) > now - timedelta(seconds=60): return None
    if db.scalar(select(Job.id).where(Job.job_type == "monitoring", Job.resource_id == config.website_id,
        Job.status.in_(["queued", "running"])).limit(1)): return None
    old_due, old_enqueued = config.next_due, config.last_enqueued_at
    changed = db.execute(update(MonitoringConfig).where(MonitoringConfig.website_id == config.website_id,
        MonitoringConfig.enabled.is_(True), MonitoringConfig.revision == config.revision,
        MonitoringConfig.next_due == old_due,
        MonitoringConfig.last_enqueued_at.is_(None) if old_enqueued is None else MonitoringConfig.last_enqueued_at == old_enqueued
    ).values(next_due=now + timedelta(seconds=config.interval_seconds), last_enqueued_at=now).execution_options(synchronize_session=False))
    if changed.rowcount != 1: return None
    key = f"monitoring:{config.website_id}:{config.revision}:{now.isoformat()}"
    job = engine.enqueue(db, "monitoring", config.website_id, config.revision, key, now)
    engine.event(db, "manual_check" if manual else "scheduled_check", job, actor_id=actor_id)
    return job


def scheduler_tick(db, now=None):
    now = now or utc_now(); engine.heartbeat(db, "scheduler")
    for config in list(db.scalars(select(MonitoringConfig).where(MonitoringConfig.enabled.is_(True), MonitoringConfig.next_due <= now).limit(100))):
        if not permission(db, config, now):
            config.enabled = False; config.revision += 1; config.state = "blocked"
            cancel_pending(db, config.website_id)
            engine.event(db, "monitoring_paused_permission", resource_id=config.website_id)
        else: enqueue_due(db, config, now=now)
    db.commit()


class MonitoringHandler:
    schedule = staticmethod(scheduler_tick)

    @staticmethod
    def eligible(db, job, lock=False, verify_file=True):
        config = db.get(MonitoringConfig, job.resource_id)
        if not config or not config.enabled or config.revision != job.revision: return False
        if lock:
            changed = db.execute(update(MonitoringConfig).where(MonitoringConfig.website_id == job.resource_id,
                MonitoringConfig.revision == job.revision, MonitoringConfig.enabled.is_(True)).values(
                    revision=job.revision).execution_options(synchronize_session=False))
            if changed.rowcount != 1: return False
            db.refresh(config)
        return permission(db, config, verify_file=verify_file)

    @staticmethod
    def process(db, job, payload, now):
        config = db.get(MonitoringConfig, job.resource_id)
        if payload["state"] == "blocked":
            config.state = "blocked"; config.enabled = False; config.revision += 1
            engine.event(db, "monitoring_paused_destination", job)
            return
        if payload["state"] == "unknown": config.state = "unknown"; return
        failed = payload["state"] in {"down", "degraded"}
        config.failures = config.failures + 1 if failed else 0
        config.successes = 0 if failed else config.successes + 1
        incident = db.scalar(select(MonitoringIncident).where(MonitoringIncident.website_id == config.website_id,
            MonitoringIncident.closed_at.is_(None)).limit(1))
        config.state = payload["state"]
        if failed and config.failures >= config.failure_threshold and not incident:
            incident = MonitoringIncident(id=str(uuid4()), website_id=config.website_id, opened_at=now, opening_job_id=job.id)
            db.add(incident); db.flush()
            notify(db, config.website_id, "incident_opened", incident.id, now)
        elif not failed and incident and config.successes >= config.recovery_threshold:
            incident.closed_at = now; incident.closing_job_id = job.id
            notify(db, config.website_id, "recovered", incident.id, now)


def notify(db, website_id, action, incident_id, now):
    db.add(NotificationDelivery(id=str(uuid4()), website_id=website_id,
        dedupe_key=f"{incident_id}:{action}", event=action, created_at=now, next_due=now, status="pending", attempts=0))


engine.register("monitoring", MonitoringHandler)
