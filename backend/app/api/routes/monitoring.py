from datetime import datetime
from uuid import uuid4
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, ConfigDict, field_validator
from sqlalchemy import select, update, func
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.core.security import get_current_admin
from app.core.time import as_utc, utc_now
from app.db.session import get_db
from app.models.admin import Admin
from app.models.website import Website
from app.models.monitoring import MonitoringConfig, MonitoringConsent, MonitoringIncident, NotificationDelivery
from app.models.jobs import Job, JobResult, JobAttempt, ExecutionEvent, WorkerHeartbeat
from app.services import monitoring as service
from app.services import job_engine as engine
from app.services.monitor_probe import target

router = APIRouter(tags=["Monitoring"], dependencies=[Depends(get_current_admin)])


class Configuration(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    evidence_id: str
    consent_reference: str = Field(min_length=10, max_length=150)
    monitoring_permission_reviewed: Literal[True]
    expires_at: datetime
    interval_seconds: Literal[60, 300, 900, 3600] = 300
    timeout_seconds: int = Field(default=10, ge=2, le=20)
    failure_threshold: int = Field(default=2, ge=1, le=5)
    recovery_threshold: int = Field(default=1, ge=1, le=5)

    @field_validator("expires_at")
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None: raise ValueError("Include a timezone")
        return as_utc(value)


def serial(row):
    return {column.name: as_utc(value).isoformat() if isinstance(value, datetime) else value
            for column in row.__table__.columns if column.name != "claim_token" for value in [getattr(row, column.name)]}


def site(db, key):
    row = db.get(Website, key)
    if not row: raise HTTPException(404, "Website not found")
    return row


def configuration(db, key):
    site(db, key); config = db.get(MonitoringConfig, key)
    if not config: raise HTTPException(404, "Configure monitoring and permission first")
    return config


@router.get("/monitoring/overview")
def overview(db: Session = Depends(get_db)):
    now = utc_now(); rows = []
    for website in db.scalars(select(Website).order_by(Website.id)):
        config = db.get(MonitoringConfig, website.id)
        result = db.execute(select(JobResult, Job).join(Job, JobResult.job_id == Job.id).where(
            Job.job_type == "monitoring", Job.resource_id == website.id).order_by(JobResult.recorded_at.desc()).limit(1)).first()
        last = serial(result[0]) if result else None
        stale = bool(config and (not result or (now - as_utc(result[0].recorded_at)).total_seconds() > config.interval_seconds * 2 + 30))
        state = "not_configured" if not config else "blocked" if config.state == "blocked" else "disabled" if not config.enabled else "blocked" if not service.permission(db, config) else "stale" if stale else config.state
        rows.append({"website_id": website.id, "name": website.name, "url": website.url,
            "config": serial(config) if config else None, "state": state, "latest": last,
            "consent": serial(db.get(MonitoringConsent, config.consent_id)) if config else None})
    return {"as_of": now.isoformat(), "websites": rows, "workers": [serial(x) for x in db.scalars(select(WorkerHeartbeat))]}


@router.get("/websites/{website_id}/monitoring")
def read_configuration(website_id: int, db: Session = Depends(get_db)):
    config = configuration(db, website_id)
    return {"config": serial(config), "consent": serial(db.get(MonitoringConsent, config.consent_id))}


@router.post("/websites/{website_id}/monitoring/configure")
def configure(website_id: int, payload: Configuration, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    website = site(db, website_id)
    try: target(website.url)
    except ValueError: raise HTTPException(422, "Monitoring supports HTTP/HTTPS on standard ports without credentials")
    now = utc_now()
    if payload.expires_at <= now: raise HTTPException(422, "Monitoring consent must expire in the future")
    evidence = service.reviewed_document(db, website.id, payload.evidence_id, admin.id)
    if payload.expires_at > as_utc(evidence.retain_until):
        raise HTTPException(422, "Consent cannot outlive evidence retention")
    consent = MonitoringConsent(id=str(uuid4()), website_id=website.id, evidence_id=evidence.id,
        reference=payload.consent_reference, url=website.url, reviewed_by=admin.id,
        created_at=now, expires_at=payload.expires_at)
    db.add(consent); db.flush()
    config = db.get(MonitoringConfig, website.id)
    if config:
        revision = config.revision
        changed = db.execute(update(MonitoringConfig).where(MonitoringConfig.website_id == website.id,
            MonitoringConfig.revision == revision).values(enabled=False, revision=revision+1,
                consent_id=consent.id, interval_seconds=payload.interval_seconds, timeout_seconds=payload.timeout_seconds,
                failure_threshold=payload.failure_threshold, recovery_threshold=payload.recovery_threshold,
                state="unknown", failures=0, successes=0, next_due=now).execution_options(synchronize_session=False))
        if changed.rowcount != 1: db.rollback(); raise HTTPException(409, "Configuration changed; refresh")
        service.cancel_pending(db, website.id, admin.id)
    else:
        config = MonitoringConfig(website_id=website.id, consent_id=consent.id, enabled=False, revision=1,
            interval_seconds=payload.interval_seconds, timeout_seconds=payload.timeout_seconds,
            failure_threshold=payload.failure_threshold, recovery_threshold=payload.recovery_threshold,
            next_due=now, state="unknown", failures=0, successes=0)
        try:
            db.add(config); db.flush()
        except IntegrityError:
            db.rollback(); raise HTTPException(409, "Configuration was created concurrently; refresh")
    engine.event(db, "monitoring_configured_disabled", resource_id=website.id, actor_id=admin.id,
        detail={"consent_id": consent.id, "interval_seconds": payload.interval_seconds})
    db.commit(); db.refresh(config); return serial(config)


@router.post("/websites/{website_id}/monitoring/{action}")
def manage(website_id: int, action: Literal["enable", "disable", "check-now", "revoke-consent"],
           db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    config = configuration(db, website_id); now = utc_now()
    if action in {"enable", "check-now"} and not service.permission(db, config, verify_file=True):
        raise HTTPException(409, "Monitoring consent or evidence is invalid")
    if action == "check-now":
        job = service.enqueue_due(db, config, manual=True, actor_id=admin.id)
        if not job: raise HTTPException(429, "Enable monitoring and wait for the current job or 60-second cooldown")
        db.commit(); return {"job_id": job.id, "status": "queued"}
    if action == "enable" and config.enabled: return serial(config)
    revision = config.revision
    changed = db.execute(update(MonitoringConfig).where(MonitoringConfig.website_id == website_id,
        MonitoringConfig.revision == revision).values(enabled=action == "enable", revision=revision+1,
            next_due=now, state="unknown" if action == "enable" else "disabled").execution_options(synchronize_session=False))
    if changed.rowcount != 1: db.rollback(); raise HTTPException(409, "Configuration changed; refresh")
    if action == "revoke-consent": db.get(MonitoringConsent, config.consent_id).revoked_at = now
    if action != "enable": service.cancel_pending(db, website_id, admin.id)
    engine.event(db, "monitoring_" + action, resource_id=website_id, actor_id=admin.id)
    db.commit(); db.refresh(config); return serial(config)


@router.get("/websites/{website_id}/monitoring/{collection}")
def history(website_id: int, collection: Literal["results", "jobs", "attempts", "incidents", "events", "notifications", "consents"],
            limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0), db: Session = Depends(get_db)):
    site(db, website_id)
    if collection == "results":
        statement = select(JobResult).join(Job, JobResult.job_id == Job.id).where(Job.job_type == "monitoring", Job.resource_id == website_id).order_by(JobResult.recorded_at.desc())
    elif collection == "attempts":
        statement = select(JobAttempt).join(Job, JobAttempt.job_id == Job.id).where(Job.job_type == "monitoring", Job.resource_id == website_id).order_by(JobAttempt.started_at.desc())
    elif collection == "jobs": statement = select(Job).where(Job.job_type == "monitoring", Job.resource_id == website_id).order_by(Job.created_at.desc())
    elif collection == "incidents": statement = select(MonitoringIncident).where(MonitoringIncident.website_id == website_id).order_by(MonitoringIncident.opened_at.desc())
    elif collection == "events": statement = select(ExecutionEvent).where(ExecutionEvent.resource_id == website_id).order_by(ExecutionEvent.occurred_at.desc())
    elif collection == "consents": statement = select(MonitoringConsent).where(MonitoringConsent.website_id == website_id).order_by(MonitoringConsent.created_at.desc())
    else: statement = select(NotificationDelivery).where(NotificationDelivery.website_id == website_id).order_by(NotificationDelivery.created_at.desc())
    return [serial(row) for row in db.scalars(statement.offset(offset).limit(limit))]


@router.post("/monitoring/stop")
def stop_all(db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    for config in db.scalars(select(MonitoringConfig)):
        config.enabled = False; config.revision += 1; config.state = "disabled"
        service.cancel_pending(db, config.website_id, admin.id)
    engine.event(db, "all_monitoring_stopped", actor_id=admin.id)
    db.commit(); return {"stopped": True}
