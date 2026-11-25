"""Legacy (analyst-era) assessment records: read-only since Phase 1.

The written-permission gate that used to authorise these runs was removed, so no legacy assessment can be
requested or executed any more: `AssessmentHandler.eligible` refuses every job, and a queued legacy job is
cancelled when the assessment worker next sees it. Past requests, reports and events stay readable.
Self-service scans live in `services/scans.py`. This module is deleted once Phases 2-4 replace it.
"""
from hashlib import sha256
from datetime import timedelta
import json
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select, update

from app.core.time import as_utc, utc_now
from app.models.assessment import AssessmentRequest, AssessmentReport
from app.models.jobs import Job, JobAttempt
from app.services import job_engine as engine

PROFILE_ID = "authorization-preflight-v1"
PROFILES = {
    PROFILE_ID: {
        "id": PROFILE_ID,
        "name": "Non-intrusive assessment permission preflight",
        "version": 1,
        "mode": "policy_only",
        "required_methods": ["automated_non_intrusive_scanning"],
        "network_execution": False,
        "description": "Validate permission for a future non-intrusive assessment. No tool or network execution.",
    }
}

HTTP_PROFILE_ID = "local-http-headers-v1"
PROFILES[HTTP_PROFILE_ID] = {
    "id":HTTP_PROFILE_ID, "name":"Local HTTP header observations", "version":1,
    "mode":"local_http", "required_methods":["automated_non_intrusive_scanning"],
    "network_execution":True, "request_budget":1, "redirect_budget":0, "body_byte_limit":0,
    "adapter":"local-python-v1", "timeout_seconds":10,
}

REMOTE_PROFILE_ID = "remote-docker-headers-v1"
PROFILES[REMOTE_PROFILE_ID] = {
    "id": REMOTE_PROFILE_ID, "name": "HTTP headers · Azure Docker analysis", "version": 1,
    "mode": "remote_docker", "required_methods": ["automated_non_intrusive_scanning"],
    "network_execution": True, "request_budget": 1, "redirect_budget": 0, "body_byte_limit": 0,
    "adapter": "ssh-docker-headers-v1", "timeout_seconds": 55,
}

NMAP_PROFILE_ID = "remote-nmap-web-ports-v1"
PROFILES[NMAP_PROFILE_ID] = {
    "id": NMAP_PROFILE_ID, "name": "Nmap · restricted TCP ports 80 and 443", "version": 1,
    "mode": "remote_nmap", "required_methods": ["automated_non_intrusive_scanning", "tcp_port_discovery"],
    "network_execution": True, "ports": [80, 443], "ip_version": 4,
    "adapter": "ssh-nmap-web-ports-v1", "timeout_seconds": 55,
    "description": "Two-port TCP connect discovery; no scripts, banners, OS detection or application requests.",
}
NETWORK_PROFILES = (HTTP_PROFILE_ID, REMOTE_PROFILE_ID, NMAP_PROFILE_ID)


def image_snapshot(profile_id):
    from app.core.config import settings
    if profile_id == REMOTE_PROFILE_ID: return {"image_id": settings.assessment_remote_image_id}
    if profile_id == NMAP_PROFILE_ID: return {"image_id": settings.assessment_nmap_image_id}
    return {}


def profile_available(selected):
    from app.core.config import settings
    if selected["id"] == REMOTE_PROFILE_ID:
        return settings.assessment_remote_docker_enabled and bool(settings.assessment_remote_image_id)
    if selected["id"] == NMAP_PROFILE_ID:
        return settings.assessment_nmap_enabled and bool(settings.assessment_nmap_image_id)
    return not selected["network_execution"] or settings.assessment_local_http_enabled


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Denied(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def profile(profile_id):
    value = PROFILES.get(profile_id)
    if value is None:
        raise Denied("profile_not_available")
    return value


def get_request(db, assessment_id):
    row = db.get(AssessmentRequest, assessment_id)
    if row is None:
        raise HTTPException(404, "Assessment request not found")
    return row


def cancel(db, row, actor_id, reason):
    job = db.get(Job, row.job_id)
    changed = db.execute(update(Job).where(Job.id == job.id, Job.job_type == "assessment",
        Job.status.in_(["queued", "running"])).values(status="cancelled", claim_token=None,
        lease_until=None, completed_at=utc_now()).execution_options(synchronize_session=False))
    if changed.rowcount:
        db.execute(update(JobAttempt).where(JobAttempt.job_id == job.id, JobAttempt.outcome == "running").values(
            outcome="cancelled", ended_at=utc_now()))
        engine.event(db, "assessment_cancelled", job, actor_id=actor_id, detail={"reason": reason})
    return bool(changed.rowcount)


class AssessmentHandler:
    # Remote stage budgets total ~55 s; the lease leaves margin for permission
    # polling and result recording. A lapsed lease is failure, never a retry.
    lease_seconds = 120

    @staticmethod
    def schedule(db):
        # Port watch (Nmap over Docker) is retired: nothing is scheduled any more.
        return None

    @staticmethod
    def eligible(db, job, lock=False):
        # The written-permission system this relied on was removed in Phase 1, so no legacy run may proceed.
        engine.event(db, "assessment_permission_denied", job, detail={"reason": "legacy_assessments_retired"})
        return False

    @staticmethod
    def process(db, job, payload, now):
        row = db.scalar(select(AssessmentRequest).where(AssessmentRequest.job_id == job.id))
        if row.profile_id not in NETWORK_PROFILES:
            if payload.get("mode") != "policy_only" or payload.get("network_execution") is not False:
                raise ValueError("Invalid preflight result")
            return
        if payload.get("state") != "up": return
        report = payload.get("report")
        if not isinstance(report,dict) or report.get("adapter") != profile(row.profile_id)["adapter"]:
            raise ValueError("Invalid assessment report")
        content={"assessment_id":row.id,"authorization_id":row.authorization_id,
            "profile_id":row.profile_id,"requested_by":row.requested_by,"permission_digest":row.permission_digest,
            "evidence":row.permission_snapshot["documents"],"recorded_at":as_utc(now).isoformat(),**report}
        data=report_bytes(content)
        if len(data)>32768: raise ValueError("Report too large")
        stored=AssessmentReport(id=str(uuid4()),assessment_id=row.id,created_at=now,
            content=content,sha256=sha256(data).hexdigest(),size=len(data))
        db.add(stored)
        engine.event(db,"assessment_report_recorded",job,detail={"report_id":stored.id,"sha256":stored.sha256})


def report_bytes(content):
    return json.dumps(content,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()


def recovery_state(job):
    """Explain a job that cannot progress. Read-only; the engine fails expired leases when a worker next polls."""
    if job is None: return None
    now = utc_now()
    if job.status == "running" and job.lease_until and as_utc(job.lease_until) <= now:
        return {"state": "lease_expired",
                "message": "The worker holding this run stopped or lost its lease. It will be marked failed (never "
                           "repeated automatically) when the assessment worker next runs. You can also cancel it now."}
    if job.status == "queued" and as_utc(job.created_at) <= now - timedelta(minutes=2):
        return {"state": "waiting_for_worker",
                "message": "Queued for over two minutes. Check that the assessment worker is running."}
    return None


def recover_on_start(limit=50):
    """Run once when the assessment worker starts.

    A process that dies after a result commits but before ingestion leaves a completed report that no
    observation has been created from. Ingestion is idempotent, so retry those now. Expired leases are
    failed by the engine's first claim; retests reconcile themselves from the job state on read.
    """
    from app.db.session import SessionLocal
    from app.services import vulnerabilities as vulns
    with SessionLocal() as db:
        assessments = []
        for report_id in vulns.pending_reports(db, limit=limit):
            report = db.get(AssessmentReport, report_id)
            if report and report.assessment_id not in assessments: assessments.append(report.assessment_id)
    for assessment_id in assessments:
        vulns.ingest_after_assessment(assessment_id)  # audits its own failures; never raises
    from app.services import port_watch
    port_watch.reconcile_pending()  # a run stored but never compared (worker died first)
    with SessionLocal() as db:
        engine.event(db, "worker_startup_recovery", detail={"assessments_checked": len(assessments)})
        db.commit()
    return len(assessments)


def still_permitted(job_id,token):
    from app.db.session import SessionLocal
    with SessionLocal() as db:
        job=db.get(Job,job_id)
        valid=bool(job and job.status=="running" and job.claim_token==token and job.lease_until
            and as_utc(job.lease_until)>utc_now() and AssessmentHandler.eligible(db,job))
        db.commit();return valid


def worker_tick():
    """Legacy assessments are retired: a leftover queued job is claimed only to be cancelled. No scanner runs."""
    from app.db.session import SessionLocal
    with SessionLocal() as db:
        engine.heartbeat(db, "assessment-worker"); db.commit()
        claimed = engine.claim(db, "assessment")
        if not claimed:
            return
        engine.finish(db, *claimed, {"state": "cancelled", "error": "legacy_assessments_retired"})

engine.register("assessment", AssessmentHandler)
