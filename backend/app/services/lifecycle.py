"""One read-only view of a website's security lifecycle: monitor, detect, validate, protect.

Pure aggregation of data that already exists. It performs no network request, schedules nothing and writes
nothing, so it is safe to call on every page view. Each pillar reports counts and the single next step that
would move the website forward, chosen by fixed rules (see `next_step`).
"""
from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from app.core.time import as_utc, utc_now
from app.models.assessment import AssessmentRequest
from app.models.client import Client
from app.models.jobs import Job, JobResult
from app.models.monitoring import MonitoringConfig
from app.models.port_watch import PortWatch, PortWatchChange
from app.models.remediation import BLOCKING_STATUSES, VulnerabilityRemediation
from app.models.report import VaptReport
from app.models.vulnerability import Vulnerability
from app.models.website import Website
from app.services import assessments, remediation
from app.services import monitoring as monitoring_service

VALIDATION_STATES = ("unconfirmed", "confirmed", "false_positive", "not_applicable")
ASSESSMENT_LABELS = {"queued": "Queued", "running": "Running", "completed": "Completed", "failed": "Failed", "cancelled": "Cancelled"}


def _monitor(db, website, now):
    config = db.get(MonitoringConfig, website.id)
    if config is None:
        return {"state": "not_configured", "enabled": False, "last_checked_at": None, "last_result": None}
    latest = db.execute(select(JobResult, Job).join(Job, JobResult.job_id == Job.id).where(
        Job.job_type == "monitoring", Job.resource_id == website.id).order_by(JobResult.recorded_at.desc()).limit(1)).first()
    stale = latest is None or (now - as_utc(latest[0].recorded_at)).total_seconds() > config.interval_seconds * 2 + 30
    state = ("blocked" if config.state == "blocked" else "disabled" if not config.enabled
             else "blocked" if not monitoring_service.permission(db, config) else "stale" if stale else config.state)
    payload = latest[0].payload if latest else {}
    return {"state": state, "enabled": bool(config.enabled), "interval_seconds": config.interval_seconds,
            "last_checked_at": as_utc(latest[0].recorded_at).isoformat() if latest else None,
            "last_result": payload.get("state") if isinstance(payload, dict) else None}


def _port_watch(db, website_id):
    """Summary of the explicitly enabled TCP 80/443 watch, or None when it was never configured."""
    try:
        watch = db.get(PortWatch, website_id)
    except OperationalError:
        db.rollback()  # migration 0015 not applied yet: the view still works, without port watch
        return None
    if watch is None:
        return None
    change = db.scalar(select(PortWatchChange).where(PortWatchChange.website_id == website_id)
                       .order_by(PortWatchChange.detected_at.desc()).limit(1))
    return {"enabled": bool(watch.enabled), "state": watch.state, "blocked_reason": watch.blocked_reason,
            "interval_seconds": watch.interval_seconds, "last_outcome": watch.last_outcome, "baseline": watch.baseline,
            "last_checked_at": as_utc(watch.last_checked_at).isoformat() if watch.last_checked_at else None,
            "latest_change": None if change is None else {
                "assessment_id": change.assessment_id, "detected_at": as_utc(change.detected_at).isoformat(), "changes": change.changes}}


def _detect(db, actor_id, website):
    latest = db.scalar(select(AssessmentRequest).where(AssessmentRequest.website_id == website.id)
                       .order_by(AssessmentRequest.requested_at.desc()).limit(1))
    job = db.get(Job, latest.job_id) if latest else None
    total = db.scalar(select(func.count()).select_from(AssessmentRequest).where(AssessmentRequest.website_id == website.id))
    # Legacy assessments are retired (Phase 1); new scans start from ownership verification on the Websites page.
    return {"total_assessments": total,
            "latest": None if latest is None else {
                "id": latest.id, "profile_id": latest.profile_id, "status": job.status if job else "unknown",
                "requested_at": as_utc(latest.requested_at).isoformat(),
                "completed_at": as_utc(job.completed_at).isoformat() if job and job.completed_at else None},
            "can_run": False, "ready_profiles": [],
            "blocked_reason": "Legacy assessments are read-only. Verify ownership on the Websites page to scan."}


def _validate(db, website):
    counts = {state: 0 for state in VALIDATION_STATES}
    for state, n in db.execute(select(Vulnerability.validation_state, func.count()).where(
            Vulnerability.website_id == website.id).group_by(Vulnerability.validation_state)):
        counts[state] = n
    return {**counts, "awaiting_review": counts["unconfirmed"], "total": sum(counts.values())}


def _protect(db, website):
    rows = db.execute(select(Vulnerability.id, func.coalesce(VulnerabilityRemediation.status, "open")).outerjoin(
        VulnerabilityRemediation, VulnerabilityRemediation.vulnerability_id == Vulnerability.id).where(
        Vulnerability.website_id == website.id, Vulnerability.validation_state == "confirmed")).all()
    counts = {}
    for _, status in rows:
        counts[status] = counts.get(status, 0) + 1
    awaiting_signoff = sum(1 for vid, status in rows if status == "verified_fixed"
                           and (lambda s: s["required"] and s["state"] != "confirmed")(remediation.fix_verification(db, vid)))
    report = db.scalar(select(VaptReport).where(VaptReport.website_id == website.id)
                       .order_by(VaptReport.created_at.desc()).limit(1))
    approved = db.scalar(select(func.count()).select_from(VaptReport).where(
        VaptReport.website_id == website.id, VaptReport.status == "approved"))
    return {"confirmed": len(rows), "status_counts": counts,
            "unresolved": sum(n for s, n in counts.items() if s in BLOCKING_STATUSES),
            "awaiting_signoff": awaiting_signoff, "approved_reports": approved,
            "latest_report": None if report is None else {"id": report.id, "status": report.status, "revision": report.revision}}


def next_step(monitor, detect, validate, protect):
    """The single most useful next action, from fixed rules in priority order."""
    latest = detect["latest"]
    if monitor["state"] == "not_configured":
        return {"code": "set_up_monitoring", "message": "Set up monitoring so uptime, DNS and certificate changes are watched."}
    if latest is None:
        if detect["can_run"]:
            return {"code": "run_assessment", "message": "Run the first authorised assessment."}
        return {"code": "fix_permission", "message": detect["blocked_reason"] or "Verify ownership on the Websites page."}
    if latest["status"] in ("queued", "running"):
        return {"code": "wait_for_assessment", "message": "An assessment is in progress. Check that the assessment worker is running."}
    watch = monitor.get("port_watch") or {}
    if watch.get("enabled") and watch.get("last_outcome") == "changed":
        ports = ", ".join(f"{c['port']} ({c['from']} to {c['to']})" for c in (watch.get("latest_change") or {}).get("changes", []))
        return {"code": "review_port_change", "message": f"Port state changed: TCP {ports}. Review the assessment's port observations and confirm the exposure is expected."}
    if validate["awaiting_review"]:
        return {"code": "review_findings", "message": f"{validate['awaiting_review']} observation(s) need analyst validation."}
    counts = protect["status_counts"]
    if counts.get("retest_requested"):
        return {"code": "wait_for_retest", "message": "A retest is running."}
    if counts.get("fix_submitted"):
        return {"code": "request_retest", "message": f"{counts['fix_submitted']} submitted fix(es) are ready to retest."}
    if counts.get("open") or counts.get("in_progress") or counts.get("reopened"):
        return {"code": "track_remediation", "message": f"{protect['unresolved']} confirmed finding(s) are waiting for a fix."}
    if protect["confirmed"] and not protect["approved_reports"]:
        return {"code": "generate_report", "message": "Generate and approve the security report."}
    if latest["status"] in ("failed", "cancelled"):
        if detect["can_run"]:
            return {"code": "run_assessment", "message": "The last assessment did not complete. Run it again."}
        return {"code": "fix_permission", "message": detect["blocked_reason"] or "The last assessment did not complete and permission is not valid."}
    return {"code": "all_clear", "message": "Nothing needs attention. Monitoring continues; run a new assessment when scope or code changes."}


def website_lifecycle(db, actor_id, website_id):
    website = db.get(Website, website_id)
    if website is None:
        raise HTTPException(404, "Website not found")
    now = utc_now()
    client = db.get(Client, website.client_id)
    monitor, detect = _monitor(db, website, now), _detect(db, actor_id, website)
    monitor["port_watch"] = _port_watch(db, website.id)
    validate, protect = _validate(db, website), _protect(db, website)
    return {"as_of": now.isoformat(),
            "website": {"id": website.id, "name": website.name, "url": website.url, "client": client.company_name if client else None},
            "monitor": monitor, "detect": detect, "validate": validate, "protect": protect,
            "next_step": next_step(monitor, detect, validate, protect)}
