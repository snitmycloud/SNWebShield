"""Explicit assessment intents and live authorisation for fixed local profiles."""
from hashlib import sha256
from datetime import timedelta
import ipaddress
import json
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.core.time import as_utc, utc_now
from app.models.admin import Admin
from app.models.client import Client
from app.models.assessment import AssessmentRequest, AssessmentReport
from app.models.authorization import WebsiteAuthorization
from app.models.authorization_audit_event import AuthorizationAuditEvent
from app.models.evidence import EvidenceReview
from app.models.jobs import Job, JobAttempt
from app.models.website import Website
from app.services import evidence, job_engine as engine
from app.services.monitor_probe import target

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


def permission(db, website_id, authorization_id, actor_id, profile_id, *, now=None, lock=False):
    """Check live permission, not a cached website flag or monitoring consent."""
    provided_now = now
    now = now or utc_now()
    selected = profile(profile_id)
    actor = db.get(Admin, actor_id)
    if not actor or not actor.is_active or actor.role != "admin":
        raise Denied("requester_not_active_administrator")
    website = db.get(Website, website_id)
    record = db.get(WebsiteAuthorization, authorization_id)
    if not website or not db.get(Client, website.client_id) or not record or record.website_id != website_id:
        raise Denied("authorization_website_mismatch")
    if record.status != "approved" or not record.timestamps_verified:
        raise Denied("authorization_not_currently_approved")
    if lock:
        try:
            evidence.lock_revision(db, record, pending=False)
        except HTTPException as exc:
            raise Denied("authorization_changed") from exc
        db.refresh(record)
        db.refresh(website)
        now = provided_now or utc_now()
    if record.status != "approved" or not record.timestamps_verified:
        raise Denied("authorization_not_currently_approved")
    if not as_utc(record.valid_from) <= now < as_utc(record.valid_until):
        raise Denied("authorization_outside_validity_window")
    try:
        _, host, _ = target(website.url)
        # First stage accepts exact FQDNs only. DNS and egress approval are NOT
        # inferred from a syntactically valid hostname; no adapter is enabled.
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("Literal address")
        from app.schemas.authorization import _normalise_domain
        if _normalise_domain(host) != host:
            raise ValueError("Noncanonical host")
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            raise ValueError("Local hostname")
    except ValueError as exc:
        raise Denied("unsupported_assessment_destination") from exc
    if host not in record.authorized_domains:
        raise Denied("exact_domain_not_authorized")
    if not set(selected["required_methods"]).issubset(set(record.permitted_methods)):
        raise Denied("profile_methods_not_authorized")
    if profile_id == NMAP_PROFILE_ID:
        from app.services.nmap_policy import public_ipv4
        approved_ips = []
        for domain in record.authorized_domains:
            try: approved_ips.append(public_ipv4(domain))
            except ValueError: pass
        if not approved_ips: raise Denied("explicit_public_ipv4_scope_required")
    approval = db.scalar(select(AuthorizationAuditEvent).where(
        AuthorizationAuditEvent.authorization_id == record.id
    ).order_by(AuthorizationAuditEvent.id.desc()).limit(1))
    if not approval or approval.action != "approved" or not approval.evidence_reviewed:
        raise Denied("audited_human_approval_required")
    review = db.get(EvidenceReview, approval.evidence_review_id) if approval.evidence_review_id else None
    documents = evidence.available(db, record.id)
    if (not review or review.authorization_id != record.id or review.decision != "accepted"
            or review.revision != record.evidence_revision or review.reviewer_id != approval.admin_id
            or not documents or set(review.evidence_ids) != {d.id for d in documents}):
        raise Denied("current_accepted_evidence_required")
    snapshots = []
    for document in documents:
        if document.website_id != website.id or document.client_id != website.client_id:
            raise Denied("evidence_relationship_mismatch")
        try:
            evidence.verified_bytes(document)
        except (HTTPException, OSError) as exc:
            raise Denied("evidence_integrity_unavailable") from exc
        snapshots.append({"id": document.id, "sha256": document.sha256, "size": document.size})
    if as_utc(record.valid_until) <= (provided_now or utc_now()):
        raise Denied("authorization_outside_validity_window")
    return {
        "authorization_id": record.id, "website_id": website.id, "client_id": website.client_id,
        "target_url": website.url, "target_host": host,
        "authorized_domains": sorted(record.authorized_domains),
        "permitted_methods": sorted(record.permitted_methods),
        "valid_from": as_utc(record.valid_from).isoformat(),
        "valid_until": as_utc(record.valid_until).isoformat(),
        "evidence_revision": record.evidence_revision, "approval_event_id": approval.id,
        "evidence_review_id": review.id, "documents": sorted(snapshots, key=lambda d: d["id"]),
    }


def get_request(db, assessment_id):
    row = db.get(AssessmentRequest, assessment_id)
    if row is None:
        raise HTTPException(404, "Assessment request not found")
    return row


def create_request(db, actor_id, payload):
    selected = None
    key = f"assessment:{actor_id}:{payload.idempotency_key}"

    def replay():
        existing_job = db.scalar(select(Job).where(Job.idempotency_key == key))
        if not existing_job:
            return None
        existing = db.scalar(select(AssessmentRequest).where(AssessmentRequest.job_id == existing_job.id))
        if (not existing or existing.website_id != payload.website_id or existing.authorization_id != payload.authorization_id
                or existing.profile_id != payload.profile_id or existing.request_note != payload.note
                or bool((existing.execution_snapshot or {}).get("network_permission_confirmed")) != payload.network_permission_confirmed):
            raise HTTPException(409, "Idempotency key belongs to a different request")
        return existing

    existing = replay()
    if existing:
        return existing
    try:
        selected = profile(payload.profile_id)
        from app.core.config import settings
        if selected["network_execution"]:
            if not profile_available(selected):
                raise Denied("nmap_disabled_or_image_not_pinned" if selected["id"] == NMAP_PROFILE_ID else "remote_docker_disabled_or_image_not_pinned" if selected["id"] == REMOTE_PROFILE_ID else "local_http_disabled")
            if not payload.network_permission_confirmed: raise Denied("explicit_network_permission_required")
        elif payload.network_permission_confirmed:
            raise Denied("network_permission_not_applicable")
        snapshot = permission(db, payload.website_id, payload.authorization_id, actor_id, payload.profile_id, lock=True)
        existing = replay()
        if existing:
            db.rollback()
            return existing
        # Serialize competing explicit requests for this authorisation through
        # the same authorisation lock used by decisions/evidence mutation.
        if db.scalar(select(Job.id).join(AssessmentRequest, AssessmentRequest.job_id == Job.id).where(
            AssessmentRequest.website_id == payload.website_id, Job.job_type == "assessment",
            Job.status.in_(["queued", "running"])).limit(1)):
            raise HTTPException(409, "This website already has a pending assessment preflight")
        now = utc_now()
        if selected["network_execution"]:
            previous = db.scalar(select(AssessmentRequest).where(AssessmentRequest.website_id == payload.website_id,
                AssessmentRequest.profile_id.in_(NETWORK_PROFILES), AssessmentRequest.requested_at > now-timedelta(seconds=60)).limit(1))
            if previous: raise HTTPException(429, "Wait sixty seconds between network assessment requests")
        job = engine.enqueue(db, "assessment", payload.website_id, 1, key, now)
        job.max_attempts = 1  # Never automatically repeat a security operation.
        row = AssessmentRequest(
            id=str(uuid4()), job_id=job.id, website_id=payload.website_id,
            authorization_id=payload.authorization_id, requested_by=actor_id, requested_at=now,
            profile_id=selected["id"], profile_digest=digest(selected),
            target_url=snapshot["target_url"], target_host=snapshot["target_host"],
            permission_digest=digest(snapshot), permission_snapshot=snapshot, request_note=payload.note,
            execution_snapshot={"mode":selected.get("mode", "policy_only"), "adapter":selected.get("adapter"),
                "network_permission_confirmed":payload.network_permission_confirmed, "confirmed_by":actor_id,
                **image_snapshot(selected["id"])},
        )
        db.add(row)
        engine.event(db, "assessment_explicitly_requested", job, actor_id=actor_id,
                     detail={"assessment_id": row.id, "profile_id": selected["id"], "mode": selected.get("mode", "policy_only")})
        db.commit()
        return row
    except Denied as exc:
        db.rollback()
        engine.event(db, "assessment_request_denied",
                     resource_id=payload.website_id if db.get(Website, payload.website_id) else None,
                     actor_id=actor_id, detail={"reason": exc.code, "authorization_id": payload.authorization_id})
        db.commit()
        raise HTTPException(409, "Assessment blocked: " + exc.code) from exc
    except IntegrityError:
        db.rollback()
        existing = replay()
        if existing:
            return existing
        raise HTTPException(409, "Assessment request changed concurrently; refresh")
    except Exception:
        db.rollback()
        raise


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


def cancel_for_authorization(db, authorization_id, actor_id):
    # Called inside the revocation transaction, without committing it here.
    for row in db.scalars(select(AssessmentRequest).where(AssessmentRequest.authorization_id == authorization_id)):
        cancel(db, row, actor_id, "authorization_revoked")


class AssessmentHandler:
    @staticmethod
    def eligible(db, job, lock=False):
        row = db.scalar(select(AssessmentRequest).where(AssessmentRequest.job_id == job.id))
        try:
            if not row or row.website_id != job.resource_id or job.revision != 1:
                raise Denied("assessment_intent_missing_or_changed")
            if digest(profile(row.profile_id)) != row.profile_digest:
                raise Denied("profile_version_changed")
            if row.profile_id in NETWORK_PROFILES:
                from app.core.config import settings
                selected = profile(row.profile_id)
                if not profile_available(selected): raise Denied("assessment_profile_disabled")
                intent = row.execution_snapshot or {}
                if intent != {"mode":selected["mode"], "adapter":selected["adapter"], "network_permission_confirmed":True, "confirmed_by":row.requested_by,
                    **image_snapshot(row.profile_id)}:
                    raise Denied("explicit_network_permission_required")
            snapshot = permission(db, row.website_id, row.authorization_id, row.requested_by, row.profile_id, lock=lock)
            if (digest(snapshot) != row.permission_digest or snapshot != row.permission_snapshot
                    or row.target_url != snapshot["target_url"] or row.target_host != snapshot["target_host"]):
                raise Denied("approved_scope_or_evidence_changed")
            return True
        except Denied as exc:
            engine.event(db, "assessment_permission_denied", job, detail={"reason": exc.code})
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


def still_permitted(job_id,token):
    from app.db.session import SessionLocal
    with SessionLocal() as db:
        job=db.get(Job,job_id)
        valid=bool(job and job.status=="running" and job.claim_token==token and job.lease_until
            and as_utc(job.lease_until)>utc_now() and AssessmentHandler.eligible(db,job))
        db.commit();return valid


def worker_tick():
    from app.db.session import SessionLocal
    with SessionLocal() as db:
        engine.heartbeat(db,"assessment-worker");db.commit()
        claimed=engine.claim(db,"assessment")
        if not claimed:return
        row=db.scalar(select(AssessmentRequest).where(AssessmentRequest.job_id==claimed[0]))
        if row.profile_id not in NETWORK_PROFILES:
            engine.finish(db,*claimed,{"state":"up","mode":"policy_only","network_execution":False,
                "outcome":"permission_preflight_passed","findings_created":0,"destination_resolution":"not_performed"})
            return
        selected = profile(row.profile_id)
        engine.event(db,"assessment_execution_started",db.get(Job,row.job_id),detail={"adapter":selected["adapter"]});db.commit();db.refresh(row)
        db.expunge(row)
    try:
        from app.services.local_assessment_runtime import ADAPTERS
        if not still_permitted(*claimed):
            payload={"state":"cancelled","error":"permission_changed"}
        else:
            if row.profile_id == NMAP_PROFILE_ID:
                from app.services.nmap_runtime import NmapAdapter
                adapter = NmapAdapter(authorized_domains=row.permission_snapshot["authorized_domains"])
            elif row.profile_id == REMOTE_PROFILE_ID:
                from app.services.remote_assessment_runtime import RemoteDockerAdapter
                adapter = RemoteDockerAdapter()
            else:
                adapter = ADAPTERS["local-python-v1"]
            payload=adapter.execute(row.target_url,lambda:still_permitted(*claimed))
    except Exception as exc:
        from app.services.remote_assessment_runtime import RemoteFailure
        payload={"state":"failed","mode":selected["mode"],"network_execution":True,
            "error":str(exc) if isinstance(exc, RemoteFailure) else "execution_failed_or_permission_changed"}
        if isinstance(exc, RemoteFailure): payload["execution"] = exc.execution
    with SessionLocal() as db:
        # Record lifecycle telemetry even if cancellation/revocation prevents result acceptance.
        if row.profile_id in (REMOTE_PROFILE_ID, NMAP_PROFILE_ID):
            execution = payload.get("execution") or payload.get("report", {}).get("execution", {})
            engine.event(db,"remote_docker_execution_finished",db.get(Job,row.job_id), detail={
                "execution": execution, "error": payload.get("error")})
            db.commit()
        engine.finish(db,*claimed,payload)


engine.register("assessment", AssessmentHandler)
