"""Explicit assessment intents and fail-closed, network-free permission checks."""
from hashlib import sha256
import ipaddress
import json
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.core.time import as_utc, utc_now
from app.models.admin import Admin
from app.models.client import Client
from app.models.assessment import AssessmentRequest
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
                or existing.profile_id != payload.profile_id or existing.request_note != payload.note):
            raise HTTPException(409, "Idempotency key belongs to a different request")
        return existing

    existing = replay()
    if existing:
        return existing
    try:
        selected = profile(payload.profile_id)
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
        job = engine.enqueue(db, "assessment", payload.website_id, 1, key, now)
        job.max_attempts = 1  # Never automatically repeat a security operation.
        row = AssessmentRequest(
            id=str(uuid4()), job_id=job.id, website_id=payload.website_id,
            authorization_id=payload.authorization_id, requested_by=actor_id, requested_at=now,
            profile_id=selected["id"], profile_digest=digest(selected),
            target_url=snapshot["target_url"], target_host=snapshot["target_host"],
            permission_digest=digest(snapshot), permission_snapshot=snapshot, request_note=payload.note,
        )
        db.add(row)
        engine.event(db, "assessment_explicitly_requested", job, actor_id=actor_id,
                     detail={"assessment_id": row.id, "profile_id": selected["id"], "mode": "policy_only"})
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
        # No findings or "scan completed" claim: this stage checks permission only.
        if payload.get("mode") != "policy_only" or payload.get("network_execution") is not False:
            raise ValueError("Assessment adapters are not enabled")


def worker_tick():
    from app.db.session import SessionLocal
    with SessionLocal() as db:
        engine.heartbeat(db, "assessment-worker")
        db.commit()
        claimed = engine.claim(db, "assessment")
        if not claimed:
            return
        # finish() locks/rechecks live authorisation, evidence and immutable
        # request/profile snapshots before atomically accepting this result.
        engine.finish(db, *claimed, {"state": "up", "mode": "policy_only", "network_execution": False,
                                    "outcome": "permission_preflight_passed", "findings_created": 0,
                                    "destination_resolution": "not_performed"})


engine.register("assessment", AssessmentHandler)
