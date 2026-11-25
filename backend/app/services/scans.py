"""Self-service scans (Phase 1: the safe start of every scan; the actual checks arrive in Phase 2).

Safety, fail closed:
* only websites with verified ownership, scanned for the account that owns them;
* ownership is re-checked before every scan (cached 24 h); a definite failure marks it lost and pauses scans;
* the domain is resolved once per scan, every answer must be a public address, and only the stored IP is used;
* at most one scan per website (a unique index) and at most SCAN_MAX_CONCURRENT on the server;
* a total time limit: past it, or if the worker dies, the result is "incomplete", never "safe".

Every scan row is the audit record (user, website, IP, type, start, end, result) and each step also writes an
execution event.
"""
from concurrent.futures import ThreadPoolExecutor
import time
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.core.time import as_utc, utc_now
from app.models.admin import Admin
from app.models.scan import ACTIVE_SCAN_STATES, Scan
from app.models.website import Website
from app.services import ip_policy, ownership
from app.services import job_engine as engine

WORKER_NAME = "scan-worker"

MESSAGES = {
    "not_verified": "This website's ownership is not verified, so it was not scanned.",
    "verification_lost": "We could no longer find your ownership verification, so scans are paused. "
                         "Put the verification back (or verify again) and the next scan will run.",
    "could_not_recheck": "We could not re-check your ownership verification right now, so this scan did not run. "
                         "It is not a problem with your website's security; try again later.",
    "owner_mismatch": "This scan no longer matches the website's owner, so it was not run.",
    "website_removed": "The website was removed from the account, so this scan was stopped.",
    "dns_lookup_failed": "We could not find this domain's address in DNS, so the scan could not run.",
    "private_or_reserved_address": "This domain points to a private or reserved network address. "
                                   "SNWebShield only scans public addresses.",
    "cloud_metadata_address": "This domain points to a cloud internal address. SNWebShield will not scan it.",
    "server_own_address": "This domain points to SNWebShield's own server, which is never scanned.",
    "time_limit": "The scan reached its time limit before finishing. Results are incomplete.",
    "worker_stopped": "The scan stopped unexpectedly before finishing. Results are incomplete.",
    "internal_error": "Something went wrong while scanning. Results are incomplete; please try again.",
    "checks_not_available": "Ownership confirmed and your website's public address checked. "
                            "Detailed security checks (ports, versions, technologies) are not switched on yet, "
                            "so this scan is incomplete. It does not mean your website is safe.",
}


def serial(scan: Scan) -> dict:
    iso = lambda v: as_utc(v).isoformat() if v else None
    return {"id": scan.id, "website_id": scan.website_id, "scan_type": scan.scan_type, "trigger": scan.trigger,
            "status": scan.status, "requested_at": iso(scan.requested_at), "started_at": iso(scan.started_at),
            "ended_at": iso(scan.ended_at), "resolved_ip": scan.resolved_ip, "message": scan.message,
            "result": scan.result, "progress": scan.progress}


def active_scan(db, website_id: int) -> Scan | None:
    return db.scalar(select(Scan).where(Scan.website_id == website_id, Scan.status.in_(ACTIVE_SCAN_STATES)).limit(1))


def latest_scan(db, website_id: int) -> Scan | None:
    return db.scalar(select(Scan).where(Scan.website_id == website_id).order_by(Scan.requested_at.desc()).limit(1))


def request_scan(db, website: Website, trigger: str) -> Scan:
    """Queue a scan. Requires verified ownership; returns the already active scan instead of a second one."""
    if website.removed_at is not None or website.verification_status != "verified" or not website.owner_id:
        raise HTTPException(409, MESSAGES["not_verified"])
    existing = active_scan(db, website.id)
    if existing:
        return existing
    now = utc_now()
    scan = Scan(id=str(uuid4()), website_id=website.id, owner_id=website.owner_id, scan_type="standard",
                trigger=trigger, status="queued", requested_at=now,
                progress={"step": "queued", "message": "Waiting to start…"})
    try:
        with db.begin_nested():
            db.add(scan)
            db.flush()
    except IntegrityError:
        existing = active_scan(db, website.id)
        if existing:
            return existing
        raise
    engine.event(db, "scan_requested", resource_id=website.id, actor_id=website.owner_id,
                 detail={"scan_id": scan.id, "trigger": trigger, "scan_type": scan.scan_type})
    return scan


def discard_for_removal(db, website: Website) -> dict:
    """Stop the website's unfinished scans because its owner removed it. Finished scans are never touched.

    A queued scan never started, so it is deleted. A running scan is ended as "refused" (the worker's claim is
    cleared, so a late result from the worker cannot overwrite it) and stays as a past record with its audit entry.
    """
    now = utc_now()
    deleted = db.execute(delete(Scan).where(Scan.website_id == website.id, Scan.status == "queued")
                         .execution_options(synchronize_session=False)).rowcount
    stopped = 0
    for scan in list(db.scalars(select(Scan).where(Scan.website_id == website.id, Scan.status == "running"))):
        changed = db.execute(update(Scan).where(Scan.id == scan.id, Scan.status == "running").values(
            status="refused", ended_at=now, claim_token=None, lease_until=None, message=MESSAGES["website_removed"],
            result={"code": "website_removed"}, progress={"step": "finished", "message": "Stopped"})
            .execution_options(synchronize_session=False))
        if changed.rowcount:
            db.expire(scan)
            _audit_finish(db, scan)
            stopped += 1
    return {"queued_scans_deleted": deleted, "running_scans_stopped": stopped}


# --- Worker --------------------------------------------------------------------------------------

def _audit_finish(db, scan: Scan):
    engine.event(db, "scan_finished", resource_id=scan.website_id, actor_id=scan.owner_id, detail={
        "scan_id": scan.id, "user_id": scan.owner_id, "website_id": scan.website_id, "ip": scan.resolved_ip,
        "scan_type": scan.scan_type, "trigger": scan.trigger,
        "start": as_utc(scan.started_at).isoformat() if scan.started_at else None,
        "end": as_utc(scan.ended_at).isoformat() if scan.ended_at else None,
        "result": scan.status, "reason": (scan.result or {}).get("code")})


def recover_expired(db, now=None) -> int:
    """A running scan whose lease ran out belongs to a worker that died: mark it incomplete."""
    now = now or utc_now()
    count = 0
    for scan in list(db.scalars(select(Scan).where(Scan.status == "running", Scan.lease_until <= now))):
        changed = db.execute(update(Scan).where(Scan.id == scan.id, Scan.status == "running",
                                                Scan.claim_token == scan.claim_token).values(
            status="incomplete", ended_at=now, claim_token=None, lease_until=None,
            message=MESSAGES["worker_stopped"], result={"code": "worker_stopped"},
            progress={"step": "stopped", "message": "Stopped"}).execution_options(synchronize_session=False))
        if changed.rowcount:
            db.refresh(scan)
            _audit_finish(db, scan)
            count += 1
    db.commit()
    return count


def claim(db, now=None):
    """Claim the oldest queued scan if fewer than SCAN_MAX_CONCURRENT are running. Returns (id, token) or None."""
    now = now or utc_now()
    running = db.scalar(select(func.count()).select_from(Scan).where(Scan.status == "running")) or 0
    if running >= settings.scan_max_concurrent:
        return None
    candidate = db.scalar(select(Scan).where(Scan.status == "queued").order_by(Scan.requested_at, Scan.id).limit(1))
    if candidate is None:
        return None
    token = str(uuid4())
    from datetime import timedelta
    changed = db.execute(update(Scan).where(Scan.id == candidate.id, Scan.status == "queued").values(
        status="running", claim_token=token, started_at=now,
        lease_until=now + timedelta(seconds=settings.scan_time_limit_seconds + 60),
        progress={"step": "starting", "message": "Starting…"}).execution_options(synchronize_session=False))
    if changed.rowcount != 1:
        db.rollback()
        return None
    engine.event(db, "scan_started", resource_id=candidate.website_id, actor_id=candidate.owner_id,
                 detail={"scan_id": candidate.id})
    db.commit()
    return candidate.id, token


def _owned(db, scan_id, token) -> Scan | None:
    scan = db.get(Scan, scan_id)
    return scan if scan and scan.status == "running" and scan.claim_token == token else None


def _progress(db, scan_id, token, step, message):
    db.execute(update(Scan).where(Scan.id == scan_id, Scan.claim_token == token, Scan.status == "running")
               .values(progress={"step": step, "message": message}).execution_options(synchronize_session=False))
    db.commit()


def _finish(db, scan_id, token, status, code, **extra):
    now = utc_now()
    changed = db.execute(update(Scan).where(Scan.id == scan_id, Scan.claim_token == token, Scan.status == "running")
                         .values(status=status, ended_at=now, claim_token=None, lease_until=None,
                                 message=MESSAGES[code], result={"code": code, **extra},
                                 progress={"step": "finished", "message": "Finished"})
                         .execution_options(synchronize_session=False))
    if changed.rowcount == 1:
        db.expire_all()
        _audit_finish(db, db.get(Scan, scan_id))
    db.commit()
    return changed.rowcount == 1


def execute(scan_id: str, token: str, *, resolve=ip_policy.resolve_public, verify=ownership.ensure_verified) -> str:
    """Run one claimed scan. Returns the final status. Never raises."""
    from app.db.session import SessionLocal
    deadline = time.monotonic() + settings.scan_time_limit_seconds
    with SessionLocal() as db:
        try:
            scan = _owned(db, scan_id, token)
            if scan is None:
                return "lost_claim"
            website = db.get(Website, scan.website_id)
            owner = db.get(Admin, scan.owner_id)
            if website is not None and website.removed_at is not None:
                _finish(db, scan_id, token, "refused", "website_removed")
                return "refused"
            if website is None or owner is None or not owner.is_active or website.owner_id != scan.owner_id:
                _finish(db, scan_id, token, "refused", "owner_mismatch")
                return "refused"

            _progress(db, scan_id, token, "ownership", "Checking ownership verification…")
            allowed, reason = verify(db, website)
            db.commit()
            if not allowed:
                if reason == "verification_lost":
                    engine.event(db, "verification_lost", resource_id=website.id, actor_id=website.owner_id,
                                 detail={"scan_id": scan_id})
                _finish(db, scan_id, token, "refused", reason)
                return "refused"
            if time.monotonic() > deadline:
                _finish(db, scan_id, token, "incomplete", "time_limit")
                return "incomplete"

            _progress(db, scan_id, token, "resolving", "Finding your website's address…")
            try:
                addresses = resolve(website.domain)
            except ip_policy.Blocked as blocked:
                _finish(db, scan_id, token, "refused", blocked.code)
                return "refused"
            # Resolved once; every later step of this scan may contact only this address.
            db.execute(update(Scan).where(Scan.id == scan_id, Scan.claim_token == token)
                       .values(resolved_ip=addresses[0]).execution_options(synchronize_session=False))
            db.commit()
            if time.monotonic() > deadline:
                _finish(db, scan_id, token, "incomplete", "time_limit")
                return "incomplete"

            # Phase 2 adds the DETECT checks here, each bounded by the remaining time.
            _finish(db, scan_id, token, "incomplete", "checks_not_available",
                    all_addresses=addresses[:8], ownership=reason)
            return "incomplete"
        except Exception:
            db.rollback()
            try:
                _finish(db, scan_id, token, "incomplete", "internal_error")
            except Exception:
                db.rollback()
            return "incomplete"


class Worker:
    """Dispatcher for `python -m app.cli.operations scan-worker`. Run one scan-worker process."""

    def __init__(self):
        self.pool = ThreadPoolExecutor(max_workers=settings.scan_max_concurrent, thread_name_prefix="scan")
        self.running = set()

    def tick(self):
        from app.db.session import SessionLocal
        with SessionLocal() as db:
            engine.heartbeat(db, WORKER_NAME)
            db.commit()
            recover_expired(db)
        self.running = {f for f in self.running if not f.done()}
        while len(self.running) < settings.scan_max_concurrent:
            with SessionLocal() as db:
                claimed = claim(db)
            if not claimed:
                break
            self.running.add(self.pool.submit(execute, *claimed))

    def drain(self):
        self.pool.shutdown(wait=True)
