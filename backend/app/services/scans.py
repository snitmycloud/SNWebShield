"""Self-service scans: the safe start of every scan, then the DETECT steps (Phase 2).

Safety, fail closed:
* only websites with verified ownership (or an approved admin test target), scanned for the account that owns them;
* ownership is re-checked before every scan (cached 24 h); a definite failure marks it lost and pauses scans;
* the domain is resolved once per scan, every answer must be a public address, and only the stored IP is used;
* at most one scan per website (a unique index) and at most SCAN_MAX_CONCURRENT on the server;
* a total time limit, and a guard that stops a running scan cleanly if the website is removed or verification is lost
  (see scan_guard.py). A stopped scan keeps its partial results, marked incomplete with the reason, never "clean".

Every scan row is the audit record (user, website, IP, type, start, end, result) and each step also writes an
execution event.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import time
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.core.time import as_utc, utc_now
from app.models.admin import Admin
from app.models.jobs import ExecutionEvent
from app.models.scan import ACTIVE_SCAN_STATES, Scan
from app.models.website import Website
from app.services import ip_policy, ownership, plans
from app.services import job_engine as engine
from app.services.scan_guard import ScanGuard, ScanStopped, stop_latency_seconds

WORKER_NAME = "scan-worker"

MESSAGES = {
    "not_verified": "This website's ownership is not verified, so it was not scanned.",
    "verification_lost": "We could no longer find your ownership verification, so scans are paused. "
                         "Put the verification back (or verify again) and the next scan will run.",
    "could_not_recheck": "We could not re-check your ownership verification right now, so this scan did not run. "
                         "It is not a problem with your website's security; try again later.",
    "owner_mismatch": "This scan no longer matches the website's owner, so it was not run.",
    "website_removed": "The website was removed from the account, so this scan was stopped. "
                       "Results found so far are kept and are incomplete.",
    "stopped_verification_lost": "The scan stopped because ownership verification is no longer valid. "
                                 "Results found so far are kept and are incomplete.",
    "stopped_owner_disabled": "The scan stopped because the account was disabled. "
                              "Results found so far are kept and are incomplete.",
    "plan_feature": "Your plan does not include this kind of scan, so it was not run.",
    "dns_lookup_failed": "We could not find this domain's address in DNS, so the scan could not run.",
    "private_or_reserved_address": "This domain points to a private or reserved network address. "
                                   "SNWebShield only scans public addresses.",
    "recheck_fixed": "We re-checked this finding and it is no longer found. It is now marked as fixed.",
    "recheck_still_open": "We re-checked this finding and it is still there.",
    "recheck_unconfirmed": "We could not finish the re-check, so we cannot tell whether this is fixed. That is not the same as fixed. Please try again.",
    "ipv6_only": "This website only has an IPv6 address, which SNWebShield does not support yet, so it was not scanned. "
                 "It is not a problem with your website's security.",
    "cloud_metadata_address": "This domain points to a cloud internal address. SNWebShield will not scan it.",
    "server_own_address": "This domain points to SNWebShield's own server, which is never scanned.",
    "time_limit": "The scan reached its time limit before finishing. Results found so far are kept and are incomplete.",
    "worker_stopped": "The scan stopped unexpectedly before finishing. Results are incomplete.",
    "internal_error": "Something went wrong while scanning. Results are incomplete; please try again.",
    "some_checks_incomplete": "Some checks could not be completed, so the results are incomplete. "
                              "It does not mean your website is safe.",
    "detect_completed": "Detection finished. This is a list of what we found, not a security verdict: "
                        "vulnerability checks come in a later update.",
}

STOP_MESSAGES = {"verification_lost": "stopped_verification_lost", "owner_disabled": "stopped_owner_disabled",
                 "website_removed": "website_removed", "time_limit": "time_limit", "internal_error": "internal_error",
                 "scan_taken_over": "worker_stopped"}


def serial(scan: Scan) -> dict:
    iso = lambda v: as_utc(v).isoformat() if v else None
    return {"id": scan.id, "website_id": scan.website_id, "scan_type": scan.scan_type, "trigger": scan.trigger,
            "status": scan.status, "requested_at": iso(scan.requested_at), "started_at": iso(scan.started_at),
            "ended_at": iso(scan.ended_at), "resolved_ip": scan.resolved_ip, "message": scan.message,
            "result": scan.result, "progress": scan.progress}


def active_scan(db, website_id: int) -> Scan | None:
    return db.scalar(select(Scan).where(Scan.website_id == website_id, Scan.status.in_(ACTIVE_SCAN_STATES)).limit(1))


def latest_scan(db, website_id: int) -> Scan | None:
    return db.scalar(select(Scan).where(Scan.website_id == website_id, Scan.scan_type != "recheck").order_by(Scan.requested_at.desc()).limit(1))


def is_test_target(website: Website) -> bool:
    return website.verification_method == "test_target" and website.domain in settings.approved_test_targets


def time_limit_for(scan_type: str) -> int:
    """Total time a scan may run before it ends incomplete: standard 15 minutes, full (all 65,535 ports) 60 minutes."""
    if scan_type == "recheck":
        return settings.recheck_time_limit_seconds
    return settings.scan_full_time_limit_seconds if scan_type == "full" else settings.scan_time_limit_seconds


def _day_start(now):
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def _next_reset(now) -> str:
    return (_day_start(now) + timedelta(days=1)).isoformat()


def _count_events(db, action: str, *, since, resource_ids=None, actor_id=None) -> int:
    conditions = [ExecutionEvent.action == action, ExecutionEvent.occurred_at >= since]
    if resource_ids is not None:
        conditions.append(ExecutionEvent.resource_id.in_(resource_ids))
    if actor_id is not None:
        conditions.append(ExecutionEvent.actor_id == actor_id)
    return db.scalar(select(func.count()).select_from(ExecutionEvent).where(*conditions)) or 0


def _test_target_used(db, website: Website, now) -> int:
    same_domain = select(Website.id).where(Website.domain == website.domain)
    return _count_events(db, "scan_requested", since=_day_start(now), resource_ids=same_domain)


def _scan_limit_error(message: str, **extra) -> HTTPException:
    return HTTPException(429, {"code": "scan_limit", "message": message, **extra})


def _enforce_test_target_quota(db, website: Website, now) -> None:
    """At most TEST_TARGET_SCANS_PER_DAY scans of one approved test target per UTC day, across all accounts.

    Counts the permanent `scan_requested` audit events, so removing a website (which deletes its queued scans) or
    adding it again cannot reset the count.
    """
    if website.domain not in settings.approved_test_targets:
        return
    if _test_target_used(db, website, now) >= settings.test_target_scans_per_day:
        raise _scan_limit_error(
            f"Test target limit reached: {website.domain} can be scanned at most "
            f"{settings.test_target_scans_per_day} times per day (UTC). Try again tomorrow.",
            scope="test_target", remaining=0, resets_at=_next_reset(now))


def request_scan(db, website: Website, trigger: str, scan_type: str = "standard") -> Scan:
    """Queue a scan. Requires verified ownership; returns the already active scan instead of a second one."""
    ownership.expire_manual(website)   # a manual verification that ran out no longer counts
    if website.removed_at is not None or website.verification_status != "verified" or not website.owner_id:
        raise HTTPException(409, MESSAGES["not_verified"])
    existing = active_scan(db, website.id)
    if existing:
        return existing
    now = utc_now()
    _enforce_test_target_quota(db, website, now)
    scan = Scan(id=str(uuid4()), website_id=website.id, owner_id=website.owner_id, scan_type=scan_type,
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
                 detail={"scan_id": scan.id, "trigger": trigger, "scan_type": scan.scan_type,
                         "domain": website.domain, "test_target": is_test_target(website)})
    return scan


# --- "Scan now" ------------------------------------------------------------------------------------------

def scan_now_status(db, website: Website, account: Admin) -> dict:
    """What the Scan now button shows: whether it may be used, how many scans are left today, and why not."""
    now = utc_now()
    plan = plans.get(account.plan)
    limit = int(plan.get("manual_scans_per_day", 0))
    scope = plan.get("manual_scans_per", "account")
    since = _day_start(now)
    if scope == "website":
        same_site = select(Website.id).where(Website.owner_id == website.owner_id, Website.domain == website.domain)
        used = _count_events(db, "manual_scan_requested", since=since, resource_ids=same_site)
    else:
        used = _count_events(db, "manual_scan_requested", since=since, actor_id=account.id)
    remaining = max(0, limit - used)
    test_remaining = None
    if website.domain in settings.approved_test_targets:
        test_remaining = max(0, settings.test_target_scans_per_day - _test_target_used(db, website, now))
        remaining = min(remaining, test_remaining)
    status = {"limit": limit, "scope": scope, "remaining": remaining, "plan_label": plan["label"],
              "resets_at": _next_reset(now), "test_target_remaining": test_remaining,
              "allowed": True, "reason": None, "message": None}
    if website.verification_status != "verified":
        status.update(allowed=False, reason="not_verified", message="Verify ownership of this website first.")
    elif active_scan(db, website.id) is not None:
        status.update(allowed=False, reason="scan_running", message="A scan is already running for this website.")
    elif remaining <= 0:
        status.update(allowed=False, reason="limit_reached", message=limit_message(plan, scope, test_remaining == 0))
    return status


def limit_message(plan: dict, scope: str, test_target: bool = False) -> str:
    if test_target:
        return (f"This test target can be scanned at most {settings.test_target_scans_per_day} times per day (UTC). "
                "Try again tomorrow.")
    where = "for this website" if scope == "website" else "on your account"
    return (f"You have used all {plan.get('manual_scans_per_day')} manual scans {where} today on the {plan['label']} plan. "
            "They reset at 00:00 UTC. Upgrade for more scans.")


def request_manual_scan(db, website: Website, account: Admin, scan_type: str = "standard") -> tuple[Scan, dict, bool]:
    """The Scan now button. Returns (scan, status_after, already_running). Limits come from plans.json."""
    plan = plans.get(account.plan)
    if scan_type == "full":
        if is_test_target(website):
            raise HTTPException(422, "Test targets only allow standard scans.")
        if not plan.get("full_port_scan"):
            raise HTTPException(402, {"code": "plan_feature", "plan": plan["name"], "plan_label": plan["label"],
                                      "message": "Full port scans (all 65,535 ports) are available on the Pro and "
                                                 "Business plans. Upgrade to use them."})
    status = scan_now_status(db, website, account)
    if status["reason"] == "not_verified":
        raise HTTPException(409, status["message"])
    if status["reason"] == "scan_running":
        return active_scan(db, website.id), status, True
    if status["reason"] == "limit_reached":
        raise _scan_limit_error(status["message"], scope=status["scope"], remaining=0, limit=status["limit"],
                                plan_label=status["plan_label"], resets_at=status["resets_at"])
    scan = request_scan(db, website, "manual", scan_type)
    engine.event(db, "manual_scan_requested", resource_id=website.id, actor_id=account.id,
                 detail={"scan_id": scan.id, "scan_type": scan_type, "domain": website.domain})
    db.flush()  # sessions do not auto-flush: make the new event count in the "scans left" shown next to the button
    return scan, scan_now_status(db, website, account), False


def discard_for_removal(db, website: Website) -> dict:
    """Stop the website's unfinished scans because its owner removed it. Finished scans are never touched.

    A queued scan never started, so it is deleted. A running scan is ended at once as "incomplete" with the reason (its
    claim is cleared, so a late result from the worker cannot change the status) and stays as a past record with its
    audit entry. The worker notices within about a second (scan_guard), stops, and saves what it had found so far.
    """
    now = utc_now()
    deleted = db.execute(delete(Scan).where(Scan.website_id == website.id, Scan.status == "queued")
                         .execution_options(synchronize_session=False)).rowcount
    stopped = 0
    for scan in list(db.scalars(select(Scan).where(Scan.website_id == website.id, Scan.status == "running"))):
        changed = db.execute(update(Scan).where(Scan.id == scan.id, Scan.status == "running").values(
            status="incomplete", ended_at=now, claim_token=None, lease_until=None, message=MESSAGES["website_removed"],
            result={"code": "website_removed", "stopped_step": (scan.progress or {}).get("step")},
            progress={"step": "finished", "message": "Stopped"})
            .execution_options(synchronize_session=False))
        if changed.rowcount:
            db.expire(scan)
            _audit_finish(db, scan)
            stopped += 1
    return {"queued_scans_deleted": deleted, "running_scans_stopped": stopped}


# --- Worker --------------------------------------------------------------------------------------

def _audit_finish(db, scan: Scan):
    website = db.get(Website, scan.website_id)
    engine.event(db, "scan_finished", resource_id=scan.website_id, actor_id=scan.owner_id, detail={
        "scan_id": scan.id, "user_id": scan.owner_id, "website_id": scan.website_id, "ip": scan.resolved_ip,
        "scan_type": scan.scan_type, "trigger": scan.trigger,
        "test_target": bool(website and is_test_target(website)),
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


def rechecks_used_today(db, *, account_id: int | None = None, website_id: int | None = None, now=None) -> int:
    from app.models.scan import FindingRecheck
    query = select(func.count()).select_from(FindingRecheck).where(FindingRecheck.requested_at >= _day_start(now or utc_now()))
    if account_id is not None:
        query = query.where(FindingRecheck.requested_by_id == account_id)
    if website_id is not None:
        query = query.where(FindingRecheck.website_id == website_id)
    return db.scalar(query) or 0


def request_recheck(db, website: Website, account: Admin, fingerprint: str):
    """"Re-scan to confirm fix": queue a focused scan of ONE finding. Owner only; the website must be verified; separate daily allowance
    (plans.json `rechecks_per_day`, and 20 a day on a test target). Returns (scan, recheck)."""
    from app.models.scan import FindingRecheck
    from app.services import finding_states
    if website.removed_at is not None or website.owner_id != account.id or not account.is_active:
        raise HTTPException(403, "Only the owner of this website can re-check a finding.")
    ownership.expire_manual(website)
    if website.verification_status != "verified":
        raise HTTPException(409, MESSAGES["not_verified"])
    try:
        state = finding_states.ensure_state(db, website.id, fingerprint)
    except finding_states.StateError as error:
        raise HTTPException(404, error.message) from error
    if state.status == "fixed":
        raise HTTPException(409, {"code": "already_fixed", "message": "This finding is already marked as fixed."})
    if not finding_states.recheckable(state.check_id):
        raise HTTPException(422, {"code": "not_rechecked_alone", "message": "This kind of finding cannot be re-checked on its own. Run a full scan instead."})
    existing = active_scan(db, website.id)
    if existing:
        raise HTTPException(409, {"code": "scan_running", "message": "A scan is already running for this website. Wait for it to finish, then try again."})
    now = utc_now()
    plan = plans.get(account.plan)
    allowance = int(plan.get("rechecks_per_day", 0))
    if rechecks_used_today(db, account_id=account.id, now=now) >= allowance:
        raise HTTPException(429, {"code": "recheck_limit", "message": f"Your {plan['label']} plan includes {allowance} re-checks a day. Try again after 00:00 UTC."})
    if is_test_target(website) and rechecks_used_today(db, website_id=website.id, now=now) >= settings.test_target_rechecks_per_day:
        raise HTTPException(429, {"code": "recheck_limit", "message": f"This test target can be re-checked at most {settings.test_target_rechecks_per_day} times a day (UTC). Try again tomorrow."})
    scan = Scan(id=str(uuid4()), website_id=website.id, owner_id=website.owner_id, scan_type="recheck", trigger="manual", status="queued",
                requested_at=now, progress={"step": "queued", "message": "Waiting to start\u2026"})
    try:
        with db.begin_nested():
            db.add(scan)
            db.flush()
    except IntegrityError:
        raise HTTPException(409, {"code": "scan_running", "message": "A scan is already running for this website. Wait for it to finish, then try again."})
    recheck = FindingRecheck(scan_id=scan.id, website_id=website.id, fingerprint=fingerprint, check_id=state.check_id, requested_by_id=account.id, requested_at=now)
    db.add(recheck)
    engine.event(db, "recheck_requested", resource_id=website.id, actor_id=account.id, detail={
        "scan_id": scan.id, "fingerprint": fingerprint, "check_id": state.check_id, "domain": website.domain, "test_target": is_test_target(website)})
    return scan, recheck


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
    changed = db.execute(update(Scan).where(Scan.id == candidate.id, Scan.status == "queued").values(
        status="running", claim_token=token, started_at=now,
        lease_until=now + timedelta(seconds=time_limit_for(candidate.scan_type) + 60),
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


def _write_progress(scan_id, token, step, message) -> None:
    """Progress is cosmetic: a failure to write it never affects the scan."""
    from app.db.session import SessionLocal
    for attempt in range(3):  # a brief database lock must not leave a stale label on screen
        try:
            with SessionLocal() as db:
                _progress(db, scan_id, token, step, message)
            return
        except Exception:
            time.sleep(0.05 * (attempt + 1))


def _finish(db, scan_id, token, status, code, message=None, **extra):
    now = utc_now()
    changed = db.execute(update(Scan).where(Scan.id == scan_id, Scan.claim_token == token, Scan.status == "running")
                         .values(status=status, ended_at=now, claim_token=None, lease_until=None,
                                 message=message or MESSAGES[code], result={"code": code, **extra},
                                 progress={"step": "finished", "message": "Finished"})
                         .execution_options(synchronize_session=False))
    if changed.rowcount == 1:
        db.expire_all()
        _audit_finish(db, db.get(Scan, scan_id))
    db.commit()
    return changed.rowcount == 1


async def _drive(ctx, state, guard, detect) -> None:
    """Run the detection steps with the guard watching. If the guard must stop the scan, the running step is cancelled."""
    work = asyncio.create_task(detect(ctx, state, guard))
    watcher = asyncio.create_task(guard.watch(work))
    try:
        await work
    except ScanStopped:
        pass
    except asyncio.CancelledError:
        if guard.stop is None:
            raise
    finally:
        watcher.cancel()
        await asyncio.gather(watcher, return_exceptions=True)


def _conclude(db, scan_id, token, website_id, state, guard, meta) -> str:
    from app.services.detect_runner import OPTIONAL_STEPS, STEP_NAMES
    extra = {"steps": state.steps, "ports": state.ports.summary(), "counts": state.counts(), "cdn": state.cdn, "notes": state.notes, **meta}
    stop = guard.stop
    if stop is not None:
        engine.event(db, "scan_worker_stopped", resource_id=website_id, detail={
            "scan_id": scan_id, "code": stop.code, "stopped_step": state.current,
            "seconds_since_removal": stop_latency_seconds(stop), **state.counts()})
        db.commit()
        key = STOP_MESSAGES.get(stop.code, "internal_error")
        # After a removal or takeover the scan is already finished by whoever did that; this is then a no-op.
        _finish(db, scan_id, token, "incomplete", stop.code, message=MESSAGES[key], stopped_step=state.current, **extra)
        return "incomplete"
    unfinished = state.incomplete_steps()
    if unfinished:
        names = ", ".join(STEP_NAMES[name].lower() for name in unfinished)
        _finish(db, scan_id, token, "incomplete", "some_checks_incomplete",
                message=f"We could not finish these checks: {names}. Results are incomplete. "
                        "It does not mean your website is safe.", **extra)
        return "incomplete"
    counts = state.counts()
    found = counts["findings"]
    _finish(db, scan_id, token, "completed", "detect_completed",
            message=(f"Scan finished: {counts['open_ports']} open port(s), {counts['technologies']} "
                     f"technolog{'y' if counts['technologies'] == 1 else 'ies'}, {counts['exposed_files']} exposed file(s) "
                     f"or page(s) found. Findings: {found['critical']} critical, {found['high']} high, {found['medium']} medium, "
                     f"{found['low']} low; {found['needs_checking']} item(s) need your check. "
                     "This lists what we found; it is not a security verdict."
                     + "".join(f" {note}" for note in state.optional_notes())),
            **{**extra, "optional_unavailable": [n for n, st in state.steps.items()
                                                 if n in OPTIONAL_STEPS and st["state"] == "could_not_check"]})
    return "completed"


def _after_full_scan(db, scan_id: str) -> None:
    """Update the website's finding states (new / fixed / reopened) from a finished full scan. Never lets a problem here spoil the scan."""
    try:
        from app.services import finding_states
        scan = db.get(Scan, scan_id)
        if scan is not None and scan.scan_type != "recheck" and scan.status in ("completed", "incomplete"):
            finding_states.refresh_from_scan(db, scan)
            db.commit()
    except Exception:
        db.rollback()
    # Each of these is separate: one failing must not stop the others, and none may spoil the finished scan.
    for step in ("record_score", "send_alerts"):
        try:
            scan = db.get(Scan, scan_id)
            if scan is None or scan.scan_type == "recheck" or scan.status not in ("completed", "incomplete"):
                return
            if step == "record_score":
                from app.services import score_history
                score_history.record(db, scan)
            else:
                from app.services import alerts
                alerts.after_scan(db, scan)
            db.commit()
        except Exception:
            db.rollback()


def _conclude_recheck(db, scan_id, token, website_id, state, guard) -> str:
    """End a recheck: Fixed only if the check finished and the finding is gone; a stop or a failed check is never 'fixed'."""
    from sqlalchemy import select as _select
    from app.models.scan import FindingRecheck, FindingState
    from app.services import finding_states
    recheck = db.scalar(_select(FindingRecheck).where(FindingRecheck.scan_id == scan_id))
    state_row = db.scalar(_select(FindingState).where(FindingState.website_id == recheck.website_id, FindingState.fingerprint == recheck.fingerprint)) if recheck else None
    result = getattr(state, "recheck", None) or {"outcome": "could_not_check", "detail": "not_started"}
    stop = guard.stop

    def done(*args, **kwargs):   # _finish expires the session, so write what we changed first
        db.flush()
        return _finish(*args, **kwargs)
    info = {"fingerprint": recheck.fingerprint if recheck else None, "check_id": recheck.check_id if recheck else None, "detail": result.get("detail")}
    if stop is not None:
        if recheck is not None:
            recheck.outcome, recheck.detail = "could_not_check", {**info, "stopped": stop.code}
        key = STOP_MESSAGES.get(stop.code, "internal_error")
        done(db, scan_id, token, "incomplete", stop.code, message=MESSAGES[key], stopped_step=state.current, recheck={**info, "outcome": "could_not_check"})
        return "incomplete"
    outcome = result.get("outcome")
    now = utc_now()
    if outcome == "absent" and state_row is not None:
        scan_row = db.get(Scan, scan_id)
        finding_states.mark_fixed_by_recheck(db, state_row, scan_row, now)
        recheck.outcome, recheck.detail = "fixed", info
        done(db, scan_id, token, "completed", "recheck_fixed", recheck={**info, "outcome": "fixed"})
        return "completed"
    if outcome == "present":
        if state_row is not None:
            state_row.last_seen_at = now
        recheck.outcome, recheck.detail = "still_open", info
        done(db, scan_id, token, "completed", "recheck_still_open", recheck={**info, "outcome": "still_open"})
        return "completed"
    recheck.outcome, recheck.detail = "could_not_check", info
    done(db, scan_id, token, "incomplete", "recheck_unconfirmed", recheck={**info, "outcome": "could_not_check"})
    return "incomplete"


def execute(scan_id: str, token: str, *, resolve=ip_policy.resolve_public, verify=ownership.ensure_verified,
            detect=None) -> str:
    """Run one claimed scan. Returns the final status. Never raises."""
    from app.db.session import SessionLocal
    from app.services import detect_runner
    began = time.monotonic()
    deadline = began + settings.scan_time_limit_seconds
    ready = None
    with SessionLocal() as db:
        try:
            scan = _owned(db, scan_id, token)
            if scan is None:
                return "lost_claim"
            deadline = began + time_limit_for(scan.scan_type)  # 15 minutes for a standard scan, 60 for a full scan
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
            if scan.scan_type == "full":  # re-checked at run time: the plan may have changed since it was requested
                try:
                    full_ok = bool(plans.get(owner.plan).get("full_port_scan")) and not is_test_target(website)
                except HTTPException:
                    full_ok = False
                if not full_ok:
                    _finish(db, scan_id, token, "refused", "plan_feature")
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
            if ":" in addresses[0]:   # only IPv6 addresses: not supported yet (clear message, nothing is contacted)
                _finish(db, scan_id, token, "refused", "ipv6_only")
                return "refused"
            # Resolved once; every later step of this scan may contact only this address.
            db.execute(update(Scan).where(Scan.id == scan_id, Scan.claim_token == token)
                       .values(resolved_ip=addresses[0]).execution_options(synchronize_session=False))
            db.commit()
            if time.monotonic() > deadline:
                _finish(db, scan_id, token, "incomplete", "time_limit")
                return "incomplete"
            ready = (website.id, website.domain, addresses[0], scan.scan_type,
                     {"ownership": reason, "all_addresses": addresses[:8]})
        except Exception:
            db.rollback()
            try:
                _finish(db, scan_id, token, "incomplete", "internal_error")
            except Exception:
                db.rollback()
            return "incomplete"

    website_id, domain, ip, scan_type, meta = ready
    if detect is None:
        if scan_type == "recheck":
            from app.services import recheck
            detect = recheck.run
        else:
            detect = detect_runner.run
    state = detect_runner.ScanState()
    ctx = detect_runner.ScanContext(scan_id=scan_id, domain=domain, ip=ip, scan_type=scan_type,
                                    progress=lambda step, message: _write_progress(scan_id, token, step, message))
    guard = ScanGuard(scan_id, token, deadline)
    try:
        asyncio.run(_drive(ctx, state, guard, detect))
        with SessionLocal() as db:
            if scan_type == "recheck":
                return _conclude_recheck(db, scan_id, token, website_id, state, guard)
            result = _conclude(db, scan_id, token, website_id, state, guard, meta)
            _after_full_scan(db, scan_id)
            return result
    except Exception:
        try:
            with SessionLocal() as db:
                _finish(db, scan_id, token, "incomplete", "internal_error", steps=state.steps)
        except Exception:
            pass
        return "incomplete"


class Worker:
    """Dispatcher for `python -m app.cli.operations scan-worker`. Run one scan-worker process."""

    def __init__(self):
        self.pool = ThreadPoolExecutor(max_workers=settings.scan_max_concurrent, thread_name_prefix="scan")
        if settings.nuclei_enabled:   # run the Nuclei self-test once at start-up, so the first scan does not pay for it
            import threading
            threading.Thread(target=self._warm_nuclei, daemon=True, name="nuclei-selftest").start()
        self.running = set()

    @staticmethod
    def _warm_nuclei():
        try:
            from app.services import nuclei_selftest
            asyncio.run(nuclei_selftest.ensure())
        except Exception:
            pass   # a failed or crashed self-test simply leaves the engine off

    def tick(self):
        from app.db.session import SessionLocal
        with SessionLocal() as db:
            engine.heartbeat(db, WORKER_NAME)
            db.commit()
            recover_expired(db)
        try:   # accepted risks whose period ended go back to Open (and are audit-logged)
            from app.services import finding_states
            with SessionLocal() as db:
                finding_states.expire_due(db)
                db.commit()
        except Exception:
            pass
        self.running = {f for f in self.running if not f.done()}
        while len(self.running) < settings.scan_max_concurrent:
            with SessionLocal() as db:
                claimed = claim(db)
            if not claimed:
                break
            self.running.add(self.pool.submit(execute, *claimed))

    def drain(self):
        self.pool.shutdown(wait=True)
