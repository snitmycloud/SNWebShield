"""The life of a finding across scans (spec section 6): Open, Fixed (and how it was confirmed) and Accepted risk (with an expiry).

Rules (owner-approved):
* A finding is identified by its fingerprint (check id + location), so it is the same finding in every scan of a website.
* **Fixed** only when a later scan, or a recheck, finished the check that produces it and did not find it. If that check could not
  finish, the finding simply stays open ("could not confirm"): a failed or timed-out check never turns into "fixed". Fixed records
  how it was confirmed: `recheck` or `full_scan`. If a later full scan finds it again it is reopened.
* **Accepted risk**: only the website's owner, with a typed reason and a period of 30, 90 (default), 180 or 365 days. The finding
  stays listed but is not counted in the score. 7 days before the end it shows "Review soon". When the period ends it goes back to Open
  by itself, counts in the score again and the expiry is written to the audit log. The owner can accept it again with a new reason.
"""
from datetime import timedelta

from sqlalchemy import select

from app.core.time import as_utc, utc_now
from app.models.scan import FindingState, ScanFinding
from app.services import job_engine as engine

ACCEPT_DAYS = (30, 90, 180, 365)
DEFAULT_ACCEPT_DAYS = 90
REVIEW_SOON_DAYS = 7
REASON_MIN, REASON_MAX = 10, 300

# check id prefix -> the scan step that produces such findings. A finding can only be called fixed if this step finished OK.
_STEP_BY_PREFIX = (
    ("port:", "configuration"), ("exposed:", "configuration"), ("tls:", "configuration"), ("header:", "configuration"),
    ("cookie:", "configuration"), ("cors:", "configuration"), ("http:", "configuration"), ("cdn:", "configuration"),
    ("disclosure:version-hidden", "vulnerabilities"), ("disclosure:", "configuration"),
    ("cve-more:", "vulnerabilities"), ("cve:", "vulnerabilities"), ("eol:", "lifecycle"),
    ("nuclei-panel", "nuclei"), ("nuclei:", "nuclei"),
)
# Findings that only the owner's own action can change are never offered a recheck: the grouped Info line of login pages.
NOT_RECHECKABLE = ("nuclei-panels", "cve-more:")


class StateError(Exception):
    """A refused request, with a plain message for the owner."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def step_for(check_id: str) -> str | None:
    for prefix, step in _STEP_BY_PREFIX:
        if check_id.startswith(prefix):
            return step
    return None


def step_finished_ok(steps: dict | None, check_id: str) -> bool:
    step = step_for(check_id)
    return bool(step) and (steps or {}).get(step, {}).get("state") == "ok"


def recheckable(check_id: str, severity: str | None = None) -> bool:
    return step_for(check_id) is not None and not any(check_id.startswith(p) for p in NOT_RECHECKABLE)


# --- reading --------------------------------------------------------------------------------------------------------------------------------------

def states_for(db, website_id: int) -> dict[str, FindingState]:
    return {s.fingerprint: s for s in db.scalars(select(FindingState).where(FindingState.website_id == website_id))}


def accepted_active(state: FindingState | None, now=None) -> bool:
    return bool(state and state.status == "open" and state.accepted_until and as_utc(state.accepted_until) > (now or utc_now()))


def view(state: FindingState | None, now=None) -> dict:
    """The part of a finding the screen needs: its status and the details behind it."""
    now = now or utc_now()
    if state is None:
        return {"status": "open", "first_seen_at": None, "reopened": False}
    base = {"first_seen_at": as_utc(state.first_seen_at).isoformat() if state.first_seen_at else None,
            "reopened": bool(state.reopened_count), "reopened_at": as_utc(state.reopened_at).isoformat() if state.reopened_at else None}
    if state.status == "fixed":
        return {**base, "status": "fixed", "fixed_at": as_utc(state.fixed_at).isoformat() if state.fixed_at else None,
                "fixed_how": state.fixed_how, "fixed_scan_id": state.fixed_scan_id}
    if accepted_active(state, now):
        until = as_utc(state.accepted_until)
        days_left = max(0, (until - now).days)
        return {**base, "status": "accepted", "accepted": {
            "reason": state.accepted_reason, "by_id": state.accepted_by_id, "at": as_utc(state.accepted_at).isoformat() if state.accepted_at else None,
            "days": state.accepted_days, "until": until.isoformat(), "days_left": days_left,
            "review_soon": (until - now) <= timedelta(days=REVIEW_SOON_DAYS)}}
    return {**base, "status": "open"}


# --- changes ---------------------------------------------------------------------------------------------------------------------------------------

def _upsert_seen(db, website_id: int, row: ScanFinding, scan, state: FindingState | None, now):
    if state is None:
        state = FindingState(website_id=website_id, fingerprint=row.fingerprint, check_id=row.check_id, title=row.title, location=row.location,
                             severity=row.severity, status="open", first_seen_scan_id=scan.id, first_seen_at=now)
        db.add(state)
    state.check_id, state.title, state.location, state.severity = row.check_id, row.title, row.location, row.severity
    state.last_seen_scan_id, state.last_seen_at = scan.id, now
    return state


def refresh_from_scan(db, scan, now=None) -> dict:
    """Update every finding state of the scan's website after a full scan: new findings are recorded, findings seen again are kept
    (or reopened if they had been called fixed), and findings that disappeared are called fixed ONLY if their step finished OK."""
    now = now or utc_now()
    steps = (scan.result or {}).get("steps") or {}
    rows = list(db.scalars(select(ScanFinding).where(ScanFinding.scan_id == scan.id)))
    states = states_for(db, scan.website_id)
    seen = set()
    changes = {"new": 0, "reopened": 0, "fixed": 0, "could_not_confirm": 0}
    for row in rows:
        seen.add(row.fingerprint)
        state = states.get(row.fingerprint)
        was_new = state is None
        was_fixed = state is not None and state.status == "fixed"
        state = _upsert_seen(db, scan.website_id, row, scan, state, now)
        if was_new:
            changes["new"] += 1
        if was_fixed:
            state.status, state.fixed_at, state.fixed_scan_id, state.fixed_how = "open", None, None, None
            state.reopened_at, state.reopened_count = now, (state.reopened_count or 0) + 1
            changes["reopened"] += 1
            engine.event(db, "finding_reopened", resource_id=scan.website_id, actor_id=None,
                         detail={"fingerprint": row.fingerprint, "check_id": row.check_id, "scan_id": scan.id})
    for fingerprint, state in states.items():
        if fingerprint in seen or state.status != "open":
            continue
        if step_finished_ok(steps, state.check_id):
            state.status, state.fixed_at, state.fixed_scan_id, state.fixed_how = "fixed", as_utc(scan.ended_at or now), scan.id, "full_scan"
            _clear_acceptance(state)
            changes["fixed"] += 1
            engine.event(db, "finding_fixed", resource_id=scan.website_id, actor_id=None,
                         detail={"fingerprint": fingerprint, "check_id": state.check_id, "how": "full_scan", "scan_id": scan.id})
        else:
            changes["could_not_confirm"] += 1
    expire_due(db, website_id=scan.website_id, now=now)
    db.flush()
    return changes


def mark_fixed_by_recheck(db, state: FindingState, scan, now=None) -> None:
    now = now or utc_now()
    state.status, state.fixed_at, state.fixed_scan_id, state.fixed_how = "fixed", now, scan.id, "recheck"
    _clear_acceptance(state)
    engine.event(db, "finding_fixed", resource_id=state.website_id, actor_id=None,
                 detail={"fingerprint": state.fingerprint, "check_id": state.check_id, "how": "recheck", "scan_id": scan.id})


def _clear_acceptance(state: FindingState) -> None:
    state.accepted_reason = state.accepted_by_id = state.accepted_at = state.accepted_days = state.accepted_until = None


# --- risk acceptance ----------------------------------------------------------------------------------------------------------------------------------

def ensure_state(db, website_id: int, fingerprint: str) -> FindingState:
    """The state of a finding from the website's most recent scan that listed it (created on demand for scans that predate states)."""
    state = db.scalar(select(FindingState).where(FindingState.website_id == website_id, FindingState.fingerprint == fingerprint))
    if state is not None:
        return state
    from app.models.scan import Scan
    row = db.scalar(select(ScanFinding).join(Scan, Scan.id == ScanFinding.scan_id)
                    .where(Scan.website_id == website_id, ScanFinding.fingerprint == fingerprint, Scan.scan_type != "recheck")
                    .order_by(Scan.requested_at.desc()).limit(1))
    if row is None:
        raise StateError("finding_not_found", "That finding was not found on this website.")
    scan = db.get(Scan, row.scan_id)
    return _upsert_seen(db, website_id, row, scan, None, as_utc(scan.ended_at or scan.requested_at))


def accept(db, website, owner, fingerprint: str, reason: str, days: int = DEFAULT_ACCEPT_DAYS, now=None) -> FindingState:
    """Only the owner. Reason 10-300 characters; period 30, 90, 180 or 365 days."""
    now = now or utc_now()
    if owner is None or owner.id != website.owner_id or not owner.is_active:
        raise StateError("not_owner", "Only the owner of this website can accept a risk.")
    reason = (reason or "").strip()
    if not REASON_MIN <= len(reason) <= REASON_MAX:
        raise StateError("bad_reason", f"Please give a reason of {REASON_MIN} to {REASON_MAX} characters.")
    if days not in ACCEPT_DAYS:
        raise StateError("bad_days", "Choose 30, 90, 180 or 365 days.")
    state = ensure_state(db, website.id, fingerprint)
    if state.status == "fixed":
        raise StateError("already_fixed", "This finding is already fixed, so there is nothing to accept.")
    renewing = accepted_active(state, now)
    state.accepted_reason, state.accepted_by_id, state.accepted_at = reason, owner.id, now
    state.accepted_days, state.accepted_until = days, now + timedelta(days=days)
    engine.event(db, "risk_accepted", resource_id=website.id, actor_id=owner.id, detail={
        "fingerprint": fingerprint, "check_id": state.check_id, "reason": reason, "days": days, "until": state.accepted_until.isoformat(),
        "renewed": renewing, "domain": website.domain})
    db.flush()
    return state


def unaccept(db, website, owner, fingerprint: str, now=None) -> FindingState:
    now = now or utc_now()
    if owner is None or owner.id != website.owner_id or not owner.is_active:
        raise StateError("not_owner", "Only the owner of this website can change an accepted risk.")
    state = db.scalar(select(FindingState).where(FindingState.website_id == website.id, FindingState.fingerprint == fingerprint))
    if state is None or not accepted_active(state, now):
        raise StateError("not_accepted", "This finding is not marked as an accepted risk.")
    engine.event(db, "risk_unaccepted", resource_id=website.id, actor_id=owner.id, detail={
        "fingerprint": fingerprint, "check_id": state.check_id, "reason": state.accepted_reason, "domain": website.domain})
    _clear_acceptance(state)
    db.flush()
    return state


def expire_due(db, website_id: int | None = None, now=None) -> int:
    """Accepted risks whose period ended go back to Open (and count in the score again). Each one is audit-logged."""
    now = now or utc_now()
    query = select(FindingState).where(FindingState.accepted_until.is_not(None), FindingState.accepted_until <= now)
    if website_id is not None:
        query = query.where(FindingState.website_id == website_id)
    expired = list(db.scalars(query))
    for state in expired:
        engine.event(db, "risk_acceptance_expired", resource_id=state.website_id, actor_id=state.accepted_by_id, detail={
            "fingerprint": state.fingerprint, "check_id": state.check_id, "reason": state.accepted_reason, "days": state.accepted_days,
            "until": as_utc(state.accepted_until).isoformat()})
        _clear_acceptance(state)
    if expired:
        db.flush()
    return len(expired)
