"""Scheduled scans by plan (spec section 7): weekly on Free, daily on Pro and Business.

Staggering: every website has its own fixed slot inside its plan's period, worked out from its id, so scans do not all start at the
same moment. A scheduled scan is queued like any scan (`scans.request_scan(..., "scheduled")`): only a verified website of an active
account, one active scan per website, the test target's 10-a-day limit counts scheduled scans too, and the scan worker re-checks the
owner, the verification and the resolved IP right before it runs. One website failing never stops the others.
"""
from datetime import datetime, timedelta, UTC
import hashlib

from fastapi import HTTPException
from sqlalchemy import select

from app.core.config import settings
from app.core.time import as_utc, utc_now
from app.models.admin import Admin
from app.models.scan import Scan
from app.models.website import Website
from app.services import plans, scans

DEFAULT_HOURS = {"weekly": 168, "daily": 24}


def interval_seconds(account: Admin) -> int:
    plan = plans.get(account.plan)
    hours = plan.get("scan_interval_hours") or DEFAULT_HOURS.get(plan.get("automatic_scan"), 168)
    return int(hours) * 3600


def offset_seconds(website_id: int, interval: int) -> int:
    digest = hashlib.sha256(f"snwebshield-slot-{website_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % interval


def slot_start(now: datetime, interval: int, offset: int) -> datetime:
    """The most recent moment at or before `now` that belongs to this website's slot."""
    epoch = now.timestamp()
    k = int((epoch - offset) // interval)
    return datetime.fromtimestamp(k * interval + offset, UTC)


def next_slot(now: datetime, interval: int, offset: int) -> datetime:
    return slot_start(now, interval, offset) + timedelta(seconds=interval)


def last_scan_time(db, website_id: int):
    scan = db.scalar(select(Scan).where(Scan.website_id == website_id, Scan.scan_type != "recheck").order_by(Scan.requested_at.desc()).limit(1))
    return as_utc(scan.requested_at) if scan else None


def is_due(db, website: Website, account: Admin, now: datetime) -> bool:
    interval = interval_seconds(account)
    last = last_scan_time(db, website.id)
    if last is None:
        return False   # the first scan is started by ownership verification, never by the schedule
    start = slot_start(now, interval, offset_seconds(website.id, interval))
    return last < start and (now - last).total_seconds() >= interval / 2   # not twice in a row just because a slot passed


def next_scan_at(db, website: Website, account: Admin, now: datetime | None = None) -> datetime | None:
    """When the next automatic scan is expected (None when scans are paused)."""
    now = now or utc_now()
    if website.verification_status != "verified" or website.removed_at is not None:
        return None
    interval = interval_seconds(account)
    offset = offset_seconds(website.id, interval)
    if is_due(db, website, account, now):
        return now
    last = last_scan_time(db, website.id)
    start = slot_start(now, interval, offset)
    nxt = start if (last is None or last < start) else start + timedelta(seconds=interval)
    if last is not None and (nxt - last).total_seconds() < interval / 2:
        nxt += timedelta(seconds=interval)
    return nxt


def run_due(db, now: datetime | None = None, limit: int | None = None) -> dict:
    """Queue the scheduled scans that are due. At most `limit` per call, so a restart after downtime does not start everything at once."""
    now = now or utc_now()
    limit = limit or settings.scheduled_scans_per_tick
    result = {"queued": 0, "skipped": 0, "errors": 0}
    sites = db.scalars(select(Website).where(Website.verification_status == "verified", Website.removed_at.is_(None),
                                             Website.owner_id.is_not(None), Website.domain.is_not(None)).order_by(Website.id))
    for website in list(sites):
        if result["queued"] >= limit:
            break
        try:
            owner = db.get(Admin, website.owner_id)
            if not settings.monitor_may_touch(website.domain):
                continue
            if owner is None or not owner.is_active or not is_due(db, website, owner, now):
                continue
            if scans.active_scan(db, website.id) is not None:
                continue
            scans.request_scan(db, website, "scheduled", "standard")
            db.commit()
            result["queued"] += 1
        except HTTPException:   # limit reached, verification lapsed, ...: leave it, try again next time
            db.rollback()
            result["skipped"] += 1
        except Exception:
            db.rollback()
            result["errors"] += 1
    return result
