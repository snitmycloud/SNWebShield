"""Stops a running scan cleanly when it must no longer run.

While a scan runs, a watcher re-reads the database every `scan_guard_poll_seconds` (and `check()` is called at the
start of every step and before every batch of work). The scan is stopped if:

* the website was removed (`website_removed`),
* ownership verification is no longer valid, or a test target's owner is no longer an active admin (`verification_lost`),
* the owner's account was disabled (`owner_disabled`),
* the scan was taken over, e.g. ended by a removal or recovered after a worker crash (`scan_taken_over`),
* the total time limit has passed (`time_limit`),
* the database cannot be read for several polls in a row (`internal_error`: fail closed).

Stopping cancels the running step, which closes its connections, so nothing further is contacted.
"""
import asyncio
import time

from app.core.config import settings
from app.core.time import as_utc, utc_now
from app.models.admin import Admin
from app.models.scan import Scan
from app.models.website import Website

MAX_POLL_FAILURES = 5


class ScanStopped(Exception):
    def __init__(self, code: str, detail: dict | None = None):
        self.code, self.detail = code, detail or {}
        super().__init__(code)


class ScanGuard:
    def __init__(self, scan_id: str, token: str, deadline: float, *, session_factory=None, clock=time.monotonic,
                 poll_seconds: float | None = None):
        if session_factory is None:
            from app.db.session import SessionLocal
            session_factory = SessionLocal
        self.scan_id, self.token, self.deadline = scan_id, token, deadline
        self._sessions, self._clock = session_factory, clock
        self.poll_seconds = poll_seconds if poll_seconds is not None else settings.scan_guard_poll_seconds
        self.stop: ScanStopped | None = None
        self.stopped_at: float | None = None
        self._failures = 0

    # -- checks -------------------------------------------------------------------------------
    def check(self) -> None:
        """Raise ScanStopped if the scan must stop. Cheap: uses what the watcher last saw, and the clock."""
        if self.stop is None and self._clock() > self.deadline:
            self._set(ScanStopped("time_limit"))
        if self.stop is not None:
            raise self.stop

    def poll(self) -> None:
        """Re-read the database (synchronous; run it in a thread from async code)."""
        if self.stop is not None:
            return
        try:
            with self._sessions() as db:
                reason = self._reason(db)
            self._failures = 0
        except Exception:
            self._failures += 1
            reason = ScanStopped("internal_error", {"why": "database_unreadable"}) if self._failures >= MAX_POLL_FAILURES else None
        if reason is not None:
            self._set(reason)

    def _reason(self, db) -> ScanStopped | None:
        scan = db.get(Scan, self.scan_id)
        website = db.get(Website, scan.website_id) if scan else None
        if website is not None and website.removed_at is not None:
            return ScanStopped("website_removed", {"removed_at": as_utc(website.removed_at).isoformat()})
        if scan is None or scan.status != "running" or scan.claim_token != self.token:
            return ScanStopped("scan_taken_over", {"status": scan.status if scan else None,
                                                   "code": (scan.result or {}).get("code") if scan else None})
        owner = db.get(Admin, scan.owner_id)
        if owner is None or not owner.is_active or website is None or website.owner_id != scan.owner_id:
            return ScanStopped("owner_disabled")
        if website.verification_status != "verified":
            return ScanStopped("verification_lost")
        from app.services import ownership
        if ownership.manual_expired(website):
            return ScanStopped("verification_lost")
        if website.verification_method == "test_target" and (
                website.domain not in settings.approved_test_targets or owner.role != "admin"):
            return ScanStopped("verification_lost")
        return None

    def _set(self, stop: ScanStopped) -> None:
        if self.stop is None:
            self.stop, self.stopped_at = stop, self._clock()

    # -- watching -----------------------------------------------------------------------------
    async def watch(self, work: "asyncio.Task") -> None:
        """Poll until the work finishes; if it must stop, cancel the work (which closes its connections)."""
        while not work.done():
            await asyncio.sleep(self.poll_seconds)
            if work.done():
                return
            await asyncio.to_thread(self.poll)
            if self.stop is None and self._clock() > self.deadline:
                self._set(ScanStopped("time_limit"))
            if self.stop is not None:
                work.cancel()
                return


def stop_latency_seconds(stop: ScanStopped) -> float | None:
    """Seconds between the website being removed and now, when the stop was caused by a removal."""
    removed = stop.detail.get("removed_at")
    if stop.code != "website_removed" or not removed:
        return None
    from datetime import datetime
    return round((utc_now() - as_utc(datetime.fromisoformat(removed))).total_seconds(), 2)
