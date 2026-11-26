"""24-hour shared cache of vulnerability-database answers (table `vuln_cache`). Public data only: a software name and
version mapped to the advisories published for it. No scan, website or user data is stored here.

Rules that keep the cache from ever turning a failure into "safe":
* fresh entry (younger than the TTL)      -> used as is;
* expired entry + the database answers     -> refreshed;
* expired entry + the database is down     -> the OLD entry is used ONLY to add findings, flagged with its date. It is never
                                              used to conclude "no problems"; the step is still reported as "could not check";
* no entry + the database is down          -> state "failed": the caller reports "could not check".
One look-up per key at a time (single flight): two scans asking for the same product get one network request.
Entries unused for 30 days are removed by `prune()`.
"""
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.models.scan import VulnCache
from app.services import vuln_sources

PRUNE_DAYS = 30
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


@dataclass
class CacheResult:
    state: str                       # fresh | fetched | stale | failed
    data: dict | None = None         # {"advisories": [...], "truncated": bool}
    fetched_at: datetime | None = None
    reason: str | None = None        # why a refresh failed
    advisories: list = field(default_factory=list)

    @property
    def usable_for_none(self) -> bool:
        """May the caller say 'no known vulnerabilities in this database'? Only for fresh data."""
        return self.state in ("fresh", "fetched") and not (self.data or {}).get("truncated")


def _aware(value):
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _lock_for(key: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(key, threading.Lock())


def get(sessions, source: str, key: str, fetch, *, deadline: float | None = None, now: datetime | None = None) -> CacheResult:
    """`fetch()` performs the network look-up and returns the normalized dict. Blocking: call it from a thread."""
    clock = now or datetime.now(timezone.utc)
    full_key = f"{source}:{key}"

    def read():
        with sessions() as db:
            row = db.query(VulnCache).filter_by(source=source, key=key).one_or_none()
            if row is None or row.payload is None:
                return None
            row.last_used_at = clock
            db.commit()
            return row.payload, _aware(row.fetched_at), _aware(row.expires_at)

    cached = read()
    if cached and cached[2] and cached[2] > clock:
        return CacheResult("fresh", cached[0], cached[1], advisories=cached[0].get("advisories", []))
    with _lock_for(full_key):
        cached = read()  # another scan may have refreshed it while we waited
        if cached and cached[2] and cached[2] > clock:
            return CacheResult("fresh", cached[0], cached[1], advisories=cached[0].get("advisories", []))
        try:
            data = fetch()
        except vuln_sources.SourceError as error:
            _record_failure(sessions, source, key, error.reason, clock)
            if cached:
                return CacheResult("stale", cached[0], cached[1], error.reason, cached[0].get("advisories", []))
            return CacheResult("failed", None, None, error.reason)
        with sessions() as db:
            row = db.query(VulnCache).filter_by(source=source, key=key).one_or_none()
            if row is None:
                row = VulnCache(source=source, key=key)
                db.add(row)
            row.payload, row.fetched_at = data, clock
            row.expires_at = clock + timedelta(hours=settings.vuln_cache_hours)
            row.last_attempt_at = row.last_used_at = clock
            row.error_count, row.last_error = 0, None
            db.commit()
        return CacheResult("fetched", data, clock, advisories=data.get("advisories", []))


def _record_failure(sessions, source, key, reason, clock) -> None:
    with sessions() as db:
        row = db.query(VulnCache).filter_by(source=source, key=key).one_or_none()
        if row is None:
            row = VulnCache(source=source, key=key, error_count=0)
            db.add(row)
        row.last_attempt_at = clock
        row.error_count = (row.error_count or 0) + 1
        row.last_error = str(reason)[:200]
        db.commit()


def prune(sessions, now: datetime | None = None) -> int:
    clock = now or datetime.now(timezone.utc)
    cutoff = clock - timedelta(days=PRUNE_DAYS)
    with sessions() as db:
        rows = db.query(VulnCache).all()
        old = [r for r in rows if (_aware(r.last_used_at) or _aware(r.fetched_at) or _aware(r.last_attempt_at) or clock) < cutoff]
        for row in old:
            db.delete(row)
        db.commit()
        return len(old)
