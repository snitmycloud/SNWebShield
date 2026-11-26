"""The 24-hour vulnerability cache: fresh, refreshed, stale-only-adds, failure, single flight, prune."""
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from app.db.session import SessionLocal
from app.models.scan import VulnCache
from app.services import vuln_cache, vuln_sources

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)
DATA = {"advisories": [{"id": "CVE-2020-0001"}], "truncated": False}


def counted(result=None, error=None):
    calls = []

    def fetch():
        calls.append(1)
        if error:
            raise vuln_sources.SourceError(error)
        return result if result is not None else DATA
    return fetch, calls


def test_first_look_up_fetches_and_stores():
    fetch, calls = counted()
    result = vuln_cache.get(SessionLocal, "nvd", "k1", fetch, now=NOW)
    assert result.state == "fetched" and result.advisories == DATA["advisories"] and len(calls) == 1 and result.usable_for_none
    with SessionLocal() as db:
        row = db.query(VulnCache).one()
        assert row.key == "k1" and row.error_count == 0 and row.payload == DATA


def test_a_fresh_entry_is_used_without_any_request():
    fetch, calls = counted()
    vuln_cache.get(SessionLocal, "nvd", "k1", fetch, now=NOW)
    again = vuln_cache.get(SessionLocal, "nvd", "k1", fetch, now=NOW + timedelta(hours=23))
    assert again.state == "fresh" and len(calls) == 1


def test_an_expired_entry_is_refreshed():
    fetch, calls = counted()
    vuln_cache.get(SessionLocal, "nvd", "k1", fetch, now=NOW)
    newer = {"advisories": [], "truncated": False}
    fetch2, calls2 = counted(newer)
    result = vuln_cache.get(SessionLocal, "nvd", "k1", fetch2, now=NOW + timedelta(hours=25))
    assert result.state == "fetched" and result.advisories == [] and len(calls2) == 1


def test_when_the_refresh_fails_old_data_is_stale_and_cannot_support_a_none_conclusion():
    fetch, _ = counted()
    vuln_cache.get(SessionLocal, "nvd", "k1", fetch, now=NOW)
    broken, _ = counted(error="timeout")
    result = vuln_cache.get(SessionLocal, "nvd", "k1", broken, now=NOW + timedelta(days=3))
    assert result.state == "stale" and result.reason == "timeout" and result.advisories == DATA["advisories"]
    assert result.fetched_at == NOW and not result.usable_for_none
    with SessionLocal() as db:
        row = db.query(VulnCache).one()
        assert row.error_count == 1 and row.last_error == "timeout" and row.payload == DATA  # the old data is kept


def test_no_data_and_a_failed_fetch_is_failed_never_empty():
    broken, _ = counted(error="http_500")
    result = vuln_cache.get(SessionLocal, "nvd", "never-seen", broken, now=NOW)
    assert result.state == "failed" and result.reason == "http_500" and result.advisories == [] and not result.usable_for_none


def test_a_truncated_answer_never_supports_none():
    fetch, _ = counted({"advisories": [], "truncated": True})
    assert not vuln_cache.get(SessionLocal, "nvd", "big", fetch, now=NOW).usable_for_none


def test_sources_and_keys_are_separate():
    a, ca = counted()
    b, cb = counted()
    vuln_cache.get(SessionLocal, "nvd", "same", a, now=NOW)
    vuln_cache.get(SessionLocal, "osv", "same", b, now=NOW)
    assert len(ca) == len(cb) == 1


def test_two_scans_asking_at_once_cause_one_request():
    started = []

    def slow():
        started.append(1)
        time.sleep(0.5)
        return DATA
    results = []

    def ask():
        results.append(vuln_cache.get(SessionLocal, "nvd", "shared", slow, now=NOW))
    threads = [threading.Thread(target=ask) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert len(started) == 1 and len(results) == 4 and {r.state for r in results} <= {"fetched", "fresh"}


def test_old_unused_entries_are_pruned_and_recent_ones_kept():
    fetch, _ = counted()
    vuln_cache.get(SessionLocal, "nvd", "old", fetch, now=NOW - timedelta(days=40))
    vuln_cache.get(SessionLocal, "nvd", "recent", fetch, now=NOW - timedelta(days=3))
    assert vuln_cache.prune(SessionLocal, now=NOW) == 1
    with SessionLocal() as db:
        assert [r.key for r in db.query(VulnCache)] == ["recent"]


def test_the_cache_holds_no_scan_or_website_data():
    columns = {c.name for c in VulnCache.__table__.columns}
    assert not any(word in name for name in columns for word in ("scan", "website", "user", "domain", "ip"))
