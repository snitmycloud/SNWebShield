"""Scan safety (fail closed): verified owner only, one IP, refused addresses, limits, time limit, audit."""
from datetime import timedelta
import ipaddress
import time

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.models.admin import Admin
from app.models.jobs import ExecutionEvent
from app.models.scan import Scan
from app.models.website import Website
from app.services import ip_policy, scans
from account_helpers import make_account

PUBLIC = "93.184.216.34"


def verified_site(domain="example.com", owner=None, status="verified"):
    owner = owner or make_account()[0]
    with SessionLocal() as db:
        website = Website(owner_id=owner, domain=domain, name=domain, url=f"https://{domain}/", environment="production",
                          verification_token="t" * 32, verification_method="dns", verification_status=status,
                          verified_at=utc_now(), verification_checked_at=utc_now())
        db.add(website)
        db.commit()
        return website.id, owner


def queue(website_id, trigger="first"):
    with SessionLocal() as db:
        scan = scans.request_scan(db, db.get(Website, website_id), trigger)
        db.commit()
        return scan.id


def run(scan_id, **kwargs):
    with SessionLocal() as db:
        claimed = scans.claim(db)
    assert claimed and claimed[0] == scan_id
    status = scans.execute(*claimed, **kwargs)
    with SessionLocal() as db:
        return status, db.get(Scan, scan_id)


allow = lambda db, website: (True, "cached")


# --- Address policy ------------------------------------------------------------------------------

@pytest.mark.parametrize("address", [
    "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "127.0.0.1", "169.254.169.254", "169.254.1.1",
    "100.64.0.1", "100.127.255.255", "224.0.0.1", "0.0.0.0", "255.255.255.255", "::1", "fc00::1", "fd12::1",
    "fe80::1", "::ffff:10.0.0.1", "::ffff:8.8.8.8", "100.100.100.200", "fd00:ec2::254", "2001:db8::1",
])
def test_private_loopback_link_local_multicast_and_metadata_addresses_are_refused(address):
    assert ip_policy.refusal_reason(address, own=set()) is not None


@pytest.mark.parametrize("address", [PUBLIC, "103.53.43.114", "2606:4700::1111"])
def test_public_addresses_are_allowed(address):
    assert ip_policy.refusal_reason(address, own=set()) is None


def test_the_servers_own_address_is_refused(monkeypatch):
    monkeypatch.setattr(settings, "server_public_ips", PUBLIC)
    assert ip_policy.refusal_reason(PUBLIC) == "server_own_address"


def test_one_private_answer_refuses_the_whole_host(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", lambda host, *a, **k: [
        (2, 1, 6, "", (PUBLIC, 443)), (2, 1, 6, "", ("10.0.0.5", 443))] if host == "mixed.example.com" else [])
    with pytest.raises(ip_policy.Blocked) as refused:
        ip_policy.resolve_public("mixed.example.com")
    assert refused.value.code == "private_or_reserved_address"


def test_ipv4_is_preferred_for_the_single_scan_address(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", lambda host, *a, **k: [
        (23, 1, 6, "", ("2606:4700::1111", 443, 0, 0)), (2, 1, 6, "", (PUBLIC, 443))] if host == "dual.example.com" else [])
    assert ip_policy.resolve_public("dual.example.com")[0] == PUBLIC


# --- Requests ------------------------------------------------------------------------------------

@pytest.mark.parametrize("status", ["unverified", "lost"])
def test_only_verified_websites_can_be_queued(status):
    website_id, _ = verified_site(status=status)
    with SessionLocal() as db, pytest.raises(Exception) as refused:
        scans.request_scan(db, db.get(Website, website_id), "first")
    assert getattr(refused.value, "status_code", None) == 409


def test_one_active_scan_per_website():
    website_id, owner = verified_site()
    first, second = queue(website_id), queue(website_id, "manual")
    assert first == second
    with SessionLocal() as db, pytest.raises(IntegrityError):  # the database enforces it too
        db.add(Scan(id="x" * 36, website_id=website_id, owner_id=owner, scan_type="standard", trigger="manual",
                    status="queued", requested_at=utc_now()))
        db.commit()


def test_at_most_the_configured_number_of_scans_run_at_once(monkeypatch):
    monkeypatch.setattr(settings, "scan_max_concurrent", 3)
    ids = [queue(verified_site(f"s{n}.example.com")[0]) for n in range(5)]
    with SessionLocal() as db:
        claimed = [scans.claim(db) for _ in range(5)]
    assert [c[0] for c in claimed if c] == ids[:3] and claimed[3:] == [None, None]


# --- Execution -----------------------------------------------------------------------------------

def test_successful_start_pins_one_public_ip_and_never_claims_safe():
    website_id, owner = verified_site()
    scan_id = queue(website_id)
    status, scan = run(scan_id, resolve=lambda d: [PUBLIC, "2606:4700::1111"], verify=allow)
    assert status == "incomplete" and scan.status == "incomplete" and scan.resolved_ip == PUBLIC
    assert scan.result["code"] == "checks_not_available"
    assert "does not mean your website is safe" in scan.message
    assert scan.started_at and scan.ended_at and scan.claim_token is None


def test_every_scan_writes_an_audit_record():
    website_id, owner = verified_site()
    scan_id = queue(website_id)
    run(scan_id, resolve=lambda d: [PUBLIC], verify=allow)
    with SessionLocal() as db:
        events = {e.action: e for e in db.scalars(select(ExecutionEvent).where(ExecutionEvent.resource_id == website_id))}
    assert {"scan_requested", "scan_started", "scan_finished"} <= set(events)
    detail = events["scan_finished"].detail
    assert detail["user_id"] == owner and detail["website_id"] == website_id and detail["ip"] == PUBLIC
    assert detail["scan_type"] == "standard" and detail["start"] and detail["end"] and detail["result"] == "incomplete"


@pytest.mark.parametrize("code", ["private_or_reserved_address", "cloud_metadata_address", "server_own_address",
                                  "dns_lookup_failed"])
def test_refused_addresses_stop_the_scan(code):
    website_id, _ = verified_site()
    def resolve(domain):
        raise ip_policy.Blocked(code)
    status, scan = run(queue(website_id), resolve=resolve, verify=allow)
    assert status == "refused" and scan.result["code"] == code and scan.resolved_ip is None and scan.message


def test_lost_verification_refuses_and_pauses():
    website_id, _ = verified_site()
    def lost(db, website):
        website.verification_status = "lost"
        return False, "verification_lost"
    resolved = []
    status, scan = run(queue(website_id), resolve=lambda d: resolved.append(d) or [PUBLIC], verify=lost)
    assert status == "refused" and scan.result["code"] == "verification_lost" and resolved == []
    with SessionLocal() as db:
        assert db.get(Website, website_id).verification_status == "lost"
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "verification_lost")) is not None


def test_ownership_that_cannot_be_rechecked_refuses_the_scan():
    website_id, _ = verified_site()
    status, scan = run(queue(website_id), resolve=lambda d: [PUBLIC], verify=lambda db, w: (False, "could_not_recheck"))
    assert status == "refused" and scan.result["code"] == "could_not_recheck"


def test_disabled_owner_or_changed_owner_refuses_the_scan():
    website_id, owner = verified_site()
    scan_id = queue(website_id)
    with SessionLocal() as db:
        db.get(Admin, owner).is_active = False
        db.commit()
    status, scan = run(scan_id, resolve=lambda d: [PUBLIC], verify=allow)
    assert status == "refused" and scan.result["code"] == "owner_mismatch"

    website_id, owner = verified_site("other.example.com")
    scan_id = queue(website_id)
    with SessionLocal() as db:
        db.get(Website, website_id).owner_id = make_account()[0]
        db.commit()
    status, scan = run(scan_id, resolve=lambda d: [PUBLIC], verify=allow)
    assert status == "refused" and scan.result["code"] == "owner_mismatch"


def test_time_limit_makes_the_result_incomplete(monkeypatch):
    monkeypatch.setattr(settings, "scan_time_limit_seconds", 30)
    website_id, _ = verified_site()
    scan_id = queue(website_id)
    clock = [time.monotonic()]
    monkeypatch.setattr(scans.time, "monotonic", lambda: clock[0])
    def slow(domain):
        clock[0] += 31
        return [PUBLIC]
    status, scan = run(scan_id, resolve=slow, verify=allow)
    assert status == "incomplete" and scan.result["code"] == "time_limit"


def test_unexpected_error_is_incomplete_not_clean():
    website_id, _ = verified_site()
    def broken(domain):
        raise RuntimeError("boom")
    status, scan = run(queue(website_id), resolve=broken, verify=allow)
    assert status == "incomplete" and scan.result["code"] == "internal_error"


def test_a_dead_worker_leaves_the_scan_incomplete():
    website_id, _ = verified_site()
    scan_id = queue(website_id)
    with SessionLocal() as db:
        scans.claim(db)
        assert scans.recover_expired(db, utc_now()) == 0
        assert scans.recover_expired(db, utc_now() + timedelta(seconds=settings.scan_time_limit_seconds + 61)) == 1
        scan = db.get(Scan, scan_id)
        assert scan.status == "incomplete" and scan.result["code"] == "worker_stopped"


def test_a_late_result_cannot_overwrite_a_recovered_scan():
    website_id, _ = verified_site()
    scan_id = queue(website_id)
    with SessionLocal() as db:
        claimed = scans.claim(db)
        scans.recover_expired(db, utc_now() + timedelta(days=1))
    assert scans.execute(*claimed, resolve=lambda d: [PUBLIC], verify=allow) == "lost_claim"
    with SessionLocal() as db:
        assert db.get(Scan, scan_id).result["code"] == "worker_stopped"


def test_worker_tick_runs_queued_scans_and_beats(monkeypatch):
    from app.models.jobs import WorkerHeartbeat
    website_id, _ = verified_site()
    scan_id = queue(website_id)
    original = scans.execute
    monkeypatch.setattr(scans, "execute", lambda sid, tok: original(sid, tok, resolve=lambda d: [PUBLIC], verify=allow))
    worker = scans.Worker()
    worker.tick()
    worker.drain()
    with SessionLocal() as db:
        assert db.get(Scan, scan_id).status == "incomplete"
        assert db.get(WorkerHeartbeat, scans.WORKER_NAME) is not None
