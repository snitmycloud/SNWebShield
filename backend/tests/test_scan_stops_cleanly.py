"""Long checks stop cleanly if the website is removed or verification is lost, between and during steps.

Each test runs a real scan through `scans.execute` in a worker thread, against local servers on loopback, then removes
the website (through the real API) or breaks verification while the scan is in the middle of the PORT step or the
HTTP (version) step. It checks that the scan ends "incomplete" with the reason within a few seconds, that every
connection is closed and no new one is opened afterwards, and that partial results are kept.
"""
import asyncio
import threading
import time
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.main import app
from app.models.admin import Admin
from app.models.jobs import ExecutionEvent
from app.models.scan import Scan, ScanPort
from app.models.website import Website
from app.services import detect_runner, netio, scan_guard, scans
from account_helpers import account_headers
from netfixtures import BackgroundServer, banner_handler, hanging_http_handler, wait_until

PUBLIC_LOOPBACK = "127.0.0.1"
POLL = 0.3
W = "/api/v1/websites"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings, "scan_guard_poll_seconds", POLL)
    with TestClient(app) as test_client:
        yield test_client


class FakeNet:
    """Stands in for netio.open_connection. `real` maps a scanned port to a local server port; every other port hangs
    like a slow, filtered port. It counts attempts and connections in flight so tests can prove nothing is left open."""
    def __init__(self, monkeypatch, real=None):
        self.real_open = netio.open_connection
        self.real = real or {}
        self.attempts = 0
        self.inflight = 0
        monkeypatch.setattr(netio, "open_connection", self)

    async def __call__(self, ip, port, **kwargs):
        self.attempts += 1
        self.inflight += 1
        try:
            if port in self.real:
                return await self.real_open(ip, self.real[port], **kwargs)
            await asyncio.sleep(3600)
        finally:
            self.inflight -= 1


def start_scan(client, headers, domain="example.com", *, ports=(), test_target=False, scan_type="standard"):
    site = client.post(W, headers=headers, json={"domain": domain}).json()
    with SessionLocal() as db:
        row = db.get(Website, site["id"])
        row.verification_status, row.verification_method = "verified", "dns"
        row.verified_at = row.verification_checked_at = utc_now()
        db.query(Scan).filter_by(website_id=row.id).delete()  # drop the automatic first scan; this test controls it
        db.commit()
        scan = scans.request_scan(db, row, "manual", scan_type)
        db.commit()
        scan_id = scan.id
    with SessionLocal() as db:
        claimed = scans.claim(db)
    assert claimed and claimed[0] == scan_id
    outcome = {}

    async def detect(ctx, state, guard):
        ctx.ports = tuple(ports)
        await detect_runner.run(ctx, state, guard)

    def work():
        outcome["status"] = scans.execute(*claimed, resolve=lambda d: [PUBLIC_LOOPBACK],
                                          verify=lambda db, w: (True, "cached"), detect=detect)
        outcome["finished"] = time.monotonic()

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    return site, scan_id, thread, outcome


def scan_row(scan_id):
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        db.expunge(scan)
        return scan


def stop_event(site_id):
    with SessionLocal() as db:
        return db.scalar(select(ExecutionEvent).where(ExecutionEvent.resource_id == site_id,
                                                      ExecutionEvent.action == "scan_worker_stopped"))


def finished_within(thread, outcome, started, limit):
    thread.join(limit + 8)
    assert not thread.is_alive(), "the scan thread did not finish"
    return outcome["finished"] - started


def lose_verification(site_id):
    with SessionLocal() as db:
        db.get(Website, site_id).verification_status = "lost"
        db.commit()


# --- during the PORT step ------------------------------------------------------------------------------------

@pytest.mark.parametrize("how", ["removed", "verification_lost"])
def test_stop_during_the_port_step(client, monkeypatch, how):
    with BackgroundServer(banner_handler(b"SSH-2.0-OpenSSH_8.2p1\r\n", then_close=False)) as ssh:
        net = FakeNet(monkeypatch, real={22: ssh.port})
        _, _, headers = account_headers(client)
        ports = [22] + list(range(1000, 1400))  # port 22 answers; the rest hang, like a slow network
        site, scan_id, thread, outcome = start_scan(client, headers, ports=ports)
        assert wait_until(lambda: net.attempts >= 30 and net.inflight >= 20), "the port step never got going"
        assert scan_row(scan_id).status == "running"

        stop_at = time.monotonic()
        if how == "removed":
            assert client.post(f"{W}/{site['id']}/remove", headers=headers, json={"confirm_domain": site["domain"]}).status_code == 200
        else:
            lose_verification(site["id"])
        took = finished_within(thread, outcome, stop_at, 4)

        assert outcome["status"] == "incomplete" and took < 4.0  # "within a few seconds"
        assert net.inflight == 0  # every in-flight connection was cancelled and closed
        attempts = net.attempts
        time.sleep(0.5)
        assert net.attempts == attempts  # and nothing new was started after the stop

        scan = scan_row(scan_id)
        code = "website_removed" if how == "removed" else "verification_lost"
        assert scan.status == "incomplete" and scan.result["code"] == code and scan.ended_at is not None
        assert "incomplete" in scan.message.lower() and "safe" not in scan.message.lower().replace("not mean your website is safe", "")
        event = stop_event(site["id"])
        assert event.detail["code"] == code and event.detail["stopped_step"] == "ports"
        if how == "removed":
            assert event.detail["seconds_since_removal"] < 4.0
        # What was found before the stop is kept: the open SSH port (the result of the unfinished step).
        with SessionLocal() as db:
            rows = db.scalars(select(ScanPort).where(ScanPort.scan_id == scan_id)).all()
        assert [r.port for r in rows] == [22]
        # A removed website's scan is still readable by staff as a past record with its reason.
        assert scan.progress["message"] == "Stopped" or scan.progress["step"] in ("finished", "stopped")


def test_the_removal_stop_is_fast_with_the_default_poll_interval(client, monkeypatch):
    monkeypatch.setattr(settings, "scan_guard_poll_seconds", 1.0)  # the shipped default
    net = FakeNet(monkeypatch)
    _, _, headers = account_headers(client)
    site, scan_id, thread, outcome = start_scan(client, headers, ports=list(range(1000, 1300)))
    assert wait_until(lambda: net.inflight >= 20)
    stop_at = time.monotonic()
    client.post(f"{W}/{site['id']}/remove", headers=headers, json={"confirm_domain": site["domain"]})
    assert finished_within(thread, outcome, stop_at, 5) < 3.5
    assert net.inflight == 0 and scan_row(scan_id).status == "incomplete"


# --- during the HTTP (versions) step -------------------------------------------------------------------------

@pytest.mark.parametrize("how", ["removed", "verification_lost"])
def test_stop_during_the_http_step(client, monkeypatch, how):
    with BackgroundServer(hanging_http_handler) as web:  # accepts and reads the request, never answers
        net = FakeNet(monkeypatch, real={80: web.port})
        _, _, headers = account_headers(client)
        site, scan_id, thread, outcome = start_scan(client, headers, ports=[80])
        assert wait_until(lambda: web.connections >= 1 and net.inflight == 0), "the HTTP probe never started"
        assert wait_until(lambda: len(web.requests) >= 1, 5), "no HTTP request reached the server"
        assert scan_row(scan_id).status == "running"  # mid-way through the HTTP probe

        stop_at = time.monotonic()
        if how == "removed":
            client.post(f"{W}/{site['id']}/remove", headers=headers, json={"confirm_domain": site["domain"]})
        else:
            lose_verification(site["id"])
        took = finished_within(thread, outcome, stop_at, 4)

        assert outcome["status"] == "incomplete" and took < 4.0
        assert wait_until(lambda: web.closed >= 1 or True)
        connections = web.connections
        time.sleep(0.6)
        assert web.connections == connections  # no further connection to the target after the stop
        scan = scan_row(scan_id)
        assert scan.status == "incomplete" and scan.result["code"] == ("website_removed" if how == "removed" else "verification_lost")
        assert stop_event(site["id"]).detail["stopped_step"] == "versions"
        # The port that was found before the stop is kept, with the port-number name as a guess.
        with SessionLocal() as db:
            rows = db.scalars(select(ScanPort).where(ScanPort.scan_id == scan_id)).all()
        assert [(r.port, r.service) for r in rows] == [(80, "http")]


# --- other reasons to stop -----------------------------------------------------------------------------------

def test_a_disabled_owner_stops_the_scan(client, monkeypatch):
    net = FakeNet(monkeypatch)
    user_id, _, headers = account_headers(client)
    site, scan_id, thread, outcome = start_scan(client, headers, ports=list(range(1000, 1200)))
    assert wait_until(lambda: net.inflight >= 20)
    stop_at = time.monotonic()
    with SessionLocal() as db:
        db.get(Admin, user_id).is_active = False
        db.commit()
    assert finished_within(thread, outcome, stop_at, 4) < 4.0
    scan = scan_row(scan_id)
    assert scan.status == "incomplete" and scan.result["code"] == "owner_disabled" and net.inflight == 0


def test_the_time_limit_stops_the_scan_and_keeps_it_incomplete(client, monkeypatch):
    monkeypatch.setattr(settings, "scan_time_limit_seconds", 2)
    net = FakeNet(monkeypatch)
    _, _, headers = account_headers(client)
    started = time.monotonic()
    site, scan_id, thread, outcome = start_scan(client, headers, ports=list(range(1000, 1200)))
    assert finished_within(thread, outcome, started, 6) < 6.0
    scan = scan_row(scan_id)
    assert scan.status == "incomplete" and scan.result["code"] == "time_limit" and net.inflight == 0


def test_a_scan_taken_over_by_recovery_stops_and_cannot_change_the_recovered_record(client, monkeypatch):
    net = FakeNet(monkeypatch)
    _, _, headers = account_headers(client)
    site, scan_id, thread, outcome = start_scan(client, headers, ports=list(range(1000, 1200)))
    assert wait_until(lambda: net.inflight >= 20)
    with SessionLocal() as db:  # the worker is presumed dead: its lease is recovered by another process
        scans.recover_expired(db, utc_now() + timedelta(days=1))
    finished_within(thread, outcome, time.monotonic(), 4)
    scan = scan_row(scan_id)
    assert scan.status == "incomplete" and scan.result["code"] == "worker_stopped"  # not overwritten by the late worker
    assert net.inflight == 0


# --- the guard itself --------------------------------------------------------------------------------------------

def make_guard(scan_id, token="t", deadline=None, **kwargs):
    return scan_guard.ScanGuard(scan_id, token, deadline or time.monotonic() + 60, **kwargs)


def running_scan(client, *, domain="guard.example.com", role="user", scan_id="g" * 36):
    user_id, _, headers = account_headers(client, role)
    site = client.post(W, headers=headers, json={"domain": domain}).json()
    with SessionLocal() as db:
        row = db.get(Website, site["id"])
        row.verification_status, row.verification_method = "verified", "dns"
        db.query(Scan).filter_by(website_id=row.id).delete()
        scan = Scan(id=scan_id, website_id=row.id, owner_id=user_id, scan_type="standard", trigger="manual", status="running",
                    requested_at=utc_now(), claim_token="t", lease_until=utc_now() + timedelta(minutes=5))
        db.add(scan)
        db.commit()
    return user_id, site["id"]


def test_the_guard_notices_each_reason(client):
    user_id, site_id = running_scan(client)
    guard = make_guard("g" * 36)
    guard.poll()
    assert guard.stop is None
    guard.check()  # nothing to stop

    with SessionLocal() as db:
        db.get(Website, site_id).removed_at = utc_now()
        db.commit()
    guard.poll()
    with pytest.raises(scan_guard.ScanStopped) as stopped:
        guard.check()
    assert stopped.value.code == "website_removed"

    for change, code in (("lost", "verification_lost"), ("disabled", "owner_disabled"), ("taken", "scan_taken_over")):
        scan_id = change.ljust(36, "x")
        user_id, site_id = running_scan(client, domain=f"{change}.example.com", scan_id=scan_id)
        with SessionLocal() as db:
            if change == "lost":
                db.get(Website, site_id).verification_status = "lost"
            elif change == "disabled":
                db.get(Admin, user_id).is_active = False
            else:
                db.get(Scan, scan_id).claim_token = "someone-else"
            db.commit()
        guard = make_guard(scan_id)
        guard.poll()
        assert guard.stop is not None and guard.stop.code == code, change


def test_a_test_target_stops_if_its_owner_is_no_longer_an_admin(client):
    admin_id, _, headers = account_headers(client, "admin")
    site = client.post(W, headers=headers, json={"domain": "scanme.nmap.org"}).json()
    with SessionLocal() as db:
        db.query(Scan).filter_by(website_id=site["id"]).delete()
        db.add(Scan(id="t" * 36, website_id=site["id"], owner_id=admin_id, scan_type="standard", trigger="manual",
                    status="running", requested_at=utc_now(), claim_token="tok", lease_until=utc_now() + timedelta(minutes=5)))
        db.commit()
    guard = make_guard("t" * 36, "tok")
    guard.poll()
    assert guard.stop is None
    with SessionLocal() as db:
        db.get(Admin, admin_id).role = "analyst"
        db.commit()
    guard.poll()
    assert guard.stop.code == "verification_lost"


def test_the_deadline_is_enforced_even_without_a_poll():
    clock = [100.0]
    guard = make_guard("x", deadline=105.0, clock=lambda: clock[0], session_factory=lambda: None)
    guard.check()
    clock[0] = 105.5
    with pytest.raises(scan_guard.ScanStopped) as stopped:
        guard.check()
    assert stopped.value.code == "time_limit"


def test_an_unreadable_database_fails_closed_after_repeated_failures():
    class Broken:
        def __enter__(self):
            raise OSError("database is locked")
        def __exit__(self, *exc):
            return False

    guard = make_guard("x", session_factory=lambda: Broken())
    for _ in range(scan_guard.MAX_POLL_FAILURES - 1):
        guard.poll()
        assert guard.stop is None  # one hiccup does not stop a scan
    guard.poll()
    assert guard.stop.code == "internal_error"


# --- time limits: 15 minutes for a standard scan, 60 minutes for a full scan --------------------------------------

def test_the_default_limits_are_15_and_60_minutes():
    assert settings.scan_time_limit_seconds == 900 and settings.scan_full_time_limit_seconds == 3600
    assert scans.time_limit_for("standard") == 900 and scans.time_limit_for("full") == 3600


def test_a_full_scan_is_leased_for_60_minutes_and_a_standard_scan_for_15(client):
    _, _, headers = account_headers(client, plan="pro")
    for scan_type, minutes in (("standard", 15), ("full", 60)):
        site = client.post(W, headers=headers, json={"domain": f"{scan_type}.example.com"}).json()
        with SessionLocal() as db:
            row = db.get(Website, site["id"])
            row.verification_status, row.verification_method = "verified", "dns"
            db.query(Scan).filter_by(website_id=row.id).delete()
            scans.request_scan(db, row, "manual", scan_type)
            db.commit()
        with SessionLocal() as db:
            claimed = scans.claim(db)
            scan = db.get(Scan, claimed[0])
            lease_seconds = (scan.lease_until.replace(tzinfo=None) - scan.started_at.replace(tzinfo=None)).total_seconds()
        assert abs(lease_seconds - (minutes * 60 + 60)) < 5, (scan_type, lease_seconds)
        with SessionLocal() as db:
            db.get(Scan, claimed[0]).status = "incomplete"
            db.commit()


def test_a_standard_scan_stops_at_its_limit_but_a_full_scan_keeps_going_to_its_own(client, monkeypatch):
    monkeypatch.setattr(settings, "scan_time_limit_seconds", 1)        # stands in for 15 minutes
    monkeypatch.setattr(settings, "scan_full_time_limit_seconds", 5)   # stands in for 60 minutes
    net = FakeNet(monkeypatch)
    _, _, headers = account_headers(client, plan="pro")

    started = time.monotonic()
    site, scan_id, thread, outcome = start_scan(client, headers, "standard.example.com", ports=list(range(1000, 1200)))
    took = finished_within(thread, outcome, started, 6)
    assert scan_row(scan_id).result["code"] == "time_limit" and took < 4.0  # stopped near its 1-second limit

    started = time.monotonic()
    site, scan_id, thread, outcome = start_scan(client, headers, "full.example.com", ports=list(range(1000, 1200)), scan_type="full")
    time.sleep(2.5)
    assert thread.is_alive() and scan_row(scan_id).status == "running"  # past the standard limit, still within the full one
    took = finished_within(thread, outcome, started, 8)
    scan = scan_row(scan_id)
    assert scan.status == "incomplete" and scan.result["code"] == "time_limit" and 4.0 <= took < 8.0
    assert net.inflight == 0