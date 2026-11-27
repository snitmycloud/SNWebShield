"""Phase 5 (MONITOR): scheduled scans, uptime checks, alerts, score trend, supervisor and worker health."""
import asyncio
from datetime import timedelta
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.main import app
from app.models.admin import Admin
from app.models.jobs import ExecutionEvent, WorkerHeartbeat
from app.models.scan import FindingState, Scan, ScanPort
from app.models.watch import Alert, AlertPreference, ScoreHistory, UptimeCheck, UptimeState
from app.models.website import Website
from app.services import alerts, ip_policy, plans, scans, scheduling, uptime, worker_health
from account_helpers import account_headers, outbox_messages
from netfixtures import BackgroundServer, http_handler, server_tls

W = "/api/v1/websites"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def verified_site(client, plan="pro", domain=None, role="user"):
    """An account with one verified website (no scan yet)."""
    account_id, email, headers = account_headers(client, role=role, plan=plan)
    domain = domain or f"site-{uuid.uuid4().hex[:8]}.example.com"
    site = client.post(W, headers=headers, json={"domain": domain}).json()
    with SessionLocal() as db:
        row = db.get(Website, site["id"])
        row.verification_status, row.verification_method = "verified", "dns"
        row.verified_at = row.verification_checked_at = utc_now()
        db.query(Scan).filter_by(website_id=row.id).delete()
        db.commit()
    return account_id, email, headers, site["id"], domain


def add_scan(site_id, owner_id, *, when, status="completed", steps=None, trigger="manual", scan_type="standard"):
    with SessionLocal() as db:
        scan = Scan(id=str(uuid.uuid4()), website_id=site_id, owner_id=owner_id, scan_type=scan_type, trigger=trigger, status=status,
                    requested_at=when, started_at=when, ended_at=when, result={"steps": steps or {"ports": {"state": "ok"}, "configuration": {"state": "ok"}}})
        db.add(scan)
        db.commit()
        return scan.id


def inbox(email):
    return [m for m in outbox_messages(email)]


# --- scheduled scans ---------------------------------------------------------------------------------------------------------------------------

def test_plans_set_weekly_for_free_and_daily_for_pro_and_business():
    assert [plans.get(p)["scan_interval_hours"] for p in ("free", "pro", "business")] == [168, 24, 24]


def test_every_website_gets_its_own_slot_so_scans_do_not_start_together():
    interval = 24 * 3600
    offsets = {scheduling.offset_seconds(i, interval) for i in range(1, 200)}
    assert len(offsets) > 150 and all(0 <= o < interval for o in offsets)
    now = utc_now()
    start = scheduling.slot_start(now, interval, 1234)
    assert start <= now < start + timedelta(seconds=interval)


def test_a_due_website_is_queued_once_and_not_again_until_its_next_slot(client):
    owner, _, _, site, _ = verified_site(client, plan="pro")
    now = utc_now()
    add_scan(site, owner, when=now - timedelta(days=3))
    with SessionLocal() as db:
        assert scheduling.run_due(db, now)["queued"] == 1
        queued = db.scalars(select(Scan).where(Scan.website_id == site, Scan.trigger == "scheduled")).all()
        assert len(queued) == 1 and queued[0].status == "queued"
        assert scheduling.run_due(db, now)["queued"] == 0   # one active scan per website; and it was just scanned


def test_free_is_weekly_a_scan_two_days_ago_is_not_due(client):
    owner, _, _, site, _ = verified_site(client, plan="free")
    add_scan(site, owner, when=utc_now() - timedelta(days=2))
    with SessionLocal() as db:
        assert scheduling.run_due(db)["queued"] == 0
    add_scan(site, owner, when=utc_now() - timedelta(days=9))   # an older scan does not matter: the newest counts
    with SessionLocal() as db:
        assert scheduling.run_due(db)["queued"] == 0


def test_schedule_skips_unverified_removed_lost_and_inactive_accounts_and_first_scan(client):
    cases = {}
    for name in ("unverified", "lost", "inactive", "removed", "never_scanned"):
        owner, _, _, site, _ = verified_site(client, plan="pro")
        cases[name] = (owner, site)
        if name != "never_scanned":
            add_scan(site, owner, when=utc_now() - timedelta(days=5))
    with SessionLocal() as db:
        db.get(Website, cases["unverified"][1]).verification_status = "unverified"
        db.get(Website, cases["lost"][1]).verification_status = "lost"
        db.get(Admin, cases["inactive"][0]).is_active = False
        db.get(Website, cases["removed"][1]).removed_at = utc_now()
        db.commit()
        scheduling.run_due(db, utc_now(), limit=100)
        queued = {w for w in db.scalars(select(Scan.website_id).where(Scan.trigger == "scheduled"))}
    assert not queued & {site for _, site in cases.values()}


def test_scheduled_scans_count_against_the_test_target_limit(client, monkeypatch):
    target = settings.approved_test_targets[0]
    owner, _, _, site, _ = verified_site(client, plan="pro", domain=target, role="admin")
    with SessionLocal() as db:
        db.get(Website, site).verification_method = "test_target"
        db.commit()
    add_scan(site, owner, when=utc_now() - timedelta(days=3))
    from app.core import config
    monkeypatch.setattr(config, "TEST_TARGET_SCANS_PER_DAY", 0)
    with SessionLocal() as db:
        result = scheduling.run_due(db)
        assert result["queued"] == 0 and result["skipped"] >= 1
        assert not db.scalars(select(Scan).where(Scan.website_id == site, Scan.trigger == "scheduled")).all()


def test_a_scheduling_failure_for_one_website_does_not_stop_the_others(client, monkeypatch):
    first, _, _, a, _ = verified_site(client, plan="pro")
    second, _, _, b, _ = verified_site(client, plan="pro")
    for owner, site in ((first, a), (second, b)):
        add_scan(site, owner, when=utc_now() - timedelta(days=4))
    real = scans.request_scan

    def flaky(db, website, trigger, scan_type="standard"):
        if website.id == a:
            raise RuntimeError("boom")
        return real(db, website, trigger, scan_type)
    monkeypatch.setattr(scans, "request_scan", flaky)
    with SessionLocal() as db:
        result = scheduling.run_due(db, utc_now(), limit=100)
        assert result["errors"] >= 1 and db.scalars(select(Scan).where(Scan.website_id == b, Scan.trigger == "scheduled")).first() is not None


def test_a_restart_after_downtime_queues_only_a_few_scans_per_round(client):
    ids = []
    for _ in range(4):
        owner, _, _, site, _ = verified_site(client, plan="pro")
        add_scan(site, owner, when=utc_now() - timedelta(days=5))
        ids.append(site)
    with SessionLocal() as db:
        assert scheduling.run_due(db, utc_now(), limit=2)["queued"] == 2


def test_the_website_page_shows_when_the_next_automatic_scan_is_expected(client):
    owner, _, headers, site, _ = verified_site(client, plan="pro")
    add_scan(site, owner, when=utc_now() - timedelta(hours=1))
    data = client.get(f"{W}/{site}", headers=headers).json()
    assert data["schedule"]["every_hours"] == 24 and data["schedule"]["next_scan_at"]


# --- uptime ------------------------------------------------------------------------------------------------------------------------------------

def run(coro):
    return asyncio.run(coro)


def local_probe(server_port, *, tls=False):
    async def checker(domain):
        return await uptime.probe(domain, resolve=lambda d: ["127.0.0.1"], timeout=2, ports=((server_port, True), (server_port, False)) if tls else ((1, True), (server_port, False)))
    return checker


def test_probe_ok_for_2xx_and_for_404_but_not_for_5xx_or_no_answer(monkeypatch):
    from app.services import netio
    real_open = netio.open_connection

    async def closed_ports_refuse_at_once(ip, port, **kwargs):   # ports 1 and 2 stand for closed ports (a real closed local port takes about 2 s per try on Windows)
        if port in (1, 2):
            raise ConnectionRefusedError("connection refused")
        return await real_open(ip, port, **kwargs)
    monkeypatch.setattr(netio, "open_connection", closed_ports_refuse_at_once)
    with BackgroundServer(http_handler({"/": (200, {}, b"hi")})) as up, BackgroundServer(http_handler({}, default=(404, {}, b"x"))) as notfound,             BackgroundServer(http_handler({"/": (503, {}, b"x")})) as broken:
        for port, expected in ((up.port, True), (notfound.port, True), (broken.port, False)):
            result = run(uptime.probe("example.com", resolve=lambda d: ["127.0.0.1"], timeout=2, ports=((1, True), (port, False))))
            assert result["ok"] is expected, result
            assert result["response_ms"] is not None or not expected
    closed = run(uptime.probe("example.com", resolve=lambda d: ["127.0.0.1"], timeout=1, ports=((1, True), (2, False))))
    assert closed["ok"] is False and closed["error"]


def test_probe_refuses_private_addresses_and_does_not_call_that_down():
    result = run(uptime.probe("example.com", resolve=lambda d: (_ for _ in ()).throw(ip_policy.Blocked("private_or_reserved_address")), timeout=1))
    assert result["ok"] is None and result["error"].startswith("blocked_")
    gone = run(uptime.probe("example.com", resolve=lambda d: (_ for _ in ()).throw(ip_policy.Blocked("dns_lookup_failed")), timeout=1))
    assert gone["ok"] is False and gone["error"] == "dns_lookup_failed"


def test_probe_reads_the_certificate_over_https():
    pages = {"/": (200, {}, b"hi")}
    with BackgroundServer(http_handler(pages), tls=True, tls_context=server_tls) as server:
        result = run(uptime.probe("test.snwebshield.example", resolve=lambda d: ["127.0.0.1"], timeout=3, ports=((server.port, True), (1, False))))
    assert result["ok"] is True and result["scheme"] == "https" and result["cert"]["not_after"]


def checker_for(results):
    answers = iter(results)

    async def checker(domain):
        return next(answers)
    return checker


def test_two_failures_in_a_row_mean_down_one_alert_then_back_up_alert(client):
    owner, email, headers, site, domain = verified_site(client, plan="pro")
    t0 = utc_now()
    fail, good = {"ok": False, "error": "timeout", "scheme": "https"}, {"ok": True, "status_code": 200, "response_ms": 80, "scheme": "https"}
    with SessionLocal() as db:
        uptime.tick(db, t0, checker=checker_for([fail]))
        assert db.get(UptimeState, site).is_down is False and not inbox(email)   # one failure is not enough
        uptime.tick(db, t0 + timedelta(minutes=6), checker=checker_for([fail]))
        assert db.get(UptimeState, site).is_down is True
    down = [m for m in inbox(email) if "down" in m["Subject"]]
    assert len(down) == 1 and domain in down[0]["Subject"]
    with SessionLocal() as db:   # still failing: the same alert is not sent again
        uptime.tick(db, t0 + timedelta(minutes=12), checker=checker_for([fail]))
        assert len([m for m in inbox(email) if "down" in m["Subject"]]) == 1
        uptime.tick(db, t0 + timedelta(minutes=18), checker=checker_for([good]))
        state = db.get(UptimeState, site)
        assert state.is_down is False and state.consecutive_failures == 0
    assert len([m for m in inbox(email) if "back up" in m["Subject"]]) == 1
    summary_site = client.get(f"{W}/{site}", headers=headers).json()["uptime"]
    assert summary_site["status"] == "up" and summary_site["uptime_30d"] is not None


def test_a_blocked_check_is_unknown_not_down(client):
    owner, email, _, site, _ = verified_site(client, plan="pro")
    with SessionLocal() as db:
        for minutes in (0, 6, 12):
            uptime.tick(db, utc_now() + timedelta(minutes=minutes), checker=checker_for([{"ok": None, "error": "blocked_private_or_reserved_address"}]))
        assert db.get(UptimeState, site).is_down is False
    assert not inbox(email)


def test_uptime_runs_every_5_minutes_and_every_30_for_the_test_target(client):
    owner, _, _, normal, _ = verified_site(client, plan="pro")
    target = settings.approved_test_targets[0]
    _, _, _, special, _ = verified_site(client, plan="pro", domain=target, role="admin")
    with SessionLocal() as db:
        db.get(Website, special).verification_method = "test_target"
        db.commit()
    t0 = utc_now()
    good = {"ok": True, "status_code": 200, "response_ms": 5, "scheme": "https"}

    async def checker(domain):
        return good
    with SessionLocal() as db:
        uptime.tick(db, t0, checker=checker)
        before = db.query(UptimeCheck).count()
        for minutes, expect_normal, expect_special in ((3, 0, 0), (6, 1, 0), (31, 1, 1)):
            n0 = {w: db.query(UptimeCheck).filter_by(website_id=w).count() for w in (normal, special)}
            uptime.tick(db, t0 + timedelta(minutes=minutes), checker=checker)
            n1 = {w: db.query(UptimeCheck).filter_by(website_id=w).count() for w in (normal, special)}
            if minutes == 3:
                assert n1 == n0
            if minutes == 6:
                assert n1[normal] == n0[normal] + 1 and n1[special] == n0[special]
        assert before >= 2


def test_uptime_only_checks_verified_websites_and_never_counts_against_scan_limits(client):
    owner, _, _, site, _ = verified_site(client, plan="free")
    _, _, _, other, _ = verified_site(client, plan="free")
    with SessionLocal() as db:
        db.get(Website, other).verification_status = "unverified"
        db.commit()
        checked = []

        async def checker(domain):
            checked.append(domain)
            return {"ok": True, "status_code": 200, "response_ms": 1, "scheme": "https"}
        uptime.tick(db, utc_now(), checker=checker)
        assert db.get(UptimeState, other) is None
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action.in_(("scan_requested", "manual_scan_requested")), ExecutionEvent.resource_id == site)) is None


def test_the_certificate_is_read_once_a_day_and_alerts_within_14_days(client):
    owner, email, _, site, domain = verified_site(client, plan="pro")
    t0 = utc_now()
    soon = (t0 + timedelta(days=9)).isoformat()
    good = {"ok": True, "status_code": 200, "response_ms": 5, "scheme": "https", "cert": {"not_after": soon, "subject_cn": domain}}
    with SessionLocal() as db:
        uptime.tick(db, t0, checker=checker_for([good]))
        state = db.get(UptimeState, site)
        assert state.cert_not_after is not None and state.cert_checked_at is not None
        first_read = state.cert_checked_at
        uptime.tick(db, t0 + timedelta(hours=1), checker=checker_for([good]))     # same day: not read again
        assert db.get(UptimeState, site).cert_checked_at == first_read
    assert len([m for m in inbox(email) if "certificate" in m["Subject"].lower()]) == 1
    with SessionLocal() as db:   # a day later it is read again, but the same alert is not repeated within 24 hours of the first
        uptime.tick(db, t0 + timedelta(hours=25), checker=checker_for([good]))
    far = {**good, "cert": {"not_after": (t0 + timedelta(days=90)).isoformat(), "subject_cn": domain}}
    _, email2, _, site2, _ = verified_site(client, plan="pro")
    with SessionLocal() as db:
        uptime.tick(db, t0, checker=checker_for([far, far]))
    assert not [m for m in inbox(email2) if "certificate" in m["Subject"].lower()]


# --- alerts --------------------------------------------------------------------------------------------------------------------------------------

def make_alert(client, plan="pro", **kw):
    owner, email, headers, site, domain = verified_site(client, plan=plan)
    with SessionLocal() as db:
        website = db.get(Website, site)
        record = alerts.raise_alert(db, website, "site_down_up", "k1", headline="Your website is down", what="It did not answer.", do="Check your server.", **kw)
        db.commit()
        record = None if record is None else type("Sent", (), {"delivered": record.delivered, "id": record.id})()
    return owner, email, headers, site, domain, record


def test_an_alert_email_is_plain_language_with_name_what_to_do_link_and_unsubscribe(client):
    _, email, _, site, domain, record = make_alert(client)
    assert record is not None and record.delivered
    [message] = inbox(email)
    body = message.get_content()
    assert domain in message["Subject"]
    assert "What to do:" in body and f"/#/websites/{site}" in body
    assert "/#/settings/alerts/site_down_up" in body and "Turn off this kind of alert" in body


def test_the_same_alert_is_sent_at_most_once_per_24_hours(client):
    owner, email, _, site, _, first = make_alert(client)
    with SessionLocal() as db:
        website = db.get(Website, site)
        again = alerts.raise_alert(db, website, "site_down_up", "k1", headline="x", what="y", do="z")
        other_key = alerts.raise_alert(db, website, "site_down_up", "k2", headline="x", what="y", do="z")
        later = alerts.raise_alert(db, website, "site_down_up", "k1", headline="x", what="y", do="z", now=utc_now() + timedelta(hours=25))
        db.commit()
    assert first and again is None and other_key is not None and later is not None
    assert len(inbox(email)) == 3


def test_a_user_can_turn_an_alert_type_off_and_on(client):
    owner, email, headers, site, _ = verified_site(client)
    assert all(a["enabled"] for a in client.get("/api/v1/alerts/preferences", headers=headers).json()["alerts"])
    assert client.put("/api/v1/alerts/preferences/site_down_up", headers=headers, json={"enabled": False}).status_code == 200
    with SessionLocal() as db:
        assert alerts.raise_alert(db, db.get(Website, site), "site_down_up", "k", headline="h", what="w", do="d") is None
        assert alerts.raise_alert(db, db.get(Website, site), "verification_lost", "k", headline="h", what="w", do="d") is not None
        db.commit()
    assert client.put("/api/v1/alerts/preferences/site_down_up", headers=headers, json={"enabled": True}).status_code == 200
    assert client.put("/api/v1/alerts/preferences/nonsense", headers=headers, json={"enabled": True}).status_code == 404
    with SessionLocal() as db:
        assert db.query(AlertPreference).filter_by(account_id=owner, alert_type="site_down_up").one().enabled is True


def test_only_the_owner_gets_the_alert_and_not_for_removed_or_disabled_accounts(client):
    owner, email, _, site, _ = verified_site(client)
    other_id, other_email, _ = account_headers(client)
    with SessionLocal() as db:
        alerts.raise_alert(db, db.get(Website, site), "verification_lost", "k", headline="h", what="w", do="d")
        db.get(Admin, owner).is_active = False
        db.commit()
        assert alerts.raise_alert(db, db.get(Website, site), "site_down_up", "k", headline="h", what="w", do="d") is None
    assert len(inbox(email)) == 1 and not inbox(other_email)


def test_a_test_alert_goes_to_the_outbox_and_is_limited(client):
    _, email, headers = account_headers(client)
    for _ in range(5):
        assert client.post("/api/v1/alerts/test", headers=headers).json()["sent"] is True
    assert client.post("/api/v1/alerts/test", headers=headers).status_code == 429
    assert len(inbox(email)) == 5


def add_port(scan_id, port):
    with SessionLocal() as db:
        db.add(ScanPort(scan_id=scan_id, port=port, state="open", service="x"))
        db.commit()


def add_finding(scan_id, *, severity="high", confidence="confirmed", check_id="port:1234", title="Something serious"):
    from app.models.scan import ScanFinding
    import hashlib
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        db.add(ScanFinding(scan_id=scan_id, fingerprint=hashlib.sha256(check_id.encode()).hexdigest(), kind="exposure", check_id=check_id,
                           title=title, location="example.com", port=None, severity=severity, confidence=confidence, group="findings" if confidence == "confirmed" else "needs_checking",
                           you_have="a", you_should_have="b", why="c", how_to_fix="d", sources=["snwebshield"], details={}))
        db.commit()


def test_new_open_port_and_new_serious_finding_alerts_compare_with_the_previous_scan(client):
    owner, email, _, site, domain = verified_site(client, plan="pro")
    t0 = utc_now() - timedelta(days=2)
    first = add_scan(site, owner, when=t0)
    add_port(first, 80)
    add_finding(first, severity="high", check_id="exposed:o:/old", title="Old problem")
    with SessionLocal() as db:
        assert alerts.after_scan(db, db.get(Scan, first)) == {"ports": 0, "findings": 0}   # the first scan raises nothing
    second = add_scan(site, owner, when=t0 + timedelta(days=1))
    for port in (80, 8080):
        add_port(second, port)
    add_finding(second, severity="high", check_id="exposed:o:/old", title="Old problem")
    add_finding(second, severity="critical", check_id="exposed:n:/new", title="Brand new problem")
    add_finding(second, severity="low", check_id="exposed:m:/minor", title="Minor thing")
    add_finding(second, severity="critical", confidence="possible", check_id="exposed:p:/maybe", title="Maybe")
    with SessionLocal() as db:
        result = alerts.after_scan(db, db.get(Scan, second))
        db.commit()
        assert result == {"ports": 1, "findings": 1}
        assert alerts.after_scan(db, db.get(Scan, second)) == {"ports": 0, "findings": 0}   # same alerts, no repeat
    subjects = " | ".join(m["Subject"] for m in inbox(email))
    assert "8080" in subjects and "serious finding" in subjects
    body = "\n".join(m.get_content() for m in inbox(email))
    assert "Brand new problem" in body and "Minor thing" not in body and "Maybe" not in body and "/findings/" in body


def test_no_port_alert_when_the_port_step_did_not_finish(client):
    owner, email, _, site, _ = verified_site(client, plan="pro")
    t0 = utc_now() - timedelta(days=2)
    first = add_scan(site, owner, when=t0)
    second = add_scan(site, owner, when=t0 + timedelta(days=1), steps={"ports": {"state": "could_not_check"}})
    add_port(second, 9999)
    with SessionLocal() as db:
        assert alerts.after_scan(db, db.get(Scan, second))["ports"] == 0


def test_verification_lost_alert_and_accepted_risk_expiring_alert(client):
    owner, email, _, site, domain = verified_site(client, plan="pro")
    with SessionLocal() as db:
        db.get(Website, site).verification_status = "lost"
        db.commit()
        assert alerts.sweep_verification_lost(db) == 1
        assert alerts.sweep_verification_lost(db) == 0   # not twice in 24 hours
        db.commit()
    assert any("no longer prove" in m["Subject"] for m in inbox(email))
    owner2, email2, _, site2, _ = verified_site(client, plan="pro")
    first = add_scan(site2, owner2, when=utc_now() - timedelta(days=1))
    add_finding(first, check_id="exposed:x:/y", title="Exposed thing")
    with SessionLocal() as db:
        from app.services import finding_states
        row = db.get(Scan, first)
        fp = db.scalar(select(__import__("app.models.scan", fromlist=["ScanFinding"]).ScanFinding.fingerprint).where(__import__("app.models.scan", fromlist=["ScanFinding"]).ScanFinding.scan_id == first))
        finding_states.accept(db, db.get(Website, site2), db.get(Admin, owner2), fp, "We accept this for now, it is fine.", 30)
        state = db.query(FindingState).one() if db.query(FindingState).count() == 1 else db.query(FindingState).filter_by(website_id=site2).one()
        state.accepted_until = utc_now() + timedelta(days=5)
        db.commit()
        assert alerts.sweep_risk_expiring(db) == 1 and alerts.sweep_risk_expiring(db) == 0
        db.commit()
    assert any("accepted risk" in m["Subject"].lower() for m in inbox(email2))


def test_alerts_are_not_sent_on_a_plan_without_email_alerts(client, monkeypatch):
    owner, email, _, site, _ = verified_site(client, plan="free")
    real = plans.get
    monkeypatch.setattr(plans, "get", lambda name: {**real(name), "alerts": []})
    with SessionLocal() as db:
        assert alerts.raise_alert(db, db.get(Website, site), "site_down_up", "k", headline="h", what="w", do="d") is None


# --- score trend -------------------------------------------------------------------------------------------------------------------------------

def test_trend_lists_the_score_after_each_scan_oldest_first_and_fills_in_older_scans(client):
    owner, _, headers, site, _ = verified_site(client, plan="pro")
    t0 = utc_now() - timedelta(days=3)
    first = add_scan(site, owner, when=t0)
    add_finding(first, severity="high", check_id="exposed:a:/a")
    second = add_scan(site, owner, when=t0 + timedelta(days=1))
    points = client.get(f"{W}/{site}/trend", headers=headers).json()["points"]
    assert [p["scan_id"] for p in points] == [first, second]
    assert points[0]["score"] == 90 and points[1]["score"] == 100 and points[0]["grade"] == "A"
    with SessionLocal() as db:
        assert db.query(ScoreHistory).filter_by(website_id=site).count() == 2
    _, _, other = account_headers(client)
    assert client.get(f"{W}/{site}/trend", headers=other).status_code == 404


def test_the_score_is_recorded_when_a_full_scan_finishes(client):
    owner, _, _, site, _ = verified_site(client, plan="pro")
    scan_id = add_scan(site, owner, when=utc_now())
    with SessionLocal() as db:
        scans._after_full_scan(db, scan_id)
        assert db.query(ScoreHistory).filter_by(scan_id=scan_id).count() == 1


# --- worker health (admin page) ---------------------------------------------------------------------------------------------------------------

def beat(name, seconds_ago, detail=None):
    with SessionLocal() as db:
        row = db.get(WorkerHeartbeat, name)
        when = utc_now() - timedelta(seconds=seconds_ago)
        if row is None:
            db.add(WorkerHeartbeat(name=name, seen_at=when, detail=detail))
        else:
            row.seen_at, row.detail = when, detail
        db.commit()


def test_worker_health_page_is_admin_only_and_uses_the_server_clock(client):
    _, _, user_headers = account_headers(client)
    assert client.get("/api/v1/admin/workers", headers=user_headers).status_code == 403
    _, _, admin_headers = account_headers(client, role="admin")
    beat("scan-worker", 5)
    beat("monitor", 300)
    beat("supervisor", 3, {"roles": {"scan-worker": {"state": "running", "pid": 11, "restarts": 2}, "monitor": {"state": "running", "pid": 12, "restarts": 0}}})
    body = client.get("/api/v1/admin/workers", headers=admin_headers).json()
    roles = {r["role"]: r for r in body["roles"]}
    assert roles["scan-worker"]["state"] == "running" and roles["scan-worker"]["restarts"] == 2 and roles["scan-worker"]["pid"] == 11
    assert roles["monitor"]["state"] == "stale"            # no beat for 5 minutes: not running, whatever its process says
    assert roles["supervisor"]["state"] == "running" and roles["api"]["state"] == "running" and body["healthy"] is False
    beat("monitor", 2)
    assert client.get("/api/v1/admin/workers", headers=admin_headers).json()["roles"][3]["state"] == "running"


def test_worker_health_with_nothing_running_says_not_started():
    with SessionLocal() as db:
        db.query(WorkerHeartbeat).delete()
        db.commit()
        data = worker_health.status(db, web_port=1)
    states = {r["role"]: r["state"] for r in data["roles"]}
    assert states["scan-worker"] == "not_started" and states["monitor"] == "not_started" and states["supervisor"] == "not_started" and data["healthy"] is False


# --- the monitor role isolates its job types ---------------------------------------------------------------------------------------------------

def test_a_failing_job_type_does_not_stop_the_others():
    from app.services import monitor_role
    calls = []
    jobs = (("a", 1, lambda db: (_ for _ in ()).throw(RuntimeError("boom"))), ("b", 1, lambda db: calls.append("b") or "ok"))
    monitor = monitor_role.Monitor(jobs, clock=lambda: 100.0)
    result = monitor.tick()
    assert result == {"a": "failed", "b": "ok"} and calls == ["b"] and monitor.failures["a"] == 1
    assert monitor.tick() == {}   # not due again yet


# --- supervisor ------------------------------------------------------------------------------------------------------------------------------

class FakeProcess:
    _next_pid = 1000

    def __init__(self):
        FakeProcess._next_pid += 1
        self.pid, self.code = FakeProcess._next_pid, None

    def poll(self):
        return self.code


def test_supervisor_restarts_a_crashed_role_with_growing_back_off_and_resets_after_a_stable_run():
    from app.cli import supervisor as sup
    now = {"t": 0.0}
    spawned = []

    def spawn(spec):
        process = FakeProcess()
        spawned.append(process)
        return process
    s = sup.Supervisor([sup.Spec("scan-worker", ["x"], sup.BACKEND)], spawn=spawn, clock=lambda: now["t"], backoff_cap=8, stable=120, busy=lambda p: False)
    s.step()
    assert len(spawned) == 1 and s.roles[0].state == "running"
    delays = []
    for _ in range(5):   # it crashes straight away, again and again
        spawned[-1].code = 1
        s.step()
        delays.append(s.roles[0].next_start - now["t"])
        now["t"] = s.roles[0].next_start
        s.step()
    assert delays == [1, 2, 4, 8, 8] and len(spawned) == 6 and s.roles[0].restarts == 5
    now["t"] += 200   # it then runs fine for a long time, then crashes: back-off starts again at 1 second
    spawned[-1].code = 1
    s.step()
    assert s.roles[0].next_start - now["t"] == 1 and s.snapshot()["roles"]["scan-worker"]["restarts"] == 6


def test_supervisor_does_not_fight_a_process_that_already_serves_the_port_and_stops_everything():
    from app.cli import supervisor as sup
    busy = {"yes": True}
    spawned = []
    s = sup.Supervisor([sup.Spec("api", ["x"], sup.BACKEND, 8000), sup.Spec("monitor", ["y"], sup.BACKEND)], spawn=lambda spec: spawned.append(FakeProcess()) or spawned[-1],
                       clock=lambda: 0.0 if not spawned else 100.0, busy=lambda port: busy["yes"])
    s.step()
    assert s.roles[0].state == "external" and s.roles[1].state == "running" and len(spawned) == 1
    busy["yes"] = False
    s.step()
    assert s.roles[0].state == "running"
    s.stopping = False
    s.stop_all()
    assert all(r.state == "stopped" for r in s.roles)


def test_supervisor_survives_a_role_that_cannot_start():
    from app.cli import supervisor as sup
    now = {"t": 0.0}

    def broken(spec):
        raise OSError("no such file")
    s = sup.Supervisor([sup.Spec("monitor", ["nothing"], sup.BACKEND)], spawn=broken, clock=lambda: now["t"], busy=lambda p: False)
    s.step()
    assert s.roles[0].state == "failed_to_start" and s.roles[0].next_start > now["t"]


def test_only_one_supervisor_can_run_at_a_time(monkeypatch):
    from app.cli import supervisor as sup
    with __import__("socket").socket() as probe:   # a free port of its own: the real supervisor may be running on this computer
        probe.bind(("127.0.0.1", 0))
        monkeypatch.setattr(sup, "LOCK_PORT", probe.getsockname()[1])
    first = sup.acquire_lock()
    try:
        assert first is not None and sup.acquire_lock() is None
    finally:
        first.close()


def test_a_real_child_process_is_started_logged_and_restarted(tmp_path):
    import sys
    from app.cli import supervisor as sup
    s = sup.Supervisor([sup.Spec("quick", [sys.executable, "-c", "print('hello'); raise SystemExit(3)"], sup.BACKEND)], logs=tmp_path, backoff_cap=1, busy=lambda p: False)
    deadline = __import__("time").monotonic() + 15
    while __import__("time").monotonic() < deadline and s.roles[0].restarts < 2:
        s.step()
        __import__("time").sleep(0.2)
    s.stop_all()
    assert s.roles[0].restarts >= 2 and s.roles[0].last_exit_code == 3
    assert "hello" in (tmp_path / "quick.log").read_text()


# --- development safety: the monitor only touches allowed domains when an allowlist is set ----------------------------------------------------------

def test_the_monitor_allowlist_limits_scheduled_scans_and_uptime_checks(client, monkeypatch):
    owner_a, _, _, allowed, allowed_domain = verified_site(client, plan="pro")
    owner_b, _, _, other, _ = verified_site(client, plan="pro")
    for owner, site in ((owner_a, allowed), (owner_b, other)):
        add_scan(site, owner, when=utc_now() - timedelta(days=5))
    monkeypatch.setattr(settings, "monitor_domain_allowlist", allowed_domain.upper())
    assert settings.monitor_may_touch(allowed_domain) and not settings.monitor_may_touch("elsewhere.example.com")
    with SessionLocal() as db:
        scheduling.run_due(db, utc_now(), limit=100)
        queued = set(db.scalars(select(Scan.website_id).where(Scan.trigger == "scheduled")))
        assert allowed in queued and other not in queued
        checked = []

        async def checker(domain):
            checked.append(domain)
            return {"ok": True, "status_code": 200, "response_ms": 1, "scheme": "https"}
        uptime.tick(db, utc_now(), checker=checker)
        assert allowed_domain in checked and all(d == allowed_domain for d in checked)
    monkeypatch.setattr(settings, "monitor_domain_allowlist", "")
    assert settings.monitor_may_touch("anything.example.com")   # empty = every verified website (production)


# --- no valid verification, no contact: the monitor, the scheduler and scans skip such websites even with an empty allowlist -----------------------

def _break(db, site_id, how, owner_id):
    site = db.get(Website, site_id)
    if how == "unverified":
        site.verification_status = "unverified"
    elif how == "lost":
        site.verification_status = "lost"
    elif how == "manual_expired":   # still marked verified, but the 24 hours are over and nothing has swept it yet
        site.verification_method, site.verification_status = "manual", "verified"
        site.verification_result = {"expires_at": (utc_now() - timedelta(minutes=1)).isoformat()}
    elif how == "manual_no_expiry":   # an unreadable expiry fails closed
        site.verification_method, site.verification_status, site.verification_result = "manual", "verified", {}
    elif how == "fake_test_target":   # marked as a test target but not on the approved list
        site.verification_method, site.verification_status = "test_target", "verified"
    elif how == "owner_disabled":
        db.get(Admin, owner_id).is_active = False
    elif how == "removed":
        site.removed_at = utc_now()
    else:
        raise AssertionError(how)


@pytest.mark.parametrize("how", ["unverified", "lost", "manual_expired", "manual_no_expiry", "fake_test_target", "owner_disabled", "removed"])
def test_websites_without_valid_verification_are_never_scheduled_checked_or_scanned(client, monkeypatch, how):
    monkeypatch.setattr(settings, "monitor_domain_allowlist", "")   # the empty allowlist must not widen anything
    owner, _, _, bad, _ = verified_site(client, plan="pro")
    good_owner, _, _, good, good_domain = verified_site(client, plan="pro")
    for account, site in ((owner, bad), (good_owner, good)):
        add_scan(site, account, when=utc_now() - timedelta(days=5))
    with SessionLocal() as db:
        _break(db, bad, how, owner)
        db.commit()
        checked = []

        async def checker(domain):
            checked.append(domain)
            return {"ok": True, "status_code": 200, "response_ms": 1, "scheme": "https"}
        bad_domain = db.get(Website, bad).domain
        scheduling.run_due(db, utc_now(), limit=100)
        uptime.tick(db, utc_now(), checker=checker)
        queued = set(db.scalars(select(Scan.website_id).where(Scan.trigger == "scheduled")))
        assert bad not in queued and bad_domain not in checked and db.get(UptimeState, bad) is None
        assert good in queued and good_domain in checked   # the control: a properly verified website is still handled
        with pytest.raises(Exception):   # and a direct scan request is refused too
            scans.request_scan(db, db.get(Website, bad), "manual")


@pytest.mark.skipif(__import__("os").name != "nt", reason="job objects are Windows only")
def test_roles_die_with_the_supervisor_so_no_orphans_are_left(tmp_path):
    """Start a real supervisor, wait for its child, then kill the supervisor the hard way: the child must go too."""
    import subprocess, sys, time
    marker = tmp_path / "child.pid"
    child = f"import os,time,pathlib; pathlib.Path(r'{marker}').write_text(str(os.getpid())); time.sleep(300)"
    runner = (
        "import sys; sys.path.insert(0, r'" + str(__import__("app.cli.supervisor", fromlist=["x"]).BACKEND) + "');"
        "from app.cli import supervisor as s; import time;"
        f"sup = s.Supervisor([s.Spec('orphan-test', [sys.executable, '-c', {child!r}], s.BACKEND)], logs=r'{tmp_path}', busy=lambda p: False);"
        "sup.step(); time.sleep(300)")
    parent = subprocess.Popen([sys.executable, "-c", runner])
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.2)
        assert marker.exists()
        child_pid = int(marker.read_text())
        subprocess.run(["taskkill", "/PID", str(parent.pid), "/F"], capture_output=True)   # no /T: only the supervisor is killed
        gone = False
        for _ in range(50):
            alive = subprocess.run(["tasklist", "/FI", f"PID eq {child_pid}"], capture_output=True, text=True).stdout
            if str(child_pid) not in alive:
                gone = True
                break
            time.sleep(0.2)
        assert gone, "the role survived its supervisor"
    finally:
        parent.kill()
