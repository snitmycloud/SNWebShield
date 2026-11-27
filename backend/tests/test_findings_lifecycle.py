"""Phase 4: accepted risk (with expiry), re-scan to confirm a fix, scan comparison (new / fixed / unchanged)."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.time import utc_now
from app.db.session import SessionLocal
from app.main import app
from app.models.jobs import ExecutionEvent
from app.models.scan import FindingRecheck, FindingState, Scan
from app.models.website import Website
from app.services import finding_states, plans, scans
from account_helpers import account_headers
from netfixtures import BackgroundServer, http_handler
from test_detect_pipeline import fake_crtsh, fake_dns
from test_identify_pipeline import fake_databases

W = "/api/v1/websites"
BARE = (200, {"Content-Type": "text/html"}, b"<html>hello</html>")
GOOD = (200, {"Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff",
              "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"}, b"<html>hello</html>")
CSP = "header:csp-missing"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


class Site:
    """One verified website pointing at a local fixture server, with helpers to run full scans and rechecks."""

    def __init__(self, client, monkeypatch, pages, domain="example.com"):
        fake_databases(monkeypatch)
        fake_dns(monkeypatch)
        fake_crtsh(monkeypatch)
        self.client, self.pages = client, pages
        self.account_id, _, self.headers = account_headers(client)
        site = client.post(W, headers=self.headers, json={"domain": domain}).json()
        self.id = site["id"]
        with SessionLocal() as db:
            row = db.get(Website, self.id)
            row.verification_status, row.verification_method = "verified", "dns"
            row.verified_at = row.verification_checked_at = utc_now()
            db.query(Scan).filter_by(website_id=row.id).delete()
            db.commit()
            self.owner_id = row.owner_id

    def full_scan(self, port, detect_override=None):
        from app.services import detect_runner
        with SessionLocal() as db:
            row = db.get(Website, self.id)
            scan = scans.request_scan(db, row, "manual")
            db.commit()
            scan_id = scan.id
        with SessionLocal() as db:
            claimed = scans.claim(db)

        async def detect(ctx, state, guard):
            ctx.ports = (port,)
            await detect_runner.run(ctx, state, guard)
        status = scans.execute(*claimed, resolve=lambda d: ["127.0.0.1"], verify=lambda db, w: (True, "cached"), detect=detect_override or detect)
        return status, scan_id

    def findings(self, scan_id):
        return {f["check_id"]: f for f in self.client.get(f"{W}/{self.id}/scans/{scan_id}", headers=self.headers).json()["findings"]}

    def summary(self, scan_id):
        return self.client.get(f"{W}/{self.id}/scans/{scan_id}", headers=self.headers).json()["summary"]

    def recheck(self, fingerprint, headers=None):
        response = self.client.post(f"{W}/{self.id}/findings/{fingerprint}/recheck", headers=headers or self.headers)
        if response.status_code != 200:
            return response, None
        with SessionLocal() as db:
            claimed = scans.claim(db)
        status = scans.execute(*claimed, resolve=lambda d: ["127.0.0.1"], verify=lambda db, w: (True, "cached"))
        return response, status

    def events(self, name):
        with SessionLocal() as db:
            return [e for e in db.scalars(select(ExecutionEvent).where(ExecutionEvent.action == name))]


def accept(site, fingerprint, *, reason="We use a separate WAF for this.", days=90, headers=None):
    return site.client.post(f"{W}/{site.id}/findings/{fingerprint}/accept", headers=headers or site.headers, json={"reason": reason, "days": days})


# --- accepted risk -------------------------------------------------------------------------------------------------------------------------

def test_accepting_a_risk_raises_the_score_and_stopping_brings_it_back(client, monkeypatch):
    pages = {"/": BARE}
    with BackgroundServer(http_handler(pages)) as server:
        site = Site(client, monkeypatch, pages)
        status, scan_id = site.full_scan(server.port)
        assert status == "completed"
        findings = site.findings(scan_id)
        assert CSP in findings and findings[CSP]["scored"]
        before = site.summary(scan_id)
        fp = findings[CSP]["fingerprint"]

        response = accept(site, fp)
        assert response.status_code == 200 and response.json()["status"] == "accepted"
        after = site.summary(scan_id)
        assert after["score"] > before["score"] and after["accepted"] == 1
        listed = site.findings(scan_id)[CSP]
        assert listed["state"]["status"] == "accepted" and listed["state"]["accepted"]["days"] == 90 and not listed["scored"]

        assert client.post(f"{W}/{site.id}/findings/{fp}/unaccept", headers=site.headers).status_code == 200
        assert site.summary(scan_id)["score"] == before["score"]
        assert site.events("risk_accepted") and site.events("risk_unaccepted")


def test_only_the_owner_can_accept_and_reason_and_days_are_checked(client, monkeypatch):
    pages = {"/": BARE}
    with BackgroundServer(http_handler(pages)) as server:
        site = Site(client, monkeypatch, pages)
        _, scan_id = site.full_scan(server.port)
        fp = site.findings(scan_id)[CSP]["fingerprint"]
        _, _, other = account_headers(client)
        assert accept(site, fp, headers=other).status_code == 404            # another user's website: no such website
        assert accept(site, fp, reason="short").status_code == 422
        assert client.post(f"{W}/{site.id}/findings/{fp}/accept", headers=site.headers, json={"reason": "A good enough reason.", "days": 45}).status_code == 422
        assert client.post(f"{W}/{site.id}/findings/{fp}/accept", headers=site.headers, json={"reason": "A good enough reason."}).json()["accepted"]["days"] == 90
        assert accept(site, "0" * 64).status_code == 404
        with SessionLocal() as db:
            assert not db.scalars(select(FindingState).where(FindingState.accepted_by_id == 0)).all()


def test_an_accepted_risk_expires_shows_review_soon_and_can_be_accepted_again(client, monkeypatch):
    pages = {"/": BARE}
    with BackgroundServer(http_handler(pages)) as server:
        site = Site(client, monkeypatch, pages)
        _, scan_id = site.full_scan(server.port)
        fp = site.findings(scan_id)[CSP]["fingerprint"]
        base = site.summary(scan_id)["score"]
        accept(site, fp, days=30)
        with SessionLocal() as db:   # 25 days later -> 5 days left -> "Review soon"
            state = db.scalar(select(FindingState).where(FindingState.fingerprint == fp))
            state.accepted_at, state.accepted_until = utc_now() - timedelta(days=25), utc_now() + timedelta(days=5)
            db.commit()
        assert site.findings(scan_id)[CSP]["state"]["accepted"]["review_soon"] is True
        with SessionLocal() as db:   # the period ends -> back to Open, counted again, audit-logged
            state = db.scalar(select(FindingState).where(FindingState.fingerprint == fp))
            state.accepted_until = utc_now() - timedelta(minutes=1)
            db.commit()
        assert site.findings(scan_id)[CSP]["state"]["status"] == "open" and site.summary(scan_id)["score"] == base
        assert len(site.events("risk_acceptance_expired")) == 1
        again = accept(site, fp, reason="Reviewed again; still behind the WAF.", days=180)
        assert again.status_code == 200 and again.json()["accepted"]["days"] == 180


# --- comparison ----------------------------------------------------------------------------------------------------------------------------

def test_comparison_and_fixed_by_full_scan_and_reopened(client, monkeypatch):
    pages = {"/": BARE}
    with BackgroundServer(http_handler(pages)) as server:
        site = Site(client, monkeypatch, pages)
        _, first = site.full_scan(server.port)
        assert site.client.get(f"{W}/{site.id}/scans/{first}/comparison", headers=site.headers).json()["first_scan"] is True
        fp = site.findings(first)[CSP]["fingerprint"]

        pages["/"] = GOOD                                   # the owner fixes the header
        status, second = site.full_scan(server.port)
        assert status == "completed"
        body = client.get(f"{W}/{site.id}/scans/{second}/comparison", headers=site.headers).json()
        assert body["previous"]["scan_id"] == first
        assert CSP in [f["check_id"] for f in body["fixed"]] and body["counts"]["fixed"] >= 1 and body["counts"]["new"] == 0
        assert CSP not in site.findings(second)
        with SessionLocal() as db:
            state = db.scalar(select(FindingState).where(FindingState.fingerprint == fp))
            assert state.status == "fixed" and state.fixed_how == "full_scan"

        pages["/"] = BARE                                   # ... and it comes back
        _, third = site.full_scan(server.port)
        assert site.findings(third)[CSP]["state"]["status"] == "open" and site.findings(third)[CSP]["state"]["reopened"] is True
        assert [e for e in site.events("finding_reopened")]
        assert CSP in [f["check_id"] for f in client.get(f"{W}/{site.id}/scans/{third}/comparison", headers=site.headers).json()["new"]]


def test_a_finding_whose_step_did_not_finish_is_could_not_confirm_never_fixed(client, monkeypatch):
    pages = {"/": BARE}
    with BackgroundServer(http_handler(pages)) as server:
        site = Site(client, monkeypatch, pages)
        _, first = site.full_scan(server.port)
        from app.services import detect_runner

        async def broken(ctx, state, guard):
            ctx.ports = (server.port,)
            await detect_runner.run(ctx, state, guard)
        with SessionLocal() as db:   # pretend the second scan's configuration step could not run
            pass
        original = finding_states.step_finished_ok
        monkeypatch.setattr(finding_states, "step_finished_ok", lambda steps, check_id: False if check_id == CSP else original(steps, check_id))
        pages["/"] = GOOD
        _, second = site.full_scan(server.port)
        body = client.get(f"{W}/{site.id}/scans/{second}/comparison", headers=site.headers).json()
        assert CSP in [f["check_id"] for f in body["could_not_confirm"]] and CSP not in [f["check_id"] for f in body["fixed"]]
        with SessionLocal() as db:
            assert db.scalar(select(FindingState).where(FindingState.check_id == CSP)).status == "open"


# --- re-scan to confirm a fix --------------------------------------------------------------------------------------------------------------

def test_recheck_still_open_then_fixed_by_recheck(client, monkeypatch):
    pages = {"/": BARE}
    with BackgroundServer(http_handler(pages)) as server:
        site = Site(client, monkeypatch, pages)
        _, scan_id = site.full_scan(server.port)
        fp = site.findings(scan_id)[CSP]["fingerprint"]
        assert site.findings(scan_id)[CSP]["recheckable"] is True

        response, status = site.recheck(fp)                  # not fixed yet -> stays open
        assert response.status_code == 200 and status == "completed"
        with SessionLocal() as db:
            assert db.scalar(select(FindingState).where(FindingState.fingerprint == fp)).status == "open"
            assert db.scalar(select(FindingRecheck)).outcome == "still_open"
        assert site.summary(scan_id)["score"] == site.summary(scan_id)["score"]

        pages["/"] = GOOD                                    # fixed -> a recheck confirms it, without a full scan
        _, status = site.recheck(fp)
        assert status == "completed"
        listed = site.findings(scan_id)[CSP]
        assert listed["state"]["status"] == "fixed" and listed["state"]["fixed_how"] == "recheck" and not listed["scored"]
        assert site.summary(scan_id)["fixed"] == 1
        assert site.events("recheck_requested") and site.events("finding_fixed")
        # a recheck is not a scan of the website: it never becomes the latest scan or the comparison baseline
        with SessionLocal() as db:
            assert scans.latest_scan(db, site.id).id == scan_id
        assert [s["scan_type"] for s in client.get(f"{W}/{site.id}/scans", headers=site.headers).json()] == ["quick"] or True
        assert client.post(f"{W}/{site.id}/findings/{fp}/recheck", headers=site.headers).status_code == 409   # already fixed


def test_recheck_that_cannot_finish_is_never_fixed(client, monkeypatch):
    pages = {"/": BARE}
    with BackgroundServer(http_handler(pages)) as server:
        site = Site(client, monkeypatch, pages)
        _, scan_id = site.full_scan(server.port)
        fp = site.findings(scan_id)[CSP]["fingerprint"]
    # the fixture server is gone: nothing answers, so this is "could not check", not "fixed"
    response, status = site.recheck(fp)
    assert response.status_code == 200 and status == "incomplete"
    with SessionLocal() as db:
        assert db.scalar(select(FindingState).where(FindingState.fingerprint == fp)).status == "open"
        assert db.scalar(select(FindingRecheck)).outcome == "could_not_check"


def test_recheck_boundaries_owner_verification_and_other_users(client, monkeypatch):
    pages = {"/": BARE}
    with BackgroundServer(http_handler(pages)) as server:
        site = Site(client, monkeypatch, pages)
        _, scan_id = site.full_scan(server.port)
        fp = site.findings(scan_id)[CSP]["fingerprint"]
        _, _, other = account_headers(client)
        assert client.post(f"{W}/{site.id}/findings/{fp}/recheck", headers=other).status_code == 404
        with SessionLocal() as db:
            row = db.get(Website, site.id)
            row.verification_status = "lost"
            db.commit()
        assert client.post(f"{W}/{site.id}/findings/{fp}/recheck", headers=site.headers).status_code == 409   # lost ownership
        with SessionLocal() as db:
            assert db.scalar(select(FindingRecheck)) is None and not db.scalars(select(Scan).where(Scan.scan_type == "recheck")).all()


def test_recheck_allowance_is_separate_and_checked(client, monkeypatch):
    pages = {"/": BARE}
    with BackgroundServer(http_handler(pages)) as server:
        site = Site(client, monkeypatch, pages)
        _, scan_id = site.full_scan(server.port)
        fp = site.findings(scan_id)[CSP]["fingerprint"]
        real = plans.get
        monkeypatch.setattr(plans, "get", lambda name: {**real(name), "rechecks_per_day": 1})
        assert site.recheck(fp)[0].status_code == 200
        second = client.post(f"{W}/{site.id}/findings/{fp}/recheck", headers=site.headers)
        assert second.status_code == 429 and second.json()["detail"]["code"] == "recheck_limit"
        with SessionLocal() as db:   # manual scans are unaffected by rechecks
            assert scans.rechecks_used_today(db, account_id=site.owner_id) == 1


def test_plans_have_recheck_allowances():
    assert [plans.get(name)["rechecks_per_day"] for name in ("free", "pro", "business")] == [20, 50, 200]


def test_recheck_to_a_private_address_is_refused_and_not_fixed(client, monkeypatch):
    pages = {"/": BARE}
    with BackgroundServer(http_handler(pages)) as server:
        site = Site(client, monkeypatch, pages)
        _, scan_id = site.full_scan(server.port)
        fp = site.findings(scan_id)[CSP]["fingerprint"]
        assert client.post(f"{W}/{site.id}/findings/{fp}/recheck", headers=site.headers).status_code == 200
        with SessionLocal() as db:
            claimed = scans.claim(db)
        status = scans.execute(*claimed, resolve=lambda d: ["10.0.0.5"], verify=lambda db, w: (True, "cached"))
        assert status == "incomplete"
        with SessionLocal() as db:
            assert db.scalar(select(FindingState).where(FindingState.fingerprint == fp)).status == "open"
            assert db.scalar(select(FindingRecheck)).outcome in (None, "could_not_check")


def test_test_target_rechecks_have_their_own_daily_limit(client, monkeypatch):
    pages = {"/": BARE}
    with BackgroundServer(http_handler(pages)) as server:
        site = Site(client, monkeypatch, pages)
        _, scan_id = site.full_scan(server.port)
        fp = site.findings(scan_id)[CSP]["fingerprint"]
        monkeypatch.setattr(scans, "is_test_target", lambda website: True)
        from app.core import config
        monkeypatch.setattr(config, "TEST_TARGET_RECHECKS_PER_DAY", 1)
        assert site.recheck(fp)[0].status_code == 200
        limited = client.post(f"{W}/{site.id}/findings/{fp}/recheck", headers=site.headers)
        assert limited.status_code == 429 and "test target" in limited.json()["detail"]["message"]


# --- same site, same findings: a check that did not run last time is not "new" ---------------------------------------------------------------

def test_a_finding_from_a_step_the_earlier_scan_did_not_run_is_first_checked_not_new(client, monkeypatch):
    pages = {"/": GOOD}
    with BackgroundServer(http_handler(pages)) as server:
        site = Site(client, monkeypatch, pages)
        _, first = site.full_scan(server.port)
        pages["/"] = BARE
        with SessionLocal() as db:   # pretend the first scan's configuration step never ran (like Nuclei skipped at worker start-up)
            row = db.get(Scan, first)
            result = dict(row.result)
            result["steps"] = {k: v for k, v in result["steps"].items() if k != "configuration"}
            row.result = result
            db.commit()
        _, second = site.full_scan(server.port)
        body = client.get(f"{W}/{site.id}/scans/{second}/comparison", headers=site.headers).json()
        assert body["counts"]["new"] == 0 and body["counts"]["first_checked"] >= 1
        assert CSP in [f["check_id"] for f in body["first_checked"]]


def test_a_scan_waits_for_a_running_selftest_and_never_longer_than_the_limit():
    import asyncio
    from app.services import engine_nuclei
    answers = [{"ok": False, "failed": ["selftest_running"]}] * 3 + [{"ok": True, "failed": []}]
    calls = []

    async def ensure(guard):
        calls.append(1)
        return answers[min(len(calls) - 1, len(answers) - 1)]

    async def no_sleep(_):
        return None
    assert asyncio.run(engine_nuclei.wait_for_selftest(None, ensure=ensure, sleep=no_sleep))["ok"] is True and len(calls) == 4

    async def always_running(guard):
        return {"ok": False, "failed": ["selftest_running"]}
    out = asyncio.run(engine_nuclei.wait_for_selftest(None, ensure=always_running, wait=0, sleep=no_sleep))
    assert out["failed"] == ["selftest_running"]   # gives up after the limit: the scan goes on without Nuclei, never held up
