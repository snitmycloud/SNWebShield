"""The Scan now button: limits from plans.json (Free 1 per website per day, Pro 5, Business 20), remaining scans shown,
friendly messages, the stricter test-target limit, and the full 1-65535 scan gated to Pro and above."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.core.time import utc_now
from app.data.ports import FULL_PORTS, STANDARD_PORTS, ports_for
from app.db.session import SessionLocal
from app.main import app
from app.models.admin import Admin
from app.models.jobs import ExecutionEvent
from app.models.scan import Scan
from app.models.website import Website
from app.services import ownership, plans, scans
from account_helpers import account_headers, make_account

W = "/api/v1/websites"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def add_verified(client, headers, domain="example.com"):
    site = client.post(W, headers=headers, json={"domain": domain}).json()
    with SessionLocal() as db:
        row = db.get(Website, site["id"])
        row.verification_status, row.verification_method = "verified", "dns"
        row.verified_at = row.verification_checked_at = utc_now()
        db.commit()
    return site["id"]


def finish_scans(website_id=None):
    with SessionLocal() as db:
        statement = select(Scan).where(Scan.status.in_(["queued", "running"]))
        if website_id:
            statement = statement.where(Scan.website_id == website_id)
        for scan in db.scalars(statement):
            scan.status, scan.ended_at, scan.claim_token = "incomplete", utc_now(), None
        db.commit()


def press(client, headers, site_id, **body):
    return client.post(f"{W}/{site_id}/scan", headers=headers, json=body)


def state(client, headers, site_id):
    return client.get(f"{W}/{site_id}", headers=headers).json()["scan_now"]


def set_plan(user_id, plan):
    with SessionLocal() as db:
        db.get(Admin, user_id).plan = plan
        db.commit()


# --- The numbers come from plans.json --------------------------------------------------------------------------

def test_plan_numbers():
    assert [(p, plans.get(p)["manual_scans_per_day"], plans.get(p)["manual_scans_per"]) for p in ("free", "pro", "business")] == [
        ("free", 1, "website"), ("pro", 5, "account"), ("business", 20, "account")]
    assert [plans.get(p)["full_port_scan"] for p in ("free", "pro", "business")] == [False, True, True]


# --- Free: 1 per website per day ----------------------------------------------------------------------------------

def test_free_one_scan_now_per_website_per_day_with_remaining_shown_and_a_friendly_message(client):
    _, _, headers = account_headers(client)
    site = add_verified(client, headers)
    first = state(client, headers, site)
    assert first["allowed"] is True and first["remaining"] == 1 and first["limit"] == 1 and first["scope"] == "website"
    assert first["plan_label"] == "Free" and first["resets_at"].endswith("+00:00")

    response = press(client, headers, site)
    assert response.status_code == 200
    body = response.json()
    assert body["scan"]["status"] == "queued" and body["scan"]["trigger"] == "manual" and body["already_running"] is False
    assert body["scan_now"]["remaining"] == 0 and body["scan_now"]["reason"] == "scan_running"

    again = press(client, headers, site)  # while it is queued or running: nothing is used up
    assert again.status_code == 200 and again.json()["already_running"] is True and again.json()["scan"]["id"] == body["scan"]["id"]
    with SessionLocal() as db:
        assert len(db.scalars(select(Scan).where(Scan.website_id == site)).all()) == 1

    finish_scans(site)
    limited = press(client, headers, site)
    assert limited.status_code == 429
    detail = limited.json()["detail"]
    assert detail["code"] == "scan_limit" and detail["remaining"] == 0 and detail["resets_at"]
    assert "Free plan" in detail["message"] and "Upgrade" in detail["message"] and "00:00 UTC" in detail["message"]
    shown = state(client, headers, site)
    assert shown["allowed"] is False and shown["reason"] == "limit_reached" and shown["remaining"] == 0


def test_the_limit_is_per_website_on_free(client):
    _, _, headers = account_headers(client)
    one, two = add_verified(client, headers, "one.example.com"), add_verified(client, headers, "two.example.com")
    assert press(client, headers, one).status_code == 200
    assert press(client, headers, two).status_code == 200  # a different website has its own allowance
    finish_scans()
    assert press(client, headers, one).status_code == 429 and press(client, headers, two).status_code == 429


def test_the_automatic_first_scan_does_not_use_up_scan_now(client, monkeypatch):
    _, _, headers = account_headers(client)
    site = client.post(W, headers=headers, json={"domain": "example.com"}).json()
    monkeypatch.setitem(ownership.CHECKS, "dns", lambda d, t: ownership.CheckResult("dns", "verified", "x", ["x"], "ok"))
    verified = client.post(f"{W}/{site['id']}/verify", headers=headers, json={"method": "dns"}).json()
    assert verified["scan"]["trigger"] == "first"
    finish_scans(site["id"])
    assert state(client, headers, site["id"])["remaining"] == 1
    assert press(client, headers, site["id"]).status_code == 200


def test_removing_and_re_adding_a_website_does_not_reset_the_free_limit(client):
    _, _, headers = account_headers(client)
    site = add_verified(client, headers)
    press(client, headers, site)
    finish_scans(site)
    assert client.post(f"{W}/{site}/remove", headers=headers, json={"confirm_domain": "example.com"}).status_code == 200
    again = add_verified(client, headers)
    assert again != site and state(client, headers, again)["remaining"] == 0
    assert press(client, headers, again).status_code == 429


def test_yesterdays_scans_do_not_count(client):
    _, _, headers = account_headers(client)
    site = add_verified(client, headers)
    press(client, headers, site)
    finish_scans(site)
    with SessionLocal() as db:
        for event in db.scalars(select(ExecutionEvent).where(ExecutionEvent.action == "manual_scan_requested")):
            event.occurred_at = utc_now() - timedelta(days=1, hours=1)
        db.commit()
    assert state(client, headers, site)["remaining"] == 1 and press(client, headers, site).status_code == 200


# --- Pro: 5 per day, Business: 20 per day (across the account) ----------------------------------------------------

@pytest.mark.parametrize("plan, limit", [("pro", 5), ("business", 20)])
def test_paid_plans_have_an_account_wide_daily_allowance(client, plan, limit):
    user_id, _, headers = account_headers(client, plan=plan)
    sites = [add_verified(client, headers, f"s{n}.example.com") for n in range(3)]
    shown = state(client, headers, sites[0])
    assert shown["limit"] == limit and shown["scope"] == "account" and shown["remaining"] == limit
    for n in range(limit):
        response = press(client, headers, sites[n % 3])
        assert response.status_code == 200, (n, response.text)
        assert response.json()["scan_now"]["remaining"] in (limit - n - 1, 0)
        finish_scans()
    assert state(client, headers, sites[1])["remaining"] == 0  # shared by every website of the account
    refused = press(client, headers, sites[2])
    assert refused.status_code == 429 and "your account" in refused.json()["detail"]["message"]
    other_user, _, other = account_headers(client, plan=plan)  # another account is unaffected
    assert state(client, other, add_verified(client, other))["remaining"] == limit


# --- Who and when -------------------------------------------------------------------------------------------------

def test_only_the_owner_of_a_verified_website_can_press_it(client):
    _, _, owner = account_headers(client)
    _, _, other = account_headers(client)
    _, _, staff = account_headers(client, "admin")
    site = add_verified(client, owner)
    unverified = client.post(W, headers=owner, json={"domain": "unrelated-domain.org"}).json()["id"]  # not covered by example.com
    assert press(client, other, site).status_code == 404 and press(client, staff, site).status_code == 404
    assert client.post(f"{W}/{site}/scan", json={}).status_code == 401
    refused = press(client, owner, unverified)
    assert refused.status_code == 409 and "Verify ownership" in refused.json()["detail"]
    assert "scan_now" not in client.get(f"{W}/{site}", headers=staff).json()  # only the owner sees the button's state
    client.post(f"{W}/{site}/remove", headers=owner, json={"confirm_domain": "example.com"})
    assert press(client, owner, site).status_code == 404
    with SessionLocal() as db:
        assert db.scalars(select(Scan).where(Scan.website_id.in_([site, unverified]))).all() == []


def test_unknown_fields_and_scan_types_are_rejected(client):
    _, _, headers = account_headers(client)
    site = add_verified(client, headers)
    assert press(client, headers, site, scan_type="aggressive").status_code == 422
    assert press(client, headers, site, ports=[1, 2]).status_code == 422


# --- Test targets keep their stricter limit -----------------------------------------------------------------------

def test_a_test_target_keeps_its_per_day_limit_shared_by_admins_even_on_a_bigger_plan(client):
    limit = settings.test_target_scans_per_day
    _, _, first = account_headers(client, "admin", plan="business")
    _, _, second = account_headers(client, "admin", plan="business")
    site = client.post(W, headers=first, json={"domain": "scanme.nmap.org"}).json()  # scan 1 (the first scan)
    assert site["scan_now"]["test_target_remaining"] == limit - 1
    finish_scans()
    for _ in range(limit - 1):                                                       # the rest of the day
        assert press(client, first, site["id"]).status_code == 200
        finish_scans()
    limited = press(client, first, site["id"])
    assert limited.status_code == 429 and "test target" in limited.json()["detail"]["message"].lower()
    other = client.post(W, headers=second, json={"domain": "scanme.nmap.org"}).json()  # a second admin shares the same limit
    assert other["latest_scan"] is None and other["scan_now"]["remaining"] == 0
    assert press(client, second, other["id"]).status_code == 429


# --- Full 1-65535 scan: Pro and above ------------------------------------------------------------------------------

def test_free_is_refused_a_full_scan_and_nothing_is_used_up(client):
    _, _, headers = account_headers(client)
    site = add_verified(client, headers)
    refused = press(client, headers, site, scan_type="full")
    assert refused.status_code == 402
    detail = refused.json()["detail"]
    assert detail["code"] == "plan_feature" and "Pro" in detail["message"] and "65,535" in detail["message"]
    assert state(client, headers, site)["remaining"] == 1  # the refusal did not use up the day's scan
    with SessionLocal() as db:
        assert db.scalars(select(Scan).where(Scan.website_id == site)).all() == []
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "manual_scan_requested")) is None


@pytest.mark.parametrize("plan", ["pro", "business"])
def test_pro_and_business_can_queue_a_full_scan(client, plan):
    _, _, headers = account_headers(client, plan=plan)
    site = add_verified(client, headers)
    response = press(client, headers, site, scan_type="full")
    assert response.status_code == 200 and response.json()["scan"]["scan_type"] == "full"
    assert response.json()["scan_now"]["remaining"] == plans.get(plan)["manual_scans_per_day"] - 1


def test_the_full_scan_covers_every_port_and_the_standard_scan_does_not():
    assert len(ports_for("full")) == 65535 == len(FULL_PORTS) and len(ports_for("standard")) == len(STANDARD_PORTS) == 1011


def test_a_full_scan_is_refused_again_at_run_time_if_the_plan_was_downgraded(client):
    user_id, _, headers = account_headers(client, plan="pro")
    site = add_verified(client, headers)
    scan_id = press(client, headers, site, scan_type="full").json()["scan"]["id"]
    set_plan(user_id, "free")  # downgraded before the worker picked it up
    with SessionLocal() as db:
        claimed = scans.claim(db)
    resolved = []
    status = scans.execute(*claimed, resolve=lambda d: resolved.append(d) or ["127.0.0.1"], verify=lambda db, w: (True, "cached"))
    assert status == "refused" and resolved == []
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
    assert scan.result["code"] == "plan_feature" and scan.resolved_ip is None


def test_test_targets_only_allow_standard_scans(client):
    _, _, headers = account_headers(client, "admin", plan="business")
    site = client.post(W, headers=headers, json={"domain": "scanme.nmap.org"}).json()["id"]
    finish_scans()
    refused = press(client, headers, site, scan_type="full")
    assert refused.status_code == 422 and "standard" in refused.json()["detail"]
