"""Approved test targets (scanme.nmap.org): admin accounts only, labelled, fixed list, 2 scans a day, every scan audited."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core import config
from app.core.config import Settings, settings
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.main import app
from app.models.admin import Admin
from app.models.jobs import ExecutionEvent
from app.models.scan import Scan
from app.models.website import Website
from app.services import ownership, scans
from account_helpers import account_headers, make_account

W = "/api/v1/websites"
TARGET = "scanme.nmap.org"
PUBLIC = "45.33.32.156"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def finish_active_scans(website_id):
    """Pretend the queued/running scan finished, so the next scan can be requested."""
    with SessionLocal() as db:
        for scan in db.scalars(select(Scan).where(Scan.website_id == website_id, Scan.status.in_(["queued", "running"]))):
            scan.status, scan.ended_at = "incomplete", utc_now()
        db.commit()


def request(website_id):
    with SessionLocal() as db:
        scan = scans.request_scan(db, db.get(Website, website_id), "manual")
        db.commit()
        return scan.id


# --- The list is fixed -----------------------------------------------------------------------------

def test_the_approved_list_is_only_scanme_nmap_org_and_two_scans_a_day():
    assert settings.approved_test_targets == (TARGET,)
    assert settings.test_target_scans_per_day == 2


def test_the_list_cannot_be_changed_by_environment_or_code_assignment(monkeypatch):
    monkeypatch.setenv("APPROVED_TEST_TARGETS", "evil.example.com,scanme.nmap.org")
    monkeypatch.setenv("TEST_TARGET_SCANS_PER_DAY", "1000")
    fresh = Settings(approved_test_targets=("evil.example.com",), test_target_scans_per_day=99)
    assert fresh.approved_test_targets == (TARGET,) and fresh.test_target_scans_per_day == 2
    with pytest.raises((AttributeError, ValueError, TypeError)):
        settings.approved_test_targets = ("evil.example.com",)
    assert isinstance(config.APPROVED_TEST_TARGETS, tuple)  # immutable container, not a list


def test_the_list_cannot_be_read_or_changed_through_the_api(client):
    spec = client.get("/openapi.json").json()
    text = str(spec).lower()
    assert "approved_test_targets" not in text and "test-target" not in text and "test_target_scans" not in text
    for path in spec["paths"]:
        assert "target" not in path and "approved" not in path  # no route is dedicated to test targets or the list
    _, _, admin = account_headers(client, "admin")
    for method, path in (("put", "/api/v1/admin/test-targets"), ("post", "/api/v1/admin/test-targets"),
                         ("patch", "/api/v1/admin/settings"), ("post", "/api/v1/admin/settings"),
                         ("get", "/api/v1/admin/test-targets")):
        assert getattr(client, method)(path, headers=admin, **({"json": {"targets": ["evil.com"]}} if method != "get" else {})).status_code in (404, 405)
    assert settings.approved_test_targets == (TARGET,)


# --- Normal users cannot use it --------------------------------------------------------------------

@pytest.mark.parametrize("role", ["user", "analyst", "lead_analyst"])
@pytest.mark.parametrize("typed", [TARGET, "https://SCANME.NMAP.ORG/", "scanme.nmap.org.", "http://scanme.nmap.org:80/path?x=1"])
def test_only_admin_accounts_can_add_a_test_target(client, role, typed):
    user_id, _, headers = account_headers(client, role)
    response = client.post(W, headers=headers, json={"domain": typed})
    assert response.status_code == 403
    assert "reserved" in response.json()["detail"]
    with SessionLocal() as db:
        assert db.scalars(select(Website).where(Website.owner_id == user_id)).all() == []
        assert db.scalars(select(Scan).where(Scan.owner_id == user_id)).all() == []


@pytest.mark.parametrize("role", ["user", "analyst", "lead_analyst"])
def test_a_test_target_row_owned_by_anyone_but_an_active_admin_is_never_allowed_or_scanned(role):
    owner_id, _ = make_account(role)
    with SessionLocal() as db:
        site = Website(owner_id=owner_id, domain=TARGET, name=TARGET, url=f"https://{TARGET}/", environment="production",
                       verification_status="verified", verification_method="test_target",
                       verified_at=utc_now(), verification_checked_at=utc_now())
        db.add(site)
        db.commit()
        assert ownership.ensure_verified(db, site) == (False, "not_verified")
        site_id = site.id
        scan = Scan(id="n" * 36, website_id=site_id, owner_id=owner_id, scan_type="standard", trigger="manual",
                    status="running", requested_at=utc_now(), claim_token="t", lease_until=utc_now() + timedelta(minutes=5))
        db.add(scan)
        db.commit()
    resolved = []
    status = scans.execute("n" * 36, "t", resolve=lambda d: resolved.append(d) or [PUBLIC])
    assert status == "refused" and resolved == []


def test_a_demoted_or_disabled_admin_loses_the_test_target(client):
    admin_id, _, headers = account_headers(client, "admin")
    site = client.post(W, headers=headers, json={"domain": TARGET}).json()
    with SessionLocal() as db:
        website = db.get(Website, site["id"])
        assert ownership.ensure_verified(db, website) == (True, "test_target")
        db.get(Admin, admin_id).is_active = False
        db.commit()
        assert ownership.ensure_verified(db, website) == (False, "not_verified")
        account = db.get(Admin, admin_id)
        account.is_active, account.role = True, "analyst"
        db.commit()
        assert ownership.ensure_verified(db, website) == (False, "not_verified")


def test_a_test_target_marking_on_any_other_domain_is_refused():
    owner_id, _ = make_account("admin")
    with SessionLocal() as db:
        site = Website(owner_id=owner_id, domain="example.com", name="x", url="https://example.com/", environment="production",
                       verification_status="verified", verification_method="test_target",
                       verified_at=utc_now(), verification_checked_at=utc_now())
        db.add(site)
        db.commit()
        assert ownership.ensure_verified(db, site) == (False, "not_verified")


def test_a_test_target_never_covers_its_subdomains(client):
    _, _, headers = account_headers(client, "admin")
    client.post(W, headers=headers, json={"domain": TARGET})
    sub = client.post(W, headers=headers, json={"domain": f"www.{TARGET}"}).json()
    assert sub["verification_status"] == "unverified" and sub["test_target"] is False and sub["latest_scan"] is None


# --- Admin use, label, audit ---------------------------------------------------------------------------

def test_an_admin_adds_the_test_target_labelled_and_without_dns_proof(client):
    admin_id, _, headers = account_headers(client, "admin")
    response = client.post(W, headers=headers, json={"domain": "https://SCANME.nmap.org/"})
    assert response.status_code == 201, response.text
    site = response.json()
    assert site["domain"] == TARGET and site["test_target"] is True
    assert site["verification_status"] == "verified" and site["verification_method"] == "test_target"
    assert "Approved SNWebShield test target" in site["verification_result"]["message"]
    assert "verification_code" not in site and "instructions" not in site
    assert site["latest_scan"]["status"] == "queued" and site["latest_scan"]["trigger"] == "first"
    assert client.get(W, headers=headers).json()[0]["test_target"] is True
    ordinary = client.post(W, headers=headers, json={"domain": "example.com"}).json()
    assert ordinary["test_target"] is False


def test_other_accounts_never_see_an_admins_test_target(client):
    _, _, admin = account_headers(client, "admin")
    _, _, user = account_headers(client)
    site = client.post(W, headers=admin, json={"domain": TARGET}).json()
    assert client.get(W, headers=user).json() == []
    assert client.get(f"{W}/{site['id']}", headers=user).status_code == 404
    assert client.post(f"{W}/{site['id']}/verify", headers=user, json={"method": "dns"}).status_code == 404


def test_verify_on_a_test_target_changes_nothing_and_starts_no_scan(client):
    _, _, headers = account_headers(client, "admin")
    site = client.post(W, headers=headers, json={"domain": TARGET}).json()
    finish_active_scans(site["id"])
    result = client.post(f"{W}/{site['id']}/verify", headers=headers, json={"method": "dns"}).json()
    assert result["scan"] is None and result["website"]["test_target"] is True
    with SessionLocal() as db:
        assert len(db.scalars(select(Scan).where(Scan.website_id == site["id"])).all()) == 1


def test_every_test_target_scan_is_audited_with_its_flag(client):
    admin_id, _, headers = account_headers(client, "admin")
    site = client.post(W, headers=headers, json={"domain": TARGET}).json()
    with SessionLocal() as db:
        claimed = scans.claim(db)
    assert claimed
    scans.execute(*claimed, resolve=lambda d: [PUBLIC])  # real ownership check: allowed as a test target
    with SessionLocal() as db:
        events = {e.action: e for e in db.scalars(select(ExecutionEvent).where(ExecutionEvent.resource_id == site["id"]))}
        scan = db.scalar(select(Scan).where(Scan.website_id == site["id"]))
    assert {"website_added", "ownership_verified", "scan_requested", "scan_started", "scan_finished"} <= set(events)
    assert events["scan_requested"].detail["test_target"] is True and events["scan_requested"].detail["domain"] == TARGET
    finished = events["scan_finished"].detail
    assert finished["test_target"] is True and finished["user_id"] == admin_id and finished["ip"] == PUBLIC
    assert finished["start"] and finished["end"] and finished["result"] == "incomplete"
    assert scan.result["ownership"] == "test_target" and "does not mean your website is safe" in scan.message


def test_ordinary_scans_are_not_flagged_as_test_targets(client):
    user_id, _, headers = account_headers(client)
    site = client.post(W, headers=headers, json={"domain": "example.com"}).json()
    with SessionLocal() as db:
        row = db.get(Website, site["id"])
        row.verification_status, row.verification_method = "verified", "dns"
        db.commit()
    request(site["id"])
    with SessionLocal() as db:
        event = db.scalar(select(ExecutionEvent).where(ExecutionEvent.resource_id == site["id"], ExecutionEvent.action == "scan_requested"))
    assert event.detail["test_target"] is False


# --- Two scans per day -----------------------------------------------------------------------------

def test_at_most_two_test_target_scans_per_day(client):
    _, _, headers = account_headers(client, "admin")
    site = client.post(W, headers=headers, json={"domain": TARGET}).json()  # scan 1 (the first scan)
    finish_active_scans(site["id"])
    second = request(site["id"])  # scan 2
    assert second
    finish_active_scans(site["id"])
    with SessionLocal() as db, pytest.raises(Exception) as refused:
        scans.request_scan(db, db.get(Website, site["id"]), "manual")
    assert getattr(refused.value, "status_code", None) == 429
    assert "at most 2 times per day" in refused.value.detail["message"] and refused.value.detail["code"] == "scan_limit"
    with SessionLocal() as db:
        assert len(db.scalars(select(Scan).where(Scan.website_id == site["id"])).all()) == 2


def test_the_limit_is_shared_by_all_admins(client):
    _, _, first = account_headers(client, "admin")
    _, _, second = account_headers(client, "admin")
    one = client.post(W, headers=first, json={"domain": TARGET}).json()
    two = client.post(W, headers=second, json={"domain": TARGET}).json()
    assert one["latest_scan"] and two["latest_scan"]  # scans 1 and 2 of the day
    finish_active_scans(one["id"])
    finish_active_scans(two["id"])
    with SessionLocal() as db, pytest.raises(Exception) as refused:
        scans.request_scan(db, db.get(Website, one["id"]), "manual")
    assert getattr(refused.value, "status_code", None) == 429


def test_removing_and_re_adding_the_website_does_not_reset_the_limit(client):
    _, _, headers = account_headers(client, "admin")
    site = client.post(W, headers=headers, json={"domain": TARGET}).json()   # scan 1, queued
    finish_active_scans(site["id"])
    request(site["id"])                                                      # scan 2, queued
    assert client.post(f"{W}/{site['id']}/remove", headers=headers, json={"confirm_domain": TARGET}).status_code == 200
    again = client.post(W, headers=headers, json={"domain": TARGET})         # queued scan was deleted, but the audit remains
    assert again.status_code == 201 and again.json()["latest_scan"] is None
    assert again.json()["verification_method"] == "test_target"


def test_yesterdays_scans_do_not_count(client):
    _, _, headers = account_headers(client, "admin")
    site = client.post(W, headers=headers, json={"domain": TARGET}).json()
    finish_active_scans(site["id"])
    request(site["id"])
    finish_active_scans(site["id"])
    with SessionLocal() as db:
        for event in db.scalars(select(ExecutionEvent).where(ExecutionEvent.action == "scan_requested")):
            event.occurred_at = utc_now() - timedelta(days=1, hours=1)
        db.commit()
    assert request(site["id"])
