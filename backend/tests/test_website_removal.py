"""Removing a website: typed confirmation, verification and pending scans cleared, history and audit kept,
the plan slot freed, owner-only, and nothing can scan a removed website."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.time import utc_now
from app.db.session import SessionLocal
from app.main import app
from app.models.jobs import ExecutionEvent
from app.models.scan import Scan
from app.models.website import Website
from app.services import ownership, scans
from account_helpers import account_headers, make_account

W = "/api/v1/websites"
PUBLIC = "93.184.216.34"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def add(client, headers, domain="example.com"):
    response = client.post(W, headers=headers, json={"domain": domain})
    assert response.status_code == 201, response.text
    return response.json()


def verify_in_db(website_id, method="dns"):
    with SessionLocal() as db:
        site = db.get(Website, website_id)
        site.verification_status, site.verification_method = "verified", method
        site.verified_at = site.verification_checked_at = utc_now()
        site.verification_result = {"ok": True}
        db.commit()


def add_scan(website_id, owner_id, status, **extra):
    with SessionLocal() as db:
        scan = Scan(id=f"scan-{status}-{website_id}-{len(extra)}".ljust(36, "x")[:36], website_id=website_id,
                    owner_id=owner_id, scan_type="standard", trigger="manual", status=status,
                    requested_at=utc_now(), **extra)
        db.add(scan)
        db.commit()
        return scan.id


def remove(client, headers, site, typed=None):
    return client.post(f"{W}/{site['id']}/remove", headers=headers,
                       json={"confirm_domain": site["domain"] if typed is None else typed})


# --- Confirmation ---------------------------------------------------------------------------------

@pytest.mark.parametrize("typed", ["", "   ", "example.org", "www.example.com", "exampl", "example.com.evil.net"])
def test_the_exact_domain_must_be_typed(client, typed):
    _, _, headers = account_headers(client)
    site = add(client, headers)
    response = remove(client, headers, site, typed)
    assert response.status_code == 422
    assert [w["id"] for w in client.get(W, headers=headers).json()] == [site["id"]]
    with SessionLocal() as db:
        assert db.get(Website, site["id"]).removed_at is None


def test_typed_domain_ignores_case_spaces_and_a_trailing_dot(client):
    _, _, headers = account_headers(client)
    site = add(client, headers)
    assert remove(client, headers, site, "  EXAMPLE.com. ").status_code == 200


def test_the_confirmation_field_is_required(client):
    _, _, headers = account_headers(client)
    site = add(client, headers)
    assert client.post(f"{W}/{site['id']}/remove", headers=headers, json={}).status_code == 422
    assert client.post(f"{W}/{site['id']}/remove", headers=headers, json={"confirm_domain": "example.com", "x": 1}).status_code == 422


# --- What removal does ----------------------------------------------------------------------------

def test_removal_clears_verification_hides_the_site_and_keeps_the_row(client):
    user_id, _, headers = account_headers(client)
    site = add(client, headers)
    verify_in_db(site["id"])
    result = remove(client, headers, site)
    assert result.status_code == 200 and result.json()["status"] == "removed"
    assert "past scan records are kept" in result.json()["message"].lower()
    assert client.get(W, headers=headers).json() == []
    for path in (f"{W}/{site['id']}", f"{W}/{site['id']}/scans"):
        assert client.get(path, headers=headers).status_code == 404
    with SessionLocal() as db:
        row = db.get(Website, site["id"])  # the row stays: history points to it
        assert row is not None and row.removed_at is not None and row.owner_id == user_id and row.domain == "example.com"
        assert (row.verification_token, row.verification_method, row.verification_result,
                row.verified_at, row.verification_checked_at) == (None, None, None, None, None)
        assert row.verification_status == "unverified"


def test_a_removed_website_cannot_be_verified_or_removed_again(client):
    _, _, headers = account_headers(client)
    site = add(client, headers)
    assert remove(client, headers, site).status_code == 200
    assert client.post(f"{W}/{site['id']}/verify", headers=headers, json={"method": "dns"}).status_code == 404
    assert remove(client, headers, site).status_code == 404


def test_queued_scans_are_deleted_running_scans_are_stopped_and_finished_scans_are_kept(client):
    user_id, _, headers = account_headers(client)
    site = add(client, headers)
    verify_in_db(site["id"])
    old = [add_scan(site["id"], user_id, "completed", ended_at=utc_now() - timedelta(days=2)),
           add_scan(site["id"], user_id, "incomplete", ended_at=utc_now() - timedelta(days=1), result={"code": "x"}),
           add_scan(site["id"], user_id, "refused", ended_at=utc_now() - timedelta(hours=5), result={"code": "y"})]
    queued = add_scan(site["id"], user_id, "queued", claim_token=None)
    result = remove(client, headers, site).json()
    assert result["queued_scans_deleted"] == 1 and result["running_scans_stopped"] == 0
    with SessionLocal() as db:
        assert db.get(Scan, queued) is None
        assert {s.id for s in db.scalars(select(Scan).where(Scan.website_id == site["id"]))} == set(old)


def test_a_running_scan_becomes_a_past_record_and_a_late_worker_result_cannot_overwrite_it(client):
    user_id, _, headers = account_headers(client)
    site = add(client, headers)
    verify_in_db(site["id"])
    with SessionLocal() as db:
        scan = Scan(id="r" * 36, website_id=site["id"], owner_id=user_id, scan_type="standard", trigger="first",
                    status="running", requested_at=utc_now(), started_at=utc_now(), claim_token="token-1",
                    lease_until=utc_now() + timedelta(minutes=5))
        db.add(scan)
        db.commit()
    result = remove(client, headers, site).json()
    assert result["running_scans_stopped"] == 1
    with SessionLocal() as db:
        kept = db.get(Scan, "r" * 36)
        assert kept.status == "incomplete" and kept.result["code"] == "website_removed" and kept.claim_token is None
        assert kept.ended_at is not None and "removed" in kept.message
    # The worker that was running it finishes later: it has lost its claim and must change nothing.
    assert scans.execute("r" * 36, "token-1", resolve=lambda d: [PUBLIC], verify=lambda db, w: (True, "cached")) == "lost_claim"
    with SessionLocal() as db:
        assert db.get(Scan, "r" * 36).result["code"] == "website_removed"


def test_audit_trail_is_kept_and_the_removal_is_logged(client):
    user_id, _, headers = account_headers(client)
    site = add(client, headers)
    verify_in_db(site["id"])
    scan_id = add_scan(site["id"], user_id, "queued")
    with SessionLocal() as db:
        before = {e.id for e in db.scalars(select(ExecutionEvent).where(ExecutionEvent.resource_id == site["id"]))}
        assert before  # website_added at least
    remove(client, headers, site)
    with SessionLocal() as db:
        events = list(db.scalars(select(ExecutionEvent).where(ExecutionEvent.resource_id == site["id"])))
        assert before <= {e.id for e in events}  # nothing was deleted
        removal = next(e for e in events if e.action == "website_removed")
        assert removal.actor_id == user_id
        assert removal.detail["domain"] == "example.com" and removal.detail["user_id"] == user_id
        assert removal.detail["verification_was"] == "verified" and removal.detail["queued_scans_deleted"] == 1
        assert removal.detail["removed_at"]
        assert db.get(Scan, scan_id) is None


# --- Plan slots -----------------------------------------------------------------------------------

def test_removing_a_website_frees_a_slot_on_the_free_plan(client):
    _, _, headers = account_headers(client)
    sites = [add(client, headers, f"site{n}.example.com") for n in range(5)]
    assert client.post(W, headers=headers, json={"domain": "extra.example.com"}).status_code == 402
    assert client.get("/api/v1/auth/me/plan", headers=headers).json()["websites_used"] == 5
    assert remove(client, headers, sites[2]).status_code == 200
    assert client.get("/api/v1/auth/me/plan", headers=headers).json()["websites_used"] == 4
    assert client.post(W, headers=headers, json={"domain": "extra.example.com"}).status_code == 201
    assert client.post(W, headers=headers, json={"domain": "more.example.com"}).status_code == 402


def test_a_removed_domain_can_be_added_again_with_a_new_code(client):
    _, _, headers = account_headers(client)
    first = add(client, headers)
    remove(client, headers, first)
    second = add(client, headers)
    assert second["id"] != first["id"] and second["verification_code"] != first["verification_code"]
    assert second["verification_status"] == "unverified"
    assert client.post(W, headers=headers, json={"domain": "example.com"}).status_code == 409  # live duplicate still refused


def test_admin_user_list_does_not_count_removed_websites(client):
    user_id, _, headers = account_headers(client)
    _, _, admin = account_headers(client, "admin")
    site = add(client, headers)
    add(client, headers, "keep.example.com")
    remove(client, headers, site)
    users = client.get("/api/v1/admin/users", headers=admin).json()["users"]
    assert next(u for u in users if u["id"] == user_id)["websites"] == 1


# --- Who may remove -------------------------------------------------------------------------------

def test_only_the_owner_can_remove_a_website(client):
    _, _, owner = account_headers(client)
    _, _, other = account_headers(client)
    _, _, staff = account_headers(client, "admin")
    site = add(client, owner)
    assert remove(client, other, site).status_code == 404
    assert remove(client, staff, site).status_code == 404
    assert client.post(f"{W}/{site['id']}/remove", json={"confirm_domain": "example.com"}).status_code == 401
    with SessionLocal() as db:
        assert db.get(Website, site["id"]).removed_at is None


def test_staff_can_still_read_a_removed_website_but_it_has_no_code(client):
    _, _, owner = account_headers(client)
    _, _, staff = account_headers(client, "admin")
    site = add(client, owner)
    remove(client, owner, site)
    seen = client.get(f"{W}/{site['id']}", headers=staff).json()
    assert seen["removed_at"] and "verification_code" not in seen
    assert site["id"] in [w["id"] for w in client.get(W, headers=staff, params={"all_accounts": True}).json()]


# --- Nothing scans a removed website --------------------------------------------------------------

def test_scans_cannot_be_queued_or_run_for_a_removed_website(client):
    user_id, _, headers = account_headers(client)
    site = add(client, headers)
    verify_in_db(site["id"])
    remove(client, headers, site)
    with SessionLocal() as db, pytest.raises(Exception) as refused:
        scans.request_scan(db, db.get(Website, site["id"]), "manual")
    assert getattr(refused.value, "status_code", None) == 409
    # A scan that somehow still exists is refused by the worker before anything is contacted.
    with SessionLocal() as db:
        db.add(Scan(id="q" * 36, website_id=site["id"], owner_id=user_id, scan_type="standard", trigger="manual",
                    status="running", requested_at=utc_now(), claim_token="t", lease_until=utc_now() + timedelta(minutes=5)))
        db.commit()
    resolved = []
    status = scans.execute("q" * 36, "t", resolve=lambda d: resolved.append(d) or [PUBLIC], verify=lambda db, w: (True, "cached"))
    assert status == "refused" and resolved == []
    with SessionLocal() as db:
        assert db.get(Scan, "q" * 36).result["code"] == "website_removed"


def test_removing_a_verified_parent_stops_covering_its_subdomains(client):
    user_id, _, headers = account_headers(client)
    parent = add(client, headers)
    verify_in_db(parent["id"])
    child = add(client, headers, "shop.example.com")
    assert child["verification_method"] == "parent"
    remove(client, headers, parent)
    with SessionLocal() as db:
        allowed, reason = ownership.ensure_verified(db, db.get(Website, child["id"]))
    assert (allowed, reason) == (False, "verification_lost")
    # And a new subdomain is no longer auto-verified by the removed parent.
    assert add(client, headers, "blog.example.com")["verification_status"] == "unverified"
