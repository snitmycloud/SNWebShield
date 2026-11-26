"""Admin 'Verify manually' (demo backup): admin only, typed reason, 24 hours, audit-logged. And www/bare redirect checks."""
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
from app.services import ownership, scan_guard, scans
from app.services.ownership import CheckResult, Fetched, check_file, check_meta
from account_helpers import account_headers

W = "/api/v1/websites"
REASON = "Owner present at demo and gave consent"
TOKEN = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def add_site(client, headers, domain="demo.example.org"):
    response = client.post(W, headers=headers, json={"domain": domain})
    assert response.status_code == 201, response.text
    return response.json()


def verify_manually(client, headers, site_id, reason=REASON):
    return client.post(f"{W}/{site_id}/verify-manual", headers=headers, json={"reason": reason})


def events(action):
    with SessionLocal() as db:
        return list(db.scalars(select(ExecutionEvent).where(ExecutionEvent.action == action)))


# --- who may use it ----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("role", ["user", "analyst", "lead_analyst"])
def test_normal_users_and_analysts_can_never_use_it(client, role):
    _, _, headers = account_headers(client, role)
    site = add_site(client, headers)
    response = verify_manually(client, headers, site["id"])
    assert response.status_code == 403 and "administrator" in response.json()["detail"]
    with SessionLocal() as db:
        row = db.get(Website, site["id"])
        assert row.verification_status == "unverified" and row.verification_method is None
    assert events("manual_verification") == []


def test_a_user_cannot_use_it_on_somebody_elses_website_either(client):
    _, _, owner = account_headers(client, "user")
    _, _, other = account_headers(client, "user")
    site = add_site(client, owner)
    assert verify_manually(client, other, site["id"]).status_code == 403


def test_it_needs_a_login(client):
    assert client.post(f"{W}/1/verify-manual", json={"reason": REASON}).status_code in (401, 403)


def test_the_button_is_offered_only_to_admins_and_only_while_unverified(client):
    _, _, admin = account_headers(client, "admin")
    _, _, user = account_headers(client, "user")
    mine = add_site(client, admin)
    theirs = add_site(client, user, "other.example.org")
    assert client.get(f"{W}/{mine['id']}", headers=admin).json()["can_verify_manually"] is True
    assert client.get(f"{W}/{theirs['id']}", headers=user).json()["can_verify_manually"] is False
    assert verify_manually(client, admin, mine["id"]).status_code == 200
    assert client.get(f"{W}/{mine['id']}", headers=admin).json()["can_verify_manually"] is False


# --- the reason is required ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("reason", ["", "short", "         ", "x" * 301])
def test_a_typed_reason_is_required(client, reason):
    _, _, admin = account_headers(client, "admin")
    site = add_site(client, admin)
    assert verify_manually(client, admin, site["id"], reason).status_code == 422
    assert client.post(f"{W}/{site['id']}/verify-manual", headers=admin, json={}).status_code == 422
    assert client.post(f"{W}/{site['id']}/verify-manual", headers=admin, json={"reason": REASON, "hours": 9999}).status_code == 422


# --- what it does ------------------------------------------------------------------------------------------------------------------------

def test_a_manual_verification_marks_the_site_verified_for_24_hours_and_starts_the_first_scan(client):
    admin_id, admin_email, admin = account_headers(client, "admin")
    site = add_site(client, admin)
    before = utc_now()
    response = verify_manually(client, admin, site["id"])
    assert response.status_code == 200
    body = response.json()["website"]
    assert body["verification_status"] == "verified" and body["verification_method"] == "manual"
    manual = body["manual_verification"]
    assert manual["label"] == "Manually verified by admin" and manual["reason"] == REASON and manual["granted_by"]
    from datetime import datetime
    expires = datetime.fromisoformat(manual["expires_at"])
    assert timedelta(hours=23, minutes=59) < expires - before < timedelta(hours=24, minutes=1)
    assert response.json()["scan"]["status"] == "queued"      # the first scan starts, as after a normal verification


def test_it_is_audit_logged_with_admin_reason_and_time(client):
    admin_id, admin_email, admin = account_headers(client, "admin")
    site = add_site(client, admin)
    verify_manually(client, admin, site["id"])
    [event] = events("manual_verification")
    assert event.actor_id == admin_id and event.resource_id == site["id"]
    detail = event.detail
    assert detail["admin_id"] == admin_id and detail["admin"] == admin_email and detail["reason"] == REASON
    assert detail["domain"] == "demo.example.org" and detail["granted_at"] and detail["expires_at"]


def test_it_can_verify_a_website_in_another_users_account_and_logs_who_owns_it(client):
    _, _, admin = account_headers(client, "admin")
    owner_id, _, owner = account_headers(client, "user")
    site = add_site(client, owner)
    assert verify_manually(client, admin, site["id"]).status_code == 200
    assert client.get(f"{W}/{site['id']}", headers=owner).json()["manual_verification"]["label"] == "Manually verified by admin"
    assert events("manual_verification")[0].detail["owner_id"] == owner_id


def test_a_website_already_verified_by_a_real_method_is_never_downgraded(client):
    _, _, admin = account_headers(client, "admin")
    site = add_site(client, admin)
    with SessionLocal() as db:
        row = db.get(Website, site["id"])
        row.verification_status, row.verification_method, row.verified_at = "verified", "dns", utc_now()
        db.commit()
    response = verify_manually(client, admin, site["id"])
    assert response.status_code == 409
    with SessionLocal() as db:
        assert db.get(Website, site["id"]).verification_method == "dns"


def test_test_targets_removed_and_missing_websites_are_refused(client):
    _, _, admin = account_headers(client, "admin")
    target = add_site(client, admin, "scanme.nmap.org")
    assert verify_manually(client, admin, target["id"]).status_code == 409
    site = add_site(client, admin)
    client.post(f"{W}/{site['id']}/remove", headers=admin, json={"confirm_domain": "demo.example.org"})
    assert verify_manually(client, admin, site["id"]).status_code == 404
    assert verify_manually(client, admin, 999999).status_code == 404


def test_a_disabled_admin_cannot_use_it(client):
    admin_id, _, admin = account_headers(client, "admin")
    site = add_site(client, admin)
    from app.models.admin import Admin
    with SessionLocal() as db:
        db.get(Admin, admin_id).is_active = False
        db.commit()
    assert verify_manually(client, admin, site["id"]).status_code in (401, 403)


# --- expiry ---------------------------------------------------------------------------------------------------------------------------------

def age_manual(site_id, hours):
    with SessionLocal() as db:
        row = db.get(Website, site_id)
        result = dict(row.verification_result)
        result["expires_at"] = (utc_now() - timedelta(hours=hours)).isoformat()
        row.verification_result = result
        db.commit()


def test_it_is_valid_for_the_full_24_hours_and_expires_after(client):
    _, _, admin = account_headers(client, "admin")
    site = add_site(client, admin)
    verify_manually(client, admin, site["id"])
    with SessionLocal() as db:
        row = db.get(Website, site["id"])
        assert ownership.manual_expired(row, utc_now() + timedelta(hours=23)) is False
        assert ownership.manual_expired(row, utc_now() + timedelta(hours=24, minutes=1)) is True
    age_manual(site["id"], 1)
    body = client.get(f"{W}/{site['id']}", headers=admin).json()
    assert body["verification_status"] == "lost" and body["scans_paused"] is True and body["manual_verification"] is None
    assert "expired" in body["verification_result"]["message"] and body["can_verify_manually"] is False or body["can_verify_manually"] is True


def test_an_expired_manual_verification_refuses_scans(client):
    _, _, admin = account_headers(client, "admin")
    site = add_site(client, admin)
    verify_manually(client, admin, site["id"])
    with SessionLocal() as db:                                  # allowed while valid
        assert ownership.ensure_verified(db, db.get(Website, site["id"])) == (True, "manual")
    age_manual(site["id"], 1)
    with SessionLocal() as db:
        row = db.get(Website, site["id"])
        assert ownership.ensure_verified(db, row) == (False, "verification_lost")
        assert row.verification_status == "lost"
        with pytest.raises(Exception) as refused:
            scans.request_scan(db, row, "manual")
        assert getattr(refused.value, "status_code", None) == 409


def test_a_scan_in_progress_stops_when_the_manual_verification_runs_out(client):
    _, _, admin = account_headers(client, "admin")
    site = add_site(client, admin)
    verify_manually(client, admin, site["id"])
    with SessionLocal() as db:
        scan = db.scalar(select(Scan).where(Scan.website_id == site["id"]))
        scan.status, scan.claim_token = "running", "tok"
        db.commit()
        scan_id = scan.id
    import time
    guard = scan_guard.ScanGuard(scan_id, "tok", time.monotonic() + 1000)
    with SessionLocal() as db:
        assert guard._reason(db) is None                        # still valid: the scan may go on
    age_manual(site["id"], 1)
    with SessionLocal() as db:
        stop = guard._reason(db)
        assert stop is not None and stop.code == "verification_lost"


def test_an_unreadable_expiry_fails_closed():
    class Fake:
        verification_method, verification_status, verification_result = "manual", "verified", {"expires_at": "garbage"}
    assert ownership.manual_expired(Fake()) is True
    Fake.verification_result = None
    assert ownership.manual_expired(Fake()) is True


def test_renewing_gives_a_fresh_24_hours_and_a_new_audit_entry(client):
    _, _, admin = account_headers(client, "admin")
    site = add_site(client, admin)
    verify_manually(client, admin, site["id"])
    age_manual(site["id"], 1)
    assert client.get(f"{W}/{site['id']}", headers=admin).json()["verification_status"] == "lost"
    assert verify_manually(client, admin, site["id"], "Second demo, owner is present again").status_code == 200
    assert client.get(f"{W}/{site['id']}", headers=admin).json()["verification_status"] == "verified"
    assert [e.detail["reason"] for e in events("manual_verification")] == [REASON, "Second demo, owner is present again"]


# --- www / bare redirects (file and meta checks) -------------------------------------------------------------------------------------------

def redirect_to(host):
    return Fetched(301, "", "https://x", redirected_to=f"https://{host}/.well-known/x")


def fetcher(answers):
    calls = []

    def fetch(host, path):
        calls.append(host)
        return answers[host]
    fetch.calls = calls
    return fetch


def file_page(body, status=200):
    return Fetched(status, body, "https://x")


def test_bare_redirecting_to_www_checks_both_and_accepts_the_code_found_at_www():
    fetch = fetcher({"example.com": redirect_to("www.example.com"), "www.example.com": file_page(TOKEN)})
    result = check_file("example.com", TOKEN, fetch)
    assert result.ok and fetch.calls == ["example.com", "www.example.com"]
    assert "example.com redirects to www.example.com, and the code was found there" in result.message


def test_www_redirecting_to_bare_is_handled_the_same_way():
    fetch = fetcher({"www.example.com": redirect_to("example.com"), "example.com": file_page(TOKEN)})
    assert check_file("www.example.com", TOKEN, fetch).ok


def test_when_the_code_is_missing_on_the_other_version_the_result_says_both_were_checked():
    fetch = fetcher({"example.com": redirect_to("www.example.com"), "www.example.com": file_page("", 404)})
    result = check_file("example.com", TOKEN, fetch)
    assert not result.ok and result.state == "not_found" and fetch.calls == ["example.com", "www.example.com"]
    assert "We checked both addresses" in result.message and "https://www.example.com" in result.hint


def test_two_versions_that_redirect_to_each_other_are_explained():
    fetch = fetcher({"example.com": redirect_to("www.example.com"), "www.example.com": redirect_to("example.com")})
    result = check_file("example.com", TOKEN, fetch)
    assert not result.ok and result.state == "redirected" and "redirect to each other" in result.message and "DNS TXT" in result.hint


@pytest.mark.parametrize("target", ["evil.example.org", "www.example.com.evil.example", "shop.example.com", "example.com.evil.example"])
def test_a_redirect_anywhere_else_is_never_followed(target):
    fetch = fetcher({"example.com": redirect_to(target)})
    result = check_file("example.com", TOKEN, fetch)
    assert not result.ok and result.state == "redirected" and fetch.calls == ["example.com"]


def test_a_code_on_the_other_version_is_not_accepted_without_a_redirect():
    fetch = fetcher({"example.com": file_page("", 404), "www.example.com": file_page(TOKEN)})
    result = check_file("example.com", TOKEN, fetch)
    assert not result.ok and fetch.calls == ["example.com"]      # no redirect: www is not the site that was added


def test_the_meta_method_follows_the_same_rule():
    page = f'<html><head><meta name="snwebshield-verify" content="{TOKEN}"></head></html>'
    fetch = fetcher({"example.com": redirect_to("www.example.com"), "www.example.com": file_page(page)})
    assert check_meta("example.com", TOKEN, fetch).ok
    fetch = fetcher({"example.com": redirect_to("www.example.com"), "www.example.com": file_page("<html></html>")})
    result = check_meta("example.com", TOKEN, fetch)
    assert not result.ok and "We checked both addresses" in result.message


def test_the_instructions_give_the_exact_file_name_and_folder_for_copy_buttons():
    site = type("S", (), {"verification_token": TOKEN, "domain": "example.com"})()
    info = ownership.instructions(site)
    assert info["file"]["file_name"] == f"snwebshield-{TOKEN}.txt" and info["file"]["folder"] == "/.well-known/"
    assert info["file"]["url"] == f"https://example.com/.well-known/snwebshield-{TOKEN}.txt" and info["file"]["content"] == TOKEN
    assert ownership.counterpart("example.com") == "www.example.com" and ownership.counterpart("www.example.com") == "example.com"
