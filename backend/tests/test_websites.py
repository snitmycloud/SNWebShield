"""Phase 1 websites: domain clean-up and refusals, plan limit (Free = 5), per-user isolation, verify -> first scan."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import SessionLocal
from app.main import app
from app.models.scan import Scan
from app.models.website import Website
from app.services import ownership
from app.services.domains import DomainError, covers, normalize_domain, parents
from account_helpers import account_headers

W = "/api/v1/websites"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize("raw, expected", [
    ("www.snitsolutions.in", "www.snitsolutions.in"),
    ("HTTPS://WWW.SnitSolutions.IN/", "www.snitsolutions.in"),
    ("http://example.com/some/path?q=1#top", "example.com"),
    ("example.com:8443/", "example.com"),
    ("example.com.", "example.com"),
    ("  shop.example.co.uk  ", "shop.example.co.uk"),
    ("bücher.example", None),  # .example is reserved
    ("münchen.de", "xn--mnchen-3ya.de"),
])
def test_domain_normalisation(raw, expected):
    if expected is None:
        with pytest.raises(DomainError):
            normalize_domain(raw)
    else:
        assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "10.0.0.1", "http://192.168.1.10/", "8.8.8.8", "[::1]", "::1", "http://[2001:db8::1]/", "localhost",
    "http://localhost:8000", "intranet", "server.local", "db.internal", "printer.lan", "a.test", "x.invalid",
    "user:pass@example.com", "exa mple.com", "-bad.com", "example.123", "1.2.3.4.5",
])
def test_ip_addresses_localhost_and_internal_names_are_refused(raw):
    with pytest.raises(DomainError):
        normalize_domain(raw)


def test_coverage_rules():
    assert parents("a.b.example.com") == ["b.example.com", "example.com"]
    assert covers("example.com", "example.com") and covers("example.com", "shop.example.com")
    assert covers("www.example.com", "www.example.com")
    assert not covers("www.example.com", "example.com") and not covers("www.example.com", "shop.example.com")
    assert not covers("example.com", "badexample.com")


def test_add_website_returns_verification_instructions(client):
    _, _, headers = account_headers(client)
    response = client.post(W, headers=headers, json={"domain": "https://www.snitsolutions.in/"})
    assert response.status_code == 201, response.text
    body = response.json()
    code = body["verification_code"]
    assert body["domain"] == "www.snitsolutions.in" and body["verification_status"] == "unverified"
    assert len(code) == 32 and body["latest_scan"] is None
    assert body["instructions"]["dns"]["value"] == f"snwebshield-verify={code}"
    assert body["instructions"]["file"]["url"] == f"https://www.snitsolutions.in/.well-known/snwebshield-{code}.txt"
    assert body["instructions"]["meta"]["tag"] == f'<meta name="snwebshield-verify" content="{code}">'
    assert client.post(W, headers=headers, json={"domain": "www.snitsolutions.in"}).status_code == 409
    assert client.post(W, headers=headers, json={"domain": "127.0.0.1"}).status_code == 422


def test_tokens_are_unique_per_website_and_per_user(client):
    _, _, first = account_headers(client)
    _, _, second = account_headers(client)
    a = client.post(W, headers=first, json={"domain": "example.com"}).json()["verification_code"]
    b = client.post(W, headers=second, json={"domain": "example.com"}).json()["verification_code"]
    c = client.post(W, headers=first, json={"domain": "example.org"}).json()["verification_code"]
    assert len({a, b, c}) == 3


def test_free_plan_allows_five_websites_and_the_sixth_shows_the_upgrade_message(client):
    user_id, _, headers = account_headers(client)
    for n in range(5):
        assert client.post(W, headers=headers, json={"domain": f"site{n}.example.com"}).status_code == 201
    sixth = client.post(W, headers=headers, json={"domain": "site5.example.com"})
    assert sixth.status_code == 402
    detail = sixth.json()["detail"]
    assert detail["code"] == "plan_limit" and detail["max"] == 5 and detail["plan"] == "free"
    assert "Upgrade" in detail["message"]
    with SessionLocal() as db:
        assert len(db.scalars(select(Website).where(Website.owner_id == user_id)).all()) == 5
    # An admin moves the account to Pro: the limit comes from plans.json, not code.
    _, _, admin = account_headers(client, "admin")
    assert client.post(f"/api/v1/admin/users/{user_id}/plan", headers=admin, json={"plan": "pro"}).status_code == 200
    assert client.post(W, headers=headers, json={"domain": "site5.example.com"}).status_code == 201


def test_plan_limits_are_read_from_the_config_file(client, tmp_path, monkeypatch):
    import json
    from app.services import plans
    data = json.loads(plans.PLANS_FILE.read_text())
    data["plans"]["free"]["max_websites"] = 1
    custom = tmp_path / "plans.json"
    custom.write_text(json.dumps(data))
    original = plans.load
    monkeypatch.setattr(plans, "load", lambda path=custom: original(path))
    _, _, headers = account_headers(client)
    assert client.post(W, headers=headers, json={"domain": "one.example.com"}).status_code == 201
    assert client.post(W, headers=headers, json={"domain": "two.example.com"}).json()["detail"]["max"] == 1


def test_each_user_sees_only_their_own_websites(client):
    _, _, alice = account_headers(client)
    _, _, bob = account_headers(client)
    site = client.post(W, headers=alice, json={"domain": "alice.example.com"}).json()["id"]
    assert [w["id"] for w in client.get(W, headers=alice).json()] == [site]
    assert client.get(W, headers=bob).json() == []
    assert client.get(f"{W}/{site}", headers=bob).status_code == 404
    assert client.get(f"{W}/{site}/scans", headers=bob).status_code == 404
    assert client.post(f"{W}/{site}/verify", headers=bob, json={"method": "dns"}).status_code == 404
    # Asking for every account's websites is ignored for customers.
    assert client.get(W, headers=bob, params={"all_accounts": True}).json() == []


def test_staff_can_read_any_website_but_never_see_its_code_or_verify_it(client):
    _, _, alice = account_headers(client)
    _, _, staff = account_headers(client, "admin")
    site = client.post(W, headers=alice, json={"domain": "alice.example.com"}).json()["id"]
    assert site in [w["id"] for w in client.get(W, headers=staff, params={"all_accounts": True}).json()]
    seen = client.get(f"{W}/{site}", headers=staff).json()
    assert "verification_code" not in seen and "instructions" not in seen
    assert client.post(f"{W}/{site}/verify", headers=staff, json={"method": "dns"}).status_code == 404


def _fake(state, method="dns"):
    def check(domain, token):
        expected = f"snwebshield-verify={token}"
        if state == "verified":
            return ownership.CheckResult(method, "verified", expected, [expected], "Ownership confirmed.")
        if state == "no_https":
            return ownership.CheckResult(method, "no_https", expected, [], "No HTTPS.", ownership.DNS_HINT_NO_HTTPS)
        return ownership.CheckResult(method, "not_found", expected, ["v=spf1 -all"], "No matching TXT record.", "Add it.")
    return check


def test_failed_verification_shows_found_and_expected_and_starts_nothing(client, monkeypatch):
    _, _, headers = account_headers(client)
    site = client.post(W, headers=headers, json={"domain": "example.com"}).json()
    monkeypatch.setitem(ownership.CHECKS, "dns", _fake("missing"))
    response = client.post(f"{W}/{site['id']}/verify", headers=headers, json={"method": "dns"})
    assert response.status_code == 200
    check = response.json()["check"]
    assert check["ok"] is False and check["found"] == ["v=spf1 -all"]
    assert check["expected"] == f"snwebshield-verify={site['verification_code']}"
    assert response.json()["scan"] is None and response.json()["website"]["verification_status"] == "unverified"
    with SessionLocal() as db:
        assert db.scalars(select(Scan)).all() == []


def test_no_https_tells_the_owner_to_use_dns(client, monkeypatch):
    _, _, headers = account_headers(client)
    site = client.post(W, headers=headers, json={"domain": "example.com"}).json()
    monkeypatch.setitem(ownership.CHECKS, "file", _fake("no_https", "file"))
    check = client.post(f"{W}/{site['id']}/verify", headers=headers, json={"method": "file"}).json()["check"]
    assert check["state"] == "no_https" and "DNS TXT" in check["hint"]


def test_successful_verification_starts_the_first_scan_automatically(client, monkeypatch):
    user_id, _, headers = account_headers(client)
    site = client.post(W, headers=headers, json={"domain": "snitsolutions.in"}).json()
    monkeypatch.setitem(ownership.CHECKS, "dns", _fake("verified"))
    response = client.post(f"{W}/{site['id']}/verify", headers=headers, json={"method": "dns"}).json()
    assert response["check"]["ok"] is True
    assert response["website"]["verification_status"] == "verified"
    assert response["website"]["verification_method"] == "dns"
    assert response["scan"]["status"] == "queued" and response["scan"]["trigger"] == "first"
    # Verifying again does not queue a second first scan.
    again = client.post(f"{W}/{site['id']}/verify", headers=headers, json={"method": "dns"}).json()
    assert again["scan"] is None
    with SessionLocal() as db:
        rows = db.scalars(select(Scan)).all()
        assert len(rows) == 1 and rows[0].owner_id == user_id and rows[0].website_id == site["id"]
    listed = client.get(f"{W}/{site['id']}/scans", headers=headers).json()
    assert listed[0]["status"] == "queued"


def test_verified_parent_covers_subdomains_but_www_covers_only_itself(client, monkeypatch):
    _, _, headers = account_headers(client)
    monkeypatch.setitem(ownership.CHECKS, "dns", _fake("verified"))
    apex = client.post(W, headers=headers, json={"domain": "example.com"}).json()
    client.post(f"{W}/{apex['id']}/verify", headers=headers, json={"method": "dns"})
    shop = client.post(W, headers=headers, json={"domain": "shop.example.com"}).json()
    assert shop["verification_status"] == "verified" and shop["verification_method"] == "parent"
    assert shop["latest_scan"]["status"] == "queued"

    www = client.post(W, headers=headers, json={"domain": "www.other.com"}).json()
    client.post(f"{W}/{www['id']}/verify", headers=headers, json={"method": "dns"})
    sibling = client.post(W, headers=headers, json={"domain": "blog.other.com"}).json()
    assert sibling["verification_status"] == "unverified"


def test_another_users_verified_parent_covers_nothing(client, monkeypatch):
    _, _, alice = account_headers(client)
    _, _, mallory = account_headers(client)
    monkeypatch.setitem(ownership.CHECKS, "dns", _fake("verified"))
    apex = client.post(W, headers=alice, json={"domain": "example.com"}).json()
    client.post(f"{W}/{apex['id']}/verify", headers=alice, json={"method": "dns"})
    shop = client.post(W, headers=mallory, json={"domain": "shop.example.com"}).json()
    assert shop["verification_status"] == "unverified" and shop["latest_scan"] is None
