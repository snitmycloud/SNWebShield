"""Ownership checks (DNS TXT, file, meta tag), the hardened HTTPS fetch, and re-checks before scans."""
from datetime import timedelta
import ssl
from types import SimpleNamespace

import pytest

from app.core.time import utc_now
from app.services import ip_policy, ownership
from app.services.ownership import CheckResult, Fetched, check_dns, check_file, check_meta

TOKEN = "0123456789abcdef0123456789abcdef"


# --- DNS -----------------------------------------------------------------------------------------

def test_dns_match():
    result = check_dns("example.com", TOKEN, lookup=lambda d: ["v=spf1 -all", f"snwebshield-verify={TOKEN}"])
    assert result.ok and result.method == "dns"


def test_dns_missing_shows_what_was_found_and_expected():
    result = check_dns("example.com", TOKEN, lookup=lambda d: ["v=spf1 include:_spf.google.com ~all"])
    assert not result.ok and result.state == "not_found"
    assert result.expected == f"snwebshield-verify={TOKEN}" and result.found == ["v=spf1 include:_spf.google.com ~all"]


def test_dns_wrong_code_is_called_out():
    result = check_dns("example.com", TOKEN, lookup=lambda d: ["snwebshield-verify=somebody-elses-code"])
    assert not result.ok and "does not match" in result.message


def test_dns_partial_or_padded_value_is_not_accepted():
    assert not check_dns("example.com", TOKEN, lookup=lambda d: [f"snwebshield-verify={TOKEN[:-1]}"]).ok
    assert not check_dns("example.com", TOKEN, lookup=lambda d: [f"xsnwebshield-verify={TOKEN}"]).ok


def test_dns_failure_is_could_not_check_never_verified():
    def boom(domain):
        raise TimeoutError("dns")
    result = check_dns("example.com", TOKEN, lookup=boom)
    assert not result.ok and result.state == "could_not_check"


def test_dns_found_values_are_cut_and_cleaned():
    result = check_dns("example.com", TOKEN, lookup=lambda d: ["a\x00b\x1b[31m" + "x" * 500] * 20)
    assert len(result.found) == 10 and all(len(f) <= 201 and "\x00" not in f and "\x1b" not in f for f in result.found)


# --- File ----------------------------------------------------------------------------------------

def test_file_match_and_path():
    seen = []
    def fetch(host, path):
        seen.append((host, path))
        return Fetched(200, TOKEN + "\n", f"https://{host}{path}")
    assert check_file("example.com", TOKEN, fetch=fetch).ok
    assert seen == [("example.com", f"/.well-known/snwebshield-{TOKEN}.txt")]


@pytest.mark.parametrize("status, body", [
    (404, "Not Found"), (200, "<html>Page not found</html>"), (200, ""), (500, TOKEN), (200, TOKEN + " extra"),
])
def test_file_soft_404s_and_wrong_content_are_not_accepted(status, body):
    result = check_file("example.com", TOKEN, fetch=lambda h, p: Fetched(status, body, ""))
    assert not result.ok and result.found[0].startswith(f"HTTP {status}")


def test_file_redirect_elsewhere_is_reported_not_followed():
    result = check_file("example.com", TOKEN, fetch=lambda h, p: Fetched(301, "", "", redirected_to="https://www.example.com/x"))
    assert not result.ok and result.state == "redirected" and "www.example.com" in result.found[0]


@pytest.mark.parametrize("error", [ownership.NoHttps("certificate"), ownership.NoHttps("refused"), TimeoutError("https")])
def test_no_valid_https_tells_the_owner_to_use_dns(error):
    def fetch(host, path):
        raise error
    for check in (check_file, check_meta):
        result = check("example.com", TOKEN, fetch=fetch)
        assert not result.ok and result.state == "no_https" and "DNS TXT" in result.hint


def test_private_destination_is_refused_with_a_plain_reason():
    def fetch(host, path):
        raise ip_policy.Blocked("private_or_reserved_address")
    result = check_file("example.com", TOKEN, fetch=fetch)
    assert not result.ok and result.state == "could_not_check" and "private" in result.message


# --- Meta ----------------------------------------------------------------------------------------

def test_meta_match_in_any_attribute_order_and_case():
    page = f'<html><head><META content="{TOKEN}" NAME="SNWebShield-Verify"></head></html>'
    assert check_meta("example.com", TOKEN, fetch=lambda h, p: Fetched(200, page, "")).ok


def test_meta_missing_or_wrong():
    missing = check_meta("example.com", TOKEN, fetch=lambda h, p: Fetched(200, "<html><head></head></html>", ""))
    assert not missing.ok and missing.expected == f'<meta name="snwebshield-verify" content="{TOKEN}">'
    wrong = check_meta("example.com", TOKEN, fetch=lambda h, p: Fetched(
        200, '<meta name="snwebshield-verify" content="other">', ""))
    assert not wrong.ok and "does not match" in wrong.message
    in_text = check_meta("example.com", TOKEN, fetch=lambda h, p: Fetched(200, f"<p>{TOKEN}</p>", ""))
    assert not in_text.ok


def test_meta_on_error_page_is_not_accepted():
    page = f'<meta name="snwebshield-verify" content="{TOKEN}">'
    assert not check_meta("example.com", TOKEN, fetch=lambda h, p: Fetched(404, page, "")).ok


# --- The hardened HTTPS fetch --------------------------------------------------------------------

class FakeConnection:
    """Stands in for the pinned HTTPS connection; records where it was told to connect."""
    script = []
    opened = []

    def __init__(self, host, ip, timeout):
        self.host, self.ip = host, ip
        FakeConnection.opened.append((host, ip))

    def request(self, method, path, headers):
        self.path = path
        self.response = FakeConnection.script.pop(0)

    def getresponse(self):
        status, headers, body = self.response
        if isinstance(status, Exception):
            raise status
        return SimpleNamespace(status=status, getheader=lambda name: headers.get(name),
                               read=lambda n: body[:n])

    def close(self):
        pass


@pytest.fixture
def fake_https(monkeypatch):
    FakeConnection.script, FakeConnection.opened = [], []
    monkeypatch.setattr(ownership, "_PinnedHTTPS", FakeConnection)
    monkeypatch.setattr(ip_policy, "resolve_public", lambda host, port=443: ["93.184.216.34"])
    return FakeConnection


def test_fetch_connects_only_to_the_vetted_ip(fake_https):
    fake_https.script = [(200, {}, b"hello")]
    fetched = ownership.fetch_https("example.com", "/x")
    assert fetched.status == 200 and fetched.body == "hello"
    assert fake_https.opened == [("example.com", "93.184.216.34")]


def test_fetch_follows_same_host_https_redirects_only(fake_https):
    fake_https.script = [(302, {"Location": "/new"}, b""), (200, {}, b"ok")]
    assert ownership.fetch_https("example.com", "/old").body == "ok"
    for location in ("http://example.com/x", "https://evil.example.net/x", "https://example.com:8443/x",
                     "https://user@169.254.169.254/latest/meta-data"):
        fake_https.script = [(301, {"Location": location}, b"")]
        fetched = ownership.fetch_https("example.com", "/")
        assert fetched.redirected_to and fetched.body == ""


def test_fetch_stops_after_three_redirects(fake_https):
    fake_https.script = [(302, {"Location": "/a"}, b"")] * 4
    assert ownership.fetch_https("example.com", "/").redirected_to == "too many redirects"


def test_fetch_reads_at_most_256_kb(fake_https):
    fake_https.script = [(200, {}, b"a" * (ownership.MAX_BODY + 50000))]
    assert len(ownership.fetch_https("example.com", "/").body) == ownership.MAX_BODY


def test_fetch_maps_certificate_errors_to_no_https(fake_https):
    fake_https.script = [(ssl.SSLCertVerificationError("bad cert"), {}, b"")]
    with pytest.raises(ownership.NoHttps):
        ownership.fetch_https("example.com", "/")


def test_fetch_refuses_a_private_address_before_connecting(monkeypatch):
    opened = []
    monkeypatch.setattr(ownership, "_PinnedHTTPS", lambda *a: opened.append(a))
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(ip_policy.Blocked):
        ownership.fetch_https("example.com", "/")
    assert opened == []


# --- Re-checks before a scan -----------------------------------------------------------------------

def site(**values):
    defaults = dict(id=1, owner_id=1, domain="example.com", verification_token=TOKEN, verification_method="dns",
                    verification_status="verified", verification_checked_at=utc_now(), verification_result=None,
                    verified_at=utc_now())
    return SimpleNamespace(**{**defaults, **values})


def test_recent_verification_is_reused_for_24_hours(monkeypatch):
    calls = []
    monkeypatch.setitem(ownership.CHECKS, "dns", lambda d, t: calls.append(d))
    assert ownership.ensure_verified(None, site()) == (True, "cached") and calls == []


def test_stale_verification_is_rechecked(monkeypatch):
    monkeypatch.setitem(ownership.CHECKS, "dns", lambda d, t: CheckResult("dns", "verified", "x", ["x"]))
    website = site(verification_checked_at=utc_now() - timedelta(hours=25))
    assert ownership.ensure_verified(None, website) == (True, "rechecked")
    assert website.verification_checked_at > utc_now() - timedelta(minutes=1)


def test_proof_gone_marks_verification_lost(monkeypatch):
    monkeypatch.setitem(ownership.CHECKS, "dns", lambda d, t: CheckResult("dns", "not_found", "x", [], "missing"))
    website = site(verification_checked_at=utc_now() - timedelta(hours=25))
    assert ownership.ensure_verified(None, website) == (False, "verification_lost")
    assert website.verification_status == "lost" and "no longer find" in website.verification_result["message"]


@pytest.mark.parametrize("state", ["could_not_check", "no_https"])
def test_check_that_cannot_run_refuses_the_scan_without_declaring_loss(monkeypatch, state):
    monkeypatch.setitem(ownership.CHECKS, "dns", lambda d, t: CheckResult("dns", state, "x", []))
    website = site(verification_checked_at=utc_now() - timedelta(hours=25))
    assert ownership.ensure_verified(None, website) == (False, "could_not_recheck")
    assert website.verification_status == "verified"


@pytest.mark.parametrize("status", ["unverified", "lost"])
def test_unverified_or_lost_websites_are_never_allowed(status):
    assert ownership.ensure_verified(None, site(verification_status=status)) == (False, "not_verified")
