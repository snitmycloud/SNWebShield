"""DNS/email records and the crt.sh subdomain list: correct parsing, 'could not check' on any failure, short timeouts."""
import asyncio
import json
import time

import pytest

from app.core.config import settings
from app.services import detect_dns as dns_checks
from app.services import detect_subdomains as subs

DOMAIN = "example.com"


class Records:
    """A fake resolver: (name, type) -> list of texts, or an exception to raise."""
    def __init__(self, table):
        self.table, self.asked = table, []

    async def __call__(self, name, rdtype):
        self.asked.append((name, rdtype))
        value = self.table.get((name, rdtype), [])
        if isinstance(value, Exception):
            raise value
        return value


def check(monkeypatch, table, domain=DOMAIN, **kwargs):
    fake = Records(table)
    monkeypatch.setattr(dns_checks, "lookup", fake)
    rows = asyncio.run(dns_checks.check_dns(domain, **kwargs))
    return {r["key"]: r for r in rows}, fake


GOOD = {
    ("example.com", "TXT"): ["google-site-verification=abc", "v=spf1 include:_spf.google.com -all"],
    ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
    ("google._domainkey.example.com", "TXT"): ["v=DKIM1; k=rsa; p=MIGf..."],
    ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
    ("example.com", "MX"): ["10 mail.example.com."],
}


def test_everything_present(monkeypatch):
    rows, _ = check(monkeypatch, GOOD)
    assert rows["spf"]["status"] == "present" and rows["spf"]["data"]["policy"] == "fail"
    assert rows["dmarc"]["status"] == "present" and rows["dmarc"]["data"]["policy"] == "reject"
    assert rows["dkim"]["status"] == "present" and rows["dkim"]["data"]["selectors_found"] == ["google"]
    assert rows["caa"]["status"] == "present" and rows["mx"]["status"] == "present"


def test_a_clean_empty_answer_is_missing_not_unknown(monkeypatch):
    rows, _ = check(monkeypatch, {})
    for key in ("spf", "dmarc", "dkim", "caa", "mx"):
        assert rows[key]["status"] == "missing", key
    assert "common selectors" in rows["dkim"]["data"]["note"]


@pytest.mark.parametrize("record, policy", [
    ("v=spf1 a mx -all", "fail"), ("v=spf1 a ~all", "softfail"), ("v=spf1 ?all", "neutral"),
    ("v=spf1 +all", "pass_all"), ("v=spf1 all", "pass_all"), ("v=spf1 a mx", "no_all"),
])
def test_spf_policy(monkeypatch, record, policy):
    rows, _ = check(monkeypatch, {("example.com", "TXT"): [record]})
    assert rows["spf"]["data"]["policy"] == policy


def test_a_failed_lookup_is_could_not_check_never_missing(monkeypatch):
    broken = {("example.com", "TXT"): TimeoutError("slow"), ("_dmarc.example.com", "TXT"): OSError("servfail"),
              ("example.com", "CAA"): TimeoutError(), ("example.com", "MX"): OSError()}
    rows, _ = check(monkeypatch, broken)
    for key in ("spf", "dmarc", "caa", "mx"):
        assert rows[key]["status"] == "could_not_check", key
    assert rows["dkim"]["status"] == "missing"  # those lookups answered cleanly: none of the selectors exist


def test_dkim_is_could_not_check_only_if_every_selector_lookup_failed(monkeypatch):
    table = {(f"{s}._domainkey.example.com", "TXT"): OSError() for s in dns_checks.DKIM_SELECTORS}
    rows, _ = check(monkeypatch, table)
    assert rows["dkim"]["status"] == "could_not_check"


def test_www_hosts_look_up_email_records_on_the_main_domain(monkeypatch):
    rows, fake = check(monkeypatch, GOOD, domain="www.example.com")
    assert rows["spf"]["data"]["domain"] == "example.com" and rows["spf"]["status"] == "present"
    assert ("www.example.com", "CAA") in fake.asked and ("example.com", "MX") in fake.asked
    assert dns_checks.email_domain("shop.example.com") == "shop.example.com" and dns_checks.email_domain("www.com") == "www.com"


def test_the_guard_is_consulted_between_lookups(monkeypatch):
    class Stop(Exception):
        pass

    class Guard:
        calls = 0
        def check(self):
            Guard.calls += 1
            if Guard.calls >= 4:
                raise Stop

    with pytest.raises(Stop):
        check(monkeypatch, GOOD, guard=Guard())
    assert Guard.calls == 4


def test_records_are_cleaned_and_bounded(monkeypatch):
    rows, _ = check(monkeypatch, {("example.com", "TXT"): ["v=spf1 \x00\x1b[31m" + "x" * 5000 + " -all"]})
    assert len(rows["spf"]["data"]["record"]) <= 400 and "\x1b" not in rows["spf"]["data"]["record"]


# --- crt.sh -----------------------------------------------------------------------------------------------

CRT = json.dumps([
    {"name_value": "example.com\nwww.example.com\n*.example.com"},
    {"name_value": "shop.example.com"}, {"name_value": "API.Example.com\nmail.example.com"},
    {"name_value": "evil.com"}, {"name_value": "example.com.evil.com"}, {"name_value": "notexample.com"},
    {"name_value": "bad name.example.com"}, {"name_value": "x\x00.example.com"}, {"name_value": "-bad.example.com"},
    {"name_value": 12345}, "not a dict",
])


def test_only_real_subdomains_of_the_domain_are_listed():
    assert subs.parse_names(CRT, DOMAIN) == ["api.example.com", "example.com", "mail.example.com", "shop.example.com", "www.example.com"]


def test_invalid_json_is_an_error_and_the_list_is_capped():
    with pytest.raises(ValueError):
        subs.parse_names("<html>rate limited</html>", DOMAIN)
    many = json.dumps([{"name_value": f"h{n}.example.com"} for n in range(5000)])
    assert len(subs.parse_names(many, DOMAIN)) <= subs.MAX_NAMES


def test_listing_works_and_never_includes_the_scanned_host_itself(monkeypatch):
    monkeypatch.setattr(subs, "fetch", lambda domain: CRT)
    result = asyncio.run(subs.list_subdomains("www.example.com"))
    assert result["status"] == "listed" and result["domain"] == "example.com"
    assert "www.example.com" not in result["names"] and "shop.example.com" in result["names"]


@pytest.mark.parametrize("failure", [OSError("down"), TimeoutError(), ValueError("bad"), RuntimeError("boom")])
def test_any_failure_is_could_not_check(monkeypatch, failure):
    def broken(domain):
        raise failure
    monkeypatch.setattr(subs, "fetch", broken)
    result = asyncio.run(subs.list_subdomains(DOMAIN))
    assert result["status"] == "could_not_check" and result["names"] == [] and "crt.sh" in result["reason"]


def test_a_slow_crtsh_never_holds_the_scan_up(monkeypatch):
    monkeypatch.setattr(settings, "crtsh_timeout_seconds", 0.3)
    monkeypatch.setattr(subs, "fetch", lambda domain: (time.sleep(3), CRT)[1])
    started = time.monotonic()
    result = asyncio.run(subs.list_subdomains(DOMAIN))
    assert result["status"] == "could_not_check" and time.monotonic() - started < 2.0


def test_the_short_timeout_is_the_default():
    assert settings.crtsh_timeout_seconds <= 8
