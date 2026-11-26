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


# --- reliability: retries, a second resolver, and only then "could not check" -----------------------------------------------------------------------

class Resolvers:
    """Stands in for ONE resolver attempt (detect_dns._query). `script`: a list per call of 'ok' / a list of texts / an exception."""
    def __init__(self, script):
        self.script, self.calls = list(script), []

    async def __call__(self, nameservers, name, rdtype):
        self.calls.append(nameservers)
        step = self.script[min(len(self.calls) - 1, len(self.script) - 1)]
        if isinstance(step, BaseException):
            raise step
        return step


def system_lookup(monkeypatch, script, attempts=3, fallback="1.1.1.1,9.9.9.9"):
    fake = Resolvers(script)
    monkeypatch.setattr(dns_checks, "_query", fake)
    monkeypatch.setattr(dns_checks.settings, "scan_dns_attempts", attempts)
    monkeypatch.setattr(dns_checks.settings, "scan_dns_fallback_resolvers", fallback)
    return fake


def test_a_clean_first_answer_is_used_at_once_and_never_retried(monkeypatch):
    fake = system_lookup(monkeypatch, [["v=spf1 -all"]])
    assert asyncio.run(dns_checks.system_lookup("example.com", "TXT")) == ["v=spf1 -all"] and fake.calls == [None]


def test_a_clean_no_record_answer_is_not_retried_and_stays_missing(monkeypatch):
    fake = system_lookup(monkeypatch, [[]])
    assert asyncio.run(dns_checks.system_lookup("example.com", "CAA")) == [] and len(fake.calls) == 1


def test_a_timeout_is_retried_with_the_second_resolvers_and_can_succeed(monkeypatch):
    fake = system_lookup(monkeypatch, [TimeoutError(), ["v=DMARC1; p=none"]])
    assert asyncio.run(dns_checks.system_lookup("_dmarc.example.com", "TXT")) == ["v=DMARC1; p=none"]
    assert fake.calls == [None, ["1.1.1.1", "9.9.9.9"]]                  # this machine's resolver first, then the second resolvers


def test_the_third_attempt_goes_back_to_this_machines_resolver(monkeypatch):
    fake = system_lookup(monkeypatch, [TimeoutError(), OSError("servfail"), ["ok"]])
    assert asyncio.run(dns_checks.system_lookup("example.com", "MX")) == ["ok"]
    assert fake.calls == [None, ["1.1.1.1", "9.9.9.9"], None]


def test_only_after_every_attempt_failed_does_the_lookup_raise(monkeypatch):
    fake = system_lookup(monkeypatch, [TimeoutError("slow")])
    with pytest.raises(TimeoutError):
        asyncio.run(dns_checks.system_lookup("example.com", "TXT"))
    assert len(fake.calls) == 3                                           # one try and two retries, no more


def test_without_second_resolvers_this_machines_resolver_is_retried(monkeypatch):
    fake = system_lookup(monkeypatch, [TimeoutError()], fallback="")
    with pytest.raises(TimeoutError):
        asyncio.run(dns_checks.system_lookup("example.com", "TXT"))
    assert fake.calls == [None, None, None]


def test_the_number_of_attempts_is_a_setting(monkeypatch):
    fake = system_lookup(monkeypatch, [TimeoutError()], attempts=1)
    with pytest.raises(TimeoutError):
        asyncio.run(dns_checks.system_lookup("example.com", "TXT"))
    assert len(fake.calls) == 1
    assert dns_checks.settings.scan_dns_timeout_seconds == 2.5            # short per-attempt timeout


def test_cancellation_is_never_swallowed_by_the_retries(monkeypatch):
    fake = system_lookup(monkeypatch, [asyncio.CancelledError()])
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(dns_checks.system_lookup("example.com", "TXT"))
    assert len(fake.calls) == 1


def test_a_record_that_needed_a_retry_is_a_normal_present_record_and_the_scan_step_stays_ok(monkeypatch):
    monkeypatch.setattr(dns_checks, "lookup", dns_checks.system_lookup)
    script = {"calls": 0}

    async def flaky(nameservers, name, rdtype):
        script["calls"] += 1
        if script["calls"] % 2 == 1:
            raise TimeoutError("first attempt of every look-up fails")
        return ["v=spf1 include:_spf.example.net ~all"] if (name, rdtype) == ("example.com", "TXT") else []
    monkeypatch.setattr(dns_checks, "_query", flaky)
    monkeypatch.setattr(dns_checks.settings, "scan_dns_attempts", 3)
    rows = {r["key"]: r for r in asyncio.run(dns_checks.check_dns("example.com"))}
    assert rows["spf"]["status"] == "present" and all(r["status"] != "could_not_check" for r in rows.values())


def test_when_all_resolvers_fail_every_record_is_could_not_check_never_missing(monkeypatch):
    monkeypatch.setattr(dns_checks, "lookup", dns_checks.system_lookup)
    system_lookup(monkeypatch, [TimeoutError()])
    rows = {r["key"]: r for r in asyncio.run(dns_checks.check_dns("example.com"))}
    assert {k: v["status"] for k, v in rows.items()} == {"spf": "could_not_check", "dmarc": "could_not_check", "dkim": "could_not_check",
                                                           "caa": "could_not_check", "mx": "could_not_check"}


def test_dkim_gives_up_after_three_failures_in_a_row_instead_of_waiting_through_every_selector(monkeypatch):
    asked = []

    async def down(name, rdtype):
        asked.append(name)
        raise TimeoutError()
    monkeypatch.setattr(dns_checks, "lookup", down)
    rows = {r["key"]: r for r in asyncio.run(dns_checks.check_dns("example.com"))}
    dkim_lookups = [n for n in asked if "_domainkey" in n]
    assert len(dkim_lookups) == 3 and rows["dkim"]["status"] == "could_not_check"


def test_dkim_gives_up_early_but_never_claims_missing_for_selectors_it_did_not_ask(monkeypatch):
    names = list(dns_checks.DKIM_SELECTORS)

    async def partly(name, rdtype):
        if "_domainkey" in name and name.split(".")[0] in names[:2]:
            return []                                                     # two clean "none" answers, then the resolver stops answering
        if "_domainkey" in name:
            raise TimeoutError()
        return []
    monkeypatch.setattr(dns_checks, "lookup", partly)
    rows = {r["key"]: r for r in asyncio.run(dns_checks.check_dns("example.com"))}
    assert rows["dkim"]["status"] == "could_not_check" and rows["dkim"]["data"]["selectors_checked"] < len(names)


def test_a_scan_with_a_flaky_resolver_completes_instead_of_going_incomplete(monkeypatch):
    # The whole-scan rule: a DNS record that needed retries is fine; only a total failure makes the step (and the scan) incomplete.
    from app.services.detect_runner import ScanState
    state = ScanState()
    state.steps = {"dns": {"state": "ok"}}
    assert state.incomplete_steps() == []
    state.steps = {"dns": {"state": "could_not_check", "unchecked": ["dmarc"]}}
    assert state.incomplete_steps() == ["dns"]
