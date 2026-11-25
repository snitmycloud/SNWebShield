"""The built-in configuration checks and the TLS probes (local servers only)."""
import asyncio
import ssl
import warnings
from datetime import datetime, timedelta, timezone

import pytest

from app.services import engine_config as ec, probe_tls
from app.services.detect_runner import ScanContext, ScanState
from app.services.detect_versions import PortProbe, WebPage
from netfixtures import BackgroundServer, HOST, banner_handler, free_port, http_handler, server_tls

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)
DOMAIN = "test.snwebshield.example"
GOOD = {"strict-transport-security": "max-age=1", "content-security-policy": "default-src 'self'", "x-frame-options": "DENY",
        "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "permissions-policy": "camera=()"}


def ids(findings):
    return sorted(f.check_id for f in findings)


def cert(not_after=NOW + timedelta(days=90), san=(DOMAIN,), self_signed=False, cn=DOMAIN):
    return {"subject": f"CN={cn}", "subject_cn": cn, "issuer": "CN=Some CA", "issuer_cn": "Some CA", "san": list(san),
            "not_before": (NOW - timedelta(days=10)).isoformat(), "not_after": not_after.isoformat(), "self_signed": self_signed}


def web(port=443, tls=True, status=200, headers=None, cookies=(), body=""):
    return PortProbe(port=port, service="https" if tls else "http", http={"status": status, "over_tls": tls, "headers": {}, "cookies": []},
                     web=WebPage(port=port, tls=tls, status=status, headers=dict(headers if headers is not None else GOOD),
                                 cookies=list(cookies), body=body))


# --- certificates ------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("days, expected", [(-1, ["tls:certificate-expired"]), (3, ["tls:certificate-expires-7d"]),
                                            (6, ["tls:certificate-expires-7d"]), (7, ["tls:certificate-expires-30d"]),
                                            (29, ["tls:certificate-expires-30d"]), (31, [])])
def test_certificate_expiry_bands(days, expected):
    found = ec.certificate_findings(DOMAIN, 443, cert(NOW + timedelta(days=days, hours=1)), NOW)
    assert ids(found) == expected


def test_expired_is_high_and_expiring_soon_is_lower():
    sev = {f.check_id: f.severity for f in ec.certificate_findings(DOMAIN, 443, cert(NOW - timedelta(days=2)), NOW)}
    assert sev["tls:certificate-expired"] == "high"
    assert ec.certificate_findings(DOMAIN, 443, cert(NOW + timedelta(days=3)), NOW)[0].severity == "medium"
    assert ec.certificate_findings(DOMAIN, 443, cert(NOW + timedelta(days=20)), NOW)[0].severity == "low"


def test_hostname_matching_including_wildcards():
    assert ids(ec.certificate_findings(DOMAIN, 443, cert(san=["other.example"]), NOW)) == ["tls:hostname-mismatch"]
    assert ec.certificate_findings("www.example.com", 443, cert(san=["*.example.com"]), NOW) == []
    assert ids(ec.certificate_findings("example.com", 443, cert(san=["*.example.com"]), NOW)) == ["tls:hostname-mismatch"]
    assert ids(ec.certificate_findings("a.b.example.com", 443, cert(san=["*.example.com"]), NOW)) == ["tls:hostname-mismatch"]
    assert ec.certificate_findings(DOMAIN, 443, cert(san=[], cn=DOMAIN), NOW) == []   # no SAN: the common name is used


def test_self_signed_is_reported():
    assert "tls:self-signed" in ids(ec.certificate_findings(DOMAIN, 443, cert(self_signed=True), NOW))


def test_an_unreadable_date_never_becomes_a_pass_or_a_crash():
    broken = cert()
    broken["not_after"] = None
    assert ec.certificate_findings(DOMAIN, 443, broken, NOW) == []


# --- headers, cookies, mixed content, https -----------------------------------------------------------------------------------------

def test_a_site_with_all_headers_has_no_header_findings():
    assert ec.web_findings(DOMAIN, [web()], NOW) == []


def test_missing_headers_are_found_with_plain_severity():
    found = {f.check_id: f for f in ec.web_findings(DOMAIN, [web(headers={})], NOW)}
    assert set(found) == {"header:hsts-missing", "header:csp-missing", "header:xfo-missing", "header:xcto-missing",
                          "header:referrer-policy-missing", "header:permissions-policy-missing"}
    assert found["header:hsts-missing"].severity == "low" and found["header:referrer-policy-missing"].severity == "info"
    assert not found["header:permissions-policy-missing"].scored


def test_csp_frame_ancestors_replaces_x_frame_options_and_hsts_is_only_expected_on_https():
    headers = {**GOOD, "content-security-policy": "frame-ancestors 'none'"}
    del headers["x-frame-options"]
    assert ec.web_findings(DOMAIN, [web(headers=headers)], NOW) == []
    plain = {f.check_id for f in ec.web_findings(DOMAIN, [web(80, tls=False, headers={}), web()], NOW)}
    assert "header:hsts-missing" not in plain


def test_error_pages_and_redirects_are_not_judged_for_headers():
    assert ec.web_findings(DOMAIN, [web(status=404, headers={}), web(80, tls=False, status=301, headers={"location": "https://test.snwebshield.example/"})], NOW) == []


def test_cookie_flags_names_only():
    cookies = [{"name": "sid", "secure": False, "httponly": False, "samesite": None},
               {"name": "good", "secure": True, "httponly": True, "samesite": "Lax"}]
    found = ec.web_findings(DOMAIN, [web(cookies=cookies)], NOW)
    assert ids(found) == ["cookie:no-httponly", "cookie:no-samesite", "cookie:no-secure"]
    assert all("sid" in f.location and "good" not in f.location for f in found)
    assert "value" not in " ".join((f.evidence or "") for f in found).lower()


def test_mixed_content_is_found_only_on_secure_pages():
    body = '<html><script src="http://cdn.example/a.js"></script><a href="http://example.com/x">link</a></html>'
    assert "http:mixed-content" in ids(ec.web_findings(DOMAIN, [web(body=body)], NOW))
    assert "http:mixed-content" not in ids(ec.web_findings(DOMAIN, [web(body='<a href="http://example.com">only a link</a>')], NOW))
    assert "http:mixed-content" not in ids(ec.web_findings(DOMAIN, [web(80, tls=False, body=body)], NOW))
    assert "http:mixed-content" in ids(ec.web_findings(DOMAIN, [web(body='<link rel="stylesheet" href="http://x.example/a.css">')], NOW))


def test_no_https_only_when_plain_web_exists_and_no_https_anywhere():
    found = ec.web_findings(DOMAIN, [web(80, tls=False)], NOW)
    assert ids(found) == ["http:no-https"] and found[0].severity == "high"
    both = ec.web_findings(DOMAIN, [web(80, tls=False), web()], NOW)
    assert "http:no-https" not in ids(both)
    open_443_but_unreadable = PortProbe(port=443, service="https")
    assert "http:no-https" not in ids(ec.web_findings(DOMAIN, [web(80, tls=False), open_443_but_unreadable], NOW))


def test_redirect_from_http_to_https():
    ok = web(80, tls=False, status=301, headers={"location": "https://test.snwebshield.example/"})
    assert "http:no-redirect" not in ids(ec.web_findings(DOMAIN, [ok, web()], NOW))
    stays = web(80, tls=False, headers=GOOD)
    assert "http:no-redirect" in ids(ec.web_findings(DOMAIN, [stays, web()], NOW))
    elsewhere = web(80, tls=False, status=301, headers={"location": "http://test.snwebshield.example/"})
    assert "http:no-redirect" in ids(ec.web_findings(DOMAIN, [elsewhere, web()], NOW))


def test_version_disclosure_is_info_and_not_scored():
    found = ec.web_findings(DOMAIN, [web(headers={**GOOD, "server": "Apache/2.4.7 (Ubuntu)", "x-powered-by": "PHP/5.5.9"})], NOW)
    disclosed = [f for f in found if f.check_id == "disclosure:version"]
    assert len(disclosed) == 2 and all(f.severity == "info" and not f.scored for f in disclosed)
    assert not [f for f in ec.web_findings(DOMAIN, [web(headers={**GOOD, "server": "nginx"})], NOW)]


# --- ports and exposed files -------------------------------------------------------------------------------------------------------

def test_risky_ports_and_normal_ports():
    found = {f.check_id: f for f in ec.port_findings(DOMAIN, [22, 80, 443, 3306, 6379, 2375, 31337])}
    assert set(found) == {"port:22", "port:3306", "port:6379", "port:2375"}
    assert found["port:3306"].severity == "high" and found["port:2375"].severity == "critical" and found["port:22"].severity == "info"
    assert "database" in found["port:3306"].title.lower()


def test_exposed_file_findings_never_carry_file_contents():
    rows = [{"key": "/.env", "status": "exposed", "data": {"kind": "exposed_file", "signature": "env-file", "http_status": 200}},
            {"key": "/wp-login.php", "status": "exposed", "data": {"kind": "admin_login", "signature": "login-form", "http_status": 200}},
            {"key": "/x", "status": "exposed", "data": {"signature": "unknown-thing"}}]
    found = {f.check_id: f for f in ec.exposed_findings(DOMAIN, rows)}
    assert set(found) == {"exposed:env-file:/.env", "exposed:login-form:/wp-login.php"}
    assert found["exposed:env-file:/.env"].severity == "critical" and found["exposed:login-form:/wp-login.php"].severity == "info"
    assert "not stored" in found["exposed:env-file:/.env"].evidence


# --- CORS -------------------------------------------------------------------------------------------------------------------------

def test_cors_decisions():
    origin = ec.CORS_TEST_ORIGIN
    assert ids(ec.cors_findings(DOMAIN, 443, {"origin": origin, "credentials": "true"})) == ["cors:credentials-any-origin"]
    assert ec.cors_findings(DOMAIN, 443, {"origin": origin, "credentials": "true"})[0].severity == "high"
    assert ids(ec.cors_findings(DOMAIN, 443, {"origin": "*", "credentials": None})) == ["cors:wildcard"]
    assert ids(ec.cors_findings(DOMAIN, 443, {"origin": origin, "credentials": None})) == ["cors:wildcard"]
    assert ec.cors_findings(DOMAIN, 443, {"origin": "https://app.example.com", "credentials": "true"}) == []
    assert ec.cors_findings(DOMAIN, 443, {"origin": None, "credentials": None}) == []


def test_cors_probe_sends_one_get_with_the_test_origin_only():
    page = (200, {"Access-Control-Allow-Origin": ec.CORS_TEST_ORIGIN, "Access-Control-Allow-Credentials": "true"}, b"hi")
    with BackgroundServer(http_handler({"/": page})) as server:
        result = asyncio.run(ec.cors_probe(HOST, server.port, False, DOMAIN, 2.0))
    assert result == {"origin": ec.CORS_TEST_ORIGIN, "credentials": "true"}
    assert len(server.requests) == 1 and b"Origin: https://snwebshield-cors-test.invalid" in server.requests[0]
    assert b"Cookie" not in server.requests[0] and b"Authorization" not in server.requests[0]


def test_cors_probe_without_an_answer_is_none_not_a_pass():
    assert asyncio.run(ec.cors_probe(HOST, free_port(), False, DOMAIN, 0.5)) is None


# --- TLS probes against local servers --------------------------------------------------------------------------------------------

def old_tls(version):
    def make():
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            return server_tls(version, version, "ALL:@SECLEVEL=0")
    return make


def modern_tls():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return server_tls(ssl.TLSVersion.TLSv1_2, None)


async def _ok(reader, writer, server):
    await asyncio.sleep(0.05)


@pytest.mark.parametrize("version, name", [(ssl.TLSVersion.TLSv1, "TLSv1"), (ssl.TLSVersion.TLSv1_1, "TLSv1.1")])
def test_an_old_only_server_accepts_that_old_protocol(version, name):
    with BackgroundServer(_ok, tls_context=old_tls(version)) as server:
        answer = asyncio.run(probe_tls.protocol_supported(HOST, server.port, DOMAIN, name))
    assert answer in (probe_tls.ACCEPTED, probe_tls.LOCAL)   # LOCAL only if this computer's OpenSSL cannot speak it
    if answer == probe_tls.LOCAL:
        pytest.skip("this computer's TLS library cannot offer the old protocol")


def test_a_modern_server_refuses_tls_1_0_and_1_1():
    with BackgroundServer(_ok, tls_context=modern_tls) as server:
        answers = [asyncio.run(probe_tls.protocol_supported(HOST, server.port, DOMAIN, v)) for v in ("TLSv1", "TLSv1.1")]
    assert answers == [probe_tls.REFUSED, probe_tls.REFUSED] or probe_tls.LOCAL in answers


def test_a_closed_port_or_silent_server_is_could_not_check_not_refused():
    assert asyncio.run(probe_tls.protocol_supported(HOST, free_port(), DOMAIN, "TLSv1", timeout=0.5)) == probe_tls.UNKNOWN

    async def silent(reader, writer, server):
        await asyncio.sleep(3)
    with BackgroundServer(silent) as server:
        assert asyncio.run(probe_tls.protocol_supported(HOST, server.port, DOMAIN, "TLSv1.1", timeout=0.5)) == probe_tls.UNKNOWN


def test_weak_cipher_probe_reports_a_local_limit_honestly_or_a_server_answer():
    with BackgroundServer(_ok, tls_context=modern_tls) as server:
        answer = asyncio.run(probe_tls.weak_cipher_accepted(HOST, server.port, DOMAIN))
    assert answer in (probe_tls.REFUSED, probe_tls.LOCAL) and answer != probe_tls.ACCEPTED


def test_a_weak_cipher_that_is_accepted_is_a_finding(monkeypatch):
    async def accepted(*a, **k):
        return probe_tls.ACCEPTED
    monkeypatch.setattr(probe_tls, "weak_cipher_accepted", accepted)
    result = _run_config(monkeypatch, [_tls_probe(443, cert())], with_servers=None)
    assert "tls:weak-ciphers" in ids(result.findings)


def test_trust_says_untrusted_for_a_self_made_certificate():
    with BackgroundServer(_ok, tls=True) as server:
        result = asyncio.run(probe_tls.trust(HOST, server.port, DOMAIN))
    assert result["state"] == "untrusted" and result["reason"]


def test_trust_for_a_server_that_does_not_speak_tls_is_could_not_check():
    with BackgroundServer(banner_handler(b"hello\r\n")) as server:
        assert asyncio.run(probe_tls.trust(HOST, server.port, DOMAIN, timeout=1.0))["state"] == "could_not_check"


# --- the engine as a whole ---------------------------------------------------------------------------------------------------------

class Guard:
    def check(self):
        pass


def _tls_probe(port, certificate):
    probe = web(port)
    probe.tls = {"version": "TLSv1.3", "cipher": "x", "bits": 256, "certificate": certificate}
    return probe


def _run_config(monkeypatch, probes, ports=(), exposed=(), with_servers="default"):
    async def trust(*a, **k):
        return {"state": "trusted", "reason": None, "code": 0}

    async def proto(*a, **k):
        return probe_tls.REFUSED

    async def weak(*a, **k):
        return probe_tls.REFUSED

    async def cors(*a, **k):
        return {"origin": None, "credentials": None}
    monkeypatch.setattr(probe_tls, "trust", trust)
    monkeypatch.setattr(probe_tls, "protocol_supported", proto)
    if with_servers == "default":
        monkeypatch.setattr(probe_tls, "weak_cipher_accepted", weak)
    monkeypatch.setattr(ec, "cors_probe", cors)
    state = ScanState()
    state.probes = list(probes)
    state.ports.open = list(ports)
    state.exposed_rows = list(exposed)
    ctx = ScanContext(scan_id="s", domain=DOMAIN, ip="127.0.0.1")
    return asyncio.run(ec.ConfigurationEngine().run(ctx, state, Guard()))


def test_the_engine_runs_everything_and_is_ok_when_every_probe_answered(monkeypatch):
    result = _run_config(monkeypatch, [_tls_probe(443, cert())], ports=[443])
    assert result.state == "ok" and result.detail["unchecked"] == [] and result.findings == []


def test_a_probe_that_cannot_answer_makes_the_step_could_not_check_never_ok(monkeypatch):
    async def unknown(*a, **k):
        return probe_tls.UNKNOWN
    monkeypatch.setattr(probe_tls, "protocol_supported", unknown)
    result = _run_config(monkeypatch, [_tls_probe(443, cert())], ports=[443])
    monkeypatch.setattr(probe_tls, "protocol_supported", unknown)
    result = asyncio.run(ec.ConfigurationEngine().run(ScanContext(scan_id="s", domain=DOMAIN, ip="127.0.0.1"), _state([_tls_probe(443, cert())]), Guard()))
    assert result.state == "could_not_check" and any("TLSv1" in item for item in result.detail["unchecked"])


def _state(probes):
    state = ScanState()
    state.probes = list(probes)
    return state


def test_a_local_limit_is_listed_but_does_not_make_the_scan_incomplete(monkeypatch):
    async def local(*a, **k):
        return probe_tls.LOCAL
    result = _run_config(monkeypatch, [_tls_probe(443, cert())], ports=[443])
    monkeypatch.setattr(probe_tls, "weak_cipher_accepted", local)
    result = asyncio.run(ec.ConfigurationEngine().run(ScanContext(scan_id="s", domain=DOMAIN, ip="127.0.0.1"), _state([_tls_probe(443, cert())]), Guard()))
    assert result.state == "ok" and "weak ciphers" in result.detail["not_available"]


def test_untrusted_is_reported_once_and_not_on_top_of_an_expired_or_self_signed_certificate(monkeypatch):
    async def untrusted(*a, **k):
        return {"state": "untrusted", "reason": "unable to get local issuer certificate", "code": 20}
    result = _run_config(monkeypatch, [_tls_probe(443, cert())])
    monkeypatch.setattr(probe_tls, "trust", untrusted)
    chain = asyncio.run(ec.ConfigurationEngine().run(ScanContext(scan_id="s", domain=DOMAIN, ip="127.0.0.1"), _state([_tls_probe(443, cert())]), Guard()))
    assert ids(chain.findings) == ["tls:untrusted"]
    both = asyncio.run(ec.ConfigurationEngine().run(ScanContext(scan_id="s", domain=DOMAIN, ip="127.0.0.1"), _state([_tls_probe(443, cert(self_signed=True))]), Guard()))
    assert "tls:untrusted" not in ids(both.findings) and "tls:self-signed" in ids(both.findings)


def test_old_protocols_found_are_one_finding_naming_them(monkeypatch):
    async def old(ip, port, domain, version, **k):
        return probe_tls.ACCEPTED if version == "TLSv1" else probe_tls.REFUSED
    result = _run_config(monkeypatch, [_tls_probe(443, cert())])
    monkeypatch.setattr(probe_tls, "protocol_supported", old)
    found = asyncio.run(ec.ConfigurationEngine().run(ScanContext(scan_id="s", domain=DOMAIN, ip="127.0.0.1"), _state([_tls_probe(443, cert())]), Guard()))
    [legacy] = [f for f in found.findings if f.check_id == "tls:legacy-protocols"]
    assert "TLS 1" in legacy.evidence and legacy.severity == "medium"
