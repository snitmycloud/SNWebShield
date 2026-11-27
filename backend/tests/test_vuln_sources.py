"""The HTTP layer that talks to NVD / OSV, against a fake database server on loopback. Never the real internet."""
import http.client
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from pydantic import SecretStr

from app.core.config import settings
from app.services import ip_policy, vuln_sources as vs


class FakeDatabase:
    """Answers from a script: a list of (status, headers, body, delay) used in order; the last one repeats."""

    def __init__(self, script):
        self.script = list(script)
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                outer.requests.append({"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body})
                index = min(len(outer.requests) - 1, len(outer.script) - 1)
                status, headers, payload, delay = outer.script[index]
                time.sleep(delay)
                try:
                    self.send_response(status)
                    for key, value in headers.items():
                        self.send_header(key, value)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except OSError:
                    pass

            do_GET = do_POST = _answer

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def ok(data=None, headers=None, delay=0):
    return 200, headers or {}, json.dumps(data if data is not None else {"vulnerabilities": [], "totalResults": 0}).encode(), delay


@pytest.fixture
def sleeps(monkeypatch):
    slept = []
    monkeypatch.setattr(vs, "_sleep", lambda seconds: slept.append(seconds))
    return slept


@pytest.fixture
def connect_to(monkeypatch):
    """Send every connection to the fake server instead of the real host (and remember which host was asked for)."""
    asked = []

    def use(fake):
        monkeypatch.setattr(vs, "_resolve", lambda host: (asked.append(host), "127.0.0.1")[1])
        monkeypatch.setattr(vs, "_connect", lambda host, ip, timeout: http.client.HTTPConnection("127.0.0.1", fake.port, timeout=timeout))
        return asked
    return use


def call(source="nvd", **kw):
    return vs._http_json_impl(source, kw.pop("method", "GET"), kw.pop("path", "/rest/json/cves/2.0"), **kw)


def test_a_normal_answer_is_returned_and_only_the_fixed_host_is_asked_for(connect_to):
    with FakeDatabase([ok({"hello": 1})]) as fake:
        asked = connect_to(fake)
        assert call(params={"cpeName": "cpe:2.3:a:openbsd:openssh:6.6.1:p1:*:*:*:*:*:*"}) == {"hello": 1}
    assert asked == ["services.nvd.nist.gov"]
    request = fake.requests[0]
    assert request["headers"]["Host"] == "services.nvd.nist.gov" and "cpeName=cpe%3A2.3" in request["path"]
    assert "SNWebShield" in request["headers"]["User-Agent"]


def test_osv_is_a_post_with_a_json_body_to_its_own_host(connect_to):
    with FakeDatabase([ok({"vulns": []})]) as fake:
        asked = connect_to(fake)
        call("osv", method="POST", path="/v1/query", body={"package": {"name": "jquery", "ecosystem": "npm"}, "version": "3.6.0"})
    assert asked == ["api.osv.dev"]
    assert json.loads(fake.requests[0]["body"])["package"]["name"] == "jquery"
    assert "apiKey" not in fake.requests[0]["headers"]


@pytest.mark.parametrize("args", [("evil", "GET", "/x"), ("nvd", "GET", "http://evil.example/x"), ("nvd", "DELETE", "/x"), ("nvd", "GET", "x")])
def test_only_the_two_fixed_hosts_and_relative_paths_are_accepted(args):
    with pytest.raises(vs.SourceError) as caught:
        vs._http_json_impl(*args)
    assert caught.value.reason == "bad_request"


def test_the_nvd_key_is_sent_only_to_nvd_only_in_the_header_and_never_logged(connect_to, monkeypatch, caplog):
    monkeypatch.setattr(settings, "nvd_api_key", SecretStr("super-secret-key-123"))
    with caplog.at_level(logging.DEBUG), FakeDatabase([ok(), ok({"vulns": []}), (500, {}, b"boom", 0)]) as fake:
        connect_to(fake)
        call()
        call("osv", method="POST", path="/v1/query", body={})
        vs.reset_state()
        monkeypatch.setattr(vs, "_sleep", lambda s: None)
        with pytest.raises(vs.SourceError) as caught:
            call()
    assert fake.requests[0]["headers"]["apiKey"] == "super-secret-key-123"
    assert "apiKey" not in fake.requests[1]["headers"]
    assert "super-secret-key-123" not in str(caught.value) and "super-secret-key-123" not in caplog.text
    assert "super-secret-key-123" not in fake.requests[0]["path"]


def test_no_key_means_no_header(connect_to):
    with FakeDatabase([ok()]) as fake:
        connect_to(fake)
        call()
    assert "apiKey" not in fake.requests[0]["headers"]


def test_a_server_error_is_retried_then_succeeds(connect_to, sleeps):
    with FakeDatabase([(503, {}, b"busy", 0), ok({"fine": True})]) as fake:
        connect_to(fake)
        assert call() == {"fine": True}
    assert len(fake.requests) == 2 and len(sleeps) == 1


def test_retry_after_is_honoured_and_capped(connect_to, sleeps):
    with FakeDatabase([(429, {"Retry-After": "3"}, b"slow down", 0), (429, {"Retry-After": "9999"}, b"", 0), ok()]) as fake:
        connect_to(fake)
        call()
    assert sleeps == [3.0, vs.RETRY_AFTER_CAP]


def test_a_database_that_keeps_failing_is_could_not_check_after_two_retries(connect_to, sleeps):
    with FakeDatabase([(500, {}, b"", 0)]) as fake:
        connect_to(fake)
        with pytest.raises(vs.SourceError) as caught:
            call()
    assert caught.value.reason == "http_500" and len(fake.requests) == 3


def test_a_client_error_is_not_retried(connect_to, sleeps):
    with FakeDatabase([(404, {}, b"", 0)]) as fake:
        connect_to(fake)
        with pytest.raises(vs.SourceError) as caught:
            call()
    assert caught.value.reason == "http_404" and len(fake.requests) == 1 and sleeps == []


def test_redirects_are_refused_and_never_followed(connect_to):
    with FakeDatabase([(302, {"Location": "http://169.254.169.254/latest/meta-data/"}, b"", 0)]) as fake:
        connect_to(fake)
        with pytest.raises(vs.SourceError) as caught:
            call()
    assert caught.value.reason == "redirect" and len(fake.requests) == 1


def test_an_oversized_answer_is_refused(connect_to, monkeypatch):
    monkeypatch.setattr(settings, "vuln_max_response_bytes", 70_000)
    with FakeDatabase([(200, {}, b'{"x": "' + b"a" * 100_000 + b'"}', 0)]) as fake:
        connect_to(fake)
        with pytest.raises(vs.SourceError) as caught:
            call()
    assert caught.value.reason == "too_large"


@pytest.mark.parametrize("payload", [b"<html>not json</html>", b"", b"\xff\xfe", b"123", b'"text"'])
def test_malformed_answers_are_errors_never_empty_results(connect_to, payload):
    with FakeDatabase([(200, {}, payload, 0)]) as fake:
        connect_to(fake)
        with pytest.raises(vs.SourceError) as caught:
            call()
    assert caught.value.reason == "malformed"


def test_a_slow_database_times_out(connect_to, monkeypatch, sleeps):
    monkeypatch.setattr(settings, "vuln_http_timeout_seconds", 0.3)
    with FakeDatabase([ok(delay=1.5)]) as fake:
        connect_to(fake)
        started = time.monotonic()
        with pytest.raises(vs.SourceError) as caught:
            call()
    assert caught.value.reason == "timeout" and time.monotonic() - started < 6


def test_an_unreachable_database_is_a_connection_error(monkeypatch, sleeps):
    monkeypatch.setattr(vs, "_resolve", lambda host: "127.0.0.1")
    class Refused(http.client.HTTPConnection):   # what a closed port does, at once (a real closed port takes about 2 s per try on Windows)
        def request(self, *a, **k):
            raise ConnectionRefusedError("connection refused")
    monkeypatch.setattr(vs, "_connect", lambda host, ip, timeout: Refused("127.0.0.1", 9, timeout=timeout))
    with pytest.raises(vs.SourceError) as caught:
        call()
    assert caught.value.reason == "connection"


def test_a_host_that_resolves_to_a_private_address_is_blocked(monkeypatch):
    def blocked(host, port=443):
        raise ip_policy.Blocked("private_address")
    monkeypatch.setattr(ip_policy, "resolve_public", blocked)
    with pytest.raises(vs.SourceError) as caught:
        call()
    assert caught.value.reason == "blocked"


def test_the_rate_limit_waits_instead_of_sending_a_sixth_request(connect_to, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(vs, "_monotonic", lambda: clock[0])
    waited = []
    monkeypatch.setattr(vs, "_sleep", lambda seconds: (waited.append(seconds), clock.__setitem__(0, clock[0] + seconds)))
    with FakeDatabase([ok()]) as fake:
        connect_to(fake)
        for _ in range(6):
            call()
    assert len(fake.requests) == 6 and sum(waited) >= 29.9  # the sixth had to wait for the 30-second window


def test_with_a_key_the_window_is_larger(connect_to, monkeypatch):
    monkeypatch.setattr(settings, "nvd_api_key", SecretStr("k"))
    monkeypatch.setattr(vs, "_sleep", lambda s: (_ for _ in ()).throw(AssertionError("should not wait")))
    with FakeDatabase([ok()]) as fake:
        connect_to(fake)
        for _ in range(10):
            call()
    assert len(fake.requests) == 10


def test_a_budget_that_would_be_exceeded_stops_the_look_up(connect_to, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(vs, "_monotonic", lambda: clock[0])
    monkeypatch.setattr(vs, "_sleep", lambda s: None)
    with FakeDatabase([ok()]) as fake:
        connect_to(fake)
        for _ in range(5):
            call(deadline=1010.0)
        with pytest.raises(vs.SourceError) as caught:
            call(deadline=1010.0)  # the sixth must wait ~30 s but only 10 s are left
    assert caught.value.reason == "budget"


def test_three_failures_open_the_breaker_and_it_closes_again(connect_to, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(vs, "_monotonic", lambda: clock[0])
    monkeypatch.setattr(vs, "_sleep", lambda s: clock.__setitem__(0, clock[0] + s))
    monkeypatch.setattr(settings, "nvd_api_key", SecretStr("k"))  # a bigger rate window: only the breaker is under test
    with FakeDatabase([(500, {}, b"", 0)] * 9 + [ok()]) as fake:  # each failed call makes 3 attempts
        connect_to(fake)
        for _ in range(3):
            with pytest.raises(vs.SourceError):
                call()
        seen = len(fake.requests)
        with pytest.raises(vs.SourceError) as caught:
            call()
        assert caught.value.reason == "circuit_open" and len(fake.requests) == seen  # no request while open
        assert call("osv", method="POST", path="/v1/query", body={}) is not None  # the other source is unaffected
        clock[0] += vs.BREAKER_SECONDS + 1
        assert call() is not None
