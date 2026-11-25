"""The only code that talks to the public vulnerability databases (NVD and OSV).

What is sent: a software NAME and VERSION (for example "openssh 6.6.1p1"). Never a domain, IP address, user or scan id.
Safeguards:
* only two fixed host names (`HOSTS`); the host is resolved with the same public-address policy as everything else and the
  connection is pinned to that address with full certificate checking; redirects are refused;
* a 10-second timeout, at most 2 retries (honouring Retry-After, capped), an 8 MB response limit;
* a sliding-window rate limit (NVD: 5 requests per 30 s without a key, 50 with `NVD_API_KEY`) shared by all scans;
* a circuit breaker: after 3 failures in a row a source is left alone for 60 seconds;
* the NVD key is sent only in the `apiKey` header, is never logged and never appears in an error.
Everything returned is untrusted data: callers only read fields and never run or follow anything in it.
Failures raise SourceError(reason); the caller reports "could not check", never "safe".
"""
import http.client
import json
import socket
import ssl
import threading
import time
import urllib.parse
from collections import deque

from app.core.config import settings
from app.services import ip_policy
from app.services.ownership import _PinnedHTTPS

HOSTS = {"nvd": "services.nvd.nist.gov", "osv": "api.osv.dev"}
USER_AGENT = "SNWebShield/1.0 (vulnerability look-up; software name and version only)"
MAX_RETRIES = 2
RETRY_AFTER_CAP = 10.0
BREAKER_FAILURES = 3
BREAKER_SECONDS = 60.0
WINDOW_SECONDS = 30.0


class SourceError(Exception):
    """A look-up that did not give an answer. `reason` is a short code, safe to store and show."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --- Test seams ---------------------------------------------------------------------------------------------

_sleep = time.sleep
_monotonic = time.monotonic


def _resolve(host: str) -> str:
    try:
        return ip_policy.resolve_public(host)[0]
    except ip_policy.Blocked as error:
        raise SourceError("blocked") from error


def _connect(host: str, ip: str, timeout: float):
    return _PinnedHTTPS(host, ip, timeout)


# --- Rate limit and circuit breaker (shared by every scan in this process) ----------------------------------------

class _Window:
    def __init__(self):
        self.lock = threading.Lock()
        self.stamps: deque = deque()

    def acquire(self, limit: int, deadline: float | None) -> None:
        while True:
            with self.lock:
                now = _monotonic()
                while self.stamps and now - self.stamps[0] >= WINDOW_SECONDS:
                    self.stamps.popleft()
                if len(self.stamps) < limit:
                    self.stamps.append(now)
                    return
                wait = self.stamps[0] + WINDOW_SECONDS - now
            if deadline is not None and _monotonic() + wait > deadline:
                raise SourceError("budget")
            _sleep(max(wait, 0.05))


_windows = {name: _Window() for name in HOSTS}
_breaker = {name: {"failures": 0, "open_until": 0.0} for name in HOSTS}
_breaker_lock = threading.Lock()


def reset_state() -> None:
    """Forget the rate-limit window and breaker (used by tests)."""
    for window in _windows.values():
        with window.lock:
            window.stamps.clear()
    with _breaker_lock:
        for state in _breaker.values():
            state.update(failures=0, open_until=0.0)


def _limit_for(source: str) -> int:
    if source == "nvd":
        return 50 if settings.nvd_api_key.get_secret_value() else 5
    return 100


def _breaker_check(source: str) -> None:
    with _breaker_lock:
        if _breaker[source]["open_until"] > _monotonic():
            raise SourceError("circuit_open")


def _breaker_record(source: str, ok: bool) -> None:
    with _breaker_lock:
        state = _breaker[source]
        if ok:
            state.update(failures=0, open_until=0.0)
        else:
            state["failures"] += 1
            if state["failures"] >= BREAKER_FAILURES:
                state.update(failures=0, open_until=_monotonic() + BREAKER_SECONDS)


# --- The request --------------------------------------------------------------------------------------------------

def http_json(source: str, method: str, path: str, *, params: dict | None = None, body=None, deadline: float | None = None):
    """Module-level entry point; tests replace this so that no test reaches the internet."""
    return _http_json_impl(source, method, path, params=params, body=body, deadline=deadline)


def _http_json_impl(source, method, path, *, params=None, body=None, deadline=None):
    host = HOSTS.get(source)
    if host is None or not path.startswith("/") or method not in ("GET", "POST"):
        raise SourceError("bad_request")
    _breaker_check(source)
    target = path + ("?" + urllib.parse.urlencode(params) if params else "")
    headers = {"Host": host, "User-Agent": USER_AGENT, "Accept": "application/json"}
    payload = None
    if body is not None:
        payload = json.dumps(body)
        headers["Content-Type"] = "application/json"
    if source == "nvd":
        key = settings.nvd_api_key.get_secret_value()
        if key:
            headers["apiKey"] = key
    ip = _resolve(host)
    limit = settings.vuln_max_response_bytes
    failure = "unavailable"
    for attempt in range(MAX_RETRIES + 1):
        _windows[source].acquire(_limit_for(source), deadline)
        timeout = settings.vuln_http_timeout_seconds
        if deadline is not None:
            timeout = min(timeout, deadline - _monotonic())
            if timeout <= 0.2:
                raise SourceError("budget")
        connection = None
        retry_after = 0.0
        try:
            connection = _connect(host, ip, timeout)
            connection.request(method, target, body=payload, headers=headers)
            response = connection.getresponse()
            status = response.status
            try:
                retry_after = min(float(response.getheader("Retry-After") or 0), RETRY_AFTER_CAP)
            except ValueError:
                retry_after = 0.0
            raw = response.read(limit + 1)
        except (socket.timeout, TimeoutError):
            status, raw, failure = None, b"", "timeout"
        except (ssl.SSLError, OSError, http.client.HTTPException):
            status, raw, failure = None, b"", "connection"
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
        if status is None:
            pass
        elif 300 <= status < 400:
            _breaker_record(source, False)
            raise SourceError("redirect")
        elif status == 429 or status >= 500:
            failure = f"http_{status}"
        elif status != 200:
            _breaker_record(source, False)
            raise SourceError(f"http_{status}")
        else:
            if len(raw) > limit:
                _breaker_record(source, False)
                raise SourceError("too_large")
            try:
                data = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                _breaker_record(source, False)
                raise SourceError("malformed") from None
            if not isinstance(data, (dict, list)):
                _breaker_record(source, False)
                raise SourceError("malformed")
            _breaker_record(source, True)
            return data
        if attempt < MAX_RETRIES:
            pause = retry_after or (1.0 + attempt)
            if deadline is not None and _monotonic() + pause > deadline:
                break
            _sleep(pause)
    _breaker_record(source, False)
    raise SourceError(failure)
