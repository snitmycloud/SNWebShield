"""Trusted single-HEAD broker: fixed code, bounded public-target access.

Runnable with Python -I -S. Not an OS sandbox or a general scanner proxy.
Only selected response headers reach the separate pure analysis process.
"""
from hashlib import sha256
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import threading
import time
from urllib.parse import urljoin, urlunsplit

_spec = importlib.util.spec_from_file_location("public_monitor_policy", Path(__file__).with_name("monitor_probe.py"))
policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(policy)
MAX_HEADERS = 32768
TIMEOUT = 10
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def classify_redirect(url, status, locations):
    """Describe a redirect WITHOUT following it or retaining the Location value.

    The Location header is attacker-controlled. Only a fixed category leaves this
    function, so no target-supplied URL, host, path or token is persisted.
    """
    if status not in REDIRECT_STATUSES:
        return {"is_redirect": False, "location": None, "followed": False}
    if not locations:
        category = "missing"
    elif len(locations) > 1:
        category = "ambiguous"
    else:
        try:
            origin, host, port = policy.target(url)
            next_url, next_host, next_port = policy.target(urljoin(url, locations[0].strip()))
        except policy.Blocked:
            category = "invalid_or_unsupported"
        else:
            if (next_url.scheme, next_host, next_port) == (origin.scheme, host, port):
                category = "same_origin"
            elif next_host == host and origin.scheme == "http" and next_url.scheme == "https":
                category = "https_upgrade_same_host"
            elif next_host == host:
                category = "same_host_scheme_or_port_change"
            else:
                category = "different_host_not_followed"
    return {"is_redirect": True, "location": category, "followed": False}


def collect(url, permitted):
    started = time.monotonic()
    deadline = started + TIMEOUT
    sock = None

    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError()
        return left

    def guard():
        remaining()
        if not permitted():
            raise policy.PermissionChanged()

    try:
        parsed, host, port = policy.target(url)
        guard()
        answers = policy.resolve(host, port)
        guard()
        # Exactly one connection attempt, one HEAD, no retry and no redirects.
        family, address = answers[0]
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(remaining())
        guard()
        sock.connect(address)
        if ipaddress.ip_address(sock.getpeername()[0]) != ipaddress.ip_address(address[0]):
            raise policy.Blocked("peer_address_mismatch")
        cert_expiry = tls_version = None
        if parsed.scheme == "https":
            sock.settimeout(remaining())
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            sock = context.wrap_socket(sock, server_hostname=host)
            cert_expiry = sock.getpeercert().get("notAfter")
            tls_version = sock.version()
        path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        if len(path.encode("ascii")) > 2048:
            raise policy.Blocked("request_path_too_long")
        guard()
        wire = (f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: SNWebShield-Assessment/1.0\r\n"
                "Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii")
        sock.settimeout(remaining())
        sock.sendall(wire)
        data = bytearray()
        while not data.endswith(b"\r\n\r\n"):
            # No body is read, including when a server illegally sends one for HEAD.
            sock.settimeout(remaining())
            block = sock.recv(1)
            if not block:
                raise ValueError("incomplete_response_headers")
            data.extend(block)
            if len(data) > MAX_HEADERS:
                raise policy.Blocked("response_headers_too_large")
        lines = data.decode("iso-8859-1").split("\r\n")
        parts = lines[0].split(" ", 2)
        if len(parts) < 2 or parts[0] not in {"HTTP/1.0", "HTTP/1.1"} or not parts[1].isdigit():
            raise ValueError("invalid_http_status")
        status = int(parts[1])
        if not 200 <= status <= 599:
            raise ValueError("unsupported_http_status")
        # Only selected security-header semantics survive. Never persist cookies,
        # authentication headers, bodies, Location, CSP nonces or raw header values.
        headers = {}
        locations = []
        cookies = {"count": 0, "secure_missing": 0, "httponly_missing": 0, "samesite_missing": 0}
        allowed = {"strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy", "server", "x-powered-by"}
        for line in lines[1:-2]:
            if ":" not in line or line[0].isspace() or any(ord(c) < 32 or ord(c) == 127 for c in line):
                raise ValueError("invalid_response_header")
            name, value = line.split(":", 1)
            if not name or any(not (c.isascii() and (c.isalnum() or c in "!#$%&'*+-.^_`|~")) for c in name):
                raise ValueError("invalid_response_header")
            name = name.lower()
            if name == "set-cookie":
                # Only attribute presence is counted; cookie names and values are discarded unseen.
                attributes = {part.strip().lower().partition("=")[0] for part in value.split(";")[1:]}
                cookies["count"] = min(50, cookies["count"] + 1)
                for flag in ("secure", "httponly", "samesite"):
                    cookies[flag + "_missing"] += 0 if flag in attributes else 1
            if name == "location":
                locations.append(value)  # Classified below, then discarded.
            if name in allowed:
                if name in headers:
                    raise ValueError("ambiguous_security_header")
                headers[name] = value.strip()
        hsts = headers.get("strict-transport-security", "").lower()
        valid_age = False
        for directive in hsts.split(";"):
            k, _, v = directive.strip().partition("=")
            if k == "max-age" and v.isascii() and v.isdigit() and len(v) <= 12 and int(v) > 0:
                valid_age = True
        facts = {
            "https": parsed.scheme == "https", "hsts_positive_max_age": valid_age,
            "csp_present": bool(headers.get("content-security-policy")),
            "nosniff": headers.get("x-content-type-options", "").lower() == "nosniff",
            "frame_policy_present": headers.get("x-frame-options", "").lower() in {"deny", "sameorigin"} or "frame-ancestors" in headers.get("content-security-policy", "").lower(),
            "referrer_policy_present": bool(headers.get("referrer-policy")),
            "cookies": cookies,
        }
        return {"status": status, "connected_ip": address[0], "dns_addresses": sorted({a[0] for _, a in answers}),
                "headers_sha256": sha256(bytes(data)).hexdigest(), "response_ms": round((time.monotonic() - started) * 1000, 2), "header_bytes": len(data),
                "tls_verified": parsed.scheme == "https", "certificate_not_after": cert_expiry,
                "tls_version": tls_version, "redirect_followed": False,
                "redirect": classify_redirect(url, status, locations), "facts": facts, "selected_headers": {k: v[:2048] for k, v in headers.items()}}
    finally:
        if sock is not None:
            sock.close()


def main():
    import sys
    from importlib.util import spec_from_file_location, module_from_spec
    spec = spec_from_file_location("local_limits", Path(__file__).with_name("assessment_limits.py"))
    limits = module_from_spec(spec); spec.loader.exec_module(limits); limits.child_limits()
    watchdog = threading.Timer(TIMEOUT + 2, lambda: os._exit(2))
    watchdog.daemon = True
    watchdog.start()

    def output(value):
        print(json.dumps(value, separators=(",", ":")), flush=True)

    def permitted():
        output({"permission": True})
        return sys.stdin.buffer.readline(16).strip() == b"true"

    try:
        line = sys.stdin.buffer.readline(4097)
        if len(line) > 4096:
            raise ValueError()
        payload = json.loads(line)
        if set(payload) != {"url"} or not isinstance(payload["url"], str):
            raise ValueError()
        output({"result": collect(payload["url"], permitted)})
    except policy.PermissionChanged:
        output({"error": "permission_changed"})
    except policy.Blocked as exc:
        output({"error": str(exc)})
    except ssl.SSLCertVerificationError:
        output({"error": "tls_certificate_invalid"})
    except socket.gaierror:
        output({"error": "dns_resolution_failed"})
    except (TimeoutError, socket.timeout):
        output({"error": "probe_deadline_exceeded"})
    except Exception:
        output({"error": "http_protocol_or_connection_failed"})
    finally:
        watchdog.cancel()


if __name__ == "__main__":
    main()
