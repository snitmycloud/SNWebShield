"""Bounded, public-destination HTTP/DNS/TLS probe. No scanning or credentials."""
import http.client
import ipaddress
import socket
import ssl
import time
import threading
import os
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit, urlunsplit


class Blocked(ValueError):
    pass


def target(url):
    try:
        p = urlsplit(url)
        host = (p.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        port = p.port if p.port is not None else (443 if p.scheme == "https" else 80)
        if p.scheme not in {"http", "https"} or not host or p.username is not None or p.password is not None:
            raise Blocked("invalid_target")
        if port != (443 if p.scheme == "https" else 80) or "%" in host or any(ord(c) < 33 or ord(c) == 127 for c in url):
            raise Blocked("invalid_target")
        return p, host, port
    except (ValueError, UnicodeError) as exc:
        raise Blocked("invalid_target") from exc


def resolve(host, port):
    records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not records or len(records) > 32:
        raise Blocked("invalid_dns_answers")
    answers = []
    for family, kind, protocol, _, address in records:
        ip = ipaddress.ip_address(address[0])
        if not ip.is_global or ip.is_multicast or ip.is_unspecified or (getattr(ip, "ipv4_mapped", None) is not None):
            raise Blocked("prohibited_destination")
        # Explicit exclusions avoid differences in special-range classification
        # across supported Python/ipaddress versions.
        if ip.version == 4 and any(ip in ipaddress.ip_network(net) for net in ("192.0.0.0/24", "192.88.99.0/24")):
            raise Blocked("prohibited_special_address")
        if ip.version == 6 and (ip not in ipaddress.ip_network("2000::/3") or any(
            ip in ipaddress.ip_network(net) for net in ("2001::/23", "2002::/16", "3fff::/20")
        )):
            raise Blocked("prohibited_translation_or_special_address")
        answers.append((family, address))
    return answers


class PermissionChanged(Exception):
    pass


def probe(url, timeout, permitted=lambda: True):
    started = time.monotonic(); deadline = started + timeout
    result = {"state": "unknown", "http_status": None, "dns_ok": False,
              "addresses": [], "tls_valid": None, "certificate_expires_at": None,
              "error": None, "redirects": 0}
    def remaining():
        left = deadline - time.monotonic()
        if left <= 0: raise TimeoutError()
        return left
    def guard():
        remaining()
        if not permitted(): raise PermissionChanged()
    try:
        guard()
        initial, original_host, original_port = target(url)
        origin = (initial.scheme, original_host, original_port)
        for hop in range(4):
            parsed, host, port = target(url)
            if (parsed.scheme, host, port) != origin:
                raise Blocked("redirect_outside_consented_origin")
            guard()
            answers = resolve(host, port); guard()
            result["dns_ok"] = True
            result["addresses"] = sorted({address[0] for _, address in answers})
            sock = None
            last_error = OSError("No reachable validated address")
            for family, address in answers[:4]:
                guard()
                candidate = socket.socket(family, socket.SOCK_STREAM)
                try:
                    candidate.settimeout(min(2, remaining())); candidate.connect(address)
                    sock = candidate; break
                except (OSError, TimeoutError) as exc:
                    candidate.close(); last_error = exc
            if sock is None: raise last_error
            connection = None
            try:
                result["connected_ip"] = address[0]
                if ipaddress.ip_address(sock.getpeername()[0]) != ipaddress.ip_address(address[0]):
                    raise Blocked("peer_address_mismatch")
                if parsed.scheme == "https":
                    sock.settimeout(remaining())
                    sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
                    result["tls_valid"] = True
                    expires = ssl.cert_time_to_seconds(sock.getpeercert()["notAfter"])
                    result["certificate_expires_at"] = datetime.fromtimestamp(expires, UTC).isoformat()
                connection = http.client.HTTPConnection(host, port, timeout=remaining())
                connection.sock = sock
                sock.settimeout(remaining())
                path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
                guard()
                connection.request("GET", path, headers={"User-Agent": "SNWebShield-Monitor/1.0", "Connection": "close", "Accept": "*/*"})
                sock.settimeout(remaining()); response = connection.getresponse()
                result["http_status"] = response.status
                if response.status in {301, 302, 303, 307, 308}:
                    location = response.getheader("Location")
                    if not location or hop == 3: raise Blocked("redirect_limit_or_missing_location")
                    url = urljoin(url, location); result["redirects"] += 1
                    continue
                result["state"] = "up" if 200 <= response.status < 400 else "degraded" if response.status < 500 else "down"
                if result["certificate_expires_at"]:
                    days = (datetime.fromisoformat(result["certificate_expires_at"]) - datetime.now(UTC)).total_seconds() / 86400
                    result["certificate_days_remaining"] = round(days, 2)
                    if days <= 30 and result["state"] == "up": result["state"] = "degraded"
                break
            finally:
                if connection: connection.close()
                sock.close()
    except PermissionChanged:
        result.update(state="cancelled", error="permission_or_configuration_changed")
    except Blocked as exc:
        result.update(state="blocked", error=str(exc))
    except ssl.SSLCertVerificationError:
        result.update(state="down", tls_valid=False, error="certificate_validation_failed")
    except socket.gaierror:
        result.update(state="down", error="dns_resolution_failed")
    except (TimeoutError, socket.timeout):
        result.update(state="down", error="deadline_exceeded")
    except (OSError, ssl.SSLError, http.client.HTTPException, KeyError, ValueError):
        result.update(state="down", error="connection_or_protocol_failed")
    result["response_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def probe_child(send, url, timeout):
    watchdog = threading.Timer(timeout + 2, lambda: os._exit(2))
    watchdog.daemon = True; watchdog.start()
    def allowed():
        send.send(("permission", None))
        return send.poll(max(1, timeout)) and send.recv() is True
    try: send.send(probe(url, timeout, permitted=allowed))
    finally: watchdog.cancel(); send.close()
