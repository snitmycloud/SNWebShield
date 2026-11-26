"""Built-in configuration checks (engine "configuration"): TLS certificate and protocols, HTTPS use, security headers,
cookie flags, CORS, version disclosure, risky open ports and exposed files.

All of it works on facts DETECT already collected from the one pinned IP, plus a few extra single-handshake / single-GET
probes to that same IP (probe_tls.py and one CORS request). Anything a probe cannot answer is listed under
`detail["unchecked"]` and makes the step "could not check"; a limit of OUR TLS library is listed under
`detail["not_available"]` and never counted as a pass.
"""
import asyncio
import re
from datetime import datetime, timezone

from app.core.config import settings
from app.data.severity_rules import EXPOSED_RULES, PORT_RULES, RULES
from app.services import engines, netio, probe_tls, sensitive_panels
from app.services.detect_versions import USER_AGENT, kept_headers, parse_http_response
from app.services.finding import Finding

CORS_TEST_ORIGIN = "https://snwebshield-cors-test.invalid"
MAX_TLS_PORTS = 6
_MIXED = re.compile(r"<(?:script|img|iframe|source|video|audio|embed)\b[^>]*?\bsrc\s*=\s*[\"']http://|"
                    r"<link\b[^>]*?\bhref\s*=\s*[\"']http://[^>]*?stylesheet|<link\b[^>]*?stylesheet[^>]*?\bhref\s*=\s*[\"']http://", re.I)


def build(check_id: str, location: str, *, port=None, evidence=None, kind="config", title=None, you_have=None, **extra) -> Finding:
    severity, default_title, why, how, should = RULES[check_id]
    return Finding(kind=kind, check_id=check_id, title=title or default_title, location=location, severity=severity,
                   confidence="confirmed", port=port, you_have=you_have, you_should_have=should, why=why, how_to_fix=how,
                   evidence=evidence, sources=["snwebshield"], **extra)


def _parse_time(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def _name_matches(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.count(".") >= pattern.count(".") and host.split(".", 1)[1] == pattern[2:]
    return pattern == host


def certificate_findings(domain: str, port: int, cert: dict, now: datetime) -> list[Finding]:
    where = f"{domain}:{port}"
    found = []
    not_after = _parse_time(cert.get("not_after"))
    if not_after is not None:
        days = (not_after - now).days
        text = f"Valid until {not_after.date().isoformat()}"
        if not_after < now:
            found.append(build("tls:certificate-expired", where, port=port, evidence=f"Expired on {not_after.date().isoformat()}"))
        elif days < 7:
            found.append(build("tls:certificate-expires-7d", where, port=port, evidence=text))
        elif days < 30:
            found.append(build("tls:certificate-expires-30d", where, port=port, evidence=text))
    names = list(cert.get("san") or []) or ([cert["subject_cn"]] if cert.get("subject_cn") else [])
    if names and not any(_name_matches(name, domain) for name in names):
        found.append(build("tls:hostname-mismatch", where, port=port, evidence=f"Certificate names: {', '.join(names[:5])}",
                           you_have=f"A certificate for {', '.join(names[:3])}"))
    if cert.get("self_signed"):
        found.append(build("tls:self-signed", where, port=port, evidence=f"Issued by {cert.get('issuer_cn') or cert.get('issuer')}"))
    return found


def mixed_content(page) -> bool:
    return bool(page.tls and page.body and _MIXED.search(page.body))


async def cors_probe(ip: str, port: int, tls: bool, domain: str, timeout: float) -> dict | None:
    """One GET / with a foreign Origin. Returns the Access-Control headers, or None if no answer."""
    try:
        reader, writer = await netio.open_connection(ip, port, tls=tls, server_name=domain, timeout=min(timeout, 1.5))
    except (asyncio.TimeoutError, OSError):
        return None
    try:
        writer.write((f"GET / HTTP/1.0\r\nHost: {domain}\r\nUser-Agent: {USER_AGENT}\r\nOrigin: {CORS_TEST_ORIGIN}\r\n"
                      f"Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii"))
        await asyncio.wait_for(writer.drain(), timeout)
        data = await netio.read_until_end(reader, 16 * 1024, timeout)
    except (asyncio.TimeoutError, OSError, ValueError):
        return None
    finally:
        await netio.close(writer)
    parsed = parse_http_response(data)
    if parsed is None:
        return None
    headers = kept_headers(parsed[1])
    return {"origin": headers.get("access-control-allow-origin"), "credentials": headers.get("access-control-allow-credentials")}


def cors_findings(domain: str, port: int, result: dict) -> list[Finding]:
    where = f"{domain}:{port}"
    origin = (result.get("origin") or "").strip()
    credentials = (result.get("credentials") or "").strip().lower() == "true"
    if origin == CORS_TEST_ORIGIN and credentials:
        return [build("cors:credentials-any-origin", where, port=port,
                      evidence="Our test website was allowed to make requests that carry visitors' logins.")]
    if origin == "*":
        return [build("cors:wildcard", where, port=port, evidence="Access-Control-Allow-Origin: *")]
    if origin == CORS_TEST_ORIGIN:
        return [build("cors:wildcard", where, port=port, evidence="Any website name we tried was allowed (the server repeats back the origin it is given).")]
    return []


def web_findings(domain: str, probes, now: datetime) -> list[Finding]:
    found = []
    pages = [p.web for p in probes if p.web]
    for page in pages:
        where = f"{domain}:{page.port}"
        if not page.status or not 200 <= page.status < 300:
            continue  # error pages and redirects are not the site's real security settings
        headers = page.headers
        if page.tls and "strict-transport-security" not in headers:
            found.append(build("header:hsts-missing", where, port=page.port))
        csp = headers.get("content-security-policy", "")
        if not csp:
            found.append(build("header:csp-missing", where, port=page.port))
        if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
            found.append(build("header:xfo-missing", where, port=page.port))
        if "x-content-type-options" not in headers:
            found.append(build("header:xcto-missing", where, port=page.port))
        if "referrer-policy" not in headers:
            found.append(build("header:referrer-policy-missing", where, port=page.port))
        if "permissions-policy" not in headers:
            found.append(build("header:permissions-policy-missing", where, port=page.port))
        for cookie in page.cookies[:20]:  # names and flags only, never values
            label = f"{where} cookie {cookie['name']}"
            if page.tls and not cookie["secure"]:
                found.append(build("cookie:no-secure", label, port=page.port, evidence=f"Cookie “{cookie['name']}”"))
            if not cookie["httponly"]:
                found.append(build("cookie:no-httponly", label, port=page.port, evidence=f"Cookie “{cookie['name']}”"))
            if not cookie["samesite"]:
                found.append(build("cookie:no-samesite", label, port=page.port, evidence=f"Cookie “{cookie['name']}”"))
        if mixed_content(page):
            found.append(build("http:mixed-content", where, port=page.port))
        for name in ("server", "x-powered-by"):
            value = headers.get(name, "")
            if re.search(r"\d+\.\d+", value):
                found.append(build("disclosure:version", f"{where} {name} header", port=page.port,
                                   evidence=f"{name}: {netio.clean_text(value, 100)}", you_have=value))
    # HTTPS use
    tls_web = [p for p in probes if p.http and p.http["over_tls"]]
    plain_web = [p for p in probes if p.http and not p.http["over_tls"]]
    open_443 = any(p.port == 443 for p in probes)
    if plain_web and not tls_web and not open_443:
        found.append(build("http:no-https", domain, port=plain_web[0].port,
                           evidence=f"Your website answers on port {plain_web[0].port} without encryption and not at all on HTTPS."))
    elif tls_web:
        for probe in plain_web:
            page = probe.web
            if page is None or probe.port != 80:
                continue
            location = (page.headers.get("location") or "").lower()
            if not (page.status in (301, 302, 303, 307, 308) and location.startswith("https://")):
                found.append(build("http:no-redirect", f"{domain}:{probe.port}", port=probe.port,
                                   evidence=f"Port {probe.port} answers with status {page.status} and does not redirect to https."))
    return found


def port_findings(domain: str, ports) -> list[Finding]:
    found = []
    for port in ports:
        rule = PORT_RULES.get(port)
        if rule:
            severity, title, why, how = rule
            found.append(Finding(kind="exposure", check_id=f"port:{port}", title=title, location=f"{domain}:{port}",
                                 severity=severity, confidence="confirmed", port=port, why=why, how_to_fix=how,
                                 you_should_have="Only the ports your website really needs reachable from the internet.",
                                 evidence=f"Port {port} accepted a connection from the internet.", sources=["snwebshield"]))
    return found


def exposed_findings(domain: str, rows) -> list[Finding]:
    found = []
    for row in rows:
        signature = (row.get("data") or {}).get("signature")
        rule = EXPOSED_RULES.get(signature)
        if rule is None:
            continue
        severity, title, why, how = rule
        label = sensitive_panels.sensitive_label(row["key"].strip("/"), "") if signature == "login-form" else None
        if label:  # a database admin tool, CI server, router admin ... (editable list): its own Medium finding, not just "a login page"
            severity = "medium"
            title = f"{label} login page is reachable from the internet"
            why = ("Tools like this give wide control, are attacked constantly, and should not be open to everyone.")
            how = ("Restrict it to trusted addresses or a VPN, require strong logins and two-step verification, keep it updated, "
                   "or remove it if you do not use it.")
        found.append(Finding(kind="exposure", check_id=f"exposed:{signature}:{row['key']}", title=title,
                             location=f"{domain}{row['key']}", severity=severity, confidence="confirmed", why=why, how_to_fix=how,
                             you_should_have="Only files you meant to publish.",
                             evidence=f"{row['key']} answered with status {(row.get('data') or {}).get('http_status')}. File contents were not stored.",
                             sources=["snwebshield"]))
    return found


class ConfigurationEngine(engines.Engine):
    name = "configuration"
    label = "Checking security settings"
    title = "Security settings"

    async def run(self, ctx, state, guard) -> engines.EngineResult:
        now = datetime.now(timezone.utc)
        found = web_findings(ctx.domain, state.probes, now)
        if getattr(state, "cdn", None):
            found.append(Finding(kind="disclosure", check_id="cdn:detected", title=f"This site is behind {state.cdn['name']}", location=ctx.domain,
                                 severity="info", confidence="confirmed", port=state.cdn.get("port"), you_have=state.cdn["name"],
                                 why="Your visitors reach a CDN or firewall service first, not your own server. That is good for speed and protection, but it changes what a scan can see.",
                                 how_to_fix="Nothing to fix. Remember that open ports and server versions shown here may belong to the CDN, not to your server.",
                                 evidence=f"Detected from the {state.cdn['evidence']}.", sources=["snwebshield"]))
        found += port_findings(ctx.domain, state.ports.open)
        found += exposed_findings(ctx.domain, state.exposed_rows)
        unchecked, not_available = [], []
        timeout = settings.scan_tls_probe_timeout_seconds

        tls_probes = [p for p in state.probes if p.tls][:MAX_TLS_PORTS]
        for probe in tls_probes:
            guard.check()
            where = f"{ctx.domain}:{probe.port}"
            cert = probe.tls.get("certificate")
            cert_found = certificate_findings(ctx.domain, probe.port, cert, now) if cert else []
            found += cert_found
            if not cert_found:
                trust = await probe_tls.trust(ctx.ip, probe.port, ctx.domain, timeout=timeout)
                if trust["state"] == "could_not_check":
                    trust = await probe_tls.trust(ctx.ip, probe.port, ctx.domain, timeout=timeout)
                if trust["state"] == "untrusted":
                    found.append(build("tls:untrusted", where, port=probe.port, evidence=f"Reason: {trust['reason']}"))
                elif trust["state"] == "could_not_check":
                    unchecked.append(f"certificate trust on port {probe.port}")
            legacy = []
            for version in ("TLSv1", "TLSv1.1"):
                guard.check()
                answer = await probe_tls.protocol_supported(ctx.ip, probe.port, ctx.domain, version, timeout=timeout)
                if answer == probe_tls.UNKNOWN:   # no answer at all: ask once more before "could not check"
                    answer = await probe_tls.protocol_supported(ctx.ip, probe.port, ctx.domain, version, timeout=timeout)
                if answer == probe_tls.ACCEPTED:
                    legacy.append(version.replace("TLSv", "TLS "))
                elif answer == probe_tls.UNKNOWN:
                    unchecked.append(f"{version} on port {probe.port}")
                elif answer == probe_tls.LOCAL:
                    not_available.append(version)
            if legacy:
                found.append(build("tls:legacy-protocols", where, port=probe.port, evidence=f"Accepted: {', '.join(legacy)}"))
            guard.check()
            answer = await probe_tls.weak_cipher_accepted(ctx.ip, probe.port, ctx.domain, timeout=timeout)
            if answer == probe_tls.UNKNOWN:
                answer = await probe_tls.weak_cipher_accepted(ctx.ip, probe.port, ctx.domain, timeout=timeout)
            if answer == probe_tls.ACCEPTED:
                found.append(build("tls:weak-ciphers", where, port=probe.port, evidence="A weak cipher (RC4, 3DES, export or anonymous) was accepted."))
            elif answer == probe_tls.UNKNOWN:
                unchecked.append(f"weak ciphers on port {probe.port}")
            elif answer == probe_tls.LOCAL:
                not_available.append("weak ciphers")

        web = [p for p in state.probes if p.web and p.web.status and 200 <= p.web.status < 300]
        pick = next((p for p in web if p.port == 443), None) or (web[0] if web else None)
        if pick is not None:
            guard.check()
            result = None
            for _ in range(2):   # a busy or rate-limiting site can drop one connection; ask once more before "could not check"
                result = await cors_probe(ctx.ip, pick.port, pick.web.tls, ctx.domain, settings.scan_http_request_timeout_seconds)
                if result is not None:
                    break
                guard.check()
            if result is None:
                unchecked.append(f"cross-site access (CORS) on port {pick.port}")
            else:
                found += cors_findings(ctx.domain, pick.port, result)

        detail = {"findings": len(found), "unchecked": sorted(set(unchecked)), "not_available": sorted(set(not_available))}
        return engines.EngineResult("could_not_check" if unchecked else "ok", found, detail)
