"""Service and version detection on the OPEN ports of the one pinned IP. Harmless probes only.

Per open port (3-second limit in total, `scan_probe_timeout_seconds`):
* read the banner the server volunteers on connect (SSH, FTP, SMTP, POP3, IMAP, MySQL, ...), without sending anything;
* a TLS handshake, recording the TLS version, cipher and the certificate's subject, issuer and expiry;
* HTTP(S): `HEAD /` and `GET /`, reading `Server`, `X-Powered-By` and other identifying headers.

It never logs in and never sends attack payloads. Everything received is untrusted: it is cut to a size limit and
stripped of control characters, cookie VALUES are never kept (only names and flags), and the page body is kept in
memory only for the technology step (never stored).
"""
import asyncio
import re
from dataclasses import dataclass, field

from app.core.config import settings
from app.data.ports import SERVICE_NAMES
from app.services import netio
from app.services.x509_lite import parse_certificate

WEB_PORTS = {80, 81, 443, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443, 10443}
KEPT_HEADERS = (
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "via", "x-drupal-cache",
    "x-shopid", "x-shopify-stage", "x-wix-request-id", "cf-ray", "x-served-by", "content-type", "location",
    "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy", "access-control-allow-origin", "access-control-allow-credentials",
)
MAX_HEADER_LINES = 100
USER_AGENT = "SNWebShield/1.0 (security scan of a website whose owner verified it)"


@dataclass
class WebPage:
    port: int
    tls: bool
    status: int | None
    headers: dict
    cookies: list
    body: str
    truncated: bool = False


@dataclass
class PortProbe:
    port: int
    service: str | None = None
    service_guess: bool = False
    product: str | None = None
    version: str | None = None
    banner: str = ""
    tls: dict | None = None
    http: dict | None = None
    web: WebPage | None = None
    notes: list = field(default_factory=list)

    def row(self) -> dict:
        return {"port": self.port, "service": self.service, "product": self.product, "version": self.version,
                "banner": self.banner or None,
                "details": {"tls": self.tls, "http": self.http, "service_guess": self.service_guess, "notes": self.notes}}


# --- Parsing (pure functions, tested without a network) ----------------------------------------------

_SOFTWARE = re.compile(r"^([A-Za-z][A-Za-z0-9.\-]*?)[_/\- ](\d[\w.\-+]*)")


def split_software(text: str):
    """'OpenSSH_8.2p1' -> ('OpenSSH', '8.2p1'); 'nginx/1.18.0' -> ('nginx', '1.18.0'); 'cloudflare' -> ('cloudflare', None)."""
    text = text.strip()
    match = _SOFTWARE.match(text)
    if match:
        return match.group(1), match.group(2)
    name = re.match(r"^[A-Za-z][A-Za-z0-9.\-_]*", text)
    return (name.group(0), None) if name else (None, None)


def parse_mysql(data: bytes):
    """The MySQL/MariaDB greeting packet: 3-byte length, sequence 0, protocol 10, NUL-terminated version string."""
    if len(data) < 6 or data[3] != 0:
        return None
    if data[4] == 0xFF:  # an error packet such as "Host is not allowed to connect": still MySQL
        return {"service": "mysql", "product": "MySQL", "version": None}
    if data[4] != 10:
        return None
    end = data.find(b"\x00", 5)
    if end == -1 or end - 5 > 100:
        return None
    raw = data[5:end].decode("latin-1")
    product = "MariaDB" if "mariadb" in raw.lower() else "MySQL"
    number = re.match(r"^(?:5\.5\.5-)?(\d+(?:\.\d+)+)", raw)
    return {"service": "mysql", "product": product, "version": number.group(1) if number else None}


def parse_banner(data: bytes, port: int):
    """Identify a server-speaks-first protocol from its greeting. Returns a dict or None."""
    if not data:
        return None
    mysql = parse_mysql(data)
    if mysql:
        return mysql
    text = data[:1024].decode("latin-1", "replace")
    first = text.splitlines()[0] if text.splitlines() else ""
    if first.startswith("SSH-"):
        match = re.match(r"^SSH-\d\.\d+-(\S+)", first)
        product, version = split_software(match.group(1)) if match else (None, None)
        return {"service": "ssh", "product": product, "version": version}
    if first.startswith("HTTP/"):
        return {"service": "http", "product": None, "version": None}
    if first.startswith("RFB "):
        return {"service": "vnc", "product": None, "version": None}
    if first.startswith("220"):
        low = text.lower()
        if "smtp" in low or port in (25, 465, 587, 2525):
            exim = re.search(r"Exim ([\d.]+)", text)
            sendmail = re.search(r"Sendmail ([\d.]+)", text)
            if "postfix" in low:
                return {"service": "smtp", "product": "Postfix", "version": None}
            if exim:
                return {"service": "smtp", "product": "Exim", "version": exim.group(1)}
            if sendmail:
                return {"service": "smtp", "product": "Sendmail", "version": sendmail.group(1)}
            return {"service": "smtp", "product": None, "version": None}
        for name in ("ProFTPD", "vsFTPd", "Pure-FTPd", "FileZilla Server", "Microsoft FTP Service", "Serv-U"):
            if name.lower() in low:
                found = re.search(re.escape(name) + r"[ /]+v?(\d[\w.\-]*)", text, re.I)
                return {"service": "ftp", "product": name, "version": found.group(1) if found else None}
        return {"service": "ftp", "product": None, "version": None}
    if first.startswith("+OK"):
        return {"service": "pop3", "product": "Dovecot" if "dovecot" in first.lower() else None, "version": None}
    if first.startswith("* OK") or first.startswith("* PREAUTH"):
        low = first.lower()
        product = "Dovecot" if "dovecot" in low else "Courier-IMAP" if "courier" in low else None
        return {"service": "imap", "product": product, "version": None}
    return None


def parse_http_response(data: bytes):
    """(status, {header: [values]}, body_bytes) or None if this is not an HTTP response."""
    if not data.startswith(b"HTTP/"):
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    if not _:
        head, _, body = data.partition(b"\n\n")
    lines = head.decode("latin-1", "replace").splitlines()
    status = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0]) if lines else None
    if not status:
        return None
    headers: dict = {}
    for line in lines[1:MAX_HEADER_LINES + 1]:
        name, sep, value = line.partition(":")
        if sep and name.strip():
            headers.setdefault(name.strip().lower()[:80], []).append(value.strip())
    return int(status.group(1)), headers, body


def parse_cookies(values) -> list:
    """Cookie NAMES and flags only. Values are session secrets and are never kept."""
    cookies = []
    for value in values[:20]:
        parts = [p.strip() for p in value.split(";")]
        name = parts[0].partition("=")[0].strip()
        if not name:
            continue
        flags = {p.partition("=")[0].strip().lower(): p.partition("=")[2].strip() for p in parts[1:]}
        cookies.append({"name": netio.clean_text(name, 100), "secure": "secure" in flags, "httponly": "httponly" in flags,
                        "samesite": netio.clean_text(flags.get("samesite", ""), 20) or None})
    return cookies


def kept_headers(headers: dict) -> dict:
    return {name: netio.clean_text(", ".join(headers[name]), 300) for name in KEPT_HEADERS if name in headers}


# --- Network probing -----------------------------------------------------------------------------------

def _request(method: str, domain: str) -> bytes:
    if any(c in domain for c in "\r\n "):
        raise ValueError("invalid host name")
    return (f"{method} / HTTP/1.0\r\nHost: {domain}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\n"
            f"Connection: close\r\n\r\n").encode("ascii")


def _tls_info(writer) -> dict | None:
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    cipher = ssl_object.cipher()
    certificate = None
    try:
        certificate = parse_certificate(ssl_object.getpeercert(binary_form=True) or b"")
    except Exception:
        pass
    return {"version": ssl_object.version(), "cipher": cipher[0] if cipher else None,
            "bits": cipher[2] if cipher else None, "certificate": certificate}


def _apply(probe: PortProbe, parsed: dict | None) -> None:
    if not parsed:
        return
    probe.service = parsed.get("service") or probe.service
    probe.service_guess = False
    probe.product = parsed.get("product") or probe.product
    probe.version = parsed.get("version") or probe.version


def _apply_http(probe: PortProbe, status: int, headers: dict, tls: bool) -> None:
    probe.service, probe.service_guess = ("https" if tls else "http"), False
    probe.http = {"status": status, "over_tls": tls, "headers": kept_headers(headers),
                  "cookies": parse_cookies(headers.get("set-cookie", []))}
    server = headers.get("server", [""])[0]
    if server:
        product, version = split_software(netio.clean_text(server, 200))
        probe.product, probe.version = product or probe.product, version or probe.version


async def _http_exchange(ip, port, domain, tls, method, *, timeout, body_limit):
    """One request on a fresh connection. Returns (reader-less result) (status, headers, body_bytes) or None."""
    try:
        reader, writer = await netio.open_connection(ip, port, tls=tls, server_name=domain, timeout=min(timeout, 1.2))
    except (asyncio.TimeoutError, OSError):
        return None
    try:
        writer.write(_request(method, domain))
        await asyncio.wait_for(writer.drain(), timeout)
        data = await netio.read_until_end(reader, 8192 if method == "HEAD" else body_limit, timeout)
    except (asyncio.TimeoutError, OSError, ValueError):
        return None
    finally:
        await netio.close(writer)
    return parse_http_response(data)


async def _probe(ip: str, port: int, domain: str, probe: PortProbe) -> None:
    banner_max = settings.scan_banner_max_bytes
    body_limit = settings.scan_http_body_max_bytes
    plain_banner = b""
    if port not in WEB_PORTS:  # web servers wait for the client; everything else may greet first
        try:
            reader, writer = await netio.open_connection(ip, port, timeout=1.0)
        except (asyncio.TimeoutError, OSError):
            probe.notes.append("could_not_reconnect")
            return
        plain_banner = await netio.read_some(reader, banner_max, 0.6)
        await netio.close(writer)
        if plain_banner:
            probe.banner = netio.clean_text(plain_banner, banner_max)
            _apply(probe, parse_banner(plain_banner, port))
    greeted = bool(plain_banner) and not plain_banner.startswith(b"HTTP/")

    # TLS handshake on every open port.
    tls_writer_info = None
    try:
        reader, writer = await netio.open_connection(ip, port, tls=True, server_name=domain, timeout=settings.scan_tls_handshake_timeout_seconds)
    except (asyncio.TimeoutError, OSError):
        reader = writer = None
    if writer is not None:
        tls_writer_info = _tls_info(writer)
        probe.tls = tls_writer_info
        try:
            if not greeted:
                greeting = await netio.read_some(reader, banner_max, 0.5)  # implicit-TLS mail servers greet after the handshake
                if greeting and not greeting.startswith(b"HTTP/"):
                    probe.banner = probe.banner or netio.clean_text(greeting, banner_max)
                    _apply(probe, parse_banner(greeting, port))
                    greeted = True
            if not greeted:
                writer.write(_request("HEAD", domain))
                await asyncio.wait_for(writer.drain(), 1.5)
                head = parse_http_response(await netio.read_until_end(reader, 8192, 1.5))
                if head:
                    _apply_http(probe, head[0], head[1], tls=True)
        except (asyncio.TimeoutError, OSError, ValueError):
            pass
        finally:
            await netio.close(writer)
    elif not greeted:
        try:
            reader, writer = await netio.open_connection(ip, port, timeout=1.0)
            writer.write(_request("HEAD", domain))
            await asyncio.wait_for(writer.drain(), 1.0)
            head = parse_http_response(await netio.read_until_end(reader, 8192, 1.2))
            await netio.close(writer)
            if head:
                _apply_http(probe, head[0], head[1], tls=False)
        except (asyncio.TimeoutError, OSError, ValueError):
            pass

    if probe.http:  # GET / for the technology step
        over_tls = probe.http["over_tls"]
        got = await _http_exchange(ip, port, domain, over_tls, "GET", timeout=1.5, body_limit=body_limit)
        if got:
            status, headers, body = got
            probe.web = WebPage(port=port, tls=over_tls, status=status, headers=kept_headers(headers),
                                cookies=parse_cookies(headers.get("set-cookie", [])),
                                body=body.decode("utf-8", "replace"), truncated=len(body) >= body_limit)


async def probe_open_port(ip: str, port: int, domain: str, *, timeout: float | None = None) -> PortProbe:
    probe = PortProbe(port=port)
    try:
        await asyncio.wait_for(_probe(ip, port, domain, probe), timeout or settings.scan_probe_timeout_seconds)
    except asyncio.TimeoutError:
        probe.notes.append("probe_time_limit")
    if probe.service is None:
        guess = SERVICE_NAMES.get(port)
        probe.service, probe.service_guess = guess, guess is not None
    return probe


async def probe_ports(ip: str, ports, domain: str, store, *, guard=None, concurrency: int | None = None) -> list[PortProbe]:
    """Probe the open ports a few at a time. `store(probe)` is called as each finishes, so a stop keeps the results."""
    limit = asyncio.Semaphore(concurrency or settings.scan_probe_concurrency)
    done: list[PortProbe] = []

    async def one(port: int) -> None:
        async with limit:
            if guard is not None:
                guard.check()
            probe = await probe_open_port(ip, port, domain)
            done.append(probe)
            store(probe)

    tasks = [asyncio.create_task(one(port)) for port in ports]
    try:
        await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    return done
