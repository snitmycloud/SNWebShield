"""Domain ownership verification: the only approval step.

Three methods, the owner picks one:
* DNS TXT  - `snwebshield-verify=<token>` on the domain (looked up through this machine's DNS resolver).
* File     - https://<domain>/.well-known/snwebshield-<token>.txt containing the token.
* Meta tag - <meta name="snwebshield-verify" content="<token>"> on https://<domain>/.

Web checks are hardened: the host is resolved once and every answer must be a public address (no private,
metadata or own-server addresses), the connection is pinned to that address, HTTPS certificates are verified
for the host name, redirects are followed only within the same host over HTTPS (re-validated each hop), and at
most 256 KB is read. Responses are untrusted data: they are compared, cut short and stripped of control
characters before being shown back.
"""
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from html.parser import HTMLParser
import http.client
import socket
import ssl
from urllib.parse import urljoin, urlsplit

from sqlalchemy import select

from app.core.config import settings
from app.core.time import as_utc, utc_now
from app.models.admin import Admin
from app.models.website import Website
from app.services import domains, ip_policy

MAX_BODY = 256 * 1024
MAX_REDIRECTS = 3
META_NAME = "snwebshield-verify"
DNS_HINT_NO_HTTPS = ("Your website does not have working HTTPS, so the file and meta-tag methods cannot be used. "
                     "Use the DNS TXT method instead.")


@dataclass
class CheckResult:
    method: str
    state: str  # verified | not_found | no_https | could_not_check | redirected
    expected: str
    found: list[str] = field(default_factory=list)
    message: str = ""
    hint: str = ""

    @property
    def ok(self) -> bool:
        return self.state == "verified"

    def as_dict(self) -> dict:
        return {**asdict(self), "ok": self.ok}


def _clean(text: str, limit: int = 200) -> str:
    text = "".join(c if c.isprintable() else " " for c in str(text)).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def txt_value(token: str) -> str:
    return f"snwebshield-verify={token}"


def file_path(token: str) -> str:
    return f"/.well-known/snwebshield-{token}.txt"


def meta_tag(token: str) -> str:
    return f'<meta name="{META_NAME}" content="{token}">'


def instructions(website: Website) -> dict:
    token, domain = website.verification_token, website.domain
    return {
        "dns": {"record_type": "TXT", "host": domain, "value": txt_value(token),
                "note": "Add this TXT record at your DNS provider. Changes can take a few minutes to appear."},
        "file": {"url": f"https://{domain}{file_path(token)}", "content": token,
                 "note": "Upload a plain text file at exactly this address containing only the code. Needs working HTTPS."},
        "meta": {"page": f"https://{domain}/", "tag": meta_tag(token),
                 "note": "Put this tag inside the <head> of your homepage. Needs working HTTPS."},
    }


# --- DNS -----------------------------------------------------------------------------------------

def _dns_txt(domain: str) -> list[str]:
    import dns.exception
    import dns.resolver
    resolver = dns.resolver.Resolver()  # this machine's configured resolvers; never a third-party DoH service
    resolver.lifetime = 6.0
    try:
        answer = resolver.resolve(domain, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.resolver.NoNameservers, dns.exception.Timeout) as error:
        raise TimeoutError("dns") from error
    return [b"".join(record.strings).decode("utf-8", "replace") for record in answer]


def check_dns(domain: str, token: str, lookup=_dns_txt) -> CheckResult:
    expected = txt_value(token)
    try:
        records = lookup(domain)
    except Exception:
        return CheckResult("dns", "could_not_check", expected, [],
                           "We could not look up your DNS records right now.", "Wait a minute and click Verify again.")
    found = [_clean(r) for r in records[:10]]
    if any(r.strip() == expected for r in records):
        return CheckResult("dns", "verified", expected, found, "DNS TXT record found. Ownership confirmed.")
    ours = [r for r in found if r.startswith("snwebshield-verify=")]
    if ours:
        return CheckResult("dns", "not_found", expected, found,
                           "We found a SNWebShield TXT record, but its code does not match this website.",
                           "Replace it with the exact value shown, including the code.")
    return CheckResult("dns", "not_found", expected, found,
                       "No matching TXT record was found on " + domain + ".",
                       "Add the TXT record exactly as shown. DNS changes can take a few minutes (sometimes longer) to appear.")


# --- HTTPS ---------------------------------------------------------------------------------------

class NoHttps(Exception):
    pass


class _PinnedHTTPS(http.client.HTTPSConnection):
    """Connects to a pre-approved IP while verifying the certificate for the real host name."""

    def __init__(self, host, ip, timeout):
        super().__init__(host, 443, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, 443), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


@dataclass
class Fetched:
    status: int
    body: str
    final_url: str
    redirected_to: str | None = None


def fetch_https(host: str, path: str) -> Fetched:
    """GET https://host/path. Raises ip_policy.Blocked, NoHttps or TimeoutError."""
    url = f"https://{host}{path}"
    for _ in range(MAX_REDIRECTS + 1):
        ip = ip_policy.resolve_public(host)[0]
        connection = _PinnedHTTPS(host, ip, settings.ownership_http_timeout_seconds)
        try:
            connection.request("GET", path, headers={"Host": host, "User-Agent": "SNWebShield-Verify/1.0",
                                                     "Accept": "text/html,text/plain;q=0.9,*/*;q=0.1"})
            response = connection.getresponse()
            body = response.read(MAX_BODY + 1)[:MAX_BODY]
            status, location = response.status, response.getheader("Location")
        except (ssl.SSLCertVerificationError, ssl.SSLError, ssl.CertificateError) as error:
            raise NoHttps("certificate") from error
        except ConnectionRefusedError as error:
            raise NoHttps("refused") from error
        except (socket.timeout, TimeoutError) as error:
            raise TimeoutError("https") from error
        except OSError as error:
            raise NoHttps("connect") from error
        finally:
            connection.close()
        text = body.decode("utf-8", "replace")
        if status in (301, 302, 303, 307, 308) and location:
            target = urljoin(url, location.strip())
            parts = urlsplit(target)
            if parts.scheme != "https" or (parts.hostname or "").lower().rstrip(".") != host or parts.port not in (None, 443):
                return Fetched(status, "", url, redirected_to=_clean(target, 300))
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            url = target
            continue
        return Fetched(status, text, url)
    return Fetched(310, "", url, redirected_to="too many redirects")


def _web_failure(method: str, expected: str, error: Exception) -> CheckResult:
    if isinstance(error, ip_policy.Blocked):
        if error.code == "dns_lookup_failed":
            return CheckResult(method, "could_not_check", expected, [], "We could not find this domain in DNS.",
                               "Check the spelling, or wait if the domain is new.")
        return CheckResult(method, "could_not_check", expected, [],
                           "This domain points to a private or reserved network address, which SNWebShield will not contact.",
                           "Make sure the domain points to your public website.")
    if isinstance(error, NoHttps):
        reason = {"certificate": "its HTTPS certificate is not valid for this name",
                  "refused": "nothing answers on the HTTPS port (443)"}.get(str(error), "we could not open an HTTPS connection")
        return CheckResult(method, "no_https", expected, [], f"We could not check your website because {reason}.",
                           DNS_HINT_NO_HTTPS)
    return CheckResult(method, "no_https" if isinstance(error, TimeoutError) else "could_not_check", expected, [],
                       "Your website did not answer over HTTPS in time.", DNS_HINT_NO_HTTPS)


def _redirected(method: str, expected: str, fetched: Fetched, domain: str) -> CheckResult:
    return CheckResult(method, "redirected", expected, [f"Redirected to {fetched.redirected_to}"],
                       f"https://{domain} redirects to another address, so we could not read the page there.",
                       f"Add the website exactly as it redirects (for example the www version), or use the DNS TXT method.")


def check_file(domain: str, token: str, fetch=fetch_https) -> CheckResult:
    expected = token
    try:
        fetched = fetch(domain, file_path(token))
    except Exception as error:
        return _web_failure("file", expected, error)
    if fetched.redirected_to:
        return _redirected("file", expected, fetched, domain)
    first_line = fetched.body.strip().splitlines()[0] if fetched.body.strip() else ""
    found = [f"HTTP {fetched.status}" + (f": {_clean(first_line, 120)}" if first_line else " (empty)")]
    if fetched.status == 200 and fetched.body.strip() == token:
        return CheckResult("file", "verified", expected, found, "Verification file found. Ownership confirmed.")
    if fetched.status == 404:
        message = "The verification file was not found (the server answered 404 Not Found)."
    elif fetched.status == 200:
        message = "The address answered, but the file does not contain only the verification code."
    else:
        message = f"The server answered HTTP {fetched.status} instead of the file."
    return CheckResult("file", "not_found", expected, found, message,
                       f"Create the file at https://{domain}{file_path(token)} containing only the code.")


class _MetaFinder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.values = []

    def handle_starttag(self, tag, attrs):
        if tag == "meta":
            values = {k.lower(): (v or "") for k, v in attrs}
            if values.get("name", "").strip().lower() == META_NAME:
                self.values.append(values.get("content", ""))


def check_meta(domain: str, token: str, fetch=fetch_https) -> CheckResult:
    expected = meta_tag(token)
    try:
        fetched = fetch(domain, "/")
    except Exception as error:
        return _web_failure("meta", expected, error)
    if fetched.redirected_to:
        return _redirected("meta", expected, fetched, domain)
    if fetched.status != 200:
        return CheckResult("meta", "not_found", expected, [f"HTTP {fetched.status}"],
                           f"Your homepage answered HTTP {fetched.status}, so we could not read it.",
                           "Make sure https://" + domain + "/ loads, then try again.")
    finder = _MetaFinder()
    try:
        finder.feed(fetched.body)
    except Exception:
        pass
    found = [meta_tag(_clean(v, 80)) for v in finder.values[:5]]
    if any(v.strip() == token for v in finder.values):
        return CheckResult("meta", "verified", expected, found, "Meta tag found. Ownership confirmed.")
    if found:
        return CheckResult("meta", "not_found", expected, found,
                           "We found a SNWebShield meta tag, but its code does not match this website.",
                           "Replace it with the exact tag shown.")
    return CheckResult("meta", "not_found", expected, ["No snwebshield-verify meta tag on the homepage"],
                       "The verification meta tag was not found on your homepage.",
                       "Add the tag inside <head>. If your site caches pages, clear the cache, then try again.")


CHECKS = {"dns": check_dns, "file": check_file, "meta": check_meta}


def run_check(website: Website, method: str) -> CheckResult:
    return CHECKS[method](website.domain, website.verification_token)


# --- Coverage and re-checks ------------------------------------------------------------------------

def covering_website(db, website: Website) -> Website | None:
    """A verified website of the same owner whose verification covers this one (example.com covers shop.example.com)."""
    if not website.owner_id or not website.domain:
        return None
    candidates = domains.parents(website.domain)
    if not candidates:
        return None
    for parent in db.scalars(select(Website).where(Website.owner_id == website.owner_id, Website.domain.in_(candidates),
                                                   Website.verification_status == "verified",
                                                   Website.removed_at.is_(None))):
        # A test target proves nothing about its subdomains, so it never covers them.
        if parent.verification_method not in ("parent", "test_target") and domains.covers(parent.domain, website.domain):
            return parent
    return None


def record(website: Website, result: CheckResult, now=None) -> None:
    now = now or utc_now()
    website.verification_result = {**result.as_dict(), "checked_at": now.isoformat()}
    if result.ok:
        if website.verification_status != "verified":
            website.verified_at = now
        website.verification_status = "verified"
        website.verification_method = result.method
        website.verification_checked_at = now


def mark_covered(website: Website, parent: Website, now=None) -> None:
    now = now or utc_now()
    result = CheckResult("parent", "verified", parent.domain, [parent.domain],
                         f"Covered by your verified domain {parent.domain}.")
    record(website, result, now)


def ensure_verified(db, website: Website, now=None) -> tuple[bool, str]:
    """Re-check ownership before a scan (cached for OWNERSHIP_CACHE_HOURS). Returns (allowed, reason_code).

    A definite failure marks the website `lost`, which pauses scans until the owner fixes it. A check that
    could not be performed refuses this scan but does not change the status (fail closed, no false alarm).
    """
    now = now or utc_now()
    if website.verification_status != "verified":
        return False, "not_verified"
    if website.verification_method == "test_target":
        # No DNS proof exists for a test target: it is allowed only while the domain is on the fixed approved list
        # and its owner is a currently active admin account.
        owner = db.get(Admin, website.owner_id) if website.owner_id else None
        if (website.domain in settings.approved_test_targets and owner is not None
                and owner.is_active and owner.role == "admin"):
            return True, "test_target"
        return False, "not_verified"
    if website.verification_method == "parent":
        parent = covering_website(db, website)
        if parent is None:
            website.verification_status = "lost"
            website.verification_result = {**(website.verification_result or {}), "ok": False, "state": "not_found",
                                            "message": "The parent domain that covered this website is no longer verified.",
                                            "hint": "Verify this website directly, or re-verify the parent domain.",
                                            "checked_at": now.isoformat()}
            return False, "verification_lost"
        allowed, reason = ensure_verified(db, parent, now)
        if allowed:
            website.verification_checked_at = now
        elif reason == "verification_lost":
            website.verification_status = "lost"
        return allowed, reason
    fresh = website.verification_checked_at and as_utc(website.verification_checked_at) > now - timedelta(
        hours=settings.ownership_cache_hours)
    if fresh:
        return True, "cached"
    result = run_check(website, website.verification_method)
    if result.ok:
        record(website, result, now)
        return True, "rechecked"
    if result.state in ("could_not_check", "no_https"):
        # The site or DNS did not answer: we cannot tell, so refuse this scan without declaring the proof gone.
        return False, "could_not_recheck"
    website.verification_status = "lost"
    website.verification_result = {**result.as_dict(), "checked_at": now.isoformat(),
                                   "message": "We could no longer find your verification. " + result.message}
    return False, "verification_lost"
