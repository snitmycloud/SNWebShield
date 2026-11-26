"""DNS and email security records for the scanned domain: SPF, DMARC, DKIM (common selectors), CAA and MX.

These are DNS lookups through this machine's resolver (never a third-party DNS-over-HTTPS service); the website's own
server is not contacted. Each lookup has a short timeout. A lookup that fails or times out is "could not check",
never "missing": only a clean "no such record" answer counts as missing.

For a `www.` host, email records live on the main domain, so those are looked up on the name without `www.`.
"""
import asyncio

from app.core.config import settings
from app.services.netio import clean_text

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "smtp",
                  "mandrill", "mxvault", "everlytickey1", "zoho")


class DefinitiveAnswer(Exception):
    """A clean 'no such record' answer: never retried, never an error."""


async def _query(nameservers, name: str, rdtype: str) -> list[str]:
    """One attempt with one resolver set: None = this machine's configured resolvers, else the given addresses.
    Returns the record texts, [] for a clean 'no such record', and raises on any failure to get an answer."""
    import dns.asyncresolver
    import dns.resolver
    resolver = dns.asyncresolver.Resolver(configure=nameservers is None)
    if nameservers is not None:
        resolver.nameservers = list(nameservers)
    resolver.lifetime = settings.scan_dns_timeout_seconds
    try:
        answer = await resolver.resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return [b"".join(r.strings).decode("utf-8", "replace") if rdtype == "TXT" else r.to_text() for r in answer]


def attempts() -> list:
    """The resolver sets tried, in order: this machine's resolvers, then the second resolvers, then this machine's again."""
    fallback = [a.strip() for a in settings.scan_dns_fallback_resolvers.split(",") if a.strip()]
    order = [None, fallback or None, None, fallback or None, None]
    return order[:max(1, settings.scan_dns_attempts)]


async def system_lookup(name: str, rdtype: str) -> list[str]:
    """Return the record texts, [] when the name has no such record, or raise only after every attempt failed.

    A clean answer ends it at once. A timeout or resolver error is retried (up to `scan_dns_attempts` in all, switching to the
    second resolvers on the first retry) before the caller is allowed to say "could not check"."""
    last = None
    for nameservers in attempts():
        try:
            return await _query(nameservers, name, rdtype)
        except asyncio.CancelledError:
            raise
        except Exception as error:   # noqa: BLE001 - any failure to get an answer is retried
            last = error
    raise last or OSError("dns lookup failed")


# The seam tests replace, so no test ever queries real DNS.
lookup = system_lookup


def email_domain(domain: str) -> str:
    return domain[4:] if domain.startswith("www.") and domain.count(".") >= 2 else domain


def _spf_policy(record: str) -> str:
    for token in record.split():
        if token.endswith("all") and token[:-3] in ("", "+", "-", "~", "?"):
            return {"": "pass_all", "+": "pass_all", "-": "fail", "~": "softfail", "?": "neutral"}[token[:-3]]
    return "no_all"


def _dmarc_policy(record: str) -> str | None:
    for part in record.split(";"):
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "p":
            return value.strip().lower() or None
    return None


async def _txt(name: str):
    """(records, error) where error is None on a clean answer."""
    try:
        return await lookup(name, "TXT"), None
    except Exception:
        return [], "lookup_failed"


async def check_dns(domain: str, *, guard=None) -> list[dict]:
    """Return observations: {key, status (present|missing|could_not_check), data}."""
    base = email_domain(domain)
    out: list[dict] = []

    def step() -> None:
        if guard is not None:
            guard.check()

    step()
    records, error = await _txt(base)
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    out.append({"key": "spf", "status": "could_not_check" if error else "present" if spf else "missing",
                "data": {"record": clean_text(spf[0], 400), "policy": _spf_policy(spf[0]), "domain": base} if spf else {"domain": base}})
    step()
    records, error = await _txt(f"_dmarc.{base}")
    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
    out.append({"key": "dmarc", "status": "could_not_check" if error else "present" if dmarc else "missing",
                "data": {"record": clean_text(dmarc[0], 400), "policy": _dmarc_policy(dmarc[0]), "domain": base} if dmarc else {"domain": base}})
    found, failed, in_a_row, asked, stopped_early = [], 0, 0, 0, False
    for selector in DKIM_SELECTORS:
        step()
        if in_a_row >= 3 and not found:   # the resolver is not answering at all: do not wait through every selector
            stopped_early = True
            break
        asked += 1
        records, error = await _txt(f"{selector}._domainkey.{base}")
        if error:
            failed += 1
            in_a_row += 1
        else:
            in_a_row = 0
            if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records):
                found.append(selector)
    out.append({"key": "dkim", "status": "present" if found else "could_not_check" if stopped_early or failed == len(DKIM_SELECTORS) else "missing",
                "data": {"selectors_found": found, "selectors_checked": asked, "lookups_failed": failed,
                         "note": "Only common selectors are checked, so 'missing' means none of those were found."}})
    step()
    try:
        caa = await lookup(domain, "CAA")
        out.append({"key": "caa", "status": "present" if caa else "missing",
                    "data": {"records": [clean_text(r, 200) for r in caa[:10]]}})
    except Exception:
        out.append({"key": "caa", "status": "could_not_check", "data": {}})
    step()
    try:
        mx = await lookup(base, "MX")
        out.append({"key": "mx", "status": "present" if mx else "missing",
                    "data": {"records": [clean_text(r, 200) for r in mx[:10]], "domain": base}})
    except Exception:
        out.append({"key": "mx", "status": "could_not_check", "data": {}})
    return out
