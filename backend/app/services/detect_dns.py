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


async def system_lookup(name: str, rdtype: str) -> list[str]:
    """Return the record texts, [] when the name has no such record, or raise on any failure to get an answer."""
    import dns.asyncresolver
    import dns.exception
    import dns.resolver
    resolver = dns.asyncresolver.Resolver()  # this machine's configured resolvers
    resolver.lifetime = settings.scan_dns_timeout_seconds
    try:
        answer = await resolver.resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return [b"".join(r.strings).decode("utf-8", "replace") if rdtype == "TXT" else r.to_text() for r in answer]


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
    found, failed = [], 0
    for selector in DKIM_SELECTORS:
        step()
        records, error = await _txt(f"{selector}._domainkey.{base}")
        if error:
            failed += 1
        elif any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records):
            found.append(selector)
    out.append({"key": "dkim", "status": "present" if found else "could_not_check" if failed == len(DKIM_SELECTORS) else "missing",
                "data": {"selectors_found": found, "selectors_checked": len(DKIM_SELECTORS), "lookups_failed": failed,
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
