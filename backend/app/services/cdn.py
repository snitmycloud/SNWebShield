"""Is the website behind a CDN or WAF (Cloudflare, Akamai, Fastly and others)?

Then the open ports we find belong to the CDN, not to the owner's own server, and a version banner may be the CDN's.
Detection reads only what the site already told us: response headers, cookie names and the Server banner. Nothing is
sent for this. Header text is untrusted: it is only compared with the patterns below, never used as a command or link.
"""
import re

# (name, header patterns). A pattern is (header name, regex on its value or None for "present").
SIGNATURES = (
    ("Cloudflare", (("server", r"^cloudflare"), ("cf-ray", None), ("cf-cache-status", None), ("cf-mitigated", None))),
    ("Akamai", (("server", r"akamai"), ("x-akamai-transformed", None), ("akamai-grn", None), ("x-akamai-request-id", None), ("x-akamai-staging", None))),
    ("Fastly", (("x-fastly-request-id", None), ("fastly-debug-digest", None), ("x-served-by", r"^cache-"), ("x-timer", r"^S\d"))),
    ("Amazon CloudFront", (("x-amz-cf-id", None), ("x-amz-cf-pop", None), ("via", r"cloudfront"), ("server", r"^cloudfront"))),
    ("Microsoft Azure Front Door", (("x-azure-ref", None), ("x-fd-healthprobe", None))),
    ("Sucuri", (("x-sucuri-id", None), ("x-sucuri-cache", None), ("server", r"^sucuri"))),
    ("Imperva Incapsula", (("x-iinfo", None), ("x-cdn", r"incapsula|imperva"))),
    ("StackPath", (("x-sp-url", None), ("x-hw", r"^\d"))),
    ("Google Cloud CDN", (("via", r"google"), ("server", r"^gws$|^gfe"))),
    ("Vercel", (("server", r"^vercel"), ("x-vercel-id", None))),
    ("Netlify", (("server", r"^netlify"), ("x-nf-request-id", None))),
    ("GitHub Pages", (("server", r"^github\.com$"), ("x-github-request-id", None))),
    ("DDoS-Guard", (("server", r"^ddos-guard"),)),
    ("BunnyCDN", (("server", r"^bunnycdn"), ("cdn-pullzone", None))),
    ("KeyCDN", (("server", r"^keycdn"), ("x-edge-location", None))),
    ("Reblaze / other WAF", (("x-reblaze", None),)),
)
COOKIE_SIGNATURES = (("Imperva Incapsula", r"^(incap_ses|visid_incap)"), ("Cloudflare", r"^(__cf_bm|cf_clearance|__cfduid)$"), ("Akamai", r"^(ak_bmsc|bm_sz|akamai)"))
CHALLENGE = re.compile(r"just a moment|checking your browser|attention required|access denied|enable javascript and cookies|are you a robot|captcha", re.I)


def detect_headers(headers: dict | None, cookies=()) -> dict | None:
    """{'name': 'Cloudflare', 'evidence': 'cf-ray header'} or None."""
    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    for name, patterns in SIGNATURES:
        for header, regex in patterns:
            value = lowered.get(header)
            if value is None:
                continue
            if regex is None or re.search(regex, value.strip(), re.I):
                return {"name": name, "evidence": f"{header} header"}
    for cookie in cookies or ():
        for name, regex in COOKIE_SIGNATURES:
            if re.match(regex, str(cookie.get("name", "")), re.I):
                return {"name": name, "evidence": "cookie name"}
    return None


def detect(probes) -> dict | None:
    """Look at every web page we fetched; the first CDN found wins."""
    for probe in probes:
        page = getattr(probe, "web", None)
        if page is not None:
            found = detect_headers(page.headers, page.cookies)
            if found:
                return {**found, "port": page.port}
        if probe.http:
            found = detect_headers(probe.http.get("headers"), probe.http.get("cookies"))
            if found:
                return {**found, "port": probe.port}
    return None


def message(cdn: dict | None) -> str | None:
    if not cdn:
        return None
    return f"This site is behind {cdn['name']}. Port results show the CDN, not your server."


def looks_like_challenge(page) -> bool:
    """A 'checking your browser' / access-denied page served instead of the real site."""
    headers = {str(k).lower(): str(v) for k, v in (page.headers or {}).items()}
    if headers.get("cf-mitigated"):
        return True
    return page.status in (403, 429, 503) and bool(CHALLENGE.search((page.body or "")[:20000]))
