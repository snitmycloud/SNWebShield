"""Plain-language notes about what a scan could and could not see on THIS website (shown above the results).

Built only from what the scan already collected. A note explains a limitation; it never says anything is safe.
"""
from urllib.parse import urlsplit

from app.services import cdn as cdn_module


def _host(location: str) -> str:
    return (urlsplit(location if "://" in location else f"//{location}").hostname or "").lower().rstrip(".")


def build(domain: str, *, ports_ok: bool, open_ports, probes, cdn: dict | None) -> list[dict]:
    notes = []
    if cdn:
        notes.append({"kind": "cdn", "tone": "warn", "text": cdn_module.message(cdn)})
    pages = [p.web for p in probes if getattr(p, "web", None)]
    blocked = next((page for page in pages if cdn_module.looks_like_challenge(page) or page.status in (403, 429)), None)
    if blocked is not None:
        notes.append({"kind": "blocked", "tone": "warn", "text": (
            f"Your website answered with \u201cHTTP {blocked.status}\u201d (an access-denied or \u201cchecking your browser\u201d page) when we visited it, "
            "so some web checks could not run. Some sites block security scanners; that is not the same as being secure.")})
    for page in pages:
        if page.status in (301, 302, 303, 307, 308):
            target = _host((page.headers or {}).get("location", ""))
            if target and target != domain.lower().rstrip("."):
                notes.append({"kind": "redirect", "tone": "info", "text": (
                    f"{domain} redirects to {target}. We scanned the address you added; add {target} as a website to check the page visitors actually see.")})
                break
    if ports_ok and not list(open_ports):
        notes.append({"kind": "no_ports", "tone": "warn", "text": (
            "None of the ports we checked answered. The website may be offline, or a firewall may be blocking our scanner. "
            "That is not the same as being secure.")})
    return notes
