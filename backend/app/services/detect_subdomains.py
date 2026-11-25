"""Subdomain LIST from public certificate-transparency logs (crt.sh). List only: nothing listed here is ever scanned.

This sends the scanned domain NAME (nothing else) to crt.sh, as the product spec requires. It has a short timeout and
a size cap, so a slow or unavailable crt.sh gives "could not check" and never holds the scan up. The answer is
untrusted: only names that end with the scanned domain and look like host names are kept.
"""
import asyncio
import http.client
import json
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from app.core.config import settings
from app.services import ip_policy
from app.services.netio import clean_text
from app.services.ownership import _PinnedHTTPS

MAX_BYTES = 2 * 1024 * 1024
MAX_NAMES = 500
HOST = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="crtsh")


def _fetch(domain: str) -> str:
    """Blocking GET of crt.sh's JSON for `%.domain`. Raises on any failure."""
    ip = ip_policy.resolve_public("crt.sh")[0]
    connection = _PinnedHTTPS("crt.sh", ip, settings.crtsh_timeout_seconds)
    try:
        connection.request("GET", f"/?q={quote('%.' + domain)}&output=json",
                           headers={"Host": "crt.sh", "User-Agent": "SNWebShield/1.0", "Accept": "application/json"})
        response = connection.getresponse()
        if response.status != 200:
            raise http.client.HTTPException("status")
        return response.read(MAX_BYTES).decode("utf-8", "replace")
    finally:
        connection.close()


# The seam tests replace, so no test ever reaches crt.sh.
fetch = _fetch


def parse_names(text: str, domain: str) -> list[str]:
    try:
        rows = json.loads(text)
    except ValueError:
        raise ValueError("not json")
    names: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        for raw in str(row.get("name_value", "")).splitlines() if isinstance(row, dict) else []:
            raw = raw.strip()
            if len(raw) > 255 or any(ord(c) < 33 or ord(c) == 127 for c in raw):
                continue  # reject, never "clean" a hostile name into a different valid-looking one
            name = raw.lower().lstrip("*.")
            if (name == domain or name.endswith("." + domain)) and HOST.match(name):
                names.add(name)
            if len(names) >= MAX_NAMES:
                return sorted(names)
    return sorted(names)


async def list_subdomains(domain: str) -> dict:
    """{status: listed | could_not_check, names: [...], reason}. Never raises for a slow or failing crt.sh."""
    from app.services.detect_dns import email_domain
    base = email_domain(domain)  # for www.example.com, ask about example.com
    loop = asyncio.get_running_loop()
    try:
        text = await asyncio.wait_for(loop.run_in_executor(_executor, fetch, base), settings.crtsh_timeout_seconds + 1)
        names = parse_names(text, base)
        return {"status": "listed", "names": [n for n in names if n != domain], "domain": base}
    except asyncio.CancelledError:
        raise
    except Exception:
        return {"status": "could_not_check", "names": [], "domain": base,
                "reason": "crt.sh did not answer in time or is unavailable"}
