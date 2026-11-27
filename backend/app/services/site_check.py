"""Does the built landing page show the same prices as plans.json?

The landing page is built ahead of time (frontend/dist/index.html) and carries the prices it was built with in a
`<meta name="snwebshield-prices">` tag. plans.json is the only source of truth: checkout and billing NEVER read the page.
This module only detects a page that has gone stale, so it can be logged, shown on the Admin page and rebuilt by the supervisor.

Status: ok | mismatch | not_built | unreadable. Anything but "ok" is shown as a warning; "could not check" is never "fine".
"""
import html
import json
import logging
import re
import shutil
import subprocess
import sys
from pathlib import Path

from app.services import plans

log = logging.getLogger("snwebshield.site_check")
ROOT = Path(__file__).resolve().parents[3]
FRONTEND = ROOT / "frontend"
LANDING = FRONTEND / "dist" / "index.html"
_TAG = re.compile(r'<meta\s+name="snwebshield-prices"\s+content="([^"]*)"', re.I)


def expected(path: Path = plans.PLANS_FILE) -> dict:
    data = plans.load(path)
    return {"currency": data.get("currency", "INR"),
            "prices": {k: [int(p.get("price", {}).get("monthly", 0)), int(p.get("price", {}).get("yearly", 0))] for k, p in data["plans"].items()}}


def built(landing: Path = LANDING) -> dict | None:
    """The prices in the built page, or None when the page has no (readable) price tag."""
    match = _TAG.search(landing.read_text(encoding="utf-8"))
    if not match:
        return None
    data = json.loads(html.unescape(match.group(1)))
    return {"currency": data.get("currency"), "prices": {k: [int(v[0]), int(v[1])] for k, v in data["prices"].items()}}


def check(landing: Path = LANDING, plans_path: Path = plans.PLANS_FILE) -> dict:
    try:
        want = expected(plans_path)
    except Exception:
        return {"status": "unreadable", "message": "plans.json could not be read, so the landing page prices could not be checked.", "differences": []}
    if not landing.exists():
        return {"status": "not_built", "message": "The landing page has not been built (frontend/dist is missing), so its prices could not be checked.", "differences": []}
    try:
        have = built(landing)
    except Exception:
        have = None
    if have is None:
        return {"status": "unreadable", "message": "The built landing page has no readable price tag. Rebuild the site (npm run build in frontend).", "differences": []}
    differences = []
    if have["currency"] != want["currency"]:
        differences.append({"plan": "*", "field": "currency", "page": have["currency"], "plans_json": want["currency"]})
    for key in sorted(set(want["prices"]) | set(have["prices"])):
        for index, field in enumerate(("monthly", "yearly")):
            a = have["prices"].get(key, [None, None])[index]
            b = want["prices"].get(key, [None, None])[index]
            if a != b:
                differences.append({"plan": key, "field": field, "page": a, "plans_json": b})
    if differences:
        return {"status": "mismatch", "differences": differences,
                "message": "The landing page shows different prices from plans.json. Checkout always uses plans.json. Rebuild the site (the supervisor does this automatically)."}
    return {"status": "ok", "message": "The landing page prices match plans.json.", "differences": []}


def log_result(result: dict | None = None) -> dict:
    result = result or check()
    if result["status"] == "ok":
        log.info(result["message"])
    else:
        # Prices only; nothing secret is in plans.json or the page.
        log.error("LANDING PAGE PRICE CHECK: %s %s %s", result["status"], result["message"], json.dumps(result["differences"]))
    return result


def rebuild(timeout: int = 300) -> bool:
    """Rebuild the site with the local vite (no shell, fixed arguments). True when it finished and the prices now match."""
    node = shutil.which("node")
    vite = FRONTEND / "node_modules" / "vite" / "bin" / "vite.js"
    if not node or not vite.exists():
        log.error("site rebuild skipped: node or vite is not installed")
        return False
    try:
        done = subprocess.run([node, str(vite), "build"], cwd=str(FRONTEND), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0)
    except Exception as error:
        log.error("site rebuild failed: %s", type(error).__name__)
        return False
    return done.returncode == 0 and check()["status"] == "ok"
