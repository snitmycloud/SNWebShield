"""End-of-life engine: is the operating system or the software branch behind a version still getting security updates?

Data is the committed file app/data/eol.json (generated from endoflife.date, MIT licence, by tools/update_eol.py) plus
the hand-written app/data/eol_hints.json. A scan makes NO network call for this.

Rules (product spec 5.5, reviewed):
* A finding is made only when the data is clear. For a distribution package (a banner that says Ubuntu / Debian / Red
  Hat) we judge the DISTRIBUTION release, not the upstream version: a patched Apache 2.4.7 on a supported Ubuntu is not
  end of life. If the release cannot be worked out, no finding. If several releases ship that version, EVERY one of them
  must be past its end of support, otherwise no finding.
* Vanilla software (no distribution banner) is judged by its own branch (PHP 7.4, nginx 1.18, ...). The longest matching
  branch wins. OpenSSH has no branches, so it is only ever judged through its distribution.
* Two tiers, worded differently: High "No longer receives security updates" (all support, including paid, has ended);
  Medium "Only paid extended support remains". Both are confirmed and count in the score.
* One finding per operating-system release or product branch (not one per port).
* If the data file is older than 90 days the findings say so, because newer end-of-life dates may be missing.
"""
import json
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from app.services import engines, identify_items
from app.services.finding import Finding

DATA = Path(__file__).resolve().parent.parent / "data"
STALE_AFTER_DAYS = 90
ENDED, PAID_ONLY, SUPPORTED, UNKNOWN = "ended", "paid_only", "supported", "unknown"
_DEB = re.compile(r"[+~]deb(\d+)u\d+", re.I)


def load():
    eol = json.loads((DATA / "eol.json").read_text(encoding="utf-8"))
    hints = json.loads((DATA / "eol_hints.json").read_text(encoding="utf-8"))
    return eol, hints


def _date(value):
    try:
        return date.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None


def status(row: dict, today: date) -> tuple[str, date | None, date | None]:
    """(state, free_support_end, paid_support_end) for one release row of eol.json."""
    eol, extended = row.get("eol"), row.get("extendedSupport")
    free_end = _date(eol)
    if eol is False or (eol is None):
        return (SUPPORTED if eol is False else UNKNOWN), None, None
    if eol is True:
        free_end = today - timedelta(days=1)
    if free_end is None:
        return UNKNOWN, None, None
    paid_end = _date(extended) if isinstance(extended, str) else None
    if extended is True:
        paid_end = None
    if today < free_end:
        return SUPPORTED, free_end, paid_end
    if paid_end is not None and today < paid_end:
        return PAID_ONLY, free_end, paid_end
    return ENDED, free_end, paid_end


def _row(eol: dict, slug: str, cycle: str):
    return next((r for r in eol["products"].get(slug, []) if r["cycle"] == cycle), None)


def _branch_row(eol: dict, slug: str, version: str):
    best = None
    for row in eol["products"].get(slug, []):
        cycle = str(row["cycle"])
        if version == cycle or version.startswith(cycle + "."):
            if best is None or len(cycle) > len(str(best["cycle"])):
                best = row
    return best


def _best(states):
    """The most favourable state among candidates: supported beats paid-only beats ended. Unknown if any is unknown."""
    if not states or UNKNOWN in states:
        return UNKNOWN
    for wanted in (SUPPORTED, PAID_ONLY, ENDED):
        if wanted in states:
            return wanted
    return UNKNOWN


def release_for(item, hints) -> list[tuple[str, str]]:
    """Candidate (family_slug, release) pairs for a distribution package, or [] if it cannot be worked out."""
    family = item.family
    slugs = hints["slugs"]["family"].get(family, [])
    found = _DEB.search(item.context_text or "")
    if family == "debian" and found:
        return [("debian", found.group(1))]
    table = hints.get(item.key, {}).get(family, {})
    releases = table.get(item.version or "", [])
    return [(slug, release) for slug in slugs for release in releases]


def _wording(state, title_subject):
    if state == ENDED:
        return "high", f"{title_subject} no longer receives security updates", "No longer receives security updates"
    return "medium", f"{title_subject}: only paid extended support remains", "Only paid extended support remains"


def evaluate(domain: str, items, eol: dict, hints: dict, today: date) -> list[Finding]:
    names = hints["slugs"]["family_names"]
    found: dict[str, Finding] = {}
    old_data = (today - (_date(eol.get("as_of")) or today)).days > STALE_AFTER_DAYS
    for item in items:
        if not item.version:
            continue
        if item.family:
            candidates = release_for(item, hints)
            states = []
            for slug, release in candidates:
                row = _row(eol, slug, release)
                states.append(status(row, today)[0] if row else UNKNOWN)
            verdict = _best(states)
            if verdict not in (ENDED, PAID_ONLY):
                continue
            slug, release = max(candidates, key=lambda c: _rank(eol, c, today))
            row = _row(eol, slug, release)
            _, free_end, paid_end = status(row, today)
            label = f"{names.get(slug, slug)} {release}"
            severity, title, short = _wording(verdict, f"Your server's operating system ({label})")
            check_id, where = f"eol:distro:{slug}-{release}", domain
            evidence_item = f"{item.display} {item.version} (port {item.port})" if item.port else f"{item.display} {item.version}"
            ends = _ends_text(free_end, paid_end)
            current = found.get(check_id)
            if current:
                current.evidence += f"; {evidence_item}"
                continue
            found[check_id] = Finding(
                kind="lifecycle", check_id=check_id, title=title, location=where, severity=severity, confidence="confirmed",
                port=None, you_have=label, you_should_have="An operating-system release that still receives security updates",
                why=f"{short}. New security problems are no longer fixed for {label}, so every newly discovered weakness stays open on your server.",
                how_to_fix=f"Upgrade the server to a supported release (or move to a supported hosting image). {ends}",
                evidence=f"Worked out from {evidence_item}.", sources=["endoflife.date"],
                caveat=_data_caveat(eol) if old_data else None, details={"release": release, "tier": verdict, "family": slug})
        else:
            slug = hints["slugs"]["product"].get(item.key)
            if slug is None:
                continue
            row = _branch_row(eol, slug, item.version)
            if row is None:
                continue
            verdict, free_end, paid_end = status(row, today)
            if verdict not in (ENDED, PAID_ONLY):
                continue
            subject = f"{item.display} {row['cycle']}"
            severity, title, short = _wording(verdict, subject)
            check_id, where = f"eol:product:{item.key}-{row['cycle']}", f"{domain}:{item.port}" if item.port else domain
            caveat = " ".join(filter(None, [
                "This version may belong to a proxy or CDN in front of your server rather than to your server itself." if item.proxy else None,
                _data_caveat(eol) if old_data else None])) or None
            found[check_id] = Finding(
                kind="lifecycle", check_id=check_id, title=title, location=where, severity=severity,
                confidence="possible" if item.proxy else "confirmed", port=item.port, you_have=f"{item.display} {item.version}",
                you_should_have=f"A {item.display} version that still receives security updates",
                why=f"{short}. New security problems are no longer fixed in the {row['cycle']} branch.",
                how_to_fix=f"Upgrade {item.display} to a supported version (latest in your branch: {row.get('latest')}; supported branches are listed at endoflife.date). {_ends_text(free_end, paid_end)}",
                evidence=f"Your server reports {item.display} {item.version}.", caveat=caveat, sources=["endoflife.date"],
                details={"branch": row["cycle"], "tier": verdict})
    return sorted(found.values(), key=lambda f: f.check_id)


def _rank(eol, candidate, today):
    row = _row(eol, *candidate)
    state = status(row, today)[0] if row else UNKNOWN
    return {SUPPORTED: 3, PAID_ONLY: 2, ENDED: 1, UNKNOWN: 0}[state]


def _ends_text(free_end, paid_end) -> str:
    parts = []
    if free_end:
        parts.append(f"Free security updates ended on {free_end.isoformat()}.")
    if paid_end:
        parts.append(f"Paid extended support {'ends' if paid_end > date.today() else 'ended'} on {paid_end.isoformat()}.")
    return " ".join(parts)


def _data_caveat(eol) -> str:
    return (f"Our end-of-life data was last updated on {eol.get('as_of')}, so a newer date may be missing. "
            "Check the vendor's support page to be sure.")


class LifecycleEngine(engines.Engine):
    name = "lifecycle"
    label = "Checking whether your software still gets security updates"
    title = "End of life"

    async def run(self, ctx, state, guard) -> engines.EngineResult:
        try:
            eol, hints = load()
        except (OSError, ValueError):
            return engines.EngineResult("could_not_check", [], {"reason": "eol_data_unavailable"})
        items = identify_items.collect(ctx.domain, state.probes, state.technologies)
        found = evaluate(ctx.domain, items, eol, hints, datetime.now(timezone.utc).date())
        age = (datetime.now(timezone.utc).date() - (_date(eol.get("as_of")) or datetime.now(timezone.utc).date())).days
        return engines.EngineResult("ok", found, {"items": len(items), "findings": len(found), "data_as_of": eol.get("as_of"),
                                                  "data_older_than_90_days": age > STALE_AFTER_DAYS})
