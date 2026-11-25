"""Vulnerability engine: matches the software versions DETECT found against NVD (servers and CMS) and OSV (JavaScript
libraries), with a 24-hour cache.

How false positives are avoided (product spec 5.5):
* A finding is `confirmed` ONLY if (a) the affected range in the database was checked with our own version comparison and
  includes this version, (b) the software is not a Linux-distribution package (Ubuntu/Debian/Red Hat back-port fixes
  without changing the version number), (c) it is not behind a proxy/CDN, (d) the CVE is not marked disputed and does not
  need a second component (an AND-configuration). Otherwise it is `possible`: shown under "Needs checking" with a plain
  explanation and how to check, and it never counts in the score.
* Rejected CVEs are skipped. A CVE with no score is Medium + possible. At most 50 CVEs per item (highest score first).
* No disclosed version -> an Info finding saying we cannot check it. Never "safe".
* If a database cannot be reached the engine says so ("could not check"); old cached data is only ever used to ADD findings.
"""
import re
from datetime import datetime, timezone

from app.core.config import settings
from app.services import cvss, distro, engines, identify_items, versions, vuln_cache, vuln_sources
from app.services.finding import Finding
from app.data.severity_rules import RULES

MAX_PER_ITEM = 50
MAX_DESCRIPTION = 400
OSV_ECOSYSTEM = "npm"


# --- Normalizing database answers (pure functions) ------------------------------------------------------------------

def _score_from_nvd_metrics(metrics: dict):
    for name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        for metric in metrics.get(name) or []:
            data = metric.get("cvssData") or {}
            if isinstance(data.get("baseScore"), (int, float)):
                return float(data["baseScore"]), data.get("vectorString")
    for metric in metrics.get("cvssMetricV2") or []:
        data = metric.get("cvssData") or {}
        if isinstance(data.get("baseScore"), (int, float)):
            return float(data["baseScore"]), data.get("vectorString")
    return None, None


def _ranges_from_nvd(configurations, vendor: str, product: str):
    """(ranges, needs_other_component) for the given vendor:product."""
    ranges, and_config = [], False
    for config in configurations or []:
        nodes = config.get("nodes") or []
        if config.get("operator") == "AND" and len(nodes) > 1:
            and_config = True
        for node in nodes:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                parts = str(match.get("criteria", "")).split(":")
                if len(parts) < 7 or parts[3] != vendor or parts[4] != product:
                    continue
                entry = {k: match.get(v) for k, v in (("start_including", "versionStartIncluding"), ("start_excluding", "versionStartExcluding"),
                                                      ("end_including", "versionEndIncluding"), ("end_excluding", "versionEndExcluding"))}
                version, update = parts[5], parts[6]
                if version not in ("*", "-"):
                    entry["exact"] = version + (update if update not in ("*", "-") else "")
                ranges.append(entry)
    return ranges, and_config


def normalize_nvd(data, vendor: str, product: str) -> dict:
    advisories = []
    items = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise vuln_sources.SourceError("malformed")
    for wrapper in items:
        cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
        if not isinstance(cve, dict) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(cve.get("id", ""))):
            continue
        status = str(cve.get("vulnStatus", ""))
        if status.lower() == "rejected":
            continue
        text = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        disputed = "** DISPUTED **" in text or any("disputed" in (t.get("tags") or []) for t in cve.get("cveTags", []) if isinstance(t, dict))
        if text.startswith("** REJECT **"):
            continue
        score, vector = _score_from_nvd_metrics(cve.get("metrics") or {})
        ranges, and_config = _ranges_from_nvd(cve.get("configurations"), vendor, product)
        advisories.append({"id": cve["id"], "aliases": [], "description": text[:MAX_DESCRIPTION], "score": score, "vector": vector,
                           "disputed": disputed, "and_config": and_config, "ranges": ranges, "source": "nvd"})
    total = data.get("totalResults") if isinstance(data, dict) else None
    return {"advisories": advisories, "truncated": isinstance(total, int) and total > len(items)}


def normalize_osv(data) -> dict:
    items = data.get("vulns", []) if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise vuln_sources.SourceError("malformed")
    advisories = []
    for vuln in items:
        if not isinstance(vuln, dict) or vuln.get("withdrawn") or not vuln.get("id"):
            continue
        aliases = [a for a in vuln.get("aliases", []) if isinstance(a, str)]
        cve = next((a for a in aliases if a.startswith("CVE-")), None)
        score = vector = label = None
        for entry in vuln.get("severity", []) or []:
            if isinstance(entry, dict) and str(entry.get("type", "")).startswith("CVSS_V3"):
                score, vector = cvss.base_score(str(entry.get("score", ""))), str(entry.get("score", ""))[:120]
        if score is None:
            label = (vuln.get("database_specific") or {}).get("severity")
        ranges = []
        for affected in vuln.get("affected", []) or []:
            for rng in affected.get("ranges", []) or []:
                if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                    continue
                current = {}
                for event in rng.get("events", []) or []:
                    if "introduced" in event:
                        current = {"start_including": None if event["introduced"] in ("0", 0) else event["introduced"]}
                    elif "fixed" in event:
                        current["end_excluding"] = event["fixed"]
                        ranges.append(current)
                        current = {}
                    elif "last_affected" in event:
                        current["end_including"] = event["last_affected"]
                        ranges.append(current)
                        current = {}
                if current:
                    ranges.append(current)
            for exact in affected.get("versions", []) or []:
                pass  # explicit version lists are long; the ranges above are authoritative
        advisories.append({"id": cve or vuln["id"], "aliases": [vuln["id"]] if cve else [], "description": str(vuln.get("summary") or vuln.get("details") or "")[:MAX_DESCRIPTION],
                           "score": score, "vector": vector, "label": label, "disputed": False, "and_config": False,
                           "ranges": ranges, "source": "osv"})
    return {"advisories": advisories, "truncated": False}


# --- Matching -----------------------------------------------------------------------------------------------------------

def verify(version: str, advisory: dict) -> tuple[bool | None, dict | None]:
    """(True, range) if our own comparison says the version is inside an affected range; (False|None, None) otherwise."""
    result = False
    for rng in advisory.get("ranges") or []:
        if rng.get("exact"):
            answer = versions.compare(version, rng["exact"])
            answer = None if answer is None else answer == 0
        else:
            answer = versions.in_range(version, start_including=rng.get("start_including"), start_excluding=rng.get("start_excluding"),
                                       end_including=rng.get("end_including"), end_excluding=rng.get("end_excluding"))
        if answer is True:
            return True, rng
        if answer is None:
            result = None
    if not advisory.get("ranges"):
        return None, None
    return result, None


def _severity(advisory) -> tuple[str, float | None]:
    score = advisory.get("score")
    band = cvss.severity_from_score(score)
    if band is None:
        band = cvss.severity_from_label(advisory.get("label"))
    return band or "medium", score


def advisory_finding(item: identify_items.Item, advisory: dict, *, stale_at: datetime | None = None) -> Finding:
    ok, matched = verify(item.version, advisory)
    severity, score = _severity(advisory)
    reasons = []
    if item.family:
        reasons.append("distro")
    if item.proxy:
        reasons.append("proxy")
    caveat = distro.caveat(item.family, item.key, item.display, item.version, proxy=item.proxy)
    if ok is not True:
        reasons.append("range_not_verified")
        caveat = caveat or (f"We could not verify against {advisory['source'].upper()}'s data that version {item.version} is inside the "
                            "affected range, so please check the details before acting on this.")
    if advisory.get("disputed"):
        reasons.append("disputed")
        caveat = (caveat + " " if caveat else "") + "This issue is disputed by the software's maker, so it may not apply."
    if advisory.get("and_config"):
        reasons.append("needs_other_component")
        caveat = (caveat + " " if caveat else "") + "It only applies together with another component or setting, which we cannot see."
    if advisory.get("score") is None and not advisory.get("label"):
        reasons.append("unscored")
    if stale_at is not None:
        caveat = (caveat + " " if caveat else "") + f"The vulnerability database could not be reached, so this uses data from {stale_at.date().isoformat()}."
    confident = not any(r in reasons for r in ("distro", "proxy", "range_not_verified", "disputed", "needs_other_component", "unscored"))
    first_fixed = (matched or {}).get("end_excluding") or next((r.get("end_excluding") for r in advisory.get("ranges", []) if r.get("end_excluding")), None)
    ranged = versions.describe_range(**{k: (matched or {}).get(k) for k in ("start_including", "start_excluding", "end_including", "end_excluding")},
                                     exact=(matched or {}).get("exact")) if matched else None
    cve = advisory["id"]
    return Finding(
        kind="vulnerability", check_id=f"cve:{cve}", title=f"{item.display} {item.version} has a known vulnerability ({cve})",
        location=item.location, severity=severity, confidence="confirmed" if confident else "possible", port=item.port,
        you_have=f"{item.display} {item.version}",
        you_should_have=f"{item.display} {first_fixed} or later" if first_fixed else f"A supported, up-to-date version of {item.display}",
        cve_id=cve, cvss_score=score, cvss_vector=advisory.get("vector"), affected_range=ranged, first_fixed=first_fixed,
        why=advisory.get("description") or "A security problem is publicly known for this version.",
        how_to_fix=(f"Update {item.display} to version {first_fixed} or later." if first_fixed else f"Update {item.display} to the latest supported version.") +
                   " Then run the scan again.",
        evidence=f"Your server reports {item.display} {item.version}.", caveat=caveat, sources=[advisory["source"]],
        details={"reasons": reasons, "aliases": advisory.get("aliases", []), **({"data_date": stale_at.date().isoformat()} if stale_at else {})})


def hidden_version_finding(item: identify_items.Item) -> Finding:
    severity, title, why, how, should = RULES["disclosure:version-hidden"]
    return Finding(kind="disclosure", check_id=f"disclosure:version-hidden:{item.key}", title=f"The version of {item.display} is hidden, so we cannot check it for known problems",
                   location=item.location, severity=severity, confidence="confirmed", port=item.port, you_have=f"{item.display} (version not disclosed)",
                   you_should_have=should, why=why, how_to_fix=how, evidence=f"{item.display} was identified but did not report a version.",
                   sources=["snwebshield"])


# --- Look-ups ------------------------------------------------------------------------------------------------------------

def cpe_for(vendor: str, product: str, version: str, split_update: bool) -> str:
    update = "*"
    match = re.fullmatch(r"(\d+(?:\.\d+)*)([a-z]+\d*)", version) if split_update else None
    if match:
        version, update = match.group(1), match.group(2)
    return f"cpe:2.3:a:{vendor}:{product}:{version}:{update}:*:*:*:*:*:*"


def _fetch_nvd(vendor, product, version, split_update, deadline):
    def fetch():
        data = vuln_sources.http_json("nvd", "GET", "/rest/json/cves/2.0",
                                      params={"cpeName": cpe_for(vendor, product, version, split_update), "resultsPerPage": 2000}, deadline=deadline)
        return normalize_nvd(data, vendor, product)
    return fetch


def _fetch_osv(package, version, deadline):
    def fetch():
        data = vuln_sources.http_json("osv", "POST", "/v1/query", body={"package": {"name": package, "ecosystem": OSV_ECOSYSTEM}, "version": version},
                                      deadline=deadline)
        return normalize_osv(data)
    return fetch


class VulnerabilityEngine(engines.Engine):
    name = "vulnerabilities"
    label = "Checking software versions for known vulnerabilities"
    title = "Known vulnerabilities"

    async def run(self, ctx, state, guard) -> engines.EngineResult:
        sessions = _sessions(ctx)
        deadline = vuln_sources._monotonic() + settings.scan_identify_budget_seconds
        items = identify_items.collect(ctx.domain, state.probes, state.technologies)
        found: list[Finding] = []
        failed, checked, stale = [], 0, 0
        for item in items:
            guard.check()
            if not item.version:
                if item.ecosystem == "cpe":
                    found.append(hidden_version_finding(item))
                continue
            lookups = []
            if item.ecosystem == "cpe":
                for vendor, product in item.entry["cpes"]:
                    lookups.append(("nvd", f"{vendor}:{product}:{item.version}", _fetch_nvd(vendor, product, item.version, item.entry.get("split_update", False), deadline)))
            else:
                lookups.append(("osv", f"{OSV_ECOSYSTEM}:{item.entry['package']}:{item.version}", _fetch_osv(item.entry["package"], item.version, deadline)))
            advisories, stale_at, item_failed = {}, None, False
            for source, key, fetch in lookups:
                guard.check()
                result = await engines.run_blocking(vuln_cache.get, sessions, source, key, fetch, deadline=deadline)
                if result.state == "failed":
                    item_failed = True
                    failed.append({"item": f"{item.display} {item.version}", "source": source, "reason": result.reason})
                    continue
                if result.state == "stale":
                    stale_at = result.fetched_at
                    stale += 1
                    failed.append({"item": f"{item.display} {item.version}", "source": source, "reason": result.reason, "used_old_data": True})
                for advisory in result.advisories:
                    advisories.setdefault(advisory["id"], advisory)
            if not item_failed:
                checked += 1
            ordered = sorted(advisories.values(), key=lambda a: -(a.get("score") or 0))
            found += [advisory_finding(item, advisory, stale_at=stale_at) for advisory in ordered[:MAX_PER_ITEM]]
            if len(ordered) > MAX_PER_ITEM:
                found[-1].details["more_not_shown"] = len(ordered) - MAX_PER_ITEM
        detail = {"items": len(items), "checked": checked, "failed": failed, "findings": len(found)}
        return engines.EngineResult("could_not_check" if failed else "ok", found, detail)


def _sessions(ctx):
    if ctx.sessions is None:
        from app.db.session import SessionLocal
        return SessionLocal
    return ctx.sessions
