"""The Nuclei engine: an ordinary engine (see engines.py) that adds template-based checks to the built-in findings.

It is OFF by default (`NUCLEI_ENABLED`) and refuses to run unless ALL of these hold, checked every scan:
  1. the installed binary's SHA-256 equals the pin in engines.lock.json;
  2. every vendored template still matches MANIFEST.json (no file added, changed or missing);
  3. the self-test passed within the last hour: the egress proxy refuses a foreign host AND the operating-system firewall
     blocks the binary's direct access (nuclei_selftest.py). If it fails, the engine stays off and says why.
It runs against the scan's verified host only, through the per-scan egress proxy to the one pinned IP, and every result is
treated as untrusted data (cut to size, host re-checked, severity capped, never "confirmed" for CVE templates).
Not running is never "safe": the step is `skipped` (disabled) or `could_not_check` (a safety check failed or a run broke).
"""
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

from app.core.config import settings
from app.services import detect_tech, egress_proxy, engines, netio, nuclei_lock, nuclei_runner, nuclei_selftest, sensitive_panels
from app.services.finding import Finding

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "data" / "nuclei" / "templates"
SEVERITY_CAP = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "info", "unknown": "info"}
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,120}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
EQUIVALENTS_PATH = Path(__file__).resolve().parent.parent / "data" / "nuclei" / "equivalents.json"


class TemplateSetError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def verify_templates(directory: Path = TEMPLATES_DIR) -> dict:
    """The vendored set must be EXACTLY what the manifest lists. Returns the manifest, raises TemplateSetError otherwise."""
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        listed = manifest["templates"]
    except (OSError, ValueError, KeyError):
        raise TemplateSetError("manifest_missing")
    if not listed:
        raise TemplateSetError("no_templates")
    present = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file() and p.suffix.lower() in (".yaml", ".yml")}
    if present != set(listed):
        raise TemplateSetError("template_set_changed")
    import hashlib
    for name, digest in listed.items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
            raise TemplateSetError("template_hash_mismatch")
    return manifest


def web_targets(domain: str, probes) -> list[str]:
    """Only standard web ports, because the egress proxy only allows 80 and 443."""
    targets = []
    for probe in probes:
        if probe.http and probe.port == 443 and probe.http["over_tls"]:
            targets.append(f"https://{domain}")
        elif probe.http and probe.port == 80 and not probe.http["over_tls"]:
            targets.append(f"http://{domain}")
    return sorted(set(targets))


def load_equivalents() -> dict:
    try:
        return json.loads(EQUIVALENTS_PATH.read_text(encoding="utf-8")).get("templates", {})
    except (OSError, ValueError):
        return {}


def to_finding(raw: dict, domain: str, equivalents: dict) -> Finding | None:
    """One Nuclei result -> one common finding, or None if it is not about our host or not understood."""
    template_id = raw.get("template-id")
    info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
    matched = str(raw.get("matched-at") or raw.get("url") or "")
    if not isinstance(template_id, str) or not SAFE_ID.match(template_id):
        return None
    parts = urlsplit(matched if "://" in matched else f"http://{matched}")
    if (parts.hostname or "").lower().rstrip(".") != domain.lower():
        return None  # never report on anything but the verified host
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    severity = SEVERITY_CAP.get(str(info.get("severity", "info")).lower(), "info")
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    cve_raw = classification.get("cve-id")
    cve = next((c.upper() for c in (cve_raw if isinstance(cve_raw, list) else [cve_raw]) if isinstance(c, str) and CVE_RE.match(c)), None)
    if cve is None and CVE_RE.match(template_id):
        cve = template_id.upper()
    name = netio.clean_text(info.get("name") or template_id, 200)
    description = netio.clean_text(info.get("description") or "", 600) or None
    mapped = equivalents.get(template_id)
    if cve:
        location, kind = f"{domain}:{port}", "vulnerability"
    elif mapped:
        location, kind = f"{domain}{path}", "exposure"
    else:
        location, kind = f"{domain}{path}" if path != "/" else f"{domain}:{port}", "exposure"
    finding = Finding(
        kind=kind, check_id=f"nuclei:{template_id}", title=name, location=location, severity=severity,
        confidence="possible" if cve else "confirmed", port=port, you_have=None,
        why=description or "A check from the Nuclei template library matched your website.",
        how_to_fix=("Update the affected software to a supported, patched version, then run the scan again." if cve else
                    "Remove or restrict what the check found, or change the setting it points to, then run the scan again."),
        evidence=f"Matched by the Nuclei check “{template_id}” at {path[:120]}.", cve_id=cve,
        caveat=("A template-based check matched. Because the same version problem can be fixed without changing what the server "
                "shows, please confirm it before acting." if cve else None),
        sources=["nuclei"], details={"template": template_id, "tier": str(info.get("severity", ""))[:20],
                                    **({"equivalent_to": mapped.replace("{path}", path)} if mapped else {})})
    return finding


load_sensitive = sensitive_panels.load_sensitive      # kept here for callers and tests that already use these names
sensitive_label = sensitive_panels.sensitive_label
_TECH_SUFFIX = re.compile(r"\s*\b(?:version\s+)?(?:detect(?:ion|ed)?|fingerprint(?:ing)?|technology|panel|exposure)\s*$", re.I)
_VERSION = re.compile(r"^v?(\d[\w.\-+]{0,30})$")
MAX_PANELS = 100


def technology_name(name: str) -> str:
    cleaned = name
    for _ in range(3):
        cleaned = _TECH_SUFFIX.sub("", cleaned).strip(" -:")
    return netio.clean_text(cleaned or name, 80)


def to_technology(raw: dict, domain: str, existing_names: dict) -> dict | None:
    """A Nuclei technology result -> a row for the Technologies list (never a finding). `existing_names` maps lower-case
    built-in names to their spelling so the same technology is merged, not listed twice."""
    template_id = raw.get("template-id")
    info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
    matched = str(raw.get("matched-at") or raw.get("url") or "")
    parts = urlsplit(matched if "://" in matched else f"http://{matched}")
    if not isinstance(template_id, str) or not SAFE_ID.match(template_id) or (parts.hostname or "").lower().rstrip(".") != domain.lower():
        return None
    name = technology_name(str(info.get("name") or template_id))
    if not name:
        return None
    version = None
    extracted = raw.get("extracted-results")
    for item in (extracted if isinstance(extracted, list) else []):
        found = _VERSION.match(str(item).strip())
        if found:
            version = found.group(1)
            break
    return {"name": existing_names.get(name.lower(), name), "category": "Other", "version": version, "source": "nuclei",
            "evidence": f"Nuclei check {template_id}"[:200], "port": parts.port or (443 if parts.scheme == "https" else 80)}


def panel_findings(panels: list[dict], domain: str) -> list[Finding]:
    """One Info finding listing every ordinary login/admin page, plus one Medium finding per SENSITIVE panel."""
    found: list[Finding] = []
    ordinary = [p for p in panels if not p["sensitive"]]
    if ordinary:
        listed = ordinary[:MAX_PANELS]
        found.append(Finding(
            kind="exposure", check_id="nuclei-panels", title=f"Login or admin pages found: {len(ordinary)}", location=domain, severity="info",
            confidence="confirmed", you_have=f"{len(ordinary)} login or admin page(s)",
            why="These pages let people sign in or manage something. They are normal for many websites, but admin pages are a common target for password guessing.",
            how_to_fix="Make sure each page is needed and kept up to date, protect it with strong passwords and two-step login, and restrict admin pages to trusted addresses where you can.",
            evidence="; ".join(f"{p['name']} ({p['path']})" for p in listed[:10]) + (" ..." if len(ordinary) > 10 else ""),
            sources=["nuclei"], details={"panels": [{"name": p["name"], "path": p["path"], "template": p["template"]} for p in listed],
                                         "sensitive_reported_separately": len(panels) - len(ordinary)}))
    for panel in panels:
        if panel["sensitive"]:
            found.append(Finding(
                kind="exposure", check_id=f"nuclei-panel:{panel['template']}", title=f"{panel['name']} is reachable from the internet",
                location=f"{domain}{panel['path']}", severity="medium", confidence="confirmed", you_have=panel["name"],
                you_should_have="Admin and management tools reachable only from trusted addresses or through a VPN.",
                why=f"This looks like a {panel['sensitive'].lower()}. Tools like this give wide control, are attacked constantly, and should not be open to everyone.",
                how_to_fix="Restrict it to trusted addresses or a VPN, require strong logins and two-step verification, keep it updated, or remove it if you do not use it.",
                evidence=f"Matched by the Nuclei check \u201c{panel['template']}\u201d at {panel['path'][:120]}.", sources=["nuclei"],
                details={"template": panel["template"], "sensitive": panel["sensitive"], "equivalent_to": f"exposed:login-form:{panel['path']}"}))
    return found


def process_results(raw_results: list, domain: str, index: dict, equivalents: dict, existing_technologies: list) -> dict:
    """Sort Nuclei results by the category of their template (from the verified manifest): technologies -> Technologies list,
    exposed-panels -> one grouped finding (+ Medium for sensitive ones), everything else -> ordinary findings."""
    rules = sensitive_panels.load_sensitive()
    existing = {t["name"].lower(): t["name"] for t in existing_technologies}
    findings, technologies, panels, dropped, seen_panels = [], [], [], 0, set()
    for raw in raw_results[:500]:
        template_id = raw.get("template-id") if isinstance(raw, dict) else None
        meta = index.get(template_id)
        if meta is None:
            dropped += 1                  # not one of the vendored, validated templates: ignored
            continue
        category = meta["category"]
        if category == "technologies":
            tech = to_technology(raw, domain, existing)
            if tech is None:
                dropped += 1
            else:
                technologies.append(tech)
        elif category == "exposed-panels":
            matched = str(raw.get("matched-at") or "")
            parts = urlsplit(matched if "://" in matched else f"http://{matched}")
            if (parts.hostname or "").lower().rstrip(".") != domain.lower() or not SAFE_ID.match(str(template_id)):
                dropped += 1
                continue
            path = netio.clean_text(parts.path or "/", 200)
            if (template_id, path) in seen_panels:
                continue
            seen_panels.add((template_id, path))
            info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
            name = netio.clean_text(info.get("name") or template_id, 120)
            panels.append({"template": template_id, "name": name, "path": path, "sensitive": sensitive_panels.sensitive_label(template_id, name, rules)})
        else:
            finding = to_finding(raw, domain, equivalents)
            if finding is None:
                dropped += 1
            else:
                findings.append(finding)
    findings += panel_findings(panels, domain)
    return {"findings": findings, "technologies": technologies, "dropped": dropped, "panels": len(panels),
            "sensitive_panels": sum(1 for p in panels if p["sensitive"])}


# --- Which templates run: QUICK (normal scans) or DEEP (all of them; scheduled deep scans later) ---------------------------------------
QUICK_CATEGORIES = ("exposures", "misconfiguration")
_GENERIC = {"http", "https", "server", "web", "the", "and", "for", "with", "framework", "library", "cms", "panel", "service", "api", "app",
            "login", "admin", "detect", "version", "plugin", "wp", "php", "js", "css", "html", "net", "linux", "unix", "windows"}
_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def detected_tokens(technologies, probes) -> set[str]:
    """Lower-case words for the software we already detected (names and server products), used to pick matching CVE templates."""
    import re
    names = [t.get("name", "") for t in technologies] + [getattr(p, "product", "") or "" for p in probes]
    tokens = set()
    for name in names:
        for word in re.split(r"[^a-z0-9]+", str(name).lower()):
            if len(word) >= 3 and word not in _GENERIC:
                tokens.add(word)
        compact = re.sub(r"[^a-z0-9]+", "", str(name).lower())
        if len(compact) >= 3 and compact not in _GENERIC:
            tokens.add(compact)
    return tokens


def select_templates(manifest: dict, mode: str, tokens: set[str], rules=None, max_cves: int | None = None) -> list[str]:
    """Relative template paths to run. QUICK: every exposures and misconfiguration template, the SENSITIVE panels only, and the CVE
    templates whose tags/product match software we detected (highest severity first, capped). DEEP: all vendored templates."""
    index = manifest.get("index", {})
    if mode == "deep":
        return sorted(index)
    rules = sensitive_panels.load_sensitive() if rules is None else rules
    chosen, cves = [], []
    for path, meta in index.items():
        category = meta.get("category")
        if category in QUICK_CATEGORIES:
            chosen.append(path)
        elif category == "exposed-panels":
            if sensitive_panels.sensitive_label(meta.get("id", ""), meta.get("name") or "", rules):
                chosen.append(path)
        elif category == "cves" and tokens:
            words = set(meta.get("tags") or []) | {meta.get("product")}   # not the vendor: "apache" would pull in every Apache product
            if words & tokens:
                cves.append((_RANK.get(meta.get("severity"), 5), meta.get("id", ""), path))
    limit = settings.nuclei_max_quick_cves if max_cves is None else max_cves
    chosen += [path for _, _, path in sorted(cves)[:limit]]
    return sorted(chosen)


SELFTEST_WAIT_SECONDS = 60   # the worker's start-up self-test takes about 16 s; a scan started meanwhile waits for it instead of silently running without Nuclei


async def wait_for_selftest(guard=None, *, ensure=None, wait=None, pause=1.0, sleep=None) -> dict:
    """The self-test result, waiting (never longer than `wait`, and stopping when the scan guard stops the scan) for one that is still
    running. Same site, same checks: a scan must not lose Nuclei just because it started a few seconds after the worker did."""
    import asyncio
    import time
    ensure = ensure or nuclei_selftest.ensure
    sleep = sleep or asyncio.sleep
    end = time.monotonic() + (SELFTEST_WAIT_SECONDS if wait is None else wait)
    while True:
        check = await ensure(guard)
        if check.get("failed") != ["selftest_running"] or time.monotonic() >= end:
            return check
        if guard is not None:
            guard.check()
        await sleep(pause)


class NucleiEngine(engines.Engine):
    name = "nuclei"
    parallel = True          # runs at the same time as the vulnerability and end-of-life steps
    label = "Running extra template checks"
    title = "Extra checks (Nuclei)"

    async def run(self, ctx, state, guard) -> engines.EngineResult:
        if not settings.nuclei_enabled:
            return engines.EngineResult("skipped", [], {"reason": "disabled"})
        targets = web_targets(ctx.domain, state.probes)
        if not targets:
            return engines.EngineResult("not_applicable", [], {"reason": "no_web_server_on_80_or_443"})
        try:
            binary = nuclei_lock.verified_binary()
            manifest = verify_templates()
        except nuclei_lock.LockError as error:
            if error.code == "binary_not_installed":   # not installed here (for example a fresh checkout): simply off, no note
                return engines.EngineResult("skipped", [], {"reason": "not_installed"})
            return engines.EngineResult("could_not_check", [], {"reason": error.code})
        except TemplateSetError as error:
            return engines.EngineResult("could_not_check", [], {"reason": error.code})
        check = await wait_for_selftest(guard)
        if check["failed"] == ["selftest_running"]:   # the worker's start-up self-test has not finished yet: skip this scan, no warning
            return engines.EngineResult("skipped", [], {"reason": "selftest_starting"})
        if not check["ok"]:
            return engines.EngineResult("could_not_check", [], {"reason": "selftest_failed", "selftest": check["failed"]})
        mode = "deep" if getattr(ctx, "scan_type", "standard") == "deep" else "quick"
        only = getattr(state, "only_template", None)   # a recheck of one Nuclei finding runs just that template
        if only:
            mode = "recheck"
            chosen = sorted(path for path, meta in manifest.get("index", {}).items() if meta.get("id") == only)
        else:
            chosen = select_templates(manifest, mode, detected_tokens(state.technologies, state.probes))
        if not chosen:
            return engines.EngineResult("ok", [], {"mode": mode, "templates": 0, "reason": "no_matching_templates"})
        log_path = Path(settings.nuclei_log_dir) / f"{ctx.scan_id}.jsonl"
        proxy = egress_proxy.EgressProxy(host=ctx.domain, ip=ctx.ip, scan_id=ctx.scan_id, log_path=log_path)
        await proxy.start()
        try:
            started = time.monotonic()
            outcome = await nuclei_runner.run(binary, [TEMPLATES_DIR / path for path in chosen], targets, proxy.url, guard,
                                              timeout_seconds=settings.nuclei_deep_run_seconds if mode == "deep" else 90 if mode == "recheck" else settings.nuclei_run_seconds)
            seconds = round(time.monotonic() - started, 1)
        finally:
            await proxy.stop()
        index = {meta["id"]: meta for meta in manifest.get("index", {}).values()}
        processed = process_results(outcome.results, ctx.domain, index, load_equivalents(), state.technologies)
        found, dropped = processed["findings"], processed["dropped"]
        if processed["technologies"]:
            # Technologies found by Nuclei join the built-in list (same name = one row, the best version wins); never findings.
            state.technologies = detect_tech.merge(state.technologies, processed["technologies"])
            from app.services import detect_runner   # imported here: detect_runner imports the engines
            detect_runner.save_technologies(ctx, state.technologies)
        summary = proxy.summary()
        detail = {"mode": mode, "templates": len(chosen), "templates_available": len(manifest["templates"]), "seconds": seconds,
                  "requests": summary["allowed"], "targets": targets, "findings": len(found), "dropped_results": dropped, "technologies_added": len(processed["technologies"]),
                  "panels": processed["panels"], "sensitive_panels": processed["sensitive_panels"],
                  "proxy": summary, "proxy_log": str(log_path), "exit_code": outcome.exit_code, "selftest_at": check["at"]}
        if outcome.timed_out or outcome.truncated or (outcome.exit_code not in (0, None) and not found):
            detail["reason"] = "timed_out" if outcome.timed_out else "output_too_large" if outcome.truncated else "nuclei_failed"
            if outcome.stderr_tail:
                detail["stderr_tail"] = outcome.stderr_tail
            return engines.EngineResult("could_not_check", found, detail)
        return engines.EngineResult("ok", found, detail)
