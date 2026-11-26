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
from pathlib import Path
from urllib.parse import urlsplit

from app.core.config import settings
from app.services import egress_proxy, engines, netio, nuclei_lock, nuclei_runner, nuclei_selftest
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


class NucleiEngine(engines.Engine):
    name = "nuclei"
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
            return engines.EngineResult("could_not_check", [], {"reason": error.code})
        except TemplateSetError as error:
            return engines.EngineResult("could_not_check", [], {"reason": error.code})
        check = await nuclei_selftest.ensure(guard)
        if not check["ok"]:
            return engines.EngineResult("could_not_check", [], {"reason": "selftest_failed", "selftest": check["failed"]})
        log_path = Path(settings.nuclei_log_dir) / f"{ctx.scan_id}.jsonl"
        proxy = egress_proxy.EgressProxy(host=ctx.domain, ip=ctx.ip, scan_id=ctx.scan_id, log_path=log_path)
        await proxy.start()
        try:
            outcome = await nuclei_runner.run(binary, TEMPLATES_DIR, targets, proxy.url, guard)
        finally:
            await proxy.stop()
        equivalents = load_equivalents()
        found, dropped = [], 0
        for raw in outcome.results[:500]:
            finding = to_finding(raw, ctx.domain, equivalents)
            if finding is None:
                dropped += 1
            else:
                found.append(finding)
        summary = proxy.summary()
        detail = {"templates": len(manifest["templates"]), "targets": targets, "findings": len(found), "dropped_results": dropped,
                  "proxy": summary, "proxy_log": str(log_path), "exit_code": outcome.exit_code, "selftest_at": check["at"]}
        if outcome.timed_out or outcome.truncated or (outcome.exit_code not in (0, None) and not found):
            detail["reason"] = "timed_out" if outcome.timed_out else "output_too_large" if outcome.truncated else "nuclei_failed"
            if outcome.stderr_tail:
                detail["stderr_tail"] = outcome.stderr_tail
            return engines.EngineResult("could_not_check", found, detail)
        return engines.EngineResult("ok", found, detail)
