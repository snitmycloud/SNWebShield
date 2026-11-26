"""Re-scan to confirm a fix: run ONLY the check behind one finding, against the website's one pinned IP.

The scan worker runs it like any scan (ownership re-checked, one pinned address, the stop guard, a short time limit). Nothing from a
recheck replaces the website's latest full scan: it writes no ports, technologies or findings. The result is one of
  absent           the check finished OK and the finding is no longer there  -> the caller marks it Fixed "by recheck"
  present          it is still there                                          -> stays open
  could_not_check  the check could not finish (site down, database slow, ...) -> NOT fixed, the owner is told to try again
A check that fails or times out is never "fixed".
"""
import re

from sqlalchemy import select

from app.core.config import settings
from app.models.scan import FindingRecheck, FindingState, Scan, ScanFinding, ScanPort
from app.services import (cdn as cdn_module, detect_exposed, detect_ports, detect_tech, detect_versions, engine_config, engine_eol, engine_nuclei,
                          engine_vulns, engines, finding_states)
from app.services.detect_runner import ScanState


def _sessions(ctx):
    if ctx.sessions is None:
        from app.db.session import SessionLocal
        return SessionLocal
    return ctx.sessions


def plan_for(check_id: str) -> str:
    """Which focused check to run: port | exposed | config | version | nuclei (or '' if this finding cannot be re-checked alone)."""
    if not finding_states.recheckable(check_id):
        return ""
    if check_id.startswith("port:"):
        return "port"
    if check_id.startswith("exposed:"):
        return "exposed"
    if check_id.startswith(("cve:", "eol:", "disclosure:version-hidden")):
        return "version"
    if check_id.startswith("nuclei"):
        return "nuclei"
    return "config"


def load_target(ctx) -> dict:
    """What to re-check, from the database: the finding, and the ports the website's last full scan found open."""
    with _sessions(ctx)() as db:
        recheck = db.scalar(select(FindingRecheck).where(FindingRecheck.scan_id == ctx.scan_id))
        if recheck is None:
            return {}
        state = db.scalar(select(FindingState).where(FindingState.website_id == recheck.website_id, FindingState.fingerprint == recheck.fingerprint))
        last = db.scalar(select(Scan).where(Scan.website_id == recheck.website_id, Scan.scan_type != "recheck", Scan.status.in_(("completed", "incomplete")))
                         .order_by(Scan.requested_at.desc()).limit(1))
        ports, web_ports, finding_port = [], {}, None
        if last is not None:
            for p in db.scalars(select(ScanPort).where(ScanPort.scan_id == last.id).order_by(ScanPort.port)):
                ports.append(p.port)
                http = (p.details or {}).get("http")
                if http:
                    web_ports[p.port] = bool(http.get("over_tls"))
            row = db.scalar(select(ScanFinding).where(ScanFinding.scan_id == last.id, ScanFinding.fingerprint == recheck.fingerprint))
            finding_port = row.port if row is not None else None
        return {"fingerprint": recheck.fingerprint, "check_id": recheck.check_id, "location": state.location if state else "", "ports": ports,
                "web_ports": web_ports, "finding_port": finding_port}


def _outcome(state, outcome: str, detail: str = "") -> None:
    state.recheck = {"outcome": outcome, "detail": detail}


async def _reprobe(ctx, state, ports, guard) -> None:
    """Probe only the ports that were open last time (and re-read the technologies on the web pages)."""
    state.ports.open = sorted(set(ports))
    await detect_versions.probe_ports(ctx.ip, state.ports.open, ctx.domain, store=lambda probe: state.probes.append(probe), guard=guard)
    pages = [p.web for p in state.probes if p.web]
    if pages:
        rules = detect_tech.load_rules()
        state.technologies = detect_tech.merge(*[detect_tech.detect(rules, page, port=page.port) for page in pages])
    state.cdn = cdn_module.detect(state.probes)


def _found(result, fingerprint) -> bool:
    return any(f.fingerprint == fingerprint for f in result.findings)


async def run(ctx, state, guard) -> None:
    """The `detect` function of a recheck scan. Sets state.recheck = {"outcome", "detail"}; never raises a result of its own."""
    _outcome(state, "could_not_check", "not_started")
    target = load_target(ctx)
    if not target:
        return
    check_id, fingerprint = target["check_id"], target["fingerprint"]
    kind = plan_for(check_id)
    state.current = "recheck"
    ctx.progress("recheck", "Re-checking this finding…")
    ports = list(target["ports"])
    if target["finding_port"] and target["finding_port"] not in ports:
        ports.append(target["finding_port"])
    if kind == "":
        _outcome(state, "could_not_check", "not_rechecked_alone")
        return

    if kind == "port":
        port = int(check_id.split(":", 1)[1])
        results = []
        for _ in range(2):   # a port is called closed only if it did not answer twice
            guard.check()
            found = detect_ports.PortResults()
            await detect_ports.scan_ports(ctx.ip, (port,), found, guard=guard, progress=None)
            results.append(found)
        if any(port in r.open for r in results):
            _outcome(state, "present", f"Port {port} still answers.")
        elif any(r.could_not_check for r in results):
            _outcome(state, "could_not_check", "The port check could not finish.")
        else:
            _outcome(state, "absent", f"Port {port} no longer answers.")
        return

    if kind == "exposed":
        _, signature, path = check_id.split(":", 2)
        web = target["web_ports"]
        endpoint = next(((p, tls) for p, tls in sorted(web.items(), key=lambda kv: (kv[0] != 443, not kv[1], kv[0]))), None)
        if endpoint is None:
            _outcome(state, "could_not_check", "No web server was found on the last scan.")
            return
        fetch = detect_exposed.make_fetcher(ctx.ip, endpoint[0], endpoint[1], ctx.domain, timeout=settings.scan_http_request_timeout_seconds)
        result = await detect_exposed.check_exposed(fetch, guard=guard, only_paths={path})
        hit = [o for o in result.observations if o["key"] == path and (o["data"] or {}).get("signature") == signature]
        if hit:
            _outcome(state, "present", f"{path} is still reachable.")
        elif result.failed or result.checked == 0:
            _outcome(state, "could_not_check", "The page could not be fetched.")
        else:
            _outcome(state, "absent", f"{path} is no longer found.")
        return

    await _reprobe(ctx, state, ports, guard)
    if kind == "config":
        result = await engines.run_engine(engine_config.ConfigurationEngine(), ctx, state, guard)
    elif kind == "version":
        engine = engine_eol.LifecycleEngine() if check_id.startswith("eol:") else engine_vulns.VulnerabilityEngine()
        result = await engines.run_engine(engine, ctx, state, guard)
    else:   # nuclei: one template only
        template_id = check_id.split(":", 1)[1] if check_id.startswith("nuclei:") else check_id.split(":", 1)[1]
        state.only_template = template_id
        result = await engines.run_engine(engine_nuclei.NucleiEngine(), ctx, state, guard)
    if _found(result, fingerprint):
        _outcome(state, "present", "It is still found.")
    elif result.state == "ok":
        # The site must still answer on the port the finding is about, otherwise "not found" would only mean "not reachable".
        port = target["finding_port"]
        if port and port not in [p.port for p in state.probes if p.service or p.http or p.tls]:
            _outcome(state, "could_not_check", "The service did not answer, so this could not be checked.")
        else:
            _outcome(state, "absent", "It is no longer found.")
    else:
        _outcome(state, "could_not_check", (result.detail or {}).get("reason") or "The check could not finish.")
