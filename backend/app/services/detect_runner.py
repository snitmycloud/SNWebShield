"""Runs the DETECT steps of one scan against the ONE pinned IP, in order, saving results as it goes:

  1. ports        2. versions        3. technologies        4. exposed files        5. DNS / email        6. subdomains

Every step records a state: ok | could_not_check | not_applicable | skipped | stopped. A step that fails or times
out is "could not check", never "clean". Results found so far are saved when a step finishes AND when it is stopped, so
a scan that must stop keeps its partial results (the scan itself is then marked incomplete with the reason).
The guard is checked before every step and inside every step's loop; the watcher also cancels the running step.
"""
import asyncio
import time
from dataclasses import dataclass, field

from app.core.config import settings
from app.data.ports import SERVICE_NAMES, ports_for
from app.services import detect_dns, detect_exposed, detect_ports, detect_subdomains, detect_tech, detect_versions
from app.services.scan_guard import ScanStopped

STEP_LABELS = {
    "ports": "Scanning ports",
    "versions": "Identifying services and versions",
    "technologies": "Detecting technologies",
    "exposed": "Checking for exposed files",
    "dns": "Checking email and DNS security",
    "subdomains": "Looking up subdomains",
}
STEP_NAMES = {
    "ports": "Open ports", "versions": "Service versions", "technologies": "Technologies",
    "exposed": "Exposed files", "dns": "Email and DNS records", "subdomains": "Subdomain list",
}


@dataclass
class ScanContext:
    scan_id: str
    domain: str
    ip: str
    scan_type: str = "standard"
    progress: callable = None          # progress(step, message)
    sessions: callable = None          # SessionLocal
    ports: tuple | None = None         # tests only: scan these ports instead of the fixed lists


@dataclass
class ScanState:
    steps: dict = field(default_factory=dict)
    ports: detect_ports.PortResults = field(default_factory=detect_ports.PortResults)
    probes: list = field(default_factory=list)
    technologies: list = field(default_factory=list)
    observations: dict = field(default_factory=lambda: {"exposed_file": 0, "subdomain": 0})
    current: str | None = None

    def incomplete_steps(self) -> list[str]:
        return [name for name, step in self.steps.items() if step["state"] in ("could_not_check", "stopped")]

    def counts(self) -> dict:
        return {"open_ports": len(self.ports.open), "technologies": len(self.technologies),
                "exposed_files": self.observations["exposed_file"], "subdomains": self.observations["subdomain"]}


# --- Saving ---------------------------------------------------------------------------------------------

def _sessions(ctx):
    if ctx.sessions is None:
        from app.db.session import SessionLocal
        return SessionLocal
    return ctx.sessions


def save_probe(ctx: ScanContext, probe: detect_versions.PortProbe) -> None:
    from app.models.scan import ScanPort
    row = probe.row()
    with _sessions(ctx)() as db:
        existing = db.query(ScanPort).filter_by(scan_id=ctx.scan_id, port=probe.port).one_or_none()
        if existing is None:
            existing = ScanPort(scan_id=ctx.scan_id, port=probe.port, state="open")
            db.add(existing)
        existing.service, existing.product, existing.version = row["service"], row["product"], row["version"]
        existing.banner, existing.details = row["banner"], row["details"]
        db.commit()


def save_open_ports(ctx: ScanContext, ports: list[int]) -> None:
    """Record the open ports straight away, with the port-number name as a guess until the version step knows better."""
    from app.models.scan import ScanPort
    with _sessions(ctx)() as db:
        have = {p for (p,) in db.query(ScanPort.port).filter_by(scan_id=ctx.scan_id)}
        for port in ports:
            if port not in have:
                name = SERVICE_NAMES.get(port)
                db.add(ScanPort(scan_id=ctx.scan_id, port=port, state="open", service=name,
                                details={"service_guess": name is not None, "tls": None, "http": None, "notes": []}))
        db.commit()


def save_technologies(ctx: ScanContext, techs: list[dict]) -> None:
    from app.models.scan import ScanTechnology
    with _sessions(ctx)() as db:
        db.query(ScanTechnology).filter_by(scan_id=ctx.scan_id).delete()
        for item in techs:
            db.add(ScanTechnology(scan_id=ctx.scan_id, name=item["name"], category=item["category"], version=item["version"],
                                  source=item["source"], evidence=item["evidence"], port=item.get("port")))
        db.commit()


def save_observations(ctx: ScanContext, kind: str, rows: list[dict]) -> None:
    from app.models.scan import ScanObservation
    with _sessions(ctx)() as db:
        db.query(ScanObservation).filter_by(scan_id=ctx.scan_id, kind=kind).delete()
        for row in rows:
            db.add(ScanObservation(scan_id=ctx.scan_id, kind=kind, key=row["key"][:253], status=row["status"], data=row.get("data")))
        db.commit()


# --- Steps ------------------------------------------------------------------------------------------------

def _web_endpoint(probes):
    """The one web endpoint used for the exposed-file checks: https on 443, else any https, else http on 80, else any."""
    webs = [p for p in probes if p.http]
    for pick in (lambda p: p.port == 443 and p.http["over_tls"], lambda p: p.http["over_tls"],
                 lambda p: p.port == 80, lambda p: True):
        for probe in webs:
            if pick(probe):
                return probe.port, probe.http["over_tls"]
    return None


async def run(ctx: ScanContext, state: ScanState, guard) -> None:
    ports = tuple(ctx.ports) if ctx.ports else ports_for(ctx.scan_type)
    rules = detect_tech.load_rules()

    async def stage(name: str, work):
        """Run one step: label it, check the guard, and turn a failure into 'could not check'."""
        state.current = name
        guard.check()
        ctx.progress(name, f"{STEP_LABELS[name]}…")
        try:
            return await work()
        except (ScanStopped, asyncio.CancelledError):
            state.steps[name] = {"state": "stopped"}
            raise
        except Exception:
            state.steps[name] = {"state": "could_not_check", "reason": "unexpected_error"}
            return None

    # 1. ports
    last_text = [0.0]

    def port_progress(results):
        if time.monotonic() - last_text[0] >= 1.0:
            last_text[0] = time.monotonic()
            ctx.progress("ports", f"Scanning ports… {results.done} / {results.total}")

    async def ports_step():
        try:
            await detect_ports.scan_ports(ctx.ip, ports, state.ports, guard=guard, progress=port_progress)
        finally:
            if state.ports.open:
                save_open_ports(ctx, state.ports.open)  # kept even if the step is stopped
        state.steps["ports"] = ({"state": "could_not_check", "reason": "too_many_connection_errors", **state.ports.summary()}
                                if state.ports.could_not_check else {"state": "ok", **state.ports.summary()})

    await stage("ports", ports_step)
    ports_ok = state.steps.get("ports", {}).get("state") == "ok"

    # 2. versions (needs the open ports)
    async def versions_step():
        await detect_versions.probe_ports(ctx.ip, state.ports.open, ctx.domain,
                                          store=lambda probe: (state.probes.append(probe), save_probe(ctx, probe)), guard=guard)
        state.steps["versions"] = {"state": "ok", "probed": len(state.probes)}

    if not ports_ok:
        state.steps["versions"] = {"state": "skipped", "reason": "ports_not_checked"}
    elif not state.ports.open:
        state.steps["versions"] = {"state": "not_applicable", "reason": "no_open_ports"}
    else:
        await stage("versions", versions_step)
        if state.steps.get("versions", {}).get("state") != "ok" and state.probes:
            state.steps["versions"]["probed"] = len(state.probes)

    # 3. technologies (from the pages already fetched, plus a few known files)
    pages = [p.web for p in state.probes if p.web]

    async def tech_step():
        if not pages:
            state.steps["technologies"] = {"state": "not_applicable", "reason": "no_web_page"}
            return
        found_all = [detect_tech.detect(rules, page, port=page.port) for page in pages]
        endpoint = _web_endpoint(state.probes)
        wanted = detect_tech.file_paths_needed(rules, {item["name"] for items in found_all for item in items if item["version"]})
        if wanted and endpoint:
            fetch = detect_exposed.make_fetcher(ctx.ip, endpoint[0], endpoint[1], ctx.domain, timeout=settings.scan_http_request_timeout_seconds)
            files = {}
            for path in wanted:
                guard.check()
                response = await fetch(path)
                if response is not None and response.status == 200:
                    files[path] = response.body.decode("utf-8", "replace")
            if files:
                found_all = [detect_tech.detect(rules, page, files=files, port=page.port) for page in pages]
        state.technologies = detect_tech.merge(*found_all)
        save_technologies(ctx, state.technologies)
        state.steps["technologies"] = {"state": "ok", "found": len(state.technologies), "rules_skipped": rules.skipped}

    if not ports_ok:
        state.steps["technologies"] = {"state": "skipped", "reason": "ports_not_checked"}
    else:
        await stage("technologies", tech_step)

    # 4. exposed files
    async def exposed_step():
        endpoint = _web_endpoint(state.probes)
        if endpoint is None:
            state.steps["exposed"] = {"state": "not_applicable", "reason": "no_web_server"}
            return
        fetch = detect_exposed.make_fetcher(ctx.ip, endpoint[0], endpoint[1], ctx.domain, timeout=settings.scan_http_request_timeout_seconds)
        result = await detect_exposed.check_exposed(fetch, guard=guard)
        save_observations(ctx, "exposed_file", result.observations)
        state.observations["exposed_file"] = len(result.observations)
        state.steps["exposed"] = ({"state": "could_not_check", "reason": "some_requests_failed"}
                                  if result.failed else {"state": "ok"})
        state.steps["exposed"].update(checked=result.checked, failed=result.failed, exposed=len(result.observations))

    if not ports_ok:
        state.steps["exposed"] = {"state": "skipped", "reason": "ports_not_checked"}
    else:
        await stage("exposed", exposed_step)

    # 5. DNS / email
    async def dns_step():
        rows = await detect_dns.check_dns(ctx.domain, guard=guard)
        save_observations(ctx, "dns", rows)
        unchecked = [r["key"] for r in rows if r["status"] == "could_not_check"]
        state.steps["dns"] = ({"state": "could_not_check", "unchecked": unchecked} if unchecked else {"state": "ok"})

    await stage("dns", dns_step)

    # 6. subdomains (list only)
    async def subdomains_step():
        result = await detect_subdomains.list_subdomains(ctx.domain)
        if result["status"] == "listed":
            save_observations(ctx, "subdomain", [{"key": n, "status": "listed", "data": None} for n in result["names"]])
            state.observations["subdomain"] = len(result["names"])
            state.steps["subdomains"] = {"state": "ok", "found": len(result["names"])}
        else:
            state.steps["subdomains"] = {"state": "could_not_check", "reason": result.get("reason")}

    await stage("subdomains", subdomains_step)
    state.current = None
