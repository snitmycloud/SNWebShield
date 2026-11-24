"""Read-only report of scanner containers left on the VM (risk R6).

Asks each fixed runner for its label-scoped inventory over the existing SSH transport. It never
removes, stops or prunes anything and never lists containers that do not carry a SNWebShield label.
Removal is a manual decision: the runner's `--cleanup <id>` removes only a container whose label and
image match, and nothing here calls it.
"""
from datetime import datetime
import re

from app.core.config import settings
from app.core.time import as_utc, utc_now
from app.services import job_engine as engine
from app.services import nmap_runtime, remote_assessment_runtime as remote

# The longest legitimate container lives about 35 s (guard alarm), so anything older than this is stuck.
ORPHAN_AFTER_SECONDS = 120
NAME = re.compile(r"snws-[a-z0-9-]{1,70}")


def _sources():
    return (
        ("header analysis", settings.assessment_remote_docker_enabled, remote.ssh_exchange, remote.RUNNER),
        ("nmap", settings.assessment_nmap_enabled, nmap_runtime.exchange, nmap_runtime.RUNNER),
    )


def _age(created, now):
    try:
        return max(0, int((now - as_utc(datetime.fromisoformat(created.replace("Z", "+00:00")[:32]))).total_seconds()))
    except (ValueError, TypeError, AttributeError):
        return None  # unparseable: treated as stuck rather than hidden


def classify(item, now):
    age = _age(item.get("created_at"), now)
    name = item.get("name")
    clean = {"name": name if isinstance(name, str) and NAME.fullmatch(name) else "(unrecognised name)",
             "id": item.get("id") if re.fullmatch(r"[0-9a-f]{12}", str(item.get("id"))) else None,
             "token": item.get("token") if re.fullmatch(r"[0-9a-f]{32}", str(item.get("token"))) else None,
             "role": item.get("role") if item.get("role") in ("scan", "guard", "analysis") else None,
             "state": str(item.get("state"))[:20], "age_seconds": age}
    clean["status"] = "recent" if age is not None and age <= ORPHAN_AFTER_SECONDS else "orphaned"
    return clean


def collect(db, actor_id, *, now=None):
    now = now or utc_now()
    sections, total = [], 0
    for label, enabled, exchange, runner in _sources():
        section = {"scanner": label, "status": "disabled", "containers": [], "error": None, "truncated": False}
        if enabled:
            try:
                reply = exchange("orphans", None, lambda: True, 10)
                items = reply.get("orphans") if isinstance(reply, dict) else None
                if not isinstance(items, list):
                    section.update(status="unsupported", error="This runner version cannot list containers; redeploy the runner.")
                else:
                    section.update(status="ok", containers=[classify(i, now) for i in items[:50] if isinstance(i, dict)],
                                   truncated=reply.get("truncated") is True)
            except Exception as exc:  # unreachable VM, unsupported runner, protocol error: report, never fall back
                code = re.sub(r"[^a-z0-9_]", "", str(exc).lower())[:60] or "unavailable"
                section.update(status="unavailable", error=code)
        total += sum(1 for c in section["containers"] if c["status"] == "orphaned")
        sections.append(section)
    engine.event(db, "orphan_report_generated", actor_id=actor_id,
                 detail={"orphaned": total, "sections": {s["scanner"]: s["status"] for s in sections}})
    db.commit()
    return {"generated_at": now.isoformat(), "orphan_after_seconds": ORPHAN_AFTER_SECONDS, "orphaned_total": total,
            "sections": sections,
            "guidance": "Read-only. Nothing was removed. Review each orphaned container on the VM and remove it manually "
                        "only after you approve; the runner's --cleanup <token> removes just a labelled SNWebShield container."}
