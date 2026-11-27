"""Worker health for the admin page: is each role running, judged by the SERVER clock from heartbeats (never the browser's).

Roles under the supervisor: `scan-worker` and `monitor` (heartbeats), `supervisor` itself (heartbeat with each role's process id and
restart count), `api` (this process answers, so it is running) and `web` (the supervisor reports it and the port is probed).
"""
import socket

from sqlalchemy import select

from app.core.time import as_utc, utc_now
from app.models.jobs import WorkerHeartbeat

STALE_SECONDS = 45

ROLES = (
    ("api", "API", "The service this page talks to."),
    ("web", "Web app", "The pages you are looking at."),
    ("scan-worker", "Scan worker", "Runs scans and re-checks."),
    ("monitor", "Monitor", "Scheduled scans, uptime checks, certificate checks and alerts."),
    ("supervisor", "Supervisor", "Starts the roles above at boot and restarts any that stop."),
)


def _port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def status(db, now=None, web_port: int = 5173) -> dict:
    now = now or utc_now()
    beats = {h.name: h for h in db.scalars(select(WorkerHeartbeat))}
    sup = beats.get("supervisor")
    sup_detail = ((sup.detail or {}).get("roles") or {}) if sup else {}
    sup_age = None if sup is None else max(0, int((now - as_utc(sup.seen_at)).total_seconds()))
    rows = []
    for key, label, text in ROLES:
        row = {"role": key, "label": label, "text": text, "state": "not_started", "age_seconds": None, "restarts": None, "pid": None}
        if key == "api":
            row["state"] = "running"
        elif key == "web":
            row["state"] = "running" if _port_open(web_port) else "not_running"
        else:
            beat = beats.get(key if key != "monitor" else "monitor")
            if beat is not None:
                age = max(0, int((now - as_utc(beat.seen_at)).total_seconds()))
                row.update(age_seconds=age, state="running" if age <= STALE_SECONDS else "stale")
        info = sup_detail.get(key) or {}
        if info:
            row.update(restarts=info.get("restarts"), pid=info.get("pid"), started_at=info.get("started_at"), last_exit_code=info.get("last_exit_code"))
            if key in ("api", "web") and info.get("state") not in (None, "running"):
                row["state"] = info.get("state")
        rows.append(row)
    sup_row = next(r for r in rows if r["role"] == "supervisor")
    sup_row.update(age_seconds=sup_age, state="not_started" if sup is None else "running" if sup_age <= STALE_SECONDS else "stale")
    healthy = all(r["state"] == "running" for r in rows)
    return {"as_of": now.isoformat(), "healthy": healthy, "stale_after_seconds": STALE_SECONDS, "roles": rows}
