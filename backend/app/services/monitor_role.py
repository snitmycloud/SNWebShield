"""The `monitor` role: scheduled scans, uptime checks, certificate checks and alert sweeps, in one small process.

Each job type runs on its own timer and is isolated: a failing job type is counted and the others carry on (spec: "a failing job type
must not stop the others"). The role writes its own heartbeat (name `monitor`), shown on the admin page.
"""
import time

from app.db.session import SessionLocal
from app.services import alerts, finding_states, scheduling, uptime
from app.services import job_engine as engine

NAME = "monitor"


def _expire(db):
    finding_states.expire_due(db)
    db.commit()


def _sweeps(db):
    alerts.sweep_verification_lost(db)
    alerts.sweep_risk_expiring(db)
    db.commit()


# (name, seconds between runs, function(db))
JOBS = (
    ("uptime", 15, lambda db: uptime.tick(db)),
    ("scheduled_scans", 60, lambda db: scheduling.run_due(db)),
    ("accepted_risk_expiry", 60, _expire),
    ("alert_sweeps", 300, _sweeps),
)


class Monitor:
    def __init__(self, jobs=JOBS, clock=time.monotonic):
        self.jobs, self.clock = jobs, clock
        self.next_run = {name: 0.0 for name, _, _ in jobs}
        self.failures = {name: 0 for name, _, _ in jobs}
        self.runs = {name: 0 for name, _, _ in jobs}

    def tick(self) -> dict:
        ran = {}
        try:
            with SessionLocal() as db:
                engine.heartbeat(db, NAME)
                db.commit()
        except Exception:
            pass
        for name, every, function in self.jobs:
            if self.clock() < self.next_run[name]:
                continue
            self.next_run[name] = self.clock() + every
            try:
                with SessionLocal() as db:
                    ran[name] = function(db)
                self.runs[name] += 1
            except Exception:   # never print details; the other job types carry on
                self.failures[name] += 1
                ran[name] = "failed"
        return ran
