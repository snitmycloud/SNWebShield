"""Port watch (Option A): explicit enablement, scheduled Nmap requests, change detection, fail-closed behaviour.

Synthetic VM and DNS only. No Docker, SSH or target traffic.
"""
import sqlite3
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from app.cli import operations
from app.core.config import settings
from app.db.session import SessionLocal
from app.main import app
from app.models import WebsiteAuthorization
from app.models.assessment import AssessmentRequest
from app.models.jobs import ExecutionEvent, Job
from app.models.monitoring import NotificationDelivery
from app.models.port_watch import PortWatch, PortWatchChange
from app.services import assessments as service, job_engine as engine, nmap_policy as policy, nmap_runtime as runtime
from app.services import port_watch as pw
from test_authorization_correctness import NOW, api  # noqa: F401 - fixture
from test_migrations import migrate
from test_nmap import IMAGE, nmap_job  # noqa: F401 - fixture
from test_production_hardening import login, make_user

PW = "/api/v1/port-watch"
HOUR = 3600


class Vm:
    """Synthetic VM and DNS broker whose port states the test controls; records every call it receives."""
    def __init__(self, monkeypatch, host):
        self.states, self.calls, self.fail = {"80": "open", "443": "closed"}, [], None
        def invoke(script, payload, permitted, seconds):
            assert script == "nmap_broker.py" and permitted()
            self.calls.append("DNS")
            return {"result": {"host": host, "ip": "8.8.8.8", "dns_addresses": ["8.8.8.8"]}}
        def exchange(operation, payload, permitted, seconds):
            assert permitted()
            self.calls.append(operation)
            if operation == "check": return {"runner": policy.VERSION, "image_id": IMAGE, "ports": [80, 443]}
            if operation == "cleanup": return {"cleanup_confirmed": True}
            if self.fail: raise runtime.RemoteFailure(self.fail)
            states = dict(self.states)
            return {"states": states, "analysis": policy.analysis(states), "execution": {
                "id": payload["id"], "image_id": IMAGE, "cleanup_confirmed": True, "limits": policy.LIMITS,
                "egress_ip": payload["target"]["ip"], "egress_tcp_ports": [80, 443], "duration_ms": 100,
                "container_duration_ms": 80, "scanner_cpu_seconds": .01, "scanner_peak_rss_bytes": 16000000,
                "scanner_duration_ms": 60}}
        monkeypatch.setattr(runtime, "invoke", invoke)
        monkeypatch.setattr(runtime, "exchange", exchange)

    def scans(self): return self.calls.count("run")


@pytest.fixture
def watch(nmap_job, monkeypatch):
    api, auth, body, host = nmap_job
    with SessionLocal() as db:  # the seeded window is two hours; port watch needs it to outlast several runs
        db.get(WebsiteAuthorization, auth).valid_until = NOW + timedelta(days=30); db.commit()
    vm = Vm(monkeypatch, host)
    box = SimpleNamespaceLike(api=api, auth=auth, site=body["website_id"], vm=vm, mp=monkeypatch, now=NOW)
    clock(box, 0)
    return box


class SimpleNamespaceLike:
    def __init__(self, **kw): self.__dict__.update(kw)


def clock(box, seconds):
    box.now = NOW + timedelta(seconds=seconds)
    for module in (service, engine, pw):
        box.mp.setattr(module, "utc_now", lambda moment=box.now: moment)


def enable(box, headers=None, **changes):
    body = {"interval_seconds": HOUR, "network_permission_confirmed": True, "human_validation_confirmed": True} | changes
    return box.api.post(f"{PW}/{box.site}/enable", json=body, headers=headers or {})


def tick(box):
    """One scheduler pass, then one assessment-worker pass, at the current simulated time."""
    with SessionLocal() as db:
        pw.schedule(db, box.now)
    service.worker_tick()


def state(box):
    response = box.api.get(f"{PW}/{box.site}")
    assert response.status_code == 200, response.text
    return response.json()


def events(action):
    with SessionLocal() as db:
        return list(db.scalars(select(ExecutionEvent).where(ExecutionEvent.action == action)))


def count(model):
    with SessionLocal() as db:
        return db.scalar(select(func.count()).select_from(model))


def other_user(box, role):
    email, admin_id = make_user(role)
    return {"Authorization": "Bearer " + login(box.api, email).json()["access_token"]}, admin_id


# --- Pure helpers ---------------------------------------------------------------------------------------

def report(**ports):
    states = {"80": "open", "443": "closed"} | ports
    return {"analysis": policy.analysis(states)}


def test_states_are_read_only_from_a_well_formed_report():
    assert pw.states_of(report(**{"443": "filtered"})) == {"80": "open", "443": "filtered"}
    for bad in (None, {}, {"analysis": None}, {"analysis": {"observations": []}},
                {"analysis": {"observations": [{"check": "tcp_port_80", "port_state": "open"}]}},
                {"analysis": {"observations": [{"check": "tcp_port_80", "port_state": "open"}, {"check": "tcp_port_443", "port_state": "<x>"}]}},
                {"analysis": {"observations": [{"check": "tcp_port_80"}, {"check": "tcp_port_443"}]}}):
        assert pw.states_of(bad) is None, bad


def test_diff_reports_only_real_changes():
    assert pw.diff({"80": "open", "443": "closed"}, {"80": "open", "443": "closed"}) == []
    assert pw.diff({"80": "open", "443": "closed"}, {"80": "closed", "443": "open"}) == [
        {"port": "80", "from": "open", "to": "closed"}, {"port": "443", "from": "closed", "to": "open"}]
    assert pw.diff({}, {"80": "open", "443": "open"})[0]["from"] is None


# --- Enabling is explicit and permission-gated ---------------------------------------------------------

def test_enabling_scans_nothing_by_itself(watch):
    response = enable(watch)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["enabled"] is True and body["state"] == "active" and body["interval_seconds"] == HOUR
    assert count(AssessmentRequest) == 0 and count(Job) == 0 and watch.vm.calls == []  # no request, no DNS, no VM
    assert events("port_watch_enabled")[0].actor_id is not None


def test_registration_and_approval_alone_never_create_a_watch_or_a_scan(watch):
    with SessionLocal() as db:
        pw.schedule(db, watch.now)
    assert count(PortWatch) == 0 and count(AssessmentRequest) == 0 and watch.vm.calls == []
    assert state(watch)["configured"] is False and state(watch)["can_enable"] is True


@pytest.mark.parametrize("mutation,expected", [
    (lambda r: setattr(r, "permitted_methods", ["automated_non_intrusive_scanning"]), "does not permit the methods"),
    (lambda r: setattr(r, "status", "revoked"), "no approved authorisation"),
    (lambda r: setattr(r, "valid_until", NOW), "expired or not yet valid"),
    (lambda r: setattr(r, "authorized_domains", [d for d in r.authorized_domains if d != "8.8.8.8"]), "public IPv4"),
    (lambda r: setattr(r, "authorized_domains", ["other.example.com"]), "exact domain"),
])
def test_cannot_enable_without_real_nmap_permission_and_the_reason_is_exact(watch, mutation, expected):
    with SessionLocal() as db:
        mutation(db.get(WebsiteAuthorization, watch.auth)); db.commit()
    response = enable(watch)
    assert response.status_code == 409 and expected in response.text, response.text
    assert count(PortWatch) == 0 and state(watch)["can_enable"] is False and expected in state(watch)["cannot_enable_reason"]


def test_cannot_enable_when_the_nmap_profile_is_disabled(watch, monkeypatch):
    monkeypatch.setattr(settings, "assessment_nmap_enabled", False)
    response = enable(watch)
    assert response.status_code == 409 and "disabled" in response.text and count(PortWatch) == 0


@pytest.mark.parametrize("bad", [dict(interval_seconds=60), dict(interval_seconds=3599), dict(interval_seconds=604801),
                                 dict(interval_seconds="3600"), dict(interval_seconds=3600.5), dict(network_permission_confirmed=False),
                                 dict(human_validation_confirmed=False), dict(unexpected=1)])
def test_invalid_enable_requests_are_rejected_without_writes(watch, bad):
    assert enable(watch, **bad).status_code == 422
    assert count(PortWatch) == 0 and events("port_watch_enabled") == []


def test_roles_unknown_websites_and_missing_login(watch):
    analyst, _ = other_user(watch, "analyst")
    assert enable(watch, headers=analyst).status_code == 403
    assert watch.api.post(f"{PW}/{watch.site}/disable", json={"reason": "No longer needed."}, headers=analyst).status_code == 403
    assert watch.api.get(f"{PW}/{watch.site}", headers=analyst).status_code == 200  # reading is open
    lead, _ = other_user(watch, "lead_analyst")
    assert enable(watch, headers=lead).status_code == 200
    assert watch.api.get(f"{PW}/999999").status_code == 404
    assert watch.api.get(f"{PW}/0").status_code == 422
    anonymous = TestClient(app)
    assert anonymous.get(f"{PW}/{watch.site}").status_code == 401
    assert anonymous.post(f"{PW}/{watch.site}/enable", json={}).status_code == 401


# --- Scheduling goes through the ordinary assessment path ---------------------------------------------------

def test_a_due_watch_queues_one_ordinary_nmap_assessment_and_waits_for_the_next_slot(watch):
    assert enable(watch).status_code == 200
    with SessionLocal() as db:
        pw.schedule(db, watch.now)
        pw.schedule(db, watch.now)  # same instant: the slot is already taken
    with SessionLocal() as db:
        rows = list(db.scalars(select(AssessmentRequest)))
        assert len(rows) == 1 and rows[0].profile_id == service.NMAP_PROFILE_ID and rows[0].authorization_id == watch.auth
        assert rows[0].execution_snapshot["network_permission_confirmed"] is True
        assert rows[0].requested_by == db.get(PortWatch, watch.site).enabled_by
        assert db.get(Job, rows[0].job_id).status == "queued" and db.get(Job, rows[0].job_id).max_attempts == 1
        record = db.get(PortWatch, watch.site)
        assert as_aware(record.next_due) == watch.now + timedelta(seconds=HOUR) and record.last_assessment_id == rows[0].id
    assert watch.vm.calls == []  # scheduling itself never touches the network
    clock(watch, HOUR // 2)
    with SessionLocal() as db:
        pw.schedule(db, watch.now)
    assert count(AssessmentRequest) == 1  # not due yet


def as_aware(value):
    from app.core.time import as_utc
    return as_utc(value)


def test_the_slot_key_is_stable_so_a_retry_after_a_crash_cannot_double_scan(watch):
    enable(watch)
    with SessionLocal() as db:
        due = as_aware(db.get(PortWatch, watch.site).next_due).isoformat()
        pw.schedule(db, watch.now)
        key = f"assessment:{db.get(PortWatch, watch.site).enabled_by}:portwatch:{watch.site}:1:{due}"
        assert db.scalar(select(Job.id).where(Job.idempotency_key == key)) is not None
        # Simulate a crash after the request was queued but before the watch row was advanced.
        record = db.get(PortWatch, watch.site)
        record.next_due = as_aware(db.scalar(select(Job.due_at)))  # not used: put the slot back
        from app.core.time import as_utc
        record.next_due = watch.now; db.commit()
        pw._request(db, db.get(PortWatch, watch.site), watch.now)
    assert count(AssessmentRequest) == 1 and count(Job) == 1


def test_full_cycle_baseline_unchanged_changed_and_no_repeat_alert(watch):
    enable(watch)
    tick(watch)  # baseline run
    first = state(watch)
    assert first["last_outcome"] == "baseline" and first["baseline"] == {"80": "open", "443": "closed"} and first["changes"] == []
    assert watch.vm.scans() == 1 and count(NotificationDelivery) == 0

    clock(watch, HOUR); tick(watch)  # same state
    assert state(watch)["last_outcome"] == "unchanged" and count(PortWatchChange) == 0

    watch.vm.states["443"] = "open"  # port 443 opens between runs
    clock(watch, 2 * HOUR); tick(watch)
    changed = state(watch)
    assert changed["last_outcome"] == "changed" and changed["baseline"] == {"80": "open", "443": "open"}
    assert changed["changes"][0]["changes"] == [{"port": "443", "from": "closed", "to": "open"}]
    assert changed["changes"][0]["assessment_id"] == changed["last_assessment_id"]
    with SessionLocal() as db:
        delivery = db.scalar(select(NotificationDelivery))
        assert delivery.event == "port_state_changed" and delivery.status == "pending" and delivery.dedupe_key.startswith("port_state_changed:")
    assert events("port_state_changed")[0].detail["changes"][0]["port"] == "443"

    clock(watch, 3 * HOUR); tick(watch)  # still open: already alerted, nothing new
    assert state(watch)["last_outcome"] == "unchanged" and count(PortWatchChange) == 1 and count(NotificationDelivery) == 1

    watch.vm.states.update({"80": "filtered", "443": "closed"})  # both change at once
    clock(watch, 4 * HOUR); tick(watch)
    assert [c["port"] for c in state(watch)["changes"][0]["changes"]] == ["80", "443"] and count(PortWatchChange) == 2
    assert watch.vm.scans() == 5 and watch.vm.calls.count("check") == 5


def test_the_dispatcher_delivers_the_change_notification(watch):
    enable(watch); tick(watch)
    watch.vm.states["80"] = "closed"
    clock(watch, HOUR); tick(watch)
    operations.notification_tick()
    with SessionLocal() as db:
        assert db.scalar(select(NotificationDelivery.status)) == "delivered"


def test_recording_is_idempotent(watch):
    enable(watch); tick(watch)
    watch.vm.states["80"] = "closed"
    clock(watch, HOUR); tick(watch)
    last = state(watch)["last_assessment_id"]
    with SessionLocal() as db:
        assert pw.record_result(db, last) is None and pw.record_result(db, last) is None
    assert count(PortWatchChange) == 1 and count(NotificationDelivery) == 1


def test_worker_death_before_comparison_is_recovered_on_restart(watch, monkeypatch):
    enable(watch); tick(watch)
    watch.vm.states["443"] = "open"
    clock(watch, HOUR)
    monkeypatch.setattr(pw, "record_after_assessment", lambda assessment_id: None)  # the worker dies right here
    tick(watch)
    assert state(watch)["last_outcome"] == "baseline" and count(PortWatchChange) == 0
    pw.reconcile_pending()  # the restarted worker
    assert state(watch)["last_outcome"] == "changed" and count(PortWatchChange) == 1
    pw.reconcile_pending()
    assert count(PortWatchChange) == 1 and count(NotificationDelivery) == 1


# --- Fail closed ---------------------------------------------------------------------------------------------

def test_permission_lost_between_runs_blocks_the_watch_and_scans_nothing(watch):
    enable(watch); tick(watch)
    scans = watch.vm.scans()
    with SessionLocal() as db:
        db.get(WebsiteAuthorization, watch.auth).status = "revoked"; db.commit()
    clock(watch, HOUR); tick(watch)
    blocked = state(watch)
    assert blocked["state"] == "blocked" and "no approved authorisation" in blocked["blocked_reason_text"]
    assert watch.vm.scans() == scans and count(AssessmentRequest) == 1  # nothing new queued, nothing executed
    assert events("port_watch_blocked")[0].detail["reason"] == "no_approved_authorization"
    clock(watch, 2 * HOUR); tick(watch)
    assert len(events("port_watch_blocked")) == 1  # one audit event per change of state, not per tick
    with SessionLocal() as db:  # permission restored: the watch resumes by itself at the next slot
        db.get(WebsiteAuthorization, watch.auth).status = "approved"; db.commit()
    clock(watch, 3 * HOUR); tick(watch)
    resumed = state(watch)
    assert resumed["state"] == "active" and resumed["blocked_reason"] is None and watch.vm.scans() == scans + 1


def test_revocation_after_queueing_stops_the_scan_before_any_probe(watch):
    enable(watch)
    with SessionLocal() as db:
        pw.schedule(db, watch.now)
    with SessionLocal() as db:
        db.get(WebsiteAuthorization, watch.auth).status = "revoked"; db.commit()
    service.worker_tick()  # the worker's own re-check, immediately before execution
    assert watch.vm.calls == []  # no DNS, no preflight, no scan
    with SessionLocal() as db:
        job = db.scalar(select(Job))
        assert job.status == "cancelled"
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "assessment_permission_denied"))
    clock(watch, HOUR); tick(watch)  # settles the dead run as failed and blocks
    assert state(watch)["last_outcome"] == "failed" and state(watch)["state"] == "blocked" and state(watch)["baseline"] is None
    assert events("port_watch_run_failed") and watch.vm.scans() == 0


def test_a_failed_run_keeps_the_last_known_state_and_never_alerts(watch):
    enable(watch); tick(watch)
    watch.vm.fail = "ssh_unreachable"
    clock(watch, HOUR); tick(watch)
    clock(watch, 2 * HOUR); tick(watch)  # settles the failed run
    failed = state(watch)
    assert failed["baseline"] == {"80": "open", "443": "closed"} and count(PortWatchChange) == 0 and count(NotificationDelivery) == 0
    assert events("port_watch_run_failed")
    watch.vm.fail = None; watch.vm.states["443"] = "open"
    clock(watch, 3 * HOUR); tick(watch)
    assert state(watch)["last_outcome"] == "changed"  # compares with the last GOOD state, not with the failure


def test_an_active_assessment_postpones_the_run_instead_of_stacking(watch):
    enable(watch)
    row = watch.api.post("/api/v1/assessments", json={
        "website_id": watch.site, "authorization_id": watch.auth, "profile_id": service.NMAP_PROFILE_ID, "explicitly_requested": True,
        "network_permission_confirmed": True, "note": "Manual port assessment queued before the schedule.", "idempotency_key": "11111111-1111-4111-8111-111111111111"})
    assert row.status_code == 201, row.text
    with SessionLocal() as db:
        pw.schedule(db, watch.now)
        record = db.get(PortWatch, watch.site)
        assert count(AssessmentRequest) == 1 and as_aware(record.next_due) == watch.now + timedelta(seconds=pw.RETRY_SECONDS)


def test_a_deactivated_enabler_cannot_keep_the_watch_running(watch):
    enable(watch)
    with SessionLocal() as db:
        from app.models.admin import Admin
        db.get(Admin, db.get(PortWatch, watch.site).enabled_by).is_active = False; db.commit()
    with SessionLocal() as db:
        pw.schedule(db, watch.now)
    with SessionLocal() as db:
        record = db.get(PortWatch, watch.site)
        assert record.state == "blocked" and record.blocked_reason == "requester_not_active_administrator"
    assert count(AssessmentRequest) == 0 and watch.vm.calls == []


# --- Disable and re-enable ----------------------------------------------------------------------------------

def test_disable_stops_scheduling_and_is_audited(watch):
    enable(watch); tick(watch)
    scans = watch.vm.scans()
    response = watch.api.post(f"{PW}/{watch.site}/disable", json={"reason": "Scanning window ended for this client."})
    assert response.status_code == 200 and response.json()["enabled"] is False and response.json()["state"] == "paused"
    clock(watch, 5 * HOUR); tick(watch)
    assert watch.vm.scans() == scans and count(AssessmentRequest) == 1
    assert events("port_watch_disabled")[0].detail["reason"].startswith("Scanning window")
    assert watch.api.post(f"{PW}/{watch.site}/disable", json={"reason": "Disabling it again."}).status_code == 409
    assert watch.api.post(f"{PW}/{watch.site}/disable", json={"reason": "short"}).status_code == 422


def test_re_enabling_starts_a_fresh_baseline_without_a_false_alarm(watch):
    enable(watch); tick(watch)
    watch.api.post(f"{PW}/{watch.site}/disable", json={"reason": "Pausing during the maintenance window."})
    watch.vm.states["443"] = "open"  # changed while paused
    clock(watch, 5 * HOUR)
    assert enable(watch).status_code == 200
    assert state(watch)["baseline"] is None
    tick(watch)
    assert state(watch)["last_outcome"] == "baseline" and count(PortWatchChange) == 0 and count(NotificationDelivery) == 0


# --- History cannot be rewritten ----------------------------------------------------------------------------

def test_changes_are_append_only_in_the_orm_and_the_database(watch):
    enable(watch); tick(watch)
    watch.vm.states["80"] = "closed"
    clock(watch, HOUR); tick(watch)
    with SessionLocal() as db:
        row = db.scalar(select(PortWatchChange)); row.current = {"80": "open", "443": "closed"}
        with pytest.raises(ValueError, match="append-only"): db.flush()
        db.rollback()
        db.delete(db.scalar(select(PortWatchChange)))
        with pytest.raises(ValueError, match="append-only"): db.flush()
        db.rollback()
    with SessionLocal() as db:
        for statement in ("UPDATE port_watch_changes SET changes = '[]'", "DELETE FROM port_watch_changes"):
            with pytest.raises(DBAPIError, match="append-only"): db.execute(text(statement))
            db.rollback()


def test_the_interval_floor_is_enforced_by_the_database(watch):
    enable(watch)
    with SessionLocal() as db:
        with pytest.raises(DBAPIError):
            db.execute(text("UPDATE port_watches SET interval_seconds = 60")); db.commit()


def test_migration_adds_port_watch_without_enabling_or_touching_data(tmp_path):
    path = tmp_path / "pre-portwatch.db"
    migrate(path, "0014_fix_verification_signoff")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO admins (id,email,full_name,password_hash,role,is_active) VALUES (1,'p@example.com','Test','kept-hash','admin',1)")
        before = db.execute("SELECT * FROM admins").fetchall()
    migrate(path); migrate(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0015_port_watch"
        assert db.execute("SELECT * FROM admins").fetchall() == before
        assert db.execute("SELECT COUNT(*) FROM port_watches").fetchone() == (0,)  # nothing is enabled by upgrading
        names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'port_watch_changes'")}
        assert names == {"trg_port_watch_changes_no_update", "trg_port_watch_changes_no_delete"}


# --- Lifecycle view ------------------------------------------------------------------------------------------

def test_lifecycle_surfaces_port_watch_and_routes_a_change(watch, monkeypatch):
    from app.services import lifecycle
    monkeypatch.setattr(lifecycle, "_monitor", lambda db, website, now: {
        "state": "healthy", "enabled": True, "interval_seconds": 300, "last_checked_at": None, "last_result": "up"})
    view = lambda: watch.api.get(f"/api/v1/websites/{watch.site}/lifecycle").json()
    assert view()["monitor"]["port_watch"] is None
    enable(watch); tick(watch)
    assert view()["monitor"]["port_watch"]["last_outcome"] == "baseline" and view()["next_step"]["code"] != "review_port_change"
    watch.vm.states["443"] = "open"
    clock(watch, HOUR); tick(watch)
    body = view()
    assert body["next_step"]["code"] == "review_port_change" and "443 (closed to open)" in body["next_step"]["message"]
    assert body["monitor"]["port_watch"]["latest_change"]["changes"] == [{"port": "443", "from": "closed", "to": "open"}]
    clock(watch, 2 * HOUR); tick(watch)  # nothing further changed: the alert is not repeated
    assert view()["next_step"]["code"] != "review_port_change"
