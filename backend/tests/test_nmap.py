"""Fixed Nmap profile: synthetic permission/SSH fixtures; no real target scanning."""
import importlib.util
import json
from pathlib import Path
import re
from types import ModuleType
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.db.session import SessionLocal
from app.models import WebsiteAuthorization
from app.models.assessment import AssessmentReport
from app.models.jobs import Job, ExecutionEvent
from app.services import assessments as service, job_engine, nmap_runtime as runtime, nmap_policy as policy
from app.services import nmap_broker
from test_authorization_correctness import api, NOW, APPROVAL, seed_record
from evidence_helpers import attach_review

IMAGE = "sha256:" + "b" * 64


@pytest.fixture
def nmap_job(api, monkeypatch):
    monkeypatch.setattr(service, "utc_now", lambda: NOW)
    monkeypatch.setattr(job_engine, "utc_now", lambda: NOW)
    monkeypatch.setattr(settings, "assessment_nmap_enabled", True)
    monkeypatch.setattr(settings, "assessment_nmap_image_id", IMAGE)
    auth, site = seed_record()
    with SessionLocal() as db:
        record = db.get(WebsiteAuthorization, auth)
        record.permitted_methods = ["automated_non_intrusive_scanning", "tcp_port_discovery"]
        record.authorized_domains = [*record.authorized_domains, "8.8.8.8"]
        host = next(value for value in record.authorized_domains if value != "8.8.8.8")
        db.commit()
    attach_review(api, auth)
    assert api.post(f"/api/v1/authorizations/{auth}/approve", json=APPROVAL).status_code == 200
    body = {"website_id": site, "authorization_id": auth, "profile_id": service.NMAP_PROFILE_ID,
            "explicitly_requested": True, "network_permission_confirmed": True,
            "note": "Explicit synthetic approval for the two-port TCP discovery profile.", "idempotency_key": str(uuid4())}
    return api, auth, body, host


def simulated(monkeypatch, host):
    calls = []
    def invoke(script, payload, permitted, seconds):
        assert script == "nmap_broker.py" and permitted()
        calls.append("DNS")
        return {"result": {"host": host, "ip": "8.8.8.8", "dns_addresses": ["8.8.8.8"]}}
    def exchange(operation, payload, permitted, seconds):
        assert permitted()
        calls.append(operation)
        if operation == "check": return {"runner": policy.VERSION, "image_id": IMAGE, "ports": [80, 443]}
        if operation == "cleanup": return {"cleanup_confirmed": True}
        assert set(payload) == {"id", "target"}
        policy.target(payload["target"])
        states = {"80": "open", "443": "closed"}
        return {"states": states, "analysis": policy.analysis(states), "execution": {
            "id": payload["id"], "image_id": IMAGE, "cleanup_confirmed": True, "limits": policy.LIMITS,
            "egress_ip": payload["target"]["ip"], "egress_tcp_ports": [80, 443], "duration_ms": 100,
            "container_duration_ms": 80, "scanner_cpu_seconds": .01, "scanner_peak_rss_bytes": 16000000,
            "scanner_duration_ms": 60}}
    monkeypatch.setattr(runtime, "invoke", invoke)
    monkeypatch.setattr(runtime, "exchange", exchange)
    return calls, exchange


def create(fixture):
    api, _, body, _ = fixture
    result = api.post("/api/v1/assessments", json=body)
    assert result.status_code == 201, result.text
    return result.json()


def test_fixed_profile_worker_report_review_and_findings(nmap_job, monkeypatch):
    api, _, _, host = nmap_job
    calls, _ = simulated(monkeypatch, host)
    row = create(nmap_job); service.worker_tick()
    detail = api.get(f"/api/v1/assessments/{row['id']}").json()
    assert detail["job"]["status"] == "completed", detail
    assert calls == ["check", "DNS", "run"]
    report = api.get(f"/api/v1/assessments/{row['id']}/report/download").json()
    assert report["analysis"]["observations"][0]["port_state"] == "open"
    assert report["analysis"]["confirmed_findings"] == 0
    assert report["execution"]["cleanup_confirmed"]
    review = {"expected_revision": 0, "human_validation_confirmed": True, "disposition": "confirmed",
        "severity": "low", "notes": "Synthetic analyst validated an unexpected port exposure in this lab.",
        "supporting_evidence": "Synthetic expected-exposure configuration and TCP scan were inspected.",
        "recommendation": "Review the approved exposure policy and close an unnecessary listener.",
        "owner": "Synthetic infrastructure owner", "remediation_status": "open"}
    assert api.post(f"/api/v1/assessments/{row['id']}/reviews/tcp_port_80", json=review).status_code == 201
    assert api.get("/api/v1/findings").json()["summary"]["total"] == 1
    dismissed = {**review, "disposition": "not_applicable", "severity": "informational",
        "recommendation": "", "owner": "", "remediation_status": "not_applicable"}
    assert api.post(f"/api/v1/assessments/{row['id']}/reviews/tcp_port_443", json=dismissed).status_code == 201
    exported = api.post(f"/api/v1/assessments/{row['id']}/reviewed-reports")
    assert exported.status_code == 201, exported.text
    snapshot = api.get(f"/api/v1/assessments/{row['id']}/reviewed-reports/{exported.json()['id']}/download").json()
    assert snapshot["report_type"] == "analyst_reviewed_tcp_port_assessment"
    assert snapshot["summary"]["reviewed"] == 2 and snapshot["summary"]["analyst_confirmed"] == 1


@pytest.mark.parametrize("change", ["method", "ip_scope", "private_scope", "disabled", "consent", "expired"])
def test_nmap_permission_denials(nmap_job, monkeypatch, change):
    api, auth, body, host = nmap_job
    if change == "disabled": monkeypatch.setattr(settings, "assessment_nmap_enabled", False)
    elif change == "consent": body = {**body, "network_permission_confirmed": False}
    else:
        with SessionLocal() as db:
            record = db.get(WebsiteAuthorization, auth)
            if change == "method": record.permitted_methods = ["automated_non_intrusive_scanning"]
            elif change == "ip_scope": record.authorized_domains = [host]
            elif change == "private_scope": record.authorized_domains = [host, "10.0.0.1"]
            elif change == "expired": record.valid_until = NOW
            db.commit()
    monkeypatch.setattr(runtime, "exchange", lambda *a: pytest.fail("Unexpected SSH"))
    assert api.post("/api/v1/assessments", json=body).status_code == 409


def test_dns_rotation_outside_approved_ip_does_not_scan(nmap_job, monkeypatch):
    api, _, _, host = nmap_job
    _, original = simulated(monkeypatch, host)
    monkeypatch.setattr(runtime, "invoke", lambda *a: {"result": {"host": host, "ip": "1.1.1.1", "dns_addresses": ["1.1.1.1"]}})
    def exchange(operation, *args):
        assert operation == "check", "Must never launch a scan for an unapproved IP"
        return original(operation, *args)
    monkeypatch.setattr(runtime, "exchange", exchange)
    row = create(nmap_job); service.worker_tick()
    detail = api.get(f"/api/v1/assessments/{row['id']}").json()
    assert detail["job"]["status"] == "failed"
    assert detail["result"]["payload"]["error"] == "resolved_ip_not_explicitly_authorized"


@pytest.mark.parametrize("failure", ["timeout", "wrong_ports", "wrong_states", "no_cleanup", "cancel"])
def test_failures_and_cancellation_cleanup_without_report(nmap_job, monkeypatch, failure):
    api, _, _, host = nmap_job
    calls, original = simulated(monkeypatch, host)
    row = create(nmap_job)
    def exchange(operation, *args):
        if operation != "run": return original(operation, *args)
        if failure == "timeout": raise runtime.RuntimeFailure("adapter_deadline_exceeded")
        if failure == "cancel":
            assert api.post(f"/api/v1/assessments/{row['id']}/cancel", json={"reason": "Cancel synthetic TCP assessment."}).status_code == 200
            raise runtime.RuntimeFailure("permission_changed")
        result = original(operation, *args)
        if failure == "wrong_ports": result["execution"]["egress_tcp_ports"] = [22, 80, 443]
        elif failure == "wrong_states": result["states"] = {"22": "open"}
        else: result["execution"]["cleanup_confirmed"] = False
        return result
    monkeypatch.setattr(runtime, "exchange", exchange)
    service.worker_tick()
    assert calls[-1] == "cleanup"
    with SessionLocal() as db:
        assert db.get(Job, row["job_id"]).status == ("cancelled" if failure == "cancel" else "failed")
        assert db.scalar(select(AssessmentReport)) is None
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "remote_docker_execution_finished"))


def test_pin_change_cancels_queued_job(nmap_job, monkeypatch):
    row = create(nmap_job)
    monkeypatch.setattr(settings, "assessment_nmap_image_id", "sha256:" + "c" * 64)
    monkeypatch.setattr(runtime, "exchange", lambda *a: pytest.fail("Unexpected SSH"))
    service.worker_tick()
    with SessionLocal() as db: assert db.get(Job, row["job_id"]).status == "cancelled"


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.0.0.9", "192.88.99.1", "::1", "8.8.8.8;echo", "224.0.0.1"])
def test_only_canonical_public_ipv4(ip):
    with pytest.raises(ValueError): policy.public_ipv4(ip)


def test_fixed_command_and_result_parser():
    args = policy.command("8.8.8.8")
    assert args[-1] == "8.8.8.8" and args[args.index("-p") + 1] == "80,443"
    assert "-sT" in args and "--unprivileged" in args and "-Pn" in args and "-n" in args
    assert not {"-sV", "-A", "-sS", "-O", "-sU", "--script"}.intersection(args)
    xml = b'<nmaprun><host><address addr="8.8.8.8" addrtype="ipv4"/><ports><extraports state="closed" count="1"/><port protocol="tcp" portid="80"><state state="open"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
    assert policy.parse_result(xml, "8.8.8.8") == {"80": "open", "443": "closed"}
    with pytest.raises(ValueError): policy.parse_result(xml.replace(b'portid="80"', b'portid="22"'), "8.8.8.8")
    with pytest.raises(ValueError): policy.parse_result(xml, "1.1.1.1")
    with pytest.raises(ValueError): policy.parse_result(xml.replace(b'count="1"', b'count="2"'), "8.8.8.8")


def test_broker_rejects_loopback_without_connecting():
    with pytest.raises(Exception): nmap_broker.resolve("http://127.0.0.1", lambda: True)


def test_scanner_and_guard_configuration_separate_capabilities():
    root = Path(__file__).resolve().parents[2]
    path = root / "scanner/nmap/runner.py"
    source = path.read_text().replace('"/usr/local/libexec/snwebshield-header-runner"', repr(str(root / "scanner/remote_runner.py")))
    source = source.replace('"/usr/local/lib/snwebshield/nmap_policy.py"', repr(str(root / "backend/app/services/nmap_policy.py")))
    module = ModuleType("nmap_runner_test"); exec(compile(source, str(path), "exec"), module.__dict__)
    scan = module.create_args("a" * 32, IMAGE, guard=False)
    guard = module.create_args("a" * 32, IMAGE, guard=True)
    assert "--user=65532:65532" in scan and "--cap-drop=ALL" in scan and "--read-only" in scan
    assert not any("NET_ADMIN" in a or "privileged" in a for a in scan)
    assert any(a.startswith("--network=container:snws-nmap-") for a in scan)
    assert "--cap-add=NET_ADMIN" in guard and "--network=bridge" in guard
    assert not any(a.startswith(("--network=host", "--mount", "--volume", "--publish")) for a in scan + guard)
    with pytest.raises(Exception): module.names("x;arbitrary-command")
