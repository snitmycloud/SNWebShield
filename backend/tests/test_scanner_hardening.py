"""Milestone 1 scanner-worker boundaries.

Synthetic SSH/Docker and loopback fixtures only: never contacts Azure or a real target.
"""
import importlib.util
import json
import socket
import sys
import threading
import time
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.core.time import as_utc
from app.db.session import SessionLocal
from app.models.assessment import AssessmentReport
from app.models.authorization import WebsiteAuthorization
from app.models.jobs import ExecutionEvent, Job, JobResult
from app.services import assessments as service, job_engine as engine
from app.services import assessment_broker as broker
from app.services import local_assessment_runtime as local
from app.services import nmap_runtime, remote_assessment_runtime as remote, ssh_transport
from test_authorization_correctness import api, NOW
from test_assessments import assessed
from test_remote_assessment import IMAGE, remote_job, create, simulated

SCANNER = Path(__file__).resolve().parents[2] / "scanner"


def job_state(row):
    with SessionLocal() as db:
        job = db.get(Job, row["job_id"])
        result = db.get(JobResult, row["job_id"])
        return job.status, (result.payload if result else None), db.scalar(select(AssessmentReport))


def forbid_local_execution(monkeypatch):
    """Any attempt to run the HEAD broker or the local analyser is a test failure."""
    monkeypatch.setattr(remote, "invoke", lambda *a: pytest.fail("Target HEAD must not run"))
    monkeypatch.setattr(local, "invoke", lambda *a: pytest.fail("No local fallback is allowed"))
    monkeypatch.setattr(local.ADAPTERS["local-python-v1"], "execute", lambda *a: pytest.fail("No local fallback is allowed"))


# --- SSH transport -------------------------------------------------------------------------

def test_ssh_command_is_fixed_hardened_and_pinned(monkeypatch):
    monkeypatch.setattr(ssh_transport, "ssh_binary", lambda: "/pinned/ssh")
    args = ssh_transport.command(remote.RUNNER, "run")
    expected_options = [x for option in ssh_transport.OPTIONS for x in ("-o", option)]
    assert args == ["/pinned/ssh", "-T", *expected_options, "azureuser@57.159.27.58", remote.RUNNER]
    for option in ("BatchMode=yes", "StrictHostKeyChecking=yes", "ForwardAgent=no", "ClearAllForwardings=yes",
                   "ProxyCommand=none", "ProxyJump=none", "PasswordAuthentication=no", "PermitLocalCommand=no"):
        assert option in ssh_transport.OPTIONS
    assert ssh_transport.command(remote.RUNNER, "check")[-1] == "--check"
    assert ssh_transport.command(nmap_runtime.RUNNER, "cleanup", "c" * 32)[-2:] == ["--cleanup", "c" * 32]


@pytest.mark.parametrize("runner,operation,value", [
    ("/bin/sh", "run", None),
    (remote.RUNNER, "shell", None),
    (remote.RUNNER, "cleanup", "a" * 31),
    (remote.RUNNER, "cleanup", "A" * 32),
    (remote.RUNNER, "cleanup", "a" * 32 + "; reboot"),
    (remote.RUNNER, "cleanup", ["a" * 32]),
])
def test_ssh_command_rejects_unapproved_runner_operation_or_id(monkeypatch, runner, operation, value):
    monkeypatch.setattr(ssh_transport, "ssh_binary", lambda: "/pinned/ssh")
    with pytest.raises(ValueError):
        ssh_transport.command(runner, operation, value)


def test_ssh_binary_is_absolute_os_client_not_path_lookup(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))  # A planted ssh earlier on PATH must be irrelevant.
    (tmp_path / "ssh.exe").write_text("planted")
    (tmp_path / "ssh").write_text("planted")
    try:
        binary = ssh_transport.ssh_binary()
    except ssh_transport.SSHUnavailable:
        return  # Fails closed when the OS client is absent.
    assert Path(binary).is_absolute() and str(tmp_path) not in binary


def test_missing_ssh_client_fails_closed(monkeypatch):
    def missing(): raise ssh_transport.SSHUnavailable("ssh_client_unavailable")
    monkeypatch.setattr(ssh_transport, "ssh_binary", missing)
    with pytest.raises(remote.RemoteFailure, match="ssh_client_unavailable"):
        remote.ssh_exchange("check", None, lambda: True, 1)
    with pytest.raises(remote.RemoteFailure, match="ssh_client_unavailable"):
        nmap_runtime.exchange("check", None, lambda: True, 1)


def test_unreachable_host_real_process_fails_without_result(monkeypatch):
    # A real child that exits like `ssh` does on connection failure (status 255, no output).
    monkeypatch.setattr(ssh_transport, "command",
                        lambda *a: [local.child_executable(), "-I", "-S", "-c", "import sys; sys.exit(255)"])
    started = time.monotonic()
    with pytest.raises(remote.RemoteFailure, match="adapter_exited_without_result"):
        remote.ssh_exchange("check", None, lambda: True, 10)
    assert time.monotonic() - started < 8


@pytest.mark.parametrize("failure", ["client_missing", "unreachable", "docker_unavailable", "wrong_runner"])
def test_worker_fails_closed_when_ssh_or_docker_unavailable(remote_job, monkeypatch, failure):
    row = create(remote_job)
    forbid_local_execution(monkeypatch)
    if failure == "client_missing":
        def missing(): raise ssh_transport.SSHUnavailable("ssh_client_unavailable")
        monkeypatch.setattr(ssh_transport, "ssh_binary", missing)
    elif failure == "unreachable":
        monkeypatch.setattr(ssh_transport, "command",
                            lambda *a: [local.child_executable(), "-I", "-S", "-c", "import sys; sys.exit(255)"])
    else:
        reply = ({"error": "remote_runner_unavailable_or_invalid_input"} if failure == "docker_unavailable"
                 else {"runner": "something-else", "image_id": IMAGE})
        monkeypatch.setattr(remote, "ssh_exchange", lambda operation, *a: reply if operation == "check"
                            else pytest.fail("Must stop after the failed preflight"))
    service.worker_tick()
    status, payload, report = job_state(row)
    assert status == "failed" and report is None
    assert payload["error"] == {"client_missing": "ssh_client_unavailable", "unreachable": "adapter_exited_without_result",
                                "docker_unavailable": "remote_preflight_failed", "wrong_runner": "remote_preflight_failed"}[failure]
    with SessionLocal() as db:
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "remote_docker_execution_finished"))


# --- Authorisation revalidation at execution time ------------------------------------------

@pytest.mark.parametrize("change", ["revoked", "expired", "not_yet_valid", "scope", "method", "evidence", "requester"])
def test_remote_job_revalidated_before_any_ssh(remote_job, monkeypatch, change):
    client, auth, _ = remote_job
    row = create(remote_job)
    forbid_local_execution(monkeypatch)
    monkeypatch.setattr(remote, "ssh_exchange", lambda *a: pytest.fail("No SSH after permission change"))
    if change == "revoked":
        assert client.post(f"/api/v1/authorizations/{auth}/revoke",
                           json={"reason": "Synthetic withdrawal of written permission."}).status_code == 200
    elif change == "expired":
        monkeypatch.setattr(service, "utc_now", lambda: NOW + timedelta(hours=2))
    else:
        with SessionLocal() as db:
            record = db.get(WebsiteAuthorization, auth)
            if change == "not_yet_valid": record.valid_from = NOW + timedelta(minutes=5)
            elif change == "scope": record.authorized_domains = ["other.example.com"]
            elif change == "method": record.permitted_methods = ["passive_reconnaissance"]
            elif change == "evidence": record.evidence_revision += 1
            elif change == "requester":
                from app.models.admin import Admin
                db.get(Admin, client.admin_id).is_active = False
            db.commit()
    service.worker_tick()
    status, _, report = job_state(row)
    assert status == "cancelled" and report is None


def test_revocation_during_remote_run_discards_result_and_cleans_up(remote_job, monkeypatch):
    client, auth, _ = remote_job
    calls, original = simulated(monkeypatch)
    row = create(remote_job)

    def exchange(operation, payload, permitted, seconds):
        if operation == "run":
            assert client.post(f"/api/v1/authorizations/{auth}/revoke",
                               json={"reason": "Synthetic withdrawal during execution."}).status_code == 200
            # A runner reply that arrives after revocation must not be accepted.
            return original(operation, payload, lambda: True, seconds)
        return original(operation, payload, permitted, seconds)
    monkeypatch.setattr(remote, "ssh_exchange", exchange)
    service.worker_tick()
    status, _, report = job_state(row)
    assert status == "cancelled" and report is None


# --- Cancellation and deadlines -----------------------------------------------------------

def test_real_process_cancellation_kills_child_promptly():
    channel = local.Channel([local.child_executable(), "-I", "-S", "-c", "import time; time.sleep(60)"])
    revoked_at = time.monotonic() + .3
    try:
        started = time.monotonic()
        with pytest.raises(local.RuntimeFailure, match="permission_changed"):
            channel.receive(30, lambda: time.monotonic() < revoked_at)
        assert time.monotonic() - started < 3
    finally:
        channel.close()
    assert channel.process.poll() is not None


def test_real_process_deadline_kills_child():
    channel = local.Channel([local.child_executable(), "-I", "-S", "-c", "import time; time.sleep(60)"])
    try:
        started = time.monotonic()
        with pytest.raises(local.RuntimeFailure, match="adapter_deadline_exceeded"):
            channel.receive(.5, lambda: True)
        assert time.monotonic() - started < 3
    finally:
        channel.close()
    assert channel.process.poll() is not None


def test_assessment_lease_exceeds_every_bounded_remote_budget(assessed):
    margin = 30
    assert engine.lease_seconds("assessment") >= remote.WORST_CASE_SECONDS + margin
    assert engine.lease_seconds("assessment") >= nmap_runtime.WORST_CASE_SECONDS + margin
    assert engine.lease_seconds("monitoring") == engine.DEFAULT_LEASE_SECONDS
    row = create((assessed[0], None, assessed[4]))
    with SessionLocal() as db:
        claimed = engine.claim(db, "assessment", NOW)
        job = db.get(Job, claimed[0])
        assert as_utc(job.lease_until) == NOW + timedelta(seconds=engine.lease_seconds("assessment"))
        # Before the lease lapses no other worker can reclaim or fail it.
        assert engine.claim(db, "assessment", NOW + timedelta(seconds=remote.WORST_CASE_SECONDS + 5)) is None
        assert db.get(Job, row["job_id"]).status == "running"


# --- Untrusted remote output and isolation attestation -----------------------------------

def execution(**changes):
    value = {"id": "a" * 32, "image_id": IMAGE, "limits": remote.LIMITS, "cleanup_confirmed": True,
             "duration_ms": 1, "container_duration_ms": 1, "analyzer_cpu_seconds": 0, "analyzer_peak_rss_bytes": 1,
             "analyzer_duration_ms": 1}
    value.update(changes)
    return value


def test_execution_whitelist_drops_untrusted_remote_fields():
    accepted = remote.validate_execution(execution(stdout="<script>alert(1)</script>", container_started_at="x",
                                                   isolation_verified=True), "a" * 32, IMAGE)
    assert accepted["isolation_attested"] is True
    assert "stdout" not in accepted and "container_started_at" not in accepted
    assert remote.validate_execution(execution(), "a" * 32, IMAGE)["isolation_attested"] is False


@pytest.mark.parametrize("value", [False, "true", 1, {"ok": True}])
def test_malformed_isolation_attestation_rejected(value):
    with pytest.raises(remote.RemoteFailure, match="isolation_attestation_invalid"):
        remote.validate_execution(execution(isolation_verified=value), "a" * 32, IMAGE)


def test_isolation_attestation_can_be_required(monkeypatch):
    monkeypatch.setattr(settings, "assessment_remote_require_isolation_attestation", True)
    with pytest.raises(remote.RemoteFailure, match="isolation_attestation_required"):
        remote.validate_execution(execution(), "a" * 32, IMAGE)
    assert remote.validate_execution(execution(isolation_verified=True), "a" * 32, IMAGE)["isolation_attested"]


def test_required_attestation_from_old_runner_fails_job_and_requests_cleanup(remote_job, monkeypatch):
    monkeypatch.setattr(settings, "assessment_remote_require_isolation_attestation", True)
    calls, _ = simulated(monkeypatch)
    row = create(remote_job)
    service.worker_tick()
    status, payload, report = job_state(row)
    assert status == "failed" and report is None
    assert payload["error"] == "remote_isolation_attestation_required"
    assert calls == ["check", "HEAD", "run", "cleanup"]


def test_attested_success_records_isolation_in_report(remote_job, monkeypatch):
    calls, original = simulated(monkeypatch)
    def exchange(operation, *args):
        reply = original(operation, *args)
        if operation == "run":
            reply["execution"].update(isolation_verified=True, raw_stderr="PRIVATE-runner-text")
        return reply
    monkeypatch.setattr(remote, "ssh_exchange", exchange)
    row = create(remote_job)
    service.worker_tick()
    client, _, _ = remote_job
    report = client.get(f"/api/v1/assessments/{row['id']}/report/download")
    assert report.status_code == 200
    assert report.json()["execution"]["isolation_attested"] is True
    assert "PRIVATE" not in report.text


# --- VM runner (loaded from the scanner directory; Docker is simulated) -------------------

@pytest.fixture
def runner(monkeypatch):
    spec = importlib.util.spec_from_file_location("hardening_runner", SCANNER / "remote_runner.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.signal, "signal", lambda *a: None)
    return module


def inspected(token="a" * 32, **host_changes):
    host = {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False, "CapDrop": ["ALL"], "CapAdd": None,
            "SecurityOpt": ["no-new-privileges=true"], "Memory": 67108864, "MemorySwap": 67108864,
            "NanoCpus": 250000000, "PidsLimit": 16, "IpcMode": "none", "Binds": None, "PortBindings": {},
            "Devices": [], "RestartPolicy": {"Name": "no"}}
    host.update(host_changes)
    return {"Image": IMAGE, "Mounts": [], "HostConfig": host,
            "Config": {"User": "65532:65532", "Labels": {"com.snwebshield.runner": token}}}


def test_runner_requests_ipc_none_and_no_host_access(runner):
    args = runner.create_args("a" * 32, IMAGE)
    assert "--ipc=none" in args and "--network=none" in args and "--log-driver=none" in args
    assert args[args.index("--ulimit") + 1] == "nofile=32:32"
    assert not any(a.startswith(("-v", "--volume", "--mount", "-p", "--publish", "--privileged",
                                 "--cap-add", "--device", "--pid=host", "--network=host")) for a in args)


def test_runner_accepts_exact_isolation(runner):
    assert runner.verify_isolation(inspected(), "a" * 32, IMAGE) is True


@pytest.mark.parametrize("weakening", [
    {"NetworkMode": "bridge"}, {"NetworkMode": "host"}, {"ReadonlyRootfs": False}, {"Privileged": True},
    {"CapDrop": []}, {"CapAdd": ["NET_RAW"]}, {"SecurityOpt": []}, {"Memory": 0}, {"MemorySwap": -1},
    {"NanoCpus": 0}, {"PidsLimit": 0}, {"IpcMode": "host"}, {"Binds": ["/:/host"]},
    {"PortBindings": {"80/tcp": [{"HostPort": "80"}]}}, {"Devices": [{"PathOnHost": "/dev/sda"}]},
    {"RestartPolicy": {"Name": "always"}},
])
def test_runner_refuses_weakened_isolation(runner, weakening):
    with pytest.raises(runner.RunnerError, match="isolation_mismatch"):
        runner.verify_isolation(inspected(**weakening), "a" * 32, IMAGE)


@pytest.mark.parametrize("field,value", [("User", "0:0"), ("User", ""), ("Labels", {})])
def test_runner_refuses_wrong_user_or_owner(runner, field, value):
    info = inspected()
    info["Config"][field] = value
    with pytest.raises(runner.RunnerError):
        runner.verify_isolation(info, "a" * 32, IMAGE)


def test_runner_never_starts_container_with_mismatched_isolation(runner, monkeypatch):
    calls, cleanup = [], []
    def docker(args, **kwargs):
        calls.append(args[1])
        if args[1] == "start": pytest.fail("A container with weakened isolation must never start")
        if args[1] == "inspect": return json.dumps([inspected(NetworkMode="bridge")]).encode()
        return b""
    monkeypatch.setattr(runner, "docker", docker)
    monkeypatch.setattr(runner, "cleanup", lambda *a: cleanup.append(a) or True)
    result = runner.execute("a" * 32, {"https": True, "status": 200, "headers": {}}, IMAGE)
    assert calls == ["create", "inspect"] and cleanup == [("a" * 32, IMAGE)]
    assert "analysis" not in result and result["error"]
    assert result["execution"]["cleanup_confirmed"] is True
    assert "isolation_verified" not in result["execution"]


# --- SSRF, DNS pinning and redirects -------------------------------------------------------

@pytest.mark.parametrize("address", [
    "0.0.0.0", "127.0.0.53", "10.1.2.3", "172.16.0.1", "192.168.0.1", "100.64.0.1", "169.254.169.254",
    "192.0.0.1", "192.0.2.10", "198.18.0.1", "224.0.0.1", "255.255.255.255",
    "::", "::1", "fe80::1", "fc00::1", "fd12::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2001:db8::1", "ff02::1",
])
def test_private_loopback_link_local_and_special_destinations_blocked(monkeypatch, address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    monkeypatch.setattr(broker.policy.socket, "getaddrinfo",
                        lambda *a, **k: [(family, socket.SOCK_STREAM, 6, "", (address, 443))])
    with pytest.raises(broker.policy.Blocked):
        broker.policy.resolve("synthetic.example", 443)


@pytest.mark.parametrize("url", [
    "http://user:pass@synthetic.example/", "http://synthetic.example:8080/", "file:///etc/passwd",
    "gopher://synthetic.example/", "http://synthetic.example/\r\nX-Injected: 1", "http://synthetic.example%2f@evil/",
])
def test_unsafe_target_urls_rejected_before_dns(monkeypatch, url):
    monkeypatch.setattr(broker.policy.socket, "getaddrinfo", lambda *a, **k: pytest.fail("No DNS for unsafe URL"))
    with pytest.raises(broker.policy.Blocked):
        broker.collect(url, lambda: True)


def test_dns_resolved_once_and_connection_pinned_against_rebinding(monkeypatch):
    lookups, connects = [], []
    answers = iter([
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))],
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))],  # A rebinding second answer.
    ])
    def getaddrinfo(*a, **k):
        lookups.append(a[0]); return next(answers)
    class Socket:
        def __init__(self, *a): pass
        def settimeout(self, *a): pass
        def connect(self, address):
            connects.append(address); raise ConnectionRefusedError()
        def close(self): pass
    monkeypatch.setattr(broker.policy.socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(broker.socket, "socket", Socket)
    with pytest.raises(ConnectionRefusedError):
        broker.collect("http://synthetic.example/", lambda: True)
    assert lookups == ["synthetic.example"] and connects == [("93.184.216.34", 80)]


def test_permission_revoked_after_dns_prevents_connection(monkeypatch):
    monkeypatch.setattr(broker.policy.socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))])
    monkeypatch.setattr(broker.socket, "socket", lambda *a: pytest.fail("Must not open a socket"))
    checks = iter([True, False])
    with pytest.raises(broker.policy.PermissionChanged):
        broker.collect("http://synthetic.example/", lambda: next(checks))


@pytest.mark.parametrize("location,category", [
    ("/next", "same_origin"),
    ("http://synthetic.example/other?q=1", "same_origin"),
    ("https://synthetic.example/", "https_upgrade_same_host"),
    ("https://evil.example/steal?token=PRIVATE", "different_host_not_followed"),
    ("http://127.0.0.1/PRIVATE", "different_host_not_followed"),
    ("http://169.254.169.254/latest/meta-data/PRIVATE", "different_host_not_followed"),
    ("http://synthetic.example:8080/PRIVATE", "invalid_or_unsupported"),
    ("javascript:alert('PRIVATE')", "invalid_or_unsupported"),
    ("file:///etc/PRIVATE", "invalid_or_unsupported"),
])
def test_real_head_classifies_but_never_follows_or_stores_redirect(monkeypatch, location, category):
    hits = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_HEAD(self):
            hits.append(self.path)
            self.send_response(302); self.send_header("Location", location); self.end_headers()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    monkeypatch.setattr(broker.policy, "resolve", lambda host, port: [(socket.AF_INET, ("127.0.0.1", server.server_port))])
    try:
        result = broker.collect("http://synthetic.example/start", lambda: True)
    finally:
        server.shutdown(); server.server_close(); thread.join()
    assert hits == ["/start"]
    assert result["redirect"] == {"is_redirect": True, "location": category, "followed": False}
    assert result["redirect_followed"] is False
    assert "PRIVATE" not in json.dumps(result) and location not in json.dumps(result)


def test_redirect_classification_edge_cases():
    url = "http://synthetic.example/"
    assert broker.classify_redirect(url, 200, ["https://evil.example/"]) == {"is_redirect": False, "location": None, "followed": False}
    assert broker.classify_redirect(url, 301, [])["location"] == "missing"
    assert broker.classify_redirect(url, 307, ["/a", "/b"])["location"] == "ambiguous"
    assert broker.classify_redirect("https://synthetic.example/", 308, ["http://synthetic.example/"])["location"] == "same_host_scheme_or_port_change"
    assert broker.classify_redirect(url, 302, ["http://SYNTHETIC.example./x"])["location"] == "same_origin"
