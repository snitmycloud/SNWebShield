"""Remote adapter acceptance with synthetic SSH/Docker; never contacts Azure or targets."""
import importlib.util
import json
from pathlib import Path

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.assessment import AssessmentReport
from app.models.authorization import WebsiteAuthorization
from app.models.jobs import ExecutionEvent, Job
from app.services import assessments as service, remote_assessment_runtime as remote
from app.services.header_analyzer import analyze
from test_authorization_correctness import api, NOW
from test_assessments import assessed

IMAGE = "sha256:" + "a" * 64
HEADERS = {"content-security-policy": "default-src 'self'", "server": "PRIVATE-version"}


@pytest.fixture
def remote_job(assessed, monkeypatch):
    monkeypatch.setattr(settings, "assessment_remote_docker_enabled", True)
    monkeypatch.setattr(settings, "assessment_remote_image_id", IMAGE)
    client, auth, site, key, body = assessed
    return client, auth, {**body, "profile_id": service.REMOTE_PROFILE_ID, "network_permission_confirmed": True}


def create(remote_job):
    client, _, body = remote_job
    response = client.post("/api/v1/assessments", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def simulated(monkeypatch):
    calls = []

    def broker(script, payload, permitted, seconds):
        assert script == "assessment_broker.py" and permitted()
        calls.append("HEAD")
        return {"result": {"tls_verified": True, "status": 200, "response_ms": 2,
                           "selected_headers": HEADERS.copy(), "redirect_followed": False}}

    def exchange(operation, payload, permitted, seconds):
        assert permitted()
        calls.append(operation)
        if operation == "check":
            return {"runner": remote.VERSION, "image_id": IMAGE}
        if operation == "cleanup":
            return {"cleanup_confirmed": True}
        assert set(payload) == {"id", "data"}
        assert set(payload["data"]) == {"https", "status", "headers"}
        return {"analysis": analyze(payload["data"]), "execution": {
            "id": payload["id"], "image_id": IMAGE, "cleanup_confirmed": True,
            "duration_ms": 50, "container_duration_ms": 40, "analyzer_cpu_seconds": .01, "analyzer_peak_rss_bytes": 1000000,
            "analyzer_duration_ms": 1,
            "limits": {"memory_bytes": 67108864, "cpus": .25, "pids": 16, "timeout_seconds": 8}}}

    monkeypatch.setattr(remote, "invoke", broker)
    monkeypatch.setattr(remote, "ssh_exchange", exchange)
    return calls, exchange


def test_remote_success_persists_usage_private_report_and_audit(remote_job, monkeypatch):
    calls, _ = simulated(monkeypatch)
    row = create(remote_job)
    service.worker_tick()
    client, _, _ = remote_job
    detail = client.get(f"/api/v1/assessments/{row['id']}").json()
    assert detail["job"]["status"] == "completed", detail
    assert calls == ["check", "HEAD", "run"]
    download = client.get(f"/api/v1/assessments/{row['id']}/report/download")
    assert download.status_code == 200
    assert "PRIVATE" not in download.text
    assert download.json()["execution"]["cleanup_confirmed"] is True
    assert download.json()["execution"]["image_id"] == IMAGE
    with SessionLocal() as db:
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "remote_docker_execution_finished"))


@pytest.mark.parametrize("change", ["disabled", "image", "consent", "method", "scope", "evidence", "expiry"])
def test_remote_denied_before_execution(remote_job, monkeypatch, change):
    client, auth, body = remote_job
    if change == "disabled":
        monkeypatch.setattr(settings, "assessment_remote_docker_enabled", False)
    elif change == "image":
        monkeypatch.setattr(settings, "assessment_remote_image_id", "")
    elif change == "consent":
        body = {**body, "network_permission_confirmed": False}
    else:
        with SessionLocal() as db:
            record = db.get(WebsiteAuthorization, auth)
            if change == "method": record.permitted_methods = ["passive_reconnaissance"]
            elif change == "scope": record.authorized_domains = ["other.example"]
            elif change == "evidence": record.evidence_revision += 1
            elif change == "expiry": record.valid_until = NOW
            db.commit()
    monkeypatch.setattr(remote, "ssh_exchange", lambda *a: pytest.fail("Unexpected SSH"))
    assert client.post("/api/v1/assessments", json=body).status_code == 409


def test_ssh_failure_prevents_head_and_never_falls_back(remote_job, monkeypatch):
    row = create(remote_job)
    monkeypatch.setattr(remote, "invoke", lambda *a: pytest.fail("HEAD after SSH failure"))
    def fail(*args): raise remote.RuntimeFailure("adapter_exited_without_result")
    monkeypatch.setattr(remote, "ssh_exchange", fail)
    service.worker_tick()
    with SessionLocal() as db:
        assert db.get(Job, row["job_id"]).status == "failed"
        assert db.scalar(select(AssessmentReport)) is None


@pytest.mark.parametrize("failure", ["timeout", "malformed", "cleanup", "measurement"])
def test_remote_failures_request_targeted_cleanup_without_report(remote_job, monkeypatch, failure):
    calls, original = simulated(monkeypatch)
    def exchange(operation, *args):
        if operation == "run":
            if failure == "timeout": raise remote.RuntimeFailure("adapter_deadline_exceeded")
            result = original(operation, *args)
            if failure == "malformed": result["analysis"] = {"unexpected": "PRIVATE"}
            elif failure == "cleanup": result["execution"]["cleanup_confirmed"] = False
            else: result["execution"]["analyzer_cpu_seconds"] = float("nan")
            return result
        return original(operation, *args)
    monkeypatch.setattr(remote, "ssh_exchange", exchange)
    row = create(remote_job)
    service.worker_tick()
    assert calls[-1] == "cleanup"
    with SessionLocal() as db:
        assert db.get(Job, row["job_id"]).status == "failed"
        assert db.scalar(select(AssessmentReport)) is None
        event = db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "remote_docker_execution_finished"))
        assert event.detail["execution"]["cleanup_confirmed"] is False


def test_cancellation_during_remote_execution_audits_cleanup(remote_job, monkeypatch):
    _, original = simulated(monkeypatch)
    row = create(remote_job)
    client, _, _ = remote_job
    def exchange(operation, *args):
        if operation == "run":
            assert client.post(f"/api/v1/assessments/{row['id']}/cancel",
                               json={"reason": "Cancel synthetic remote execution."}).status_code == 200
            raise remote.RuntimeFailure("permission_changed")
        return original(operation, *args)
    monkeypatch.setattr(remote, "ssh_exchange", exchange)
    service.worker_tick()
    with SessionLocal() as db:
        assert db.get(Job, row["job_id"]).status == "cancelled"
        assert db.scalar(select(AssessmentReport)) is None
        assert db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "remote_docker_execution_finished"))


def test_pinned_image_change_cancels_queued_job(remote_job, monkeypatch):
    row = create(remote_job)
    monkeypatch.setattr(settings, "assessment_remote_image_id", "sha256:" + "b" * 64)
    monkeypatch.setattr(remote, "ssh_exchange", lambda *a: pytest.fail("Unexpected SSH"))
    service.worker_tick()
    with SessionLocal() as db:
        assert db.get(Job, row["job_id"]).status == "cancelled"


@pytest.fixture
def runner(monkeypatch):
    spec = importlib.util.spec_from_file_location("remote_runner", Path(__file__).resolve().parents[2] / "scanner/remote_runner.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Signal policy belongs to the standalone Linux runner, not the pytest process.
    monkeypatch.setattr(module.signal, "signal", lambda *a: None)
    return module


def test_container_configuration_is_networkless_and_fixed(runner):
    args = runner.create_args("a" * 32, IMAGE)
    for flag in ("--network=none", "--user=65532:65532", "--read-only", "--cap-drop=ALL",
                 "--security-opt=no-new-privileges=true", "--memory=64m", "--memory-swap=64m",
                 "--cpus=0.25", "--pids-limit=16", "--pull=never", "--restart=no"):
        assert flag in args
    assert not any(a.startswith(("--mount", "--volume", "--publish", "--privileged")) for a in args)
    with pytest.raises(runner.RunnerError): runner.container_name("; arbitrary command")


@pytest.mark.parametrize("failure", [False, True])
def test_runner_cleans_up_success_and_timeout(runner, monkeypatch, failure):
    calls = []
    data = {"https": True, "status": 200, "headers": HEADERS}
    def docker(args, **kwargs):
        calls.append(args)
        if args[1] == "start":
            if failure: raise runner.RunnerError("docker_deadline_exceeded")
            return json.dumps({"analysis": analyze(data), "usage": {"analyzer_cpu_seconds": .01}}).encode()
        if args[1] == "inspect":
            return json.dumps([{"State": {"Running": False, "ExitCode": 0,
                "StartedAt": "2026-11-23T00:00:00+00:00", "FinishedAt": "2026-11-23T00:00:00.040000+00:00"},
                "Image": IMAGE, "Mounts": [], "Config": {"User": "65532:65532", "Labels": {runner.LABEL: "a" * 32}},
                "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False, "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges=true"], "Memory": 67108864, "MemorySwap": 67108864,
                    "NanoCpus": 250000000, "PidsLimit": 16, "IpcMode": "none", "RestartPolicy": {"Name": "no"}}}]).encode()
        return b""
    cleanup = []
    monkeypatch.setattr(runner, "docker", docker)
    monkeypatch.setattr(runner, "cleanup", lambda *a: cleanup.append(a) or True)
    result = runner.execute("a" * 32, data, IMAGE)
    assert cleanup == [("a" * 32, IMAGE)]
    assert result["execution"]["cleanup_confirmed"] is True
    assert result["execution"]["isolation_verified"] is True
    assert ("error" in result) == failure
    assert [c[1] for c in calls[:3]] == ["create", "inspect", "start"]


def test_runner_refuses_to_remove_unowned_container(runner, monkeypatch):
    def docker(args, **kwargs):
        assert args[1] == "inspect", "Must never delete unowned container"
        return json.dumps([{"Image": IMAGE, "Config": {"Labels": {}}}]).encode()
    monkeypatch.setattr(runner, "docker", docker)
    with pytest.raises(runner.RunnerError, match="ownership"):
        runner.cleanup("a" * 32, IMAGE)


def test_cleanup_token_rejects_shell_injection_before_ssh():
    with pytest.raises(remote.RemoteFailure, match="invalid_execution_id"):
        remote.ssh_exchange("cleanup", "x; touch /tmp/unwanted", lambda: True, 1)


def test_windows_scanner_check_uses_synthetic_headers_without_target(monkeypatch, capsys):
    from app.cli import scanner_check
    calls, exchange = simulated(monkeypatch)
    monkeypatch.setattr(settings, "assessment_remote_image_id", IMAGE)
    monkeypatch.setattr(scanner_check, "ssh_exchange", exchange)
    scanner_check.main()
    result = json.loads(capsys.readouterr().out)
    assert result["passed"] and result["target_requests"] == 0
    assert result["execution"]["cleanup_confirmed"]
    assert calls == ["check", "run"]


def test_windows_scanner_check_fails_before_run_on_wrong_image(monkeypatch):
    from app.cli import scanner_check
    monkeypatch.setattr(settings, "assessment_remote_image_id", IMAGE)
    def wrong_image(operation, *args):
        assert operation == "check", "Must stop before container execution"
        return {"runner": remote.VERSION, "image_id": "sha256:" + "b" * 64}
    monkeypatch.setattr(scanner_check, "ssh_exchange", wrong_image)
    with pytest.raises(SystemExit, match="preflight_failed"):
        scanner_check.main()


def test_ssh_profile_environment_preserves_os_paths_without_application_secrets(monkeypatch):
    from app.services.local_assessment_runtime import safe_environment
    monkeypatch.setenv("USERPROFILE", "C:/Users/test-scanner")
    monkeypatch.setenv("APPDATA", "C:/Users/test-scanner/AppData/Roaming")
    monkeypatch.setenv("SSH_AUTH_SOCK", "test-agent-socket")
    monkeypatch.setenv("JWT_SECRET_KEY", "synthetic-do-not-forward")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "synthetic-do-not-forward")
    ordinary = safe_environment()
    ssh = safe_environment(ssh_profile=True)
    assert "USERPROFILE" not in ordinary and "SSH_AUTH_SOCK" not in ordinary
    assert ssh["USERPROFILE"] == "C:/Users/test-scanner"
    assert ssh["SSH_AUTH_SOCK"] == "test-agent-socket"
    assert "JWT_SECRET_KEY" not in ssh and "AZURE_CLIENT_SECRET" not in ssh
