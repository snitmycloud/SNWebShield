"""R8 (per-run Nmap container inspection) and R6 (read-only orphan report).

Synthetic Docker inspect output and fake SSH exchanges only: no Docker, no SSH, no VM, no target traffic.
"""
import copy
import json
from datetime import timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.main import app
from app.models.jobs import ExecutionEvent
from app.services import nmap_policy as policy, nmap_runtime as runtime, orphan_report, ssh_transport
from app.services import remote_assessment_runtime as remote
from test_authorization_correctness import api  # noqa: F401
from test_production_hardening import make_user, login

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sha256:" + "b" * 64
TOKEN = "a" * 32
CARRIER = "snws-nmap-" + TOKEN + "-guard"
CARRIER_ID = "c" * 64
URL = "/api/v1/assessments/orphan-containers"


def load(relative, replacements):
    path = ROOT / relative
    source = path.read_text(encoding="utf-8")
    for old, new in replacements.items():
        source = source.replace(old, repr(str(new)))
    module = ModuleType("runner_" + path.stem)
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


@pytest.fixture
def nmap_runner():
    return load("scanner/nmap/runner.py", {
        '"/usr/local/libexec/snwebshield-header-runner"': ROOT / "scanner/remote_runner.py",
        '"/usr/local/lib/snwebshield/nmap_policy.py"': ROOT / "backend/app/services/nmap_policy.py"})


@pytest.fixture
def header_runner():
    return load("scanner/remote_runner.py", {})


def compliant(role):
    guard = role == "guard"
    return {
        "Image": IMAGE, "Id": CARRIER_ID if guard else "d" * 64, "Mounts": [],
        "Config": {"User": "0:0" if guard else "65532:65532",
                   "Labels": {"com.snwebshield.nmap": TOKEN, "com.snwebshield.nmap.role": role}},
        "HostConfig": {
            "NetworkMode": "bridge" if guard else "container:" + CARRIER, "ReadonlyRootfs": True, "Privileged": False,
            "CapDrop": ["ALL"], "CapAdd": ["NET_ADMIN"] if guard else None,
            "SecurityOpt": ["no-new-privileges=true"],
            "Memory": 67108864 if guard else 134217728, "MemorySwap": 67108864 if guard else 134217728,
            "NanoCpus": 100000000 if guard else 500000000, "PidsLimit": 16, "PidMode": "", "IpcMode": "private",
            "Binds": None, "Tmpfs": {"/run": "rw,noexec,nosuid,size=65536,mode=0700"} if guard else None,
            "PortBindings": {}, "Devices": [], "RestartPolicy": {"Name": "no"}, "LogConfig": {"Type": "none"}}}


def failures(runner, role, mutate=None):
    info = compliant(role)
    if mutate: mutate(info)
    return runner.isolation_failures(info, TOKEN, IMAGE, role, carrier_name=CARRIER, carrier_id=CARRIER_ID)


# --- R8: what Docker actually created must match policy -------------------------------------------

@pytest.mark.parametrize("role", ["guard", "scan"])
def test_compliant_containers_pass(nmap_runner, role):
    assert failures(nmap_runner, role) == []
    assert nmap_runner.verify_isolation(compliant(role), TOKEN, IMAGE, role, CARRIER, CARRIER_ID) is True


def host(info): return info["HostConfig"]

CASES = [
    ("privileged", "guard", lambda i: host(i).update(Privileged=True), "not_privileged"),
    ("privileged", "scan", lambda i: host(i).update(Privileged=True), "not_privileged"),
    ("guard_extra_cap", "guard", lambda i: host(i).update(CapAdd=["NET_ADMIN", "SYS_ADMIN"]), "capabilities"),
    ("guard_net_raw_only", "guard", lambda i: host(i).update(CapAdd=["NET_RAW"]), "capabilities"),
    ("guard_not_dropping_all", "guard", lambda i: host(i).update(CapDrop=[]), "capabilities"),
    ("scan_gets_net_admin", "scan", lambda i: host(i).update(CapAdd=["NET_ADMIN"]), "capabilities"),
    ("guard_host_network", "guard", lambda i: host(i).update(NetworkMode="host"), "network"),
    ("scan_host_network", "scan", lambda i: host(i).update(NetworkMode="host"), "network"),
    ("scan_own_bridge", "scan", lambda i: host(i).update(NetworkMode="bridge"), "network"),
    ("scan_other_netns", "scan", lambda i: host(i).update(NetworkMode="container:snws-nmap-other-guard"), "network"),
    ("scan_none_network", "scan", lambda i: host(i).update(NetworkMode="none"), "network"),
    ("scan_root", "scan", lambda i: i["Config"].update(User="0:0"), "user"),
    ("guard_unexpected_user", "guard", lambda i: i["Config"].update(User="1000:1000"), "user"),
    ("writable_rootfs", "scan", lambda i: host(i).update(ReadonlyRootfs=False), "read_only_rootfs"),
    ("bind_mount", "scan", lambda i: host(i).update(Binds=["/etc:/etc:ro"]), "no_mounts"),
    ("volume_mount", "scan", lambda i: i.update(Mounts=[{"Type": "volume", "Destination": "/data"}]), "no_mounts"),
    ("guard_other_mount", "guard", lambda i: i.update(Mounts=[{"Type": "bind", "Destination": "/run"}]), "no_mounts"),
    ("guard_extra_tmpfs", "guard", lambda i: host(i)["Tmpfs"].update({"/tmp": "rw"}), "no_mounts"),
    ("scan_tmpfs", "scan", lambda i: host(i).update(Tmpfs={"/run": "rw"}), "no_mounts"),
    ("device", "scan", lambda i: host(i).update(Devices=[{"PathOnHost": "/dev/kmsg"}]), "no_devices"),
    ("published_port", "guard", lambda i: host(i).update(PortBindings={"22/tcp": [{"HostPort": "22"}]}), "no_published_ports"),
    ("host_pid", "scan", lambda i: host(i).update(PidMode="host"), "no_host_namespaces"),
    ("host_ipc", "guard", lambda i: host(i).update(IpcMode="host"), "no_host_namespaces"),
    ("shared_ipc", "scan", lambda i: host(i).update(IpcMode="container:abc"), "no_host_namespaces"),
    ("restart_always", "guard", lambda i: host(i).update(RestartPolicy={"Name": "always"}), "no_restart"),
    ("logging_enabled", "scan", lambda i: host(i).update(LogConfig={"Type": "json-file"}), "no_logging"),
    ("no_new_privileges_missing", "scan", lambda i: host(i).update(SecurityOpt=[]), "no_new_privileges"),
    ("guard_memory", "guard", lambda i: host(i).update(Memory=0, MemorySwap=0), "memory"),
    ("scan_swap", "scan", lambda i: host(i).update(MemorySwap=-1), "memory"),
    ("cpu_unlimited", "scan", lambda i: host(i).update(NanoCpus=0), "cpu"),
    ("pids_unlimited", "guard", lambda i: host(i).update(PidsLimit=0), "pids"),
    ("other_image", "scan", lambda i: i.update(Image="sha256:" + "e" * 64), "image"),
    ("foreign_token", "scan", lambda i: i["Config"]["Labels"].update({"com.snwebshield.nmap": "f" * 32}), "owner_label"),
    ("wrong_role_label", "guard", lambda i: i["Config"]["Labels"].update({"com.snwebshield.nmap.role": "scan"}), "owner_label"),
]


@pytest.mark.parametrize("name,role,mutate,check", CASES, ids=[f"{c[0]}-{c[1]}" for c in CASES])
def test_each_weakening_is_caught_and_named(nmap_runner, name, role, mutate, check):
    assert check in failures(nmap_runner, role, mutate)
    info = compliant(role); mutate(info)
    with pytest.raises(nmap_runner.RunnerError, match="container_isolation_mismatch"):
        nmap_runner.verify_isolation(info, TOKEN, IMAGE, role, CARRIER, CARRIER_ID)


def test_docker_reporting_capability_names_with_prefix_is_accepted(nmap_runner):
    assert failures(nmap_runner, "guard", lambda i: host(i).update(CapAdd=["CAP_NET_ADMIN"], CapDrop=["CAP_ALL"])) == []


def test_malformed_inspect_output_fails_closed(nmap_runner):
    for info in ({}, {"HostConfig": None, "Config": None}, {"HostConfig": {}, "Config": {}}):
        assert nmap_runner.isolation_failures(info, TOKEN, IMAGE, "scan", CARRIER, CARRIER_ID)


class FakeDocker:
    """Records every docker subcommand; refuses anything that would start or change a container early."""
    def __init__(self, runner, guard_mutation=None, scan_mutation=None):
        self.calls, self.guard_mutation, self.scan_mutation, self.created = [], guard_mutation, scan_mutation, set()
        runner.docker = self

    def __call__(self, args, *, data=None, seconds=4, allow_missing=False):
        self.calls.append(list(args))
        if args[:2] == ["container", "create"]:
            self.created.add(args[args.index("--name") + 1]); return b""
        if args[:2] == ["container", "inspect"]:
            name = args[2]
            if name not in self.created: return None if allow_missing else b"[]"
            role = "guard" if name.endswith("-guard") else "scan"
            info = compliant(role)
            info["State"] = {"Running": True}
            mutation = self.guard_mutation if role == "guard" else self.scan_mutation
            if mutation: mutation(info)
            return json.dumps([info]).encode()
        if args[:2] == ["container", "rm"]:
            self.created.discard(args[-1]); return b""
        raise AssertionError("unexpected docker call: " + " ".join(args))


class Proc:
    stdin = SimpleNamespace(write=lambda b: None, flush=lambda: None, close=lambda: None)
    stdout = SimpleNamespace(readline=lambda n: b'{"ready":true}\n', close=lambda: None)
    def poll(self): return 0
    def wait(self, timeout=None): return 0
    def kill(self): pass


@pytest.mark.parametrize("which", ["guard", "scan"])
def test_noncompliant_container_is_never_started_and_is_cleaned_up(nmap_runner, monkeypatch, which):
    bad = lambda i: host(i).update(Privileged=True)
    fake = FakeDocker(nmap_runner, guard_mutation=bad if which == "guard" else None,
                      scan_mutation=bad if which == "scan" else None)
    monkeypatch.setattr(nmap_runner, "signal", SimpleNamespace(signal=lambda *a: None, SIGTERM=15, SIGHUP=1, SIG_IGN=1))
    started = []
    # A guard that passes inspection may start (to apply the firewall); a failing one must never reach Popen.
    monkeypatch.setattr(nmap_runner.subprocess, "Popen", lambda *a, **k: started.append(a) or Proc())
    result = nmap_runner.execute(TOKEN, {"ip": "8.8.8.8", "host": "example.com", "dns_addresses": ["8.8.8.8"]},
                                 IMAGE, permitted=lambda: True)
    assert result["error"] == "nmap_execution_or_permission_failed" and "analysis" not in result
    assert result["execution"].get("isolation_verified") is not True
    assert result["execution"]["cleanup_confirmed"] is True and not fake.created
    assert not any(c[:2] == ["container", "start"] and c[-1].endswith("-scan") for c in fake.calls)
    assert bool(started) == (which == "scan")  # guard failure: nothing started at all


# --- Attestation contract with the backend --------------------------------------------------------

def execution(**extra):
    base = {"id": TOKEN, "image_id": IMAGE, "limits": policy.LIMITS, "cleanup_confirmed": True, "egress_ip": "8.8.8.8",
            "egress_tcp_ports": [80, 443], "duration_ms": 1, "container_duration_ms": 1, "scanner_cpu_seconds": 0,
            "scanner_peak_rss_bytes": 1, "scanner_duration_ms": 1}
    return {**base, **extra}


def test_older_runner_is_recorded_as_not_attested(monkeypatch):
    monkeypatch.setattr(settings, "assessment_remote_require_isolation_attestation", False)
    assert runtime.validate_execution(execution(), TOKEN, IMAGE, "8.8.8.8")["isolation_attested"] is False


def test_verified_runner_is_attested():
    assert runtime.validate_execution(execution(isolation_verified=True), TOKEN, IMAGE, "8.8.8.8")["isolation_attested"] is True


@pytest.mark.parametrize("bad", [False, 1, "true", 0])
def test_forged_or_malformed_attestation_is_rejected(bad):
    with pytest.raises(remote.RemoteFailure, match="nmap_isolation_attestation_invalid"):
        runtime.validate_execution(execution(isolation_verified=bad), TOKEN, IMAGE, "8.8.8.8")


def test_attestation_can_be_required(monkeypatch):
    monkeypatch.setattr(settings, "assessment_remote_require_isolation_attestation", True)
    with pytest.raises(remote.RemoteFailure, match="nmap_isolation_attestation_required"):
        runtime.validate_execution(execution(), TOKEN, IMAGE, "8.8.8.8")


# --- R6: read-only orphan inventory ----------------------------------------------------------------

def inspect_blob(name, token=TOKEN, role="guard", state="exited", label="com.snwebshield.nmap"):
    labels = {label: token}
    if role: labels[label + ".role"] = role
    return json.dumps([{"Name": "/" + name, "Created": "2026-11-24T10:00:00.123456789Z", "State": {"Status": state},
                        "Config": {"Labels": labels}}]).encode()


class OrphanDocker:
    def __init__(self, runner, ids, blobs):
        self.calls, self.ids, self.blobs = [], ids, blobs
        runner.docker = self

    def __call__(self, args, **kw):
        self.calls.append(list(args))
        if args[:2] == ["container", "ls"]: return ("\n".join(self.ids) + "\n").encode()
        if args[:2] == ["container", "inspect"]: return self.blobs[args[2]]
        raise AssertionError("orphan listing must be read-only, got: " + " ".join(args))


@pytest.mark.parametrize("runner_name,label", [("nmap_runner", "com.snwebshield.nmap"), ("header_runner", "com.snwebshield.runner")])
def test_runner_lists_only_its_labelled_containers_and_never_modifies(request, runner_name, label):
    runner = request.getfixturevalue(runner_name)
    ids = ["1" * 64, "2" * 64]
    fake = OrphanDocker(runner, ids + ["not-a-container-id"], {
        ids[0]: inspect_blob("snws-x-1", label=label), ids[1]: inspect_blob("evil;rm -rf /", token="<script>", role="root", label=label)})
    report = runner.orphans()
    assert fake.calls[0][-2:] == ["--filter", "label=" + label]  # label-scoped, never an unfiltered listing
    assert {c[1] for c in fake.calls} <= {"ls", "inspect"}
    assert not any(w in " ".join(" ".join(c) for c in fake.calls) for w in ("rm", "stop", "kill", "prune", "start"))
    assert [o["id"] for o in report["orphans"]] == ["1" * 12, "2" * 12]
    assert report["orphans"][0]["token"] == TOKEN
    assert report["orphans"][1]["token"] is None and report["orphans"][1]["role"] in (None, "analysis")


def test_runner_orphan_listing_is_bounded(nmap_runner):
    ids = [f"{i:064x}" for i in range(80)]
    OrphanDocker(nmap_runner, ids, {i: inspect_blob("snws-x") for i in ids})
    report = nmap_runner.orphans()
    assert len(report["orphans"]) == 50 and report["truncated"] is True


def test_ssh_transport_allows_only_the_fixed_read_only_operation():
    args = ssh_transport.command("/usr/local/libexec/snwebshield-nmap-runner", "orphans")
    assert args[-2:] == ["/usr/local/libexec/snwebshield-nmap-runner", "--orphans"]
    for bad in ("rm", "prune", "orphans; rm -rf /", "list"):
        with pytest.raises(ValueError): ssh_transport.command("/usr/local/libexec/snwebshield-nmap-runner", bad)


def old_and_new():
    now = utc_now()
    return now, [
        {"name": "snws-nmap-" + TOKEN + "-guard", "id": "1" * 12, "token": TOKEN, "role": "guard", "state": "running",
         "created_at": (now - timedelta(hours=3)).isoformat()},
        {"name": "snws-nmap-" + "b" * 32 + "-scan", "id": "2" * 12, "token": "b" * 32, "role": "scan", "state": "exited",
         "created_at": (now - timedelta(seconds=20)).isoformat()}]


def fake_exchange(monkeypatch, replies, calls):
    def make(name):
        def exchange(operation, payload, permitted, seconds):
            calls.append((name, operation))
            reply = replies[name]
            if isinstance(reply, Exception): raise reply
            return reply
        return exchange
    monkeypatch.setattr(remote, "ssh_exchange", make("header"))
    monkeypatch.setattr(runtime, "exchange", make("nmap"))


def sections(report): return {s["scanner"]: s for s in report["sections"]}


def test_report_classifies_by_age_and_issues_only_the_read_only_operation(api, monkeypatch):
    monkeypatch.setattr(settings, "assessment_remote_docker_enabled", True)
    monkeypatch.setattr(settings, "assessment_nmap_enabled", True)
    now, items = old_and_new()
    calls = []
    fake_exchange(monkeypatch, {"header": {"orphans": []}, "nmap": {"orphans": items, "truncated": False}}, calls)
    response = api.get(URL)
    assert response.status_code == 200, response.text
    report = response.json()
    assert calls == [("header", "orphans"), ("nmap", "orphans")]  # nothing else is ever requested
    nmap = sections(report)["nmap"]
    assert [c["status"] for c in nmap["containers"]] == ["orphaned", "recent"]
    assert report["orphaned_total"] == 1 and "Nothing was removed" in report["guidance"]
    with SessionLocal() as db:
        event = db.scalar(select(ExecutionEvent).where(ExecutionEvent.action == "orphan_report_generated"))
        assert event and event.actor_id is not None and event.detail["orphaned"] == 1


def test_disabled_scanner_is_not_contacted(api, monkeypatch):
    monkeypatch.setattr(settings, "assessment_remote_docker_enabled", False)
    monkeypatch.setattr(settings, "assessment_nmap_enabled", False)
    calls = []
    fake_exchange(monkeypatch, {"header": {}, "nmap": {}}, calls)
    report = api.get(URL).json()
    assert calls == [] and {s["status"] for s in report["sections"]} == {"disabled"}


def test_unreachable_vm_and_old_runner_are_reported_not_hidden(api, monkeypatch):
    monkeypatch.setattr(settings, "assessment_remote_docker_enabled", True)
    monkeypatch.setattr(settings, "assessment_nmap_enabled", True)
    fake_exchange(monkeypatch, {"header": remote.RemoteFailure("ssh_unreachable"), "nmap": {"error": "x"}}, [])
    report = api.get(URL).json()
    assert sections(report)["header analysis"]["status"] == "unavailable"
    assert sections(report)["header analysis"]["error"] == "ssh_unreachable"
    assert sections(report)["nmap"]["status"] == "unsupported"


def test_hostile_runner_output_is_sanitised_and_unparseable_age_counts_as_orphaned(api, monkeypatch):
    monkeypatch.setattr(settings, "assessment_remote_docker_enabled", False)
    monkeypatch.setattr(settings, "assessment_nmap_enabled", True)
    hostile = {"name": "<img src=x onerror=alert(1)>", "id": "zz", "token": "'; DROP TABLE x;--", "role": "root",
               "state": "<b>running</b>" * 5, "created_at": "not a date"}
    fake_exchange(monkeypatch, {"header": {}, "nmap": {"orphans": [hostile, "junk", 7]}}, [])
    container = sections(api.get(URL).json())["nmap"]["containers"][0]
    assert container["name"] == "(unrecognised name)" and container["id"] is None
    assert container["token"] is None and container["role"] is None and len(container["state"]) <= 20
    assert container["status"] == "orphaned" and container["age_seconds"] is None


def test_report_needs_authentication_and_a_senior_role(api, monkeypatch):
    monkeypatch.setattr(settings, "assessment_nmap_enabled", False)
    monkeypatch.setattr(settings, "assessment_remote_docker_enabled", False)
    assert TestClient(app).get(URL).status_code == 401
    codes = {}
    for role in ("analyst", "lead_analyst", "admin"):
        email, _ = make_user(role)
        token = login(api, email).json()["access_token"]
        codes[role] = api.get(URL, headers={"Authorization": "Bearer " + token}).status_code
    assert codes == {"analyst": 403, "lead_analyst": 200, "admin": 200}
