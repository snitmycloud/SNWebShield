#!/usr/bin/python3 -I
"""Fixed Nmap runner; scanner and firewall helper share ONLY a network namespace."""
from datetime import datetime
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import queue
import re
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec); loader.exec_module(module)
    return module


common = load("snws_header_helpers", "/usr/local/libexec/snwebshield-header-runner")
policy = load("snws_nmap_policy", "/usr/local/lib/snwebshield/nmap_policy.py")
docker, RunnerError = common.docker, common.RunnerError
LABEL = "com.snwebshield.nmap"
IMAGE_FILE = Path("/etc/snwebshield/nmap-image-id")


def image_id():
    image = IMAGE_FILE.read_text().strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image): raise RunnerError("image_not_pinned")
    info = json.loads(docker(["image", "inspect", image]))[0]
    if info["Id"] != image or info["Config"].get("Volumes"): raise RunnerError("image_invalid")
    return image


def names(token):
    if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{32}", token): raise RunnerError("invalid_execution_id")
    return ["snws-nmap-" + token + "-scan", "snws-nmap-" + token + "-guard"]


def create_args(token, image, *, guard):
    scan, carrier = names(token)
    return ["container", "create", "--pull=never", "--name", carrier if guard else scan,
        "--label", LABEL + "=" + token, "--label", LABEL + ".role=" + ("guard" if guard else "scan"),
        "--network=" + ("bridge" if guard else "container:" + carrier),
        "--user=" + ("0:0" if guard else "65532:65532"), "--read-only", "--cap-drop=ALL",
        *(["--cap-add=NET_ADMIN", "--tmpfs=/run:rw,noexec,nosuid,size=65536,mode=0700"] if guard else []),
        "--security-opt=no-new-privileges=true", "--memory=" + ("64m" if guard else "128m"),
        "--memory-swap=" + ("64m" if guard else "128m"), "--cpus=" + ("0.1" if guard else "0.5"),
        "--pids-limit=16", "--ulimit", "nofile=64:64", "--ulimit", "core=0:0", "--restart=no",
        "--log-driver=none", "--interactive", "--entrypoint=python", image,
        "-I", "-S", "-B", "/app/nmap_guard.py" if guard else "/app/nmap_entry.py"]


EXPECTED = {  # what create_args() requests; verify_isolation() checks what Docker actually created
    "guard": {"user": "0:0", "memory": 67108864, "nano_cpus": 100000000},
    "scan": {"user": "65532:65532", "memory": 134217728, "nano_cpus": 500000000},
}


def _caps(values):
    return sorted(str(v).upper().removeprefix("CAP_") for v in values or [])


def isolation_failures(info, token, image, role, carrier_name=None, carrier_id=None):
    """Names of every inspected property that differs from policy (empty list means compliant).

    Run on each container after create and BEFORE start, so a daemon default, plugin or edit that
    weakens isolation can never execute. The guard legitimately keeps root and NET_ADMIN; it is
    checked exactly (NET_ADMIN only, no privileged mode, no mounts but its tmpfs, bounded resources)
    rather than trusted. The scanner must have no added capability and share only the guard's netns.
    """
    want = EXPECTED[role]
    host, config = info.get("HostConfig") or {}, info.get("Config") or {}
    labels = config.get("Labels") or {}
    mounts = [m for m in info.get("Mounts") or []
              if not (role == "guard" and m.get("Type") == "tmpfs" and m.get("Destination") == "/run")]
    tmpfs = host.get("Tmpfs") or {}
    network = host.get("NetworkMode")
    if role == "guard":
        network_ok = network in ("bridge", "default")
        tmpfs_ok = set(tmpfs) <= {"/run"}
        caps_ok = _caps(host.get("CapAdd")) == ["NET_ADMIN"]
    else:
        network_ok = (isinstance(network, str) and network.startswith("container:")
                      and network[len("container:"):] in {carrier_name, carrier_id} - {None})
        tmpfs_ok = not tmpfs
        caps_ok = not host.get("CapAdd")
    checks = {
        "image": info.get("Image") == image,
        "owner_label": labels.get(LABEL) == token and labels.get(LABEL + ".role") == role,
        "network": network_ok,
        "user": config.get("User") == want["user"],
        "read_only_rootfs": host.get("ReadonlyRootfs") is True,
        "not_privileged": host.get("Privileged") is False,
        "capabilities": "ALL" in _caps(host.get("CapDrop")) and caps_ok,
        "no_new_privileges": any("no-new-privileges" in str(i) for i in host.get("SecurityOpt") or []),
        "memory": host.get("Memory") == want["memory"] and host.get("MemorySwap") == want["memory"],
        "cpu": host.get("NanoCpus") == want["nano_cpus"],
        "pids": host.get("PidsLimit") == 16,
        "no_host_namespaces": host.get("PidMode") in ("", None, "private")
                              and not str(host.get("IpcMode") or "").startswith(("host", "container")),
        "no_mounts": not mounts and not host.get("Binds") and tmpfs_ok,
        "no_published_ports": not host.get("PortBindings"),
        "no_devices": not host.get("Devices"),
        "no_restart": (host.get("RestartPolicy") or {}).get("Name") in ("no", ""),
        "no_logging": (host.get("LogConfig") or {}).get("Type") == "none",
    }
    return [name for name, ok in checks.items() if not ok]


def verify_isolation(info, token, image, role, carrier_name=None, carrier_id=None):
    if isolation_failures(info, token, image, role, carrier_name, carrier_id):
        raise RunnerError("container_isolation_mismatch")
    return True


def orphans(limit=50):
    """Read-only inventory of containers carrying this runner's label. Never removes anything."""
    raw = docker(["container", "ls", "--all", "--no-trunc", "--quiet", "--filter", "label=" + LABEL])
    ids = [i for i in raw.decode().split() if re.fullmatch(r"[0-9a-f]{64}", i)][:limit]
    found = []
    for cid in ids:
        info = json.loads(docker(["container", "inspect", cid]))[0]
        labels = info["Config"].get("Labels") or {}
        token = labels.get(LABEL)
        found.append({"name": str(info["Name"]).lstrip("/")[:80], "id": cid[:12],
            "token": token if isinstance(token, str) and re.fullmatch(r"[0-9a-f]{32}", token) else None,
            "role": labels.get(LABEL + ".role") if labels.get(LABEL + ".role") in ("scan", "guard") else None,
            "state": str(info["State"]["Status"])[:20], "created_at": str(info["Created"])[:40]})
    return {"runner": policy.VERSION, "label": LABEL, "orphans": found, "truncated": len(ids) == limit}


def cleanup(token, image):
    for name, role in zip(names(token), ("scan", "guard")):
        raw = docker(["container", "inspect", name], allow_missing=True)
        if raw is None: continue
        info = json.loads(raw)[0]
        labels = info["Config"].get("Labels", {})
        if info["Image"] != image or labels.get(LABEL) != token or labels.get(LABEL + ".role") != role:
            raise RunnerError("cleanup_ownership_mismatch")
        docker(["container", "rm", "--force", name])
        if docker(["container", "inspect", name], allow_missing=True) is not None:
            raise RunnerError("cleanup_unconfirmed")
    return True


def gate():
    print('{"permission":true}', flush=True)
    readable, _, _ = select.select([sys.stdin], [], [], 3)
    return bool(readable and sys.stdin.buffer.readline(16).strip() == b"true")


def execute(token, target, image, permitted=gate):
    policy.target(target)
    scan, carrier = names(token)
    started = time.monotonic()
    result = {"execution": {"id": token, "image_id": image, "limits": policy.LIMITS,
        "cleanup_confirmed": False, "egress_ip": target["ip"], "egress_tcp_ports": list(policy.PORTS)}}
    attached = None
    error_file = tempfile.TemporaryFile()
    try:
        docker(create_args(token, image, guard=True))
        guard_info = json.loads(docker(["container", "inspect", carrier]))[0]
        verify_isolation(guard_info, token, image, "guard")  # before the root/NET_ADMIN guard ever starts
        attached =subprocess.Popen(["/usr/bin/docker", "container", "start", "--attach", "--interactive", carrier],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error_file, env={"PATH": "/usr/bin:/bin"})
        ready = queue.Queue(maxsize=1)
        def read_ready():
            try:
                raw = attached.stdout.readline(1025)
                ready.put_nowait(json.loads(raw) if len(raw) <= 1024 else None)
            except Exception:
                try: ready.put_nowait(None)
                except queue.Full: pass
        reader = threading.Thread(target=read_ready, daemon=True); reader.start()
        attached.stdin.write(json.dumps({"ip": target["ip"]}).encode() + b"\n"); attached.stdin.flush()
        if ready.get(timeout=10) != {"ready": True}: raise RunnerError("egress_policy_not_ready")
        info = json.loads(docker(["container", "inspect", carrier]))[0]
        if not info["State"]["Running"]: raise RunnerError("egress_policy_exited")
        if not permitted(): raise RunnerError("permission_changed")
        docker(create_args(token, image, guard=False))
        verify_isolation(json.loads(docker(["container", "inspect", scan]))[0], token, image, "scan",
                         carrier_name=carrier, carrier_id=guard_info.get("Id"))
        result["execution"]["isolation_verified"] = True  # both containers inspected before start
        raw = docker(["container", "start", "--attach", "--interactive", scan],
            data=json.dumps({"ip": target["ip"]}).encode() + b"\n", seconds=12)
        state = json.loads(docker(["container", "inspect", scan]))[0]["State"]
        if state["Running"] or state["ExitCode"] or state.get("OOMKilled"): raise RunnerError("nmap_container_failed")
        output = json.loads(raw)
        if set(output) != {"analysis", "states", "usage"} or output["analysis"] != policy.analysis(output["states"]):
            raise RunnerError("nmap_contract_invalid")
        result.update(analysis=output["analysis"], states=output["states"])
        result["execution"].update(output["usage"])
        result["execution"]["container_duration_ms"] = round((datetime.fromisoformat(state["FinishedAt"]) -
            datetime.fromisoformat(state["StartedAt"])).total_seconds() * 1000, 3)
    except Exception:
        result.pop("analysis", None); result.pop("states", None)
        result["error"] = "nmap_execution_or_permission_failed"
    finally:
        for name in ("SIGTERM", "SIGHUP"):
            if hasattr(signal, name): signal.signal(getattr(signal, name), signal.SIG_IGN)
        result["execution"]["duration_ms"] = round((time.monotonic() - started) * 1000, 3)
        try: result["execution"]["cleanup_confirmed"] = cleanup(token, image)
        except Exception:
            result["error"] = "nmap_cleanup_unconfirmed"; result.pop("analysis", None); result.pop("states", None)
        if attached:
            if attached.poll() is None: attached.kill()
            try: attached.wait(timeout=2)
            except subprocess.TimeoutExpired: pass
            attached.stdin.close(); attached.stdout.close()
        error_file.close()
    return result


def main():
    def interrupted(*_): raise RunnerError("interrupted")
    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name): signal.signal(getattr(signal, name), interrupted)
    image = image_id()
    args = sys.argv[1:]
    if args == ["--check"]:
        if docker(["info", "--format", "{{.OSType}}"]).strip() != b"linux": raise RunnerError("linux_required")
        return {"runner": policy.VERSION, "image_id": image, "ports": list(policy.PORTS)}
    if args == ["--orphans"]: return orphans()
    if len(args) == 2 and args[0] == "--cleanup": return {"cleanup_confirmed": cleanup(args[1], image)}
    if args: raise RunnerError("unsupported_operation")
    signal.alarm(4)
    raw = sys.stdin.buffer.readline(4097)
    signal.alarm(0)
    if len(raw) > 4096: raise RunnerError("input_limit")
    payload = json.loads(raw)
    if not isinstance(payload, dict) or set(payload) != {"id", "target"}: raise RunnerError("invalid_input")
    return execute(payload["id"], payload["target"], image)


if __name__ == "__main__":
    try: result = main()
    except Exception: result = {"error": "nmap_runner_unavailable_or_input_rejected"}
    print(json.dumps(result, separators=(",", ":")), flush=True)
