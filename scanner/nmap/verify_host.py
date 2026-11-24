#!/usr/bin/python3 -I
"""Admin acceptance; only the existing VM's own public IP is a live test target."""
import importlib.machinery
import importlib.util
import json
import queue
import re
import subprocess
import threading
import time
from uuid import uuid4

RUNNER = "/usr/local/libexec/snwebshield-nmap-runner"
TARGET = {"ip": "57.159.27.58", "host": "vm.snwebshield.example", "dns_addresses": ["57.159.27.58"]}
DIAGNOSTIC = '''import errno,json,os,re,socket,subprocess
checks={"non_root":os.getuid()==65532,"no_capabilities":int(re.search(r"CapEff:\\s*(\\w+)",open("/proc/self/status").read()).group(1),16)==0}
try:
    with open("/app/snws-write-test","w") as stream:stream.write("test")
except OSError as error:checks["read_only"]=error.errno==errno.EROFS
else:checks["read_only"]=False
blocked=True
for host,port in [("57.159.27.58",22),("57.159.27.58",8080),("169.254.169.254",80),("127.0.0.1",53),("1.1.1.1",443),("::1",80)]:
    try:
        connection=socket.create_connection((host,port),timeout=.25)
    except TimeoutError:pass
    except OSError as error:
        if error.errno not in {errno.ENETUNREACH,errno.EHOSTUNREACH}:blocked=False
    else:
        connection.close();blocked=False
checks["forbidden_destinations_and_ports_blocked"]=blocked
attempt=subprocess.run(["/usr/sbin/iptables","-S","OUTPUT"],capture_output=True,timeout=2)
checks["scanner_cannot_manage_firewall"]=attempt.returncode!=0
print(json.dumps(checks),flush=True)
raise SystemExit(0 if all(checks.values()) else 2)
'''


def load():
    loader = importlib.machinery.SourceFileLoader("snws_nmap_test", RUNNER)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec); loader.exec_module(module)
    return module


def absent(runner, token):
    return all(runner.docker(["container", "inspect", name], allow_missing=True) is None for name in runner.names(token))


def verify():
    runner = load(); image = runner.image_id()
    result = {"image_id": image, "test_target": "existing_VM_only", "checks": {}}
    token = uuid4().hex
    scan = runner.execute(token, TARGET, image, lambda: True)
    assert "analysis" in scan and scan["execution"]["cleanup_confirmed"] and absent(runner, token), "nmap_smoke_failed"
    result["states"] = scan["states"]; result["execution"] = scan["execution"]
    result["checks"]["nmap_and_cleanup"] = True
    for ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1"):
        try: runner.policy.target({**TARGET, "ip": ip, "dns_addresses": [ip]})
        except ValueError: continue
        raise AssertionError("unsafe_input_accepted")
    result["checks"]["unsafe_targets_rejected"] = True

    token = uuid4().hex
    def inspect_boundary():
        scanner, guard = runner.names(token)
        args = runner.create_args(token, image, guard=False)
        args[-4:] = ["-I", "-S", "-B", "-c", DIAGNOSTIC]
        runner.docker(args)
        info = json.loads(runner.docker(["container", "inspect", scanner]))[0]
        host = info["HostConfig"]
        assert info["Config"]["User"] == "65532:65532" and host["ReadonlyRootfs"] and not info.get("Mounts"), "scanner_boundary_config"
        assert host["CapDrop"] == ["ALL"] and not host.get("CapAdd") and not host["Privileged"], "scanner_capability_config"
        assert host["NetworkMode"].startswith("container:") and host["Memory"] == 134217728 and host["NanoCpus"] == 500000000 and host["PidsLimit"] == 16, "scanner_resource_config"
        guard_info = json.loads(runner.docker(["container", "inspect", guard]))[0]
        guard_host = guard_info["HostConfig"]
        guard_caps = {cap.removeprefix("CAP_") for cap in guard_host["CapAdd"]}
        assert guard_host["NetworkMode"] == "bridge" and guard_caps == {"NET_ADMIN"} and not guard_host["Privileged"] and not guard_host.get("Binds"), "guard_scope_config: " + repr({key: guard_host.get(key) for key in ("NetworkMode", "CapAdd", "Privileged", "Binds")})
        checks = json.loads(runner.docker(["container", "start", "--attach", "--interactive", scanner], data=b"", seconds=8))
        assert all(checks.values()), "kernel_boundary_failed"
        result["checks"].update(checks)
        counters = runner.docker(["container", "exec", guard, "/usr/sbin/iptables", "-L", "OUTPUT", "-n", "-v", "-x"]).decode()
        dropped = re.search(r"policy DROP (\d+) packets", counters)
        assert dropped and int(dropped.group(1)) >= 5, "kernel_drop_counters_missing"
        ipv6 = runner.docker(["container", "exec", guard, "/usr/sbin/ip6tables", "-S", "OUTPUT"])
        assert b"-P OUTPUT DROP" in ipv6, "ipv6_policy_not_closed"
        result["checks"]["kernel_drop_counters_and_ipv6_policy"] = True
        return False  # Exercise the pre-scan permission gate and its cleanup.
    boundary_errors = []
    def checked_boundary():
        try: return inspect_boundary()
        except Exception as error:
            boundary_errors.append(str(error))
            raise
    isolated = runner.execute(token, TARGET, image, checked_boundary)
    assert "error" in isolated and isolated["execution"]["cleanup_confirmed"] and absent(runner, token), "gate_cleanup_failed"
    assert result["checks"].get("kernel_drop_counters_and_ipv6_policy"), "boundary_check_not_completed: " + repr(boundary_errors)
    result["checks"]["permission_gate_and_cleanup"] = True

    token = uuid4().hex
    original = runner.create_args
    def sleepy(token, image, *, guard):
        args = original(token, image, guard=guard)
        if not guard: args[-4:] = ["-I", "-S", "-B", "-c", "import time;time.sleep(30)"]
        return args
    runner.create_args = sleepy
    started = time.monotonic()
    try: timed = runner.execute(token, TARGET, image, lambda: True)
    finally: runner.create_args = original
    assert "error" in timed and timed["execution"]["cleanup_confirmed"] and absent(runner, token), "timeout_cleanup_failed"
    assert time.monotonic() - started < 28, "timeout_not_bounded"
    result["checks"]["timeout_and_cleanup"] = True

    token = uuid4().hex
    child_code = '''import importlib.machinery,importlib.util,json
loader=importlib.machinery.SourceFileLoader("snws_child","/usr/local/libexec/snwebshield-nmap-runner")
spec=importlib.util.spec_from_loader(loader.name,loader);runner=importlib.util.module_from_spec(spec);loader.exec_module(runner)
original=runner.create_args
def sleepy(token,image,*,guard):
    args=original(token,image,guard=guard)
    if not guard:args[-4:]=["-I","-S","-B","-c","import time;time.sleep(30)"]
    return args
runner.create_args=sleepy
print(json.dumps(runner.main()),flush=True)
'''
    child = subprocess.Popen(["/usr/bin/python3", "-I", "-c", child_code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        child.stdin.write(json.dumps({"id": token, "target": TARGET}).encode() + b"\n"); child.stdin.flush()
        ready = queue.Queue(maxsize=1)
        threading.Thread(target=lambda: ready.put(child.stdout.readline(1025)), daemon=True).start()
        assert json.loads(ready.get(timeout=14)) == {"permission": True}, "cancellation_gate_missing"
        child.stdin.write(b"true\n"); child.stdin.flush()
        deadline = time.monotonic() + 6
        running = False
        while time.monotonic() < deadline:
            raw = runner.docker(["container", "inspect", runner.names(token)[0]], allow_missing=True)
            if raw and json.loads(raw)[0]["State"]["Running"]: running = True; break
            time.sleep(.2)
        assert running, "cancellation_fixture_not_running"
        child.terminate()
        out, _ = child.communicate(timeout=12)
        cancelled = json.loads(out)
        assert "error" in cancelled and cancelled["execution"]["cleanup_confirmed"] and absent(runner, token), "cancellation_cleanup_failed"
        result["checks"]["cancellation_and_cleanup"] = True
    finally:
        if child.poll() is None: child.kill(); child.communicate(timeout=3)
        assert runner.cleanup(token, image), "final_cleanup_unconfirmed"
    result["passed"] = all(result["checks"].values())
    return result


if __name__ == "__main__":
    try: output = verify()
    except Exception as error:
        print(json.dumps({"passed": False, "error": str(error)[:300], "type": type(error).__name__}), flush=True)
        raise SystemExit(1)
    print(json.dumps(output, separators=(",", ":")), flush=True)
