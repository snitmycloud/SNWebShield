#!/usr/bin/python3 -I
"""Administrator-run acceptance on the existing VM, never an API scanner mode.

Uses only the installed approved image and new randomly labelled test containers.
No pulls/builds, target requests, host mounts or deletion of pre-existing objects.
"""
import importlib.machinery
import importlib.util
import json
import subprocess
import sys
import time
from uuid import uuid4

RUNNER = "/usr/local/libexec/snwebshield-header-runner"
DATA = {"https": True, "status": 200, "headers": {"x-content-type-options": "nosniff"}}
ISOLATION_CODE = '''import errno,json,os,socket
checks={"non_root":os.getuid()==65532,"only_loopback":set(n for _,n in socket.if_nameindex())=={"lo"}}
try:
    with open("/app/snws-write-test","w") as stream: stream.write("test")
except OSError as error: checks["read_only"]=error.errno==errno.EROFS
else: checks["read_only"]=False
try:
    connection=socket.create_connection(("1.1.1.1",443),timeout=1)
except OSError as error: checks["network_unreachable"]=error.errno in {errno.ENETUNREACH,errno.EHOSTUNREACH}
else:
    connection.close(); checks["network_unreachable"]=False
print(json.dumps(checks),flush=True)
raise SystemExit(0 if all(checks.values()) else 2)
'''


def load_runner():
    loader = importlib.machinery.SourceFileLoader("snws_installed_runner", RUNNER)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def absent(runner, token):
    return runner.docker(["container", "inspect", runner.container_name(token)], allow_missing=True) is None


def fixed_test_args(runner, token, image, code):
    args = runner.create_args(token, image)
    args[-4:] = ["-I", "-S", "-B", "-c", code]
    return args


def verify():
    runner = load_runner()
    image = runner.image_id()
    result = {"image_id": image, "checks": {}}

    token = uuid4().hex
    smoke = runner.execute(token, DATA, image)
    assert "analysis" in smoke and smoke["execution"]["cleanup_confirmed"] and absent(runner, token), "smoke_or_cleanup_failed"
    result["checks"]["analysis_and_cleanup"] = True
    result["usage"] = {k: v for k, v in smoke["execution"].items() if k.endswith(("_ms", "_seconds", "_bytes"))}

    token = uuid4().hex
    denied = runner.execute(token, {**DATA, "headers": {"cookie": "synthetic-rejected"}}, image)
    assert "error" in denied and "analysis" not in denied and denied["execution"]["cleanup_confirmed"] and absent(runner, token), "unselected_header_not_rejected"
    result["checks"]["unselected_header_denied"] = True

    token = uuid4().hex
    try:
        runner.docker(fixed_test_args(runner, token, image, ISOLATION_CODE))
        info = json.loads(runner.docker(["container", "inspect", runner.container_name(token)]))[0]
        host = info["HostConfig"]
        assert host["NetworkMode"] == "none" and host["ReadonlyRootfs"] and not info.get("Mounts"), "isolation_config_failed"
        assert info["Config"]["User"] == "65532:65532", "user_config_failed"
        assert host["Memory"] == 67108864 and host["MemorySwap"] == 67108864 and host["NanoCpus"] == 250000000 and host["PidsLimit"] == 16, "resource_config_failed"
        assert "ALL" in host["CapDrop"] and any("no-new-privileges" in item for item in host["SecurityOpt"]), "privilege_config_failed"
        checks = json.loads(runner.docker(["container", "start", "--attach", "--interactive", runner.container_name(token)], data=b"", seconds=8))
        assert checks and all(checks.values()), "kernel_isolation_failed"
        result["checks"].update(checks)
        result["checks"]["docker_resource_and_privilege_config"] = True
    finally:
        assert runner.cleanup(token, image), "isolation_cleanup_unconfirmed"

    # Test the installed execution watchdog with a fixed sleeping program using
    # the same approved image/config, without extending the production protocol.
    token = uuid4().hex
    original_args = runner.create_args
    def sleepy_args(test_token, test_image):
        args = original_args(test_token, test_image)
        args[-4:] = ["-I", "-S", "-B", "-c", "import time;time.sleep(30)"]
        return args
    runner.create_args = sleepy_args
    started = time.monotonic()
    try:
        timed = runner.execute(token, DATA, image)
    finally:
        runner.create_args = original_args
    assert "error" in timed and timed["execution"]["cleanup_confirmed"] and absent(runner, token), "timeout_cleanup_failed"
    assert time.monotonic() - started < 24, "deadline_not_bounded"
    result["checks"]["timeout_and_cleanup"] = True

    # SIGTERM the installed lifecycle after a test container is actually running.
    # The child installs the runner's own handlers via main(), not test handlers.
    token = uuid4().hex
    child_code = '''import importlib.machinery,importlib.util,json
loader=importlib.machinery.SourceFileLoader("snws_child_runner","/usr/local/libexec/snwebshield-header-runner")
spec=importlib.util.spec_from_loader(loader.name,loader)
runner=importlib.util.module_from_spec(spec);loader.exec_module(runner)
original=runner.create_args
def sleepy(token,image):
    args=original(token,image);args[-4:]=["-I","-S","-B","-c","import time;time.sleep(30)"];return args
runner.create_args=sleepy
print(json.dumps(runner.main()),flush=True)
'''
    child = subprocess.Popen(["/usr/bin/python3", "-I", "-c", child_code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        child.stdin.write(json.dumps({"id": token, "data": DATA}).encode() + b"\n")
        child.stdin.flush()
        deadline = time.monotonic() + 10
        running = False
        while time.monotonic() < deadline and child.poll() is None:
            raw = runner.docker(["container", "inspect", runner.container_name(token)], allow_missing=True)
            if raw and json.loads(raw)[0]["State"]["Running"]:
                running = True
                break
            time.sleep(.2)
        assert running, "cancellation_fixture_not_running"
        child.terminate()
        out, _ = child.communicate(timeout=16)
        assert len(out) <= 32768, "cancellation_output_limit"
        cancelled = json.loads(out)
        assert "error" in cancelled and cancelled["execution"]["cleanup_confirmed"] and absent(runner, token), "cancellation_cleanup_failed"
        result["checks"]["cancellation_and_cleanup"] = True
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=3)
        assert runner.cleanup(token, image), "cancellation_final_cleanup_unconfirmed"
    result["passed"] = all(result["checks"].values())
    return result


if __name__ == "__main__":
    try:
        output = verify()
    except Exception as error:
        print(json.dumps({"passed": False, "error_type": type(error).__name__, "error": str(error)[:300]}), flush=True)
        raise SystemExit(1)
    print(json.dumps(output, separators=(",", ":")), flush=True)
