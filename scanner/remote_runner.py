#!/usr/bin/python3 -I
"""Install as /usr/local/libexec/snwebshield-header-runner. No shell or arbitrary argv.

Only creates/removes its own randomly named analysis containers. No daemon, build,
pull, host mounts, application data or credentials. Standard library only.
"""
import json
import re
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

DOCKER = "/usr/bin/docker"
IMAGE_FILE = Path("/etc/snwebshield/header-image-id")
LABEL = "com.snwebshield.runner"
VERSION = "ssh-docker-headers-v1"
LIMITS = {"memory_bytes": 67108864, "cpus": 0.25, "pids": 16, "timeout_seconds": 8}


class RunnerError(Exception):
    pass


def docker(args, *, data=None, seconds=4, allow_missing=False):
    # Temporary files bound memory even if a failing CLI emits excessive output.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            result = subprocess.run([DOCKER, *args], input=data, stdout=out, stderr=err,
                                    timeout=seconds, check=False, env={"PATH": "/usr/bin:/bin"})
        except subprocess.TimeoutExpired as exc:
            raise RunnerError("docker_deadline_exceeded") from exc
        out.seek(0)
        raw = out.read(32769)
        if len(raw) > 32768:
            raise RunnerError("docker_output_limit")
        if result.returncode:
            err.seek(0)
            error = err.read(4096)
            if allow_missing and b"No such container" in error:
                return None
            raise RunnerError("docker_command_failed")
        return raw


def image_id():
    image = IMAGE_FILE.read_text().strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise RunnerError("approved_image_not_configured")
    info = json.loads(docker(["image", "inspect", image]))[0]
    if info["Id"] != image or info["Config"].get("Volumes"):
        raise RunnerError("approved_image_invalid")
    return image


def container_name(token):
    if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{32}", token):
        raise RunnerError("invalid_execution_id")
    return "snws-headers-" + token


def cleanup(token, image):
    name = container_name(token)
    raw = docker(["container", "inspect", name], allow_missing=True)
    if raw is None:
        return True
    info = json.loads(raw)[0]
    if (info["Config"].get("Labels", {}).get(LABEL) != token or info["Image"] != image):
        raise RunnerError("cleanup_ownership_mismatch")
    docker(["container", "rm", "--force", name])
    return docker(["container", "inspect", name], allow_missing=True) is None


def create_args(token, image):
    return ["container", "create", "--pull=never", "--name", container_name(token),
            "--label", LABEL + "=" + token, "--network=none", "--user=65532:65532",
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
            "--memory=64m", "--memory-swap=64m", "--cpus=0.25", "--pids-limit=16",
            "--ulimit", "nofile=32:32", "--ulimit", "core=0:0", "--restart=no",
            "--log-driver=none", "--interactive", "--entrypoint=python", image,
            "-I", "-S", "-B", "/app/container_entry.py"]


def execute(token, data, image):
    name = container_name(token)
    started = time.monotonic()
    result = {"execution": {"id": token, "image_id": image, "limits": LIMITS,
                            "cleanup_confirmed": False}}
    try:
        docker(create_args(token, image))
        raw = docker(["container", "start", "--attach", "--interactive", name],
                     data=json.dumps(data, separators=(",", ":")).encode() + b"\n", seconds=8)
        state = json.loads(docker(["container", "inspect", name]))[0]["State"]
        if state["Running"] or state["ExitCode"] != 0 or state.get("OOMKilled"):
            raise RunnerError("analysis_container_failed")
        output = json.loads(raw)
        if set(output) != {"analysis", "usage"}:
            raise RunnerError("analysis_contract_invalid")
        result["analysis"] = output["analysis"]
        result["execution"].update(output["usage"])
        result["execution"].update(container_started_at=state["StartedAt"], container_finished_at=state["FinishedAt"])
        result["execution"]["container_duration_ms"] = round((
            datetime.fromisoformat(state["FinishedAt"]) - datetime.fromisoformat(state["StartedAt"])
        ).total_seconds() * 1000, 3)
    except (RunnerError, ValueError, KeyError, TypeError):
        result.pop("analysis", None)
        result["error"] = "remote_container_failed_or_timed_out"
    finally:
        # Finish targeted cleanup even if SSH teardown signals the remote process.
        for signame in ("SIGTERM", "SIGHUP"):
            if hasattr(signal, signame):
                signal.signal(getattr(signal, signame), signal.SIG_IGN)
        result["execution"]["duration_ms"] = round((time.monotonic() - started) * 1000, 3)
        try:
            result["execution"]["cleanup_confirmed"] = cleanup(token, image)
        except Exception:
            result["error"] = "remote_cleanup_unconfirmed"
            result.pop("analysis", None)
    return result


def main():
    # Commands are fixed; cleanup accepts only a broker-generated random hex ID.
    def interrupted(*_):
        raise RunnerError("remote_interrupted")
    for signame in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, signame):
            signal.signal(getattr(signal, signame), interrupted)
    image = image_id()
    args = sys.argv[1:]
    if args == ["--check"]:
        if docker(["info", "--format", "{{.OSType}}"]).strip() != b"linux":
            raise RunnerError("linux_docker_required")
        return {"runner": VERSION, "image_id": image}
    if len(args) == 2 and args[0] == "--cleanup":
        return {"cleanup_confirmed": cleanup(args[1], image)}
    if args:
        raise RunnerError("unsupported_operation")
    signal.alarm(5)  # Bound waiting for an input frame, too.
    raw = sys.stdin.buffer.readline(32769)
    signal.alarm(0)
    if len(raw) > 32768 or not raw.endswith(b"\n"):
        raise RunnerError("input_limit")
    payload = json.loads(raw)
    if set(payload) != {"id", "data"}:
        raise RunnerError("invalid_input")
    container_name(payload["id"])
    return execute(payload["id"], payload["data"], image)


if __name__ == "__main__":
    try:
        value = main()
    except Exception:
        value = {"error": "remote_runner_unavailable_or_invalid_input"}
    print(json.dumps(value, separators=(",", ":")), flush=True)
