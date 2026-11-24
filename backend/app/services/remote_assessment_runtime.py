"""Fixed SSH protocol to the existing VM. No local-analysis fallback or key handling."""
import math
import time
from uuid import uuid4

from app.core.config import settings
from app.services.header_analyzer import analyze
from app.services.local_assessment_runtime import Channel, RuntimeFailure, invoke

RUNNER = "/usr/local/libexec/snwebshield-header-runner"
VERSION = "ssh-docker-headers-v1"


class RemoteFailure(RuntimeFailure):
    def __init__(self, code, execution=None):
        super().__init__(code)
        self.execution = execution or {}


def ssh_exchange(operation, payload, permitted, seconds):
    # No host, command, image, Docker flags or SSH options originate in an API request.
    args = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=4", "-o", "ConnectionAttempts=1",
            "-o", "ServerAliveInterval=2", "-o", "ServerAliveCountMax=2",
            "azureuser@57.159.27.58", RUNNER]
    if operation == "check":
        args.append("--check")
    elif operation == "cleanup":
        import re
        if not isinstance(payload, str) or not re.fullmatch(r"[0-9a-f]{32}", payload):
            raise RemoteFailure("invalid_execution_id")
        args.extend(["--cleanup", payload])
    elif operation != "run":
        raise RemoteFailure("unsupported_remote_operation")
    channel = Channel(args, ssh_profile=True)
    try:
        if operation == "run":
            channel.send(payload)
        result = channel.receive(seconds, permitted)
        if not isinstance(result, dict):
            raise RemoteFailure("remote_protocol_invalid")
        return result
    finally:
        channel.close()


def validate_execution(value, token, image):
    from copy import deepcopy
    expected_limits = {"memory_bytes": 67108864, "cpus": 0.25, "pids": 16, "timeout_seconds": 8}
    if (not isinstance(value, dict) or value.get("id") != token or value.get("image_id") != image
            or value.get("limits") != expected_limits or value.get("cleanup_confirmed") is not True):
        raise RemoteFailure("remote_execution_contract_invalid")
    for field in ("duration_ms", "container_duration_ms", "analyzer_cpu_seconds", "analyzer_peak_rss_bytes", "analyzer_duration_ms"):
        number = value.get(field)
        if type(number) not in (float, int) or not math.isfinite(number) or number < 0:
            raise RemoteFailure("remote_usage_contract_invalid")
    # Whitelist persisted measurements, never persist arbitrary remote text/raw headers.
    return {k: deepcopy(value[k]) for k in ("id", "image_id", "limits", "cleanup_confirmed", "duration_ms",
        "container_duration_ms", "analyzer_cpu_seconds", "analyzer_peak_rss_bytes", "analyzer_duration_ms")}


class RemoteDockerAdapter:
    name = VERSION

    def execute(self, url, permitted):
        image = settings.assessment_remote_image_id
        if not settings.assessment_remote_docker_enabled or not image:
            raise RemoteFailure("remote_docker_disabled_or_image_not_pinned")
        if not permitted():
            raise RemoteFailure("permission_changed")
        # Establish SSH, Docker and image availability BEFORE any target network access.
        check = ssh_exchange("check", None, permitted, 10)
        if check != {"runner": VERSION, "image_id": image}:
            raise RemoteFailure("remote_preflight_failed")
        message = invoke("assessment_broker.py", {"url": url}, permitted, 13)
        if not isinstance(message, dict) or set(message) != {"result"}:
            raise RemoteFailure("local_head_broker_failed")
        transport = message["result"]
        data = {"https": transport["tls_verified"], "status": transport["status"],
                "headers": transport.pop("selected_headers")}
        expected = analyze(data)  # Contract validation of fixed observations, no scanner fallback.
        token = uuid4().hex
        started = time.monotonic()
        execution = {"id": token, "image_id": image, "cleanup_confirmed": False}
        completed = False
        try:
            if not permitted():
                raise RemoteFailure("permission_changed")
            reply = ssh_exchange("run", {"id": token, "data": data}, permitted, 22)
            if reply.get("error") or reply.get("analysis") != expected:
                raise RemoteFailure("remote_analysis_failed_or_contract_invalid")
            execution = validate_execution(reply.get("execution"), token, image)
            if not permitted():
                raise RemoteFailure("permission_changed", execution)
            completed = True
            transport.pop("facts", None)
            return {"state": "up", "mode": "remote_docker", "network_execution": True,
                    "outcome": "header_assessment_completed", "findings_created": 0,
                    "report": {"transport": transport, "analysis": reply["analysis"],
                               "adapter": self.name, "execution": execution}}
        except Exception as exc:
            # Disconnection is not evidence that remote removal completed. The runner has
            # its own bounded lifecycle. Attempt targeted removal and retain uncertainty.
            if not execution.get("cleanup_confirmed"):
                try:
                    cleanup = ssh_exchange("cleanup", token, lambda: True, 10)
                    execution["cleanup_request_succeeded"] = cleanup == {"cleanup_confirmed": True}
                except Exception:
                    execution["cleanup_request_succeeded"] = False
            code = str(exc) if isinstance(exc, RuntimeFailure) else "remote_execution_failed"
            raise RemoteFailure(code, execution) from exc
        finally:
            if not completed:
                execution["local_elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
