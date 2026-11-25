"""Fixed SSH protocol to the existing VM. No local-analysis fallback or key handling."""
import math
import time
from uuid import uuid4

from app.core.config import settings
from app.services import ssh_transport
from app.services.header_analyzer import analyze
from app.services.local_assessment_runtime import Channel, RuntimeFailure, invoke

RUNNER = "/usr/local/libexec/snwebshield-header-runner"
VERSION = "ssh-docker-headers-v1"
LIMITS = {"memory_bytes": 67108864, "cpus": 0.25, "pids": 16, "timeout_seconds": 8}
# Stage budgets. Their sum (plus margin) must stay below the assessment job lease
# so a slow run is failed by its own deadline, never silently by lease expiry.
CHECK_SECONDS, BROKER_SECONDS, RUN_SECONDS, CLEANUP_SECONDS = 10, 13, 22, 10
WORST_CASE_SECONDS = CHECK_SECONDS + BROKER_SECONDS + RUN_SECONDS + CLEANUP_SECONDS


class RemoteFailure(RuntimeFailure):
    def __init__(self, code, execution=None):
        super().__init__(code)
        self.execution = execution or {}


def open_channel(runner, operation, payload=None):
    """Start the fixed SSH process or fail closed. There is no local fallback."""
    try:
        args = ssh_transport.command(runner, operation, payload if operation == "cleanup" else None)
    except ValueError as exc:
        raise RemoteFailure(str(exc)) from exc
    except ssh_transport.SSHUnavailable as exc:
        raise RemoteFailure("ssh_client_unavailable") from exc
    try:
        return Channel(args, ssh_profile=True)
    except OSError as exc:
        raise RemoteFailure("ssh_client_unavailable") from exc


def ssh_exchange(operation, payload, permitted, seconds):
    # No host, command, image, Docker flags or SSH options originate in an API request.
    channel = open_channel(RUNNER, operation, payload)
    try:
        if operation == "run":
            channel.send(payload)
        result = channel.receive(seconds, permitted)
        if not isinstance(result, dict):
            raise RemoteFailure("remote_protocol_invalid")
        return result
    except RemoteFailure:
        raise
    except RuntimeFailure as exc:
        # Keep the specific transport code (unreachable, deadline, cancelled) for the audit trail.
        raise RemoteFailure(str(exc)) from exc
    finally:
        channel.close()


def validate_execution(value, token, image):
    from copy import deepcopy
    if (not isinstance(value, dict) or value.get("id") != token or value.get("image_id") != image
            or value.get("limits") != LIMITS or value.get("cleanup_confirmed") is not True):
        raise RemoteFailure("remote_execution_contract_invalid")
    for field in ("duration_ms", "container_duration_ms", "analyzer_cpu_seconds", "analyzer_peak_rss_bytes", "analyzer_duration_ms"):
        number = value.get(field)
        if type(number) not in (float, int) or not math.isfinite(number) or number < 0:
            raise RemoteFailure("remote_usage_contract_invalid")
    # Runners from Milestone 1 onward inspect each created container and refuse to
    # start it unless its isolation matches policy. Older installed runners do not
    # report this; record that honestly and optionally require the attestation.
    attestation = value.get("isolation_verified")
    if attestation is not None and attestation is not True:  # identity: 1 == True must not pass
        raise RemoteFailure("remote_isolation_attestation_invalid")
    if attestation is None and settings.assessment_remote_require_isolation_attestation:
        raise RemoteFailure("remote_isolation_attestation_required")
    # Whitelist persisted measurements, never persist arbitrary remote text/raw headers.
    accepted = {k: deepcopy(value[k]) for k in ("id", "image_id", "limits", "cleanup_confirmed", "duration_ms",
        "container_duration_ms", "analyzer_cpu_seconds", "analyzer_peak_rss_bytes", "analyzer_duration_ms")}
    accepted["isolation_attested"] = attestation is True
    return accepted


class RemoteDockerAdapter:
    name = VERSION

    def execute(self, url, permitted):
        image = settings.assessment_remote_image_id
        if not settings.assessment_remote_docker_enabled or not image:
            raise RemoteFailure("remote_docker_disabled_or_image_not_pinned")
        if not permitted():
            raise RemoteFailure("permission_changed")
        # Establish SSH, Docker and image availability BEFORE any target network access.
        check = ssh_exchange("check", None, permitted, CHECK_SECONDS)
        if check != {"runner": VERSION, "image_id": image}:
            raise RemoteFailure("remote_preflight_failed")
        message = invoke("assessment_broker.py", {"url": url}, permitted, BROKER_SECONDS)
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
            reply = ssh_exchange("run", {"id": token, "data": data}, permitted, RUN_SECONDS)
            if reply.get("error") or reply.get("analysis") != expected:
                raise RemoteFailure("remote_analysis_failed_or_contract_invalid")
            execution = validate_execution(reply.get("execution"), token, image)
            if not permitted():
                raise RemoteFailure("permission_changed", execution)
            completed = True
            from app.services.passive_checks import merge
            analysis = merge(reply["analysis"], transport, transport.pop("facts", None))  # backend-only extras
            return {"state": "up", "mode": "remote_docker", "network_execution": True,
                    "outcome": "header_assessment_completed", "findings_created": 0,
                    "report": {"transport": transport, "analysis": analysis,
                               "adapter": self.name, "execution": execution}}
        except Exception as exc:
            # Disconnection is not evidence that remote removal completed. The runner has
            # its own bounded lifecycle. Attempt targeted removal and retain uncertainty.
            if not execution.get("cleanup_confirmed"):
                try:
                    cleanup = ssh_exchange("cleanup", token, lambda: True, CLEANUP_SECONDS)
                    execution["cleanup_request_succeeded"] = cleanup == {"cleanup_confirmed": True}
                except Exception:
                    execution["cleanup_request_succeeded"] = False
            code = str(exc) if isinstance(exc, RuntimeFailure) else "remote_execution_failed"
            raise RemoteFailure(code, execution) from exc
        finally:
            if not completed:
                execution["local_elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
