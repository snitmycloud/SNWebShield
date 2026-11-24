"""Fixed SSH Nmap adapter. The local broker performs DNS only, never scanning."""
import math
import time
from uuid import uuid4

from app.core.config import settings
from app.services.local_assessment_runtime import RuntimeFailure, invoke
from app.services.remote_assessment_runtime import RemoteFailure, open_channel
from app.services import nmap_policy as policy

RUNNER = "/usr/local/libexec/snwebshield-nmap-runner"
CHECK_SECONDS, BROKER_SECONDS, RUN_SECONDS, CLEANUP_SECONDS = 8, 5, 32, 8
WORST_CASE_SECONDS = CHECK_SECONDS + BROKER_SECONDS + RUN_SECONDS + CLEANUP_SECONDS


def exchange(operation, payload, permitted, seconds):
    channel = open_channel(RUNNER, operation, payload)
    try:
        if operation == "run": channel.send(payload)
        deadline = time.monotonic() + seconds
        for _ in range(3):
            message = channel.receive(max(.01, deadline - time.monotonic()), permitted)
            if message == {"permission": True}:
                channel.send(bool(permitted()))
            elif isinstance(message, dict): return message
            else: raise RemoteFailure("nmap_protocol_invalid")
        raise RemoteFailure("nmap_protocol_budget")
    except RemoteFailure:
        raise
    except RuntimeFailure as exc:
        raise RemoteFailure(str(exc)) from exc
    finally: channel.close()


def validate_execution(value, token, image, ip):
    if (not isinstance(value, dict) or value.get("id") != token or value.get("image_id") != image
            or value.get("limits") != policy.LIMITS or value.get("cleanup_confirmed") is not True
            or value.get("egress_ip") != ip or value.get("egress_tcp_ports") != list(policy.PORTS)):
        raise RemoteFailure("nmap_execution_contract_invalid")
    fields = ("duration_ms", "container_duration_ms", "scanner_cpu_seconds", "scanner_peak_rss_bytes", "scanner_duration_ms")
    for key in fields:
        number = value.get(key)
        if type(number) not in (float, int) or not math.isfinite(number) or number < 0:
            raise RemoteFailure("nmap_usage_contract_invalid")
    # Runners from this milestone inspect both containers before starting them. Older installed runners
    # do not report it: record that honestly, and fail closed only when attestation is required.
    attestation = value.get("isolation_verified")
    if attestation is not None and attestation is not True:  # identity: 1 == True must not pass
        raise RemoteFailure("nmap_isolation_attestation_invalid")
    if attestation is None and settings.assessment_remote_require_isolation_attestation:
        raise RemoteFailure("nmap_isolation_attestation_required")
    accepted = {key: value[key] for key in ("id", "image_id", "limits", "cleanup_confirmed", "egress_ip", "egress_tcp_ports", *fields)}
    accepted["isolation_attested"] = attestation is True
    return accepted


class NmapAdapter:
    name = policy.VERSION

    def __init__(self, *, authorized_domains):
        self.authorized_domains = tuple(authorized_domains)

    def execute(self, url, permitted):
        image = settings.assessment_nmap_image_id
        if not settings.assessment_nmap_enabled or not image: raise RemoteFailure("nmap_disabled_or_image_not_pinned")
        if not permitted(): raise RemoteFailure("permission_changed")
        if exchange("check", None, permitted, CHECK_SECONDS) != {"runner": policy.VERSION, "image_id": image, "ports": list(policy.PORTS)}:
            raise RemoteFailure("nmap_preflight_failed")
        resolved = invoke("nmap_broker.py", {"url": url}, permitted, BROKER_SECONDS)
        if not isinstance(resolved, dict) or set(resolved) != {"result"}: raise RemoteFailure("nmap_dns_or_permission_rejected")
        target = policy.target(resolved["result"])
        # Domain ownership alone is not approval to port-scan a shared/CDN IP.
        # The pinned IP must also be explicitly present in the reviewed scope.
        approved = sorted(set(target["dns_addresses"]) & set(self.authorized_domains))
        if not approved or target["host"] not in self.authorized_domains:
            raise RemoteFailure("resolved_ip_not_explicitly_authorized")
        target = {**target, "ip": approved[0]}
        token, started = uuid4().hex, time.monotonic()
        execution = {"id": token, "image_id": image, "cleanup_confirmed": False}
        try:
            if not permitted(): raise RemoteFailure("permission_changed")
            result = exchange("run", {"id": token, "target": target}, permitted, RUN_SECONDS)
            expected = policy.analysis(result.get("states"))
            if result.get("error") or result.get("analysis") != expected: raise RemoteFailure("nmap_result_invalid")
            execution = validate_execution(result.get("execution"), token, image, target["ip"])
            if not permitted(): raise RemoteFailure("permission_changed")
            return {"state": "up", "mode": "remote_nmap", "network_execution": True,
                "outcome": "tcp_port_assessment_completed", "findings_created": 0,
                "report": {"adapter": self.name, "analysis": expected, "execution": execution,
                    "transport": {"protocol": "tcp", "connected_ip": target["ip"], "dns_addresses": target["dns_addresses"],
                        "ports": list(policy.PORTS), "response_ms": round((time.monotonic() - started) * 1000, 3)}}}
        except Exception as error:
            if not execution.get("cleanup_confirmed"):
                try: execution["cleanup_request_succeeded"] = exchange("cleanup", token, lambda: True, CLEANUP_SECONDS) == {"cleanup_confirmed": True}
                except Exception: execution["cleanup_request_succeeded"] = False
            execution["local_elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
            code = str(error) if isinstance(error, RuntimeFailure) else "nmap_execution_failed_or_invalid_result"
            raise RemoteFailure(code, execution) from error
