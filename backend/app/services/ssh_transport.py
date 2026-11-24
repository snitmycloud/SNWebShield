"""Single fixed SSH transport to the existing scanner VM.

No host, user, command, runner path, Docker argument or SSH option ever originates
in an API request. Keys stay with the OS SSH agent/config; this module never reads,
logs or forwards key material. Options given here take precedence over the user's
ssh_config, so a permissive config cannot enable forwarding, proxies or passwords.
"""
import os
import re
from pathlib import Path

REMOTE_HOST = "azureuser@57.159.27.58"
RUNNERS = frozenset({
    "/usr/local/libexec/snwebshield-header-runner",
    "/usr/local/libexec/snwebshield-nmap-runner",
})
OPTIONS = (
    "BatchMode=yes",                    # never prompt; no password/passphrase entry
    "StrictHostKeyChecking=yes",        # known_hosts must already pin the VM host key
    "UpdateHostKeys=no",
    "PasswordAuthentication=no",
    "KbdInteractiveAuthentication=no",
    "ConnectTimeout=4",
    "ConnectionAttempts=1",
    "ServerAliveInterval=2",
    "ServerAliveCountMax=2",
    "ForwardAgent=no",                  # the VM must never reach the local agent
    "ForwardX11=no",
    "ClearAllForwardings=yes",
    "PermitLocalCommand=no",
    "ProxyCommand=none",
    "ProxyJump=none",
    "ControlMaster=no",                 # no reuse of a pre-existing multiplexed session
    "ControlPath=none",
    "RequestTTY=no",
)
EXECUTION_ID = re.compile(r"[0-9a-f]{32}")


class SSHUnavailable(Exception):
    """The OS SSH client is missing; callers must fail closed, never fall back."""


def ssh_binary():
    # Pin the OS client instead of trusting PATH order.
    if os.name == "nt":
        root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT") or r"C:\Windows"
        candidate = Path(root) / "System32" / "OpenSSH" / "ssh.exe"
    else:
        candidate = Path("/usr/bin/ssh")
    if not candidate.is_file():
        raise SSHUnavailable("ssh_client_unavailable")
    return str(candidate)


def command(runner, operation, execution_id=None):
    """Return the complete argv for one fixed runner operation."""
    if runner not in RUNNERS:
        raise ValueError("unsupported_runner")
    args = [ssh_binary(), "-T"]
    for option in OPTIONS:
        args.extend(["-o", option])
    args.extend([REMOTE_HOST, runner])
    if operation == "check":
        args.append("--check")
    elif operation == "cleanup":
        if not isinstance(execution_id, str) or not EXECUTION_ID.fullmatch(execution_id):
            raise ValueError("invalid_execution_id")
        args.extend(["--cleanup", execution_id])
    elif operation != "run":
        raise ValueError("unsupported_remote_operation")
    return args
