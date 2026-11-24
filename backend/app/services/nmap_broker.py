"""Trusted local DNS-only broker for the fixed TCP profile; never opens target sockets."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import threading


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def resolve(url, permitted):
    policy = load("monitor_policy", "monitor_probe.py")
    if not permitted(): raise ValueError("permission_changed")
    _, host, port = policy.target(url)
    answers = policy.resolve(host, port)  # Rejects ANY unsafe IPv4 or IPv6 answer.
    if not permitted(): raise ValueError("permission_changed")
    addresses = sorted({address[0] for family, address in answers if family == socket.AF_INET})
    if not addresses: raise ValueError("ipv4_target_required")
    return load("nmap_policy", "nmap_policy.py").target({"ip": addresses[0], "host": host, "dns_addresses": addresses})


if __name__ == "__main__":
    load("limits", "assessment_limits.py").child_limits()
    watchdog = threading.Timer(4, lambda: os._exit(2)); watchdog.daemon = True; watchdog.start()
    def permitted():
        print('{"permission":true}', flush=True)
        return sys.stdin.buffer.readline(16).strip() == b"true"
    try:
        raw = sys.stdin.buffer.readline(4097)
        if len(raw) > 4096: raise ValueError("input_limit")
        data = json.loads(raw)
        if not isinstance(data, dict) or set(data) != {"url"}: raise ValueError("invalid_input")
        print(json.dumps({"result": resolve(data["url"], permitted)}, separators=(",", ":")), flush=True)
    except Exception:
        print('{"error":"dns_destination_or_permission_rejected"}', flush=True)
    finally: watchdog.cancel()
