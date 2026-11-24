import importlib.util
import json
import resource
import signal
import subprocess
import sys
import time

signal.alarm(10)
spec = importlib.util.spec_from_file_location("nmap_policy", "/app/nmap_policy.py")
policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(policy)
raw = sys.stdin.buffer.readline(1025)
if len(raw) > 1024: raise SystemExit(2)
data = json.loads(raw)
if not isinstance(data, dict) or set(data) != {"ip"}: raise SystemExit(2)
ip = policy.public_ipv4(data["ip"])
started = time.monotonic()
result = subprocess.run(policy.command(ip), capture_output=True, timeout=8, env={"PATH": "/usr/bin:/bin"})
if result.returncode or len(result.stdout) > 32768: raise SystemExit(2)
states = policy.parse_result(result.stdout, ip)
analysis = policy.analysis(states)
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
print(json.dumps({"analysis": analysis, "states": states, "usage": {
    "scanner_cpu_seconds": round(usage.ru_utime + usage.ru_stime, 6),
    "scanner_peak_rss_bytes": usage.ru_maxrss * 1024,
    "scanner_duration_ms": round((time.monotonic() - started) * 1000, 3)
}}, separators=(",", ":")), flush=True)
