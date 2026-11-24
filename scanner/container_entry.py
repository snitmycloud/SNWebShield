"""Networkless, stdlib-only container entry; bounded input and process measurements."""
import importlib.util
import json
import resource
import signal
import sys
import time

signal.alarm(5)
started = time.monotonic()
spec = importlib.util.spec_from_file_location("header_analyzer", "/app/header_analyzer.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
raw = sys.stdin.buffer.readline(32769)
if len(raw) > 32768 or not raw.endswith(b"\n"):
    raise SystemExit(2)
analysis = module.analyze(json.loads(raw))
usage = resource.getrusage(resource.RUSAGE_SELF)
print(json.dumps({"analysis": analysis, "usage": {
    "analyzer_cpu_seconds": round(usage.ru_utime + usage.ru_stime, 6),
    "analyzer_peak_rss_bytes": usage.ru_maxrss * 1024,
    "analyzer_duration_ms": round((time.monotonic() - started) * 1000, 3),
}}, separators=(",", ":")), flush=True)
