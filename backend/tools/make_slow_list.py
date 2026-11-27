"""Refresh tests/slow_tests.txt: the tests that take 0.8 seconds or more (the "slow" level).

    cd backend
    .\\.venv\\Scripts\\python.exe -m pytest -q -p no:cacheprovider --durations=0 > ..\\slow-run.txt
    .\\.venv\\Scripts\\python.exe tools\\make_slow_list.py ..\\slow-run.txt

Quick run = `pytest -m "not slow"`; full run = `pytest` (add `-n auto` with pytest-xdist from requirements-dev.txt).
A parametrized test is listed once by its function name; every variant of it counts as slow.
"""
import re
import sys
from pathlib import Path

THRESHOLD = 0.8
source = Path(sys.argv[1]).read_text(encoding="utf-8", errors="ignore") if len(sys.argv) > 1 else sys.stdin.read()
slowest: dict[str, float] = {}
for line in source.splitlines():
    match = re.match(r"\s*([\d.]+)s call\s+tests/(\S+?)(\[.*)?$", line)
    if match and float(match.group(1)) >= THRESHOLD:
        slowest[match.group(2)] = max(slowest.get(match.group(2), 0), float(match.group(1)))
out = Path(__file__).resolve().parents[1] / "tests" / "slow_tests.txt"
out.write_text("# Tests that take 0.8 s or more (marked `slow`; skipped by `pytest -m \"not slow\"`). Regenerate: tools/make_slow_list.py\n"
               + "\n".join(sorted(slowest)) + "\n", encoding="utf-8")
print(f"{len(slowest)} slow tests written to {out}")
