"""The Nuclei self-test. The engine may run only while this test is passing; any failed check keeps the engine OFF.

Checks (each recorded by name; a failure of ANY check fails the whole test, and nothing is ever assumed to pass):
  binary        the installed file has the pinned SHA-256 and reports the pinned version
  templates     the vendored set equals its manifest and every template passes the validator again
  proxy         the REAL Nuclei binary, started the way scans start it, reaches an allowed canary through the egress proxy and
                CANNOT reach a second canary: the proxy refuses an IP-literal host and a non-allowed port, and that canary
                receives no request at all
  firewall      the operating-system rule that blocks the binary's own direct network access exists and is active
                (Windows: `netsh advfirewall`; Linux: the `snwebshield-nuclei-egress` rule). Remove the rule and this check fails
  kill          a Nuclei run waiting on a hung canary is cancelled and its process tree is gone within seconds
The canaries listen on loopback only, so the test never contacts anything outside this computer. A passing result is
remembered for `nuclei_selftest_valid_minutes`; a failing one is never cached as a pass.
"""
import asyncio
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from app.core.config import settings
from app.services import egress_proxy, nuclei_lock, nuclei_runner, nuclei_templates

RULE_NAME = "SNWebShield-Nuclei-dev-block"
LINUX_MARKER = "snwebshield-nuclei-egress"
_cache: dict = {"ok": False, "at": None, "failed": ["not_run"], "checks": {}}

ALLOWED_TEMPLATE = """id: selftest-allowed
info:
  name: selftest allowed
  author: snwebshield
  severity: info
  tags: selftest
http:
  - method: GET
    path:
      - "{{BaseURL}}/selftest-ok"
    matchers:
      - type: word
        words:
          - "SELFTEST-OK"
"""
FOREIGN_TEMPLATE = """id: selftest-foreign
info:
  name: selftest foreign
  author: snwebshield
  severity: info
  tags: selftest
http:
  - method: GET
    path:
      - "http://127.0.0.1:{port}/leak-ip"
      - "http://localhost:{port}/leak-port"
    matchers:
      - type: word
        words:
          - "LEAKED"
"""
SLOW_TEMPLATE = ALLOWED_TEMPLATE.replace("selftest-allowed", "selftest-slow").replace("/selftest-ok", "/slow")


class Canary:
    """A loopback server that counts requests. `mode`: ok (answers SELFTEST-OK / LEAKED), hang (never answers)."""

    def __init__(self, mode="ok", body=b"SELFTEST-OK LEAKED"):
        self.mode, self.body, self.hits, self.port, self._server = mode, body, 0, 0, None

    async def start(self):
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            self.hits += 1
            if self.mode == "hang":
                await asyncio.sleep(120)
            else:
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(self.body) + self.body)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()


def pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True, timeout=15, check=False).stdout
        return str(pid) in out
    import os
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def firewall_rule_state(binary: Path) -> tuple[bool, str]:
    """(active, detail). Reads the OS rule; it never changes anything."""
    if sys.platform == "win32":
        try:
            out = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={RULE_NAME}", "verbose"],
                                 capture_output=True, text=True, timeout=20, check=False).stdout
        except (OSError, subprocess.SubprocessError):
            return False, "firewall_unreadable"
        if RULE_NAME not in out:
            return False, "rule_missing"

        def field(name):
            found = re.search(rf"^\s*{name}:\s*(.+?)\s*$", out, re.M | re.I)
            return found.group(1) if found else ""
        ok = (field("Enabled").lower() == "yes" and field("Direction").lower() == "out" and field("Action").lower() == "block"
              and field("Program").lower() == str(binary).lower())
        return ok, "active" if ok else "rule_present_but_not_blocking_this_binary"
    try:  # Linux: an nftables or iptables rule carrying our marker comment (set up by the administrator)
        for command in (["nft", "list", "ruleset"], ["iptables", "-S", "OUTPUT"]):
            if shutil.which(command[0]):
                out = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False).stdout
                if LINUX_MARKER in out:
                    return True, "active"
        return False, "rule_missing"
    except (OSError, subprocess.SubprocessError):
        return False, "firewall_unreadable"


async def _run_nuclei(binary, templates_dir, target, proxy, guard=None, seconds=40):
    return await nuclei_runner.run(binary, templates_dir, [target], proxy.url, guard, timeout_seconds=seconds, rate=5, concurrency=2)


async def run_all(guard=None) -> dict:
    checks: dict = {}
    failed: list[str] = []

    def record(name, ok, detail=""):
        checks[name] = {"ok": bool(ok), "detail": detail}
        if not ok:
            failed.append(name)

    try:
        binary = nuclei_lock.verified_binary()
    except nuclei_lock.LockError as error:
        record("binary", False, error.code)
        return _finish(checks, failed)
    version = await nuclei_runner.run(binary, Path("."), [], "", None, timeout_seconds=30, command=[str(binary), "-version", "-duc", "-nc"])
    version_text = " ".join(str(item) for item in version.results) + " " + version.stderr_tail
    pinned = nuclei_lock.load_lock()["version"]
    record("binary", pinned in version_text, "hash ok, version " + (pinned if pinned in version_text else "NOT confirmed"))

    try:
        manifest = nuclei_templates_ok()
        record("templates", True, f"{manifest} templates")
    except Exception as error:  # noqa: BLE001
        record("templates", False, getattr(error, "code", type(error).__name__))

    ok_rule, rule_detail = firewall_rule_state(binary)
    record("firewall", ok_rule, rule_detail)

    work = Path(tempfile.mkdtemp(prefix="snwebshield-selftest-"))
    allowed, foreign, slow = Canary(), Canary(body=b"LEAKED"), Canary("hang")
    try:
        for canary in (allowed, foreign, slow):
            await canary.start()
        (work / "allowed").mkdir()
        (work / "allowed" / "t.yaml").write_text(ALLOWED_TEMPLATE, encoding="utf-8")
        (work / "foreign").mkdir()
        (work / "foreign" / "t.yaml").write_text(FOREIGN_TEMPLATE.replace("{port}", str(foreign.port)), encoding="utf-8")
        (work / "slow").mkdir()
        (work / "slow" / "t.yaml").write_text(SLOW_TEMPLATE, encoding="utf-8")

        proxy = egress_proxy.EgressProxy(host="localhost", ip="127.0.0.1", scan_id="selftest", allow_ip=lambda ip: True,
                                         port_map={80: allowed.port})
        await proxy.start()
        try:
            good = await _run_nuclei(binary, work / "allowed", "http://localhost", proxy, guard)
            bad = await _run_nuclei(binary, work / "foreign", "http://localhost", proxy, guard)
        finally:
            await proxy.stop()
        summary = proxy.summary()
        reached = any(r.get("template-id") == "selftest-allowed" for r in good.results)
        refused = summary["refused_reasons"]
        record("proxy", reached and foreign.hits == 0 and not any(r.get("template-id") == "selftest-foreign" for r in bad.results)
               and summary["ips_contacted"] in ([], ["127.0.0.1"]),
               f"allowed canary reached={reached}, foreign canary hits={foreign.hits}, refused={refused}")

        proxy2 = egress_proxy.EgressProxy(host="localhost", ip="127.0.0.1", scan_id="selftest-kill", allow_ip=lambda ip: True,
                                          port_map={80: slow.port})
        await proxy2.start()
        pids: list[int] = []
        started = asyncio.Event()

        def note_start(process):
            pids.append(process.pid)
            started.set()

        async def hung_run():
            await nuclei_runner.run(binary, work / "slow", ["http://localhost"], proxy2.url, None, timeout_seconds=60, rate=5,
                                    concurrency=2, on_start=note_start)
        task = asyncio.ensure_future(hung_run())
        try:
            await asyncio.wait_for(started.wait(), 15)
            deadline = time.monotonic() + 15
            while slow.hits == 0 and time.monotonic() < deadline:
                await asyncio.sleep(0.2)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await asyncio.sleep(1.5)
            record("kill", bool(pids) and not pid_alive(pids[0]), f"hung request seen={slow.hits > 0}, process gone={bool(pids) and not pid_alive(pids[0])}")
        except asyncio.TimeoutError:
            task.cancel()
            record("kill", False, "process did not start")
        finally:
            await proxy2.stop()
    finally:
        for canary in (allowed, foreign, slow):
            await canary.stop()
        shutil.rmtree(work, ignore_errors=True)
    return _finish(checks, failed)


def nuclei_templates_ok() -> int:
    from app.services import engine_nuclei
    manifest = engine_nuclei.verify_templates()
    root = engine_nuclei.TEMPLATES_DIR
    for name in manifest["templates"]:
        verdict = nuclei_templates.validate_file(root / name, root)
        if not verdict.ok:
            raise ValueError(f"{name}: {verdict.reasons}")
    return len(manifest["templates"])


def _finish(checks, failed) -> dict:
    result = {"ok": not failed, "failed": failed, "checks": checks, "at": time.time()}
    _cache.clear()
    _cache.update(result)
    return result


async def ensure(guard=None) -> dict:
    """The cached passing result if it is recent, else a fresh run. A failed result is never reused as a pass."""
    age = time.time() - (_cache.get("at") or 0)
    if _cache.get("ok") and age < settings.nuclei_selftest_valid_minutes * 60:
        rule_ok, _ = firewall_rule_state(nuclei_lock.binary_path())  # the cheap, changeable part is re-read every scan
        if rule_ok:
            return _cache
    return await run_all(guard)


def reset() -> None:
    _cache.clear()
    _cache.update({"ok": False, "at": None, "failed": ["not_run"], "checks": {}})


if __name__ == "__main__":
    outcome = asyncio.run(run_all())
    print(json.dumps(outcome, indent=1))
    sys.exit(0 if outcome["ok"] else 1)
