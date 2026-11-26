"""Starts the ONE pinned Nuclei binary safely and reads its results as untrusted data.

* No shell: a fixed argument list. Targets are built by us from the verified host name (never from scan data).
* Minimal environment: no `.env`, tokens, proxy variables or user profile; config, cache and temp folders are a private
  throw-away directory that is deleted afterwards.
* All traffic is forced through the local egress proxy (`-p`). An operating-system firewall rule (scripts/nuclei-firewall-*)
  blocks the binary's own direct network access, and the self-test proves that before the engine may run.
* Templates are only the vendored, validated set; unsigned-template checks stay on; update checks, interactsh/OAST,
  headless, code, file and network protocols and every dangerous tag are switched off on the command line as well.
* The process tree is killed when the scan guard stops the scan, when the time limit passes, or when output exceeds its cap.
"""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings
from app.services import netio

BANNED_TAGS_ARG = "intrusive,dos,fuzz,bruteforce,rce,sqli,xss,lfi,ssrf,xxe,ssti,oast,dast,fuzzing,default-login"
EXCLUDED_TYPES_ARG = "dns,file,headless,tcp,workflow,ssl,websocket,whois,code,javascript"
MAX_LINE = 256 * 1024


@dataclass
class RunResult:
    results: list = field(default_factory=list)      # parsed JSON objects (untrusted)
    exit_code: int | None = None
    timed_out: bool = False
    truncated: bool = False
    killed_by_guard: bool = False
    stderr_tail: str = ""
    bad_lines: int = 0


def build_command(binary: Path, templates: Path, targets: list[str], proxy_url: str, *, rate: int, concurrency: int,
                  timeout: int = 10) -> list[str]:
    command = [str(binary), "-t", str(templates)]
    for target in targets:
        command += ["-u", target]
    command += ["-etags", BANNED_TAGS_ARG, "-ept", EXCLUDED_TYPES_ARG, "-ni", "-fhr", "-rl", str(rate), "-c", str(concurrency),
                "-timeout", str(timeout), "-retries", "0", "-p", proxy_url, "-j", "-or", "-nc", "-duc", "-silent"]
    return command


def minimal_env(workdir: Path) -> dict:
    """Nothing from this server's environment is passed on: no secrets, no proxy variables, no user profile."""
    env = {"TEMP": str(workdir), "TMP": str(workdir), "HOME": str(workdir), "USERPROFILE": str(workdir),
           "APPDATA": str(workdir / "AppData"), "LOCALAPPDATA": str(workdir / "Local"),
           "XDG_CONFIG_HOME": str(workdir / "config"), "XDG_CACHE_HOME": str(workdir / "cache"), "NO_COLOR": "1"}
    if sys.platform == "win32":
        root = os.environ.get("SystemRoot", r"C:\Windows")
        env["SystemRoot"] = root
        env["PATH"] = str(Path(root) / "System32")
    else:
        env["PATH"] = "/usr/bin:/bin"
    return env


def kill_tree(process: asyncio.subprocess.Process) -> None:
    """Kill the process and everything it started. No shell is used."""
    pid = process.pid
    if pid is None:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, timeout=10, check=False)
        else:
            import signal
            os.killpg(os.getpgid(pid), signal.SIGKILL)
    except Exception:
        pass
    try:
        process.kill()
    except Exception:
        pass


async def run(binary: Path, templates: Path, targets: list[str], proxy_url: str, guard=None, *, timeout_seconds: int | None = None,
              rate: int | None = None, concurrency: int | None = None, extra_args: list[str] | None = None,
              workdir_parent: Path | None = None, command: list[str] | None = None, on_start=None) -> RunResult:
    limit = timeout_seconds or settings.nuclei_run_seconds
    workdir = Path(tempfile.mkdtemp(prefix="snwebshield-nuclei-run-", dir=str(workdir_parent) if workdir_parent else None))
    for sub in ("AppData", "Local", "config", "cache"):
        (workdir / sub).mkdir(exist_ok=True)
    result = RunResult()
    cmd = command or build_command(binary, templates, targets, proxy_url, rate=rate or settings.nuclei_rate_limit,
                                   concurrency=concurrency or settings.nuclei_concurrency)
    if extra_args:
        cmd = cmd + extra_args
    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    else:
        kwargs["start_new_session"] = True
    process = await asyncio.create_subprocess_exec(*cmd, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE, cwd=str(workdir), env=minimal_env(workdir), **kwargs)
    if on_start is not None:
        on_start(process)
    stderr_chunks: list[bytes] = []

    async def drain_stderr():
        total = 0
        while True:
            chunk = await process.stderr.read(4096)
            if not chunk:
                return
            if total < 64 * 1024:
                stderr_chunks.append(chunk)
                total += len(chunk)

    stderr_task = asyncio.ensure_future(drain_stderr())
    loop = asyncio.get_running_loop()
    deadline = loop.time() + limit
    total_bytes = 0
    try:
        while True:
            if guard is not None:
                guard.check()
            if loop.time() > deadline:
                result.timed_out = True
                break
            try:
                line = await asyncio.wait_for(process.stdout.readline(), 0.5)
            except asyncio.TimeoutError:
                if process.returncode is not None:
                    break
                continue
            except (ValueError, asyncio.LimitOverrunError):
                result.bad_lines += 1
                continue
            if not line:
                break
            total_bytes += len(line)
            if total_bytes > settings.nuclei_max_output_bytes:
                result.truncated = True
                break
            if len(line) > MAX_LINE:
                result.bad_lines += 1
                continue
            text = line.decode("utf-8", "replace").strip()
            if not text.startswith("{"):
                continue
            try:
                parsed = json.loads(text)
            except ValueError:
                result.bad_lines += 1
                continue
            if isinstance(parsed, dict):
                result.results.append(parsed)
        if result.timed_out or result.truncated:
            kill_tree(process)
        try:
            result.exit_code = await asyncio.wait_for(process.wait(), 10)
        except asyncio.TimeoutError:
            kill_tree(process)
    except BaseException:
        result.killed_by_guard = True
        kill_tree(process)
        raise
    finally:
        if process.returncode is None:
            kill_tree(process)
        stderr_task.cancel()
        await asyncio.gather(stderr_task, return_exceptions=True)
        result.stderr_tail = netio.clean_text(b"".join(stderr_chunks)[-2000:], 500)
        shutil.rmtree(workdir, ignore_errors=True)
    return result
