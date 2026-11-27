"""Supervisor: starts the SNWebShield roles at boot and restarts any that stop, with back-off.

    python -m app.cli.supervisor            # roles: api, web, scan-worker, monitor
    python -m app.cli.supervisor --roles scan-worker,monitor

Windows: `scripts\\install-autostart.ps1` registers this as a Task Scheduler task that runs at boot (also when nobody is logged in) and
that Task Scheduler itself restarts if the supervisor ever stops. Linux: `deploy/systemd/snwebshield.service` (see AUDIT_MATRIX: written,
not yet tested on Linux).

* No shell and no new packages. Each role is a child process with a fixed argument list and its own log file in
  ~/SNWebShield-Private/logs (outside the repository). A role's output is never read by the supervisor.
* A role that exits is started again after 1, 2, 4, ... up to 60 seconds. A role that then runs for 2 minutes starts counting again from 1.
* A role whose port is already in use by another process (for example started by hand with start-demo.ps1) is reported as `external`
  and started later if that process goes away.
* Only one supervisor runs at a time (a local socket is the lock).
* It writes a heartbeat named `supervisor` every 10 seconds with each role's process id and restart count; the admin page shows it.
"""
import argparse
from datetime import datetime, UTC
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

BACKEND = Path(__file__).resolve().parents[2]
ROOT = BACKEND.parent
LOCK_PORT = 47831
STABLE_SECONDS = 120
MAX_BACKOFF = 60
LOG_LIMIT_BYTES = 5 * 1024 * 1024


def log_dir() -> Path:
    path = Path.home() / "SNWebShield-Private" / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def make_kill_on_close_job():
    """Windows: a job object that kills every process in it when the supervisor itself ends, however it ends (Task Scheduler stop, crash,
    kill). Without it the roles would keep running as orphans and a new supervisor could not take them over. Returns the handle (keep it
    alive) or None where this does not apply."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64), ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("a", "b", "c", "d", "e", "f")]

        class EXTENDED(ctypes.Structure):
            _fields_ = [("Basic", BASIC), ("Io", IO), ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        job = kernel.CreateJobObjectW(None, None)
        if not job:
            return None
        info = EXTENDED()
        info.Basic.LimitFlags = 0x2000   # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            return None
        return job
    except Exception:
        return None


def add_to_job(job, process) -> bool:
    if not job:
        return False
    try:
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        return bool(kernel.AssignProcessToJobObject(job, int(process._handle)))
    except Exception:
        return False


class Spec:
    def __init__(self, name: str, command: list[str], cwd: Path, port: int | None = None):
        self.name, self.command, self.cwd, self.port = name, command, cwd, port


def default_specs(roles=("api", "web", "scan-worker", "monitor")) -> list[Spec]:
    python = sys.executable
    specs = []
    for role in roles:
        if role == "api":
            specs.append(Spec("api", [python, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"], BACKEND, 8000))
        elif role == "web":
            node = shutil.which("node")
            vite = ROOT / "frontend" / "node_modules" / "vite" / "bin" / "vite.js"
            if node and vite.exists() and (ROOT / "frontend" / "dist").exists():
                specs.append(Spec("web", [node, str(vite), "preview", "--host", "127.0.0.1", "--port", "5173", "--strictPort"], ROOT / "frontend", 5173))
        elif role in ("scan-worker", "monitor"):
            specs.append(Spec(role, [python, "-m", "app.cli.operations", role], BACKEND))
        else:
            raise SystemExit(f"unknown role: {role}")
    return specs


def port_in_use(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def kill_tree(process) -> None:
    """Stop a child and everything it started (the scan worker starts Nuclei)."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=15)
        else:
            process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
    except Exception:
        pass


class Role:
    def __init__(self, spec: Spec):
        self.spec = spec
        self.process = None
        self.state = "starting"
        self.restarts = 0
        self.in_a_row = 0
        self.started = 0.0
        self.started_at = None
        self.next_start = 0.0
        self.last_exit_code = None
        self.log = None

    def info(self) -> dict:
        return {"state": self.state, "pid": self.process.pid if self.process and self.process.poll() is None else None, "restarts": self.restarts,
                "started_at": self.started_at, "last_exit_code": self.last_exit_code}


class Supervisor:
    def __init__(self, specs, *, spawn=None, clock=time.monotonic, backoff_cap=MAX_BACKOFF, stable=STABLE_SECONDS, busy=port_in_use, logs=None):
        self.roles = [Role(s) for s in specs]
        self.spawn = spawn or self._spawn
        self.clock, self.cap, self.stable, self.busy = clock, backoff_cap, stable, busy
        self.logs = logs
        self.stopping = False
        self.job = make_kill_on_close_job()   # the roles die with the supervisor (Windows)

    def _spawn(self, spec: Spec):
        directory = self.logs or log_dir()
        path = Path(directory) / f"{spec.name}.log"
        if path.exists() and path.stat().st_size > LOG_LIMIT_BYTES:
            path.replace(path.with_suffix(".old.log"))
        handle = open(path, "ab")
        flags = (getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)) if os.name == "nt" else 0
        process = subprocess.Popen(spec.command, cwd=str(spec.cwd), stdin=subprocess.DEVNULL, stdout=handle, stderr=subprocess.STDOUT, creationflags=flags)
        process._sw_log = handle   # closed when the role is stopped
        add_to_job(self.job, process)
        return process

    def _start(self, role: Role) -> None:
        if role.spec.port and self.busy(role.spec.port):
            role.state = "external"   # something else already serves this port: do not fight it
            role.next_start = self.clock() + 10
            return
        try:
            role.process = self.spawn(role.spec)
        except Exception:
            role.state, role.last_exit_code = "failed_to_start", None
            role.in_a_row += 1
            role.next_start = self.clock() + min(self.cap, 2 ** role.in_a_row)
            return
        role.state, role.started = "running", self.clock()
        role.started_at = datetime.now(UTC).isoformat()

    def step(self) -> None:
        """One pass: start what is not running, notice what stopped and schedule its restart."""
        now = self.clock()
        for role in self.roles:
            if self.stopping:
                return
            process = role.process
            if process is not None and process.poll() is None:
                if role.state != "running":
                    role.state = "running"
                continue
            if process is not None:   # it was running and has stopped
                role.last_exit_code = process.poll()
                handle = getattr(process, "_sw_log", None)
                if handle:
                    try:
                        handle.close()
                    except Exception:
                        pass
                lived = now - role.started
                role.in_a_row = 0 if lived >= self.stable else role.in_a_row + 1
                role.restarts += 1
                role.process = None
                role.state = "restarting"
                role.next_start = now + (min(self.cap, 2 ** (role.in_a_row - 1)) if role.in_a_row else 1)
                continue
            if now >= role.next_start:
                self._start(role)

    def snapshot(self) -> dict:
        return {"roles": {r.spec.name: r.info() for r in self.roles}}

    def stop_all(self) -> None:
        self.stopping = True
        for role in self.roles:
            if role.process is not None and role.process.poll() is None:
                kill_tree(role.process)
            handle = getattr(role.process, "_sw_log", None) if role.process else None
            if handle:
                try:
                    handle.close()
                except Exception:
                    pass
            role.state = "stopped"


def beat(supervisor: Supervisor) -> None:
    try:
        from app.db.session import SessionLocal
        from app.services import job_engine as engine
        with SessionLocal() as db:
            engine.heartbeat(db, "supervisor", detail=supervisor.snapshot())
            db.commit()
    except Exception:
        pass   # a missed beat is itself the signal (the database may still be starting at boot)


def acquire_lock():
    lock = socket.socket()
    try:
        lock.bind(("127.0.0.1", LOCK_PORT))
    except OSError:
        return None
    return lock


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Start SNWebShield roles and keep them running.")
    parser.add_argument("--roles", default="api,web,scan-worker,monitor")
    args = parser.parse_args(argv)
    lock = acquire_lock()
    if lock is None:
        print("supervisor: another supervisor is already running", flush=True)
        return 1
    supervisor = Supervisor(default_specs(tuple(r.strip() for r in args.roles.split(",") if r.strip())))
    signal.signal(signal.SIGINT, lambda *_: setattr(supervisor, "stopping", True))
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: setattr(supervisor, "stopping", True))
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, lambda *_: setattr(supervisor, "stopping", True))
    last_beat = 0.0
    try:
        while not supervisor.stopping:
            supervisor.step()
            if time.monotonic() - last_beat >= 10:
                beat(supervisor)
                last_beat = time.monotonic()
            time.sleep(1)
    finally:
        supervisor.stop_all()
        lock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
