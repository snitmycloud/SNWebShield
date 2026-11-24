"""Fixed local Python execution adapter. No shell, arbitrary argv or tool plugins."""
import json, os, queue, subprocess, sys, tempfile, threading, time
from pathlib import Path
from app.services.assessment_limits import attach_windows
from app.services.header_analyzer import analyze

class RuntimeFailure(Exception): pass

def safe_environment(*, ssh_profile=False):
    allowed = {"SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH"}
    if ssh_profile:
        # Windows OpenSSH needs the Windows identity/profile paths to initialise.
        # These are OS paths/identity names, never private-key contents or app secrets.
        allowed.update({"USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
                        "PROGRAMDATA", "USERNAME", "USERDOMAIN", "SystemDrive", "SSH_AUTH_SOCK", "HOME"})
    return {k:v for k,v in os.environ.items() if k in allowed}

class Channel:
    """Bound stdin/stdout framing; continuously poll permission and deadlines."""
    def __init__(self, args, *, ssh_profile=False):
        self.directory = tempfile.TemporaryDirectory(prefix="snws-adapter-")
        environment = safe_environment(ssh_profile=ssh_profile)
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=environment, cwd=self.directory.name, shell=False)
        self.job_close = None
        try:
            self.job_close = attach_windows(self.process)
        except Exception:
            self.process.kill(); self.process.wait()
            self.process.stdin.close(); self.process.stdout.close()
            self.directory.cleanup(); raise
        self.messages = queue.Queue(maxsize=16)
        self.failed = threading.Event()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        budget = 131072
        try:
            while True:
                line = self.process.stdout.readline(32769)
                if not line:
                    return
                budget -= len(line)
                if len(line) > 32768 or not line.endswith(b"\n") or budget < 0:
                    raise ValueError()
                self.messages.put_nowait(json.loads(line))
        except Exception:
            self.failed.set()

    def send(self, value):
        line = json.dumps(value, separators=(",", ":")).encode() + b"\n"
        if len(line) > 32768:
            raise RuntimeFailure("adapter_input_limit")
        try:
            self.process.stdin.write(line)
            self.process.stdin.flush()
        except (OSError, ValueError) as exc:
            raise RuntimeFailure("adapter_pipe_failed") from exc

    def receive(self, seconds, permitted):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if not permitted():
                raise RuntimeFailure("permission_changed")
            if self.failed.is_set():
                raise RuntimeFailure("adapter_output_invalid_or_excessive")
            try:
                return self.messages.get(timeout=.1)
            except queue.Empty:
                if self.process.poll() is not None and not self.reader.is_alive() and self.messages.empty():
                    raise RuntimeFailure("adapter_exited_without_result")
        raise RuntimeFailure("adapter_deadline_exceeded")

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        for stream in (self.process.stdin, self.process.stdout):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        self.reader.join(timeout=.2)
        if self.job_close:
            self.job_close()
        self.directory.cleanup()

def child_executable():
    # Windows venv executables may be redirectors which spawn another process.
    # These fixed stdlib-only children need the actual interpreter, not packages.
    if os.name != "nt":
        return sys.executable
    executable = getattr(sys, "_base_executable", None)
    if not executable or not Path(executable).is_absolute() or not Path(executable).is_file():
        raise RuntimeFailure("base_interpreter_unavailable")
    return executable

def invoke(script, payload, permitted, seconds):
    path = Path(__file__).with_name(script)
    channel = Channel([child_executable(), "-I", "-S", "-B", str(path)])
    try:
        channel.send(payload)
        deadline=time.monotonic()+seconds
        for _ in range(8):
            if time.monotonic() >= deadline: raise RuntimeFailure("adapter_deadline_exceeded")
            message=channel.receive(max(.01,deadline-time.monotonic()),permitted)
            if message=={"permission":True}:
                channel.send(bool(permitted()))
            else:
                return message
        raise RuntimeFailure("adapter_protocol_budget")
    finally: channel.close()

class LocalPythonAdapter:
    name = "local-python-v1"
    def execute(self, url, permitted):
        if not permitted(): raise RuntimeFailure("permission_changed")
        message=invoke("assessment_broker.py",{"url":url},permitted,13)
        if not isinstance(message,dict) or set(message)!={"result"}:
            raise RuntimeFailure(message.get("error","broker_failed") if isinstance(message,dict) else "broker_failed")
        result=message["result"]
        data={"https":result["tls_verified"],"status":result["status"],"headers":result.pop("selected_headers")}
        expected=analyze(data)
        analysis=invoke("header_analyzer.py",data,permitted,5)
        if analysis!=expected:raise RuntimeFailure("analysis_contract_invalid")
        if not permitted():raise RuntimeFailure("permission_changed")
        result.pop("facts",None)
        return {"state":"up","mode":"local_http","network_execution":True,
            "outcome":"header_assessment_completed","findings_created":0,
            "report":{"transport":result,"analysis":analysis,"adapter":self.name}}

# Fixed registry: future adapters require reviewed code changes, never user-supplied commands.
ADAPTERS={"local-python-v1":LocalPythonAdapter()}
