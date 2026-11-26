"""Local test servers (loopback only) and small helpers for the Phase 2 detection tests. No test ever reaches the internet."""
import asyncio
import atexit
import contextlib
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

HOST = "127.0.0.1"
_cert_dir = None


def cert_paths():
    """(certificate, key) of a throwaway self-signed test certificate, created on first use with `openssl`.

    Nothing is committed to the repository (a private key must never be), and the files are deleted at exit.
    The TLS tests are skipped, with this reason, when no `openssl` program is available."""
    global _cert_dir
    if _cert_dir is None:
        exe = shutil.which("openssl") or r"C:\Program Files\Git\usr\bin\openssl.exe"
        if not Path(exe).exists():
            pytest.skip("openssl is not available to create a throwaway test certificate")
        folder = Path(tempfile.mkdtemp(prefix="snwebshield-testcert-"))
        atexit.register(shutil.rmtree, folder, True)
        subprocess.run([exe, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(folder / "key.pem"),
                        "-out", str(folder / "cert.pem"), "-days", "36500", "-sha256",
                        "-subj", "/CN=test.snwebshield.example/O=SNWebShield Tests",
                        "-addext", "subjectAltName=DNS:test.snwebshield.example,DNS:alt.snwebshield.example"],
                       check=True, capture_output=True, env={**os.environ, "MSYS2_ARG_CONV_EXCL": "*"})
        _cert_dir = folder
    return _cert_dir / "cert.pem", _cert_dir / "key.pem"


def free_port() -> int:
    """A loopback port nobody is listening on (connecting gets refused)."""
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def server_tls(minimum=None, maximum=None, ciphers=None) -> ssl.SSLContext:
    """The test server's TLS settings. Old protocol versions or weak ciphers can be switched on to test the TLS checks."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*cert_paths())
    if minimum is not None:
        context.minimum_version = minimum
    if maximum is not None:
        context.maximum_version = maximum
    if ciphers:
        context.set_ciphers(ciphers)
    return context


class BackgroundServer:
    """An asyncio server on a random loopback port, in its own thread (so it keeps running while a scan thread is stopped).

    handler(reader, writer, server) is an async function. `server.connections` counts accepted connections and
    `server.closed` counts connections the CLIENT closed while the handler was still waiting."""

    def __init__(self, handler, *, tls: bool = False, tls_context=None):
        """`tls_context`: a function returning the server's SSLContext, for servers that speak only old protocols or ciphers."""
        self.handler, self.tls_context = handler, tls_context
        self.tls = tls or tls_context is not None
        self.connections = 0
        self.closed = 0
        self.requests: list[bytes] = []
        self.port = 0
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._loop = None
        self._writers: list = []

    async def _serve(self):
        async def wrapped(reader, writer):
            self.connections += 1
            self._writers.append(writer)
            try:
                await self.handler(reader, writer, self)
            except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError, OSError):
                self.closed += 1
            finally:
                with contextlib.suppress(Exception):
                    writer.close()

        server = await asyncio.start_server(wrapped, HOST, 0, ssl=(self.tls_context() if self.tls_context else server_tls()) if self.tls else None)
        self.port = server.sockets[0].getsockname()[1]
        self._ready.set()
        try:
            await asyncio.Event().wait()
        finally:
            server.close()

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._task = self._loop.create_task(self._serve())
        try:
            self._loop.run_until_complete(self._task)
        except asyncio.CancelledError:
            pass
        finally:
            for writer in self._writers:
                with contextlib.suppress(Exception):
                    writer.close()
            self._loop.close()

    def __enter__(self):
        if self.tls:
            cert_paths()  # create (or skip) here, in the test thread, not inside the server thread
        self._thread.start()
        assert self._ready.wait(5), "test server did not start"
        return self

    def __exit__(self, *exc):
        self._loop.call_soon_threadsafe(self._task.cancel)
        self._thread.join(5)


# --- handlers -----------------------------------------------------------------------------------------------

def banner_handler(data: bytes, *, then_close: bool = True):
    async def handler(reader, writer, server):
        writer.write(data)
        await writer.drain()
        await asyncio.sleep(0.05)
        if then_close:
            writer.close()
        else:
            await reader.read(100)
    return handler


async def silent_handler(reader, writer, server):
    """Accepts and says nothing until the client leaves."""
    await reader.read(1000)


async def hanging_http_handler(reader, writer, server):
    """Reads the request but never answers: a probe waiting on it is 'mid-conversation'."""
    server.requests.append(await reader.read(2048))
    await reader.read(1)  # wait until the client closes


def http_handler(pages: dict, *, default=(404, {}, b"not found")):
    """pages: path -> (status, headers, body). Answers HEAD and GET like a small web server (HTTP/1.0, closes)."""
    async def handler(reader, writer, server):
        head = await reader.readuntil(b"\r\n\r\n")
        server.requests.append(head)
        method, path, _ = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
        status, headers, body = pages.get(path, default)
        lines = [f"HTTP/1.0 {status} X"]
        for key, value in headers.items():
            for item in (value if isinstance(value, list) else [value]):  # a list repeats the header (Set-Cookie)
                lines.append(f"{key}: {item}")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        writer.write(raw if method == "HEAD" else raw + body)
        await writer.drain()
        writer.close()
    return handler


def wait_until(condition, timeout: float = 5.0, step: float = 0.02) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(step)
    return False
