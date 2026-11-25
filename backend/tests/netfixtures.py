"""Local test servers (loopback only) and small helpers for the Phase 2 detection tests. No test ever reaches the internet."""
import asyncio
import contextlib
import socket
import ssl
import threading
import time
from pathlib import Path

DATA = Path(__file__).parent / "data"
CERT, KEY = DATA / "test_tls_cert.pem", DATA / "test_tls_key.pem"
HOST = "127.0.0.1"


def free_port() -> int:
    """A loopback port nobody is listening on (connecting gets refused)."""
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def server_tls() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT, KEY)
    return context


class BackgroundServer:
    """An asyncio server on a random loopback port, in its own thread (so it keeps running while a scan thread is stopped).

    handler(reader, writer, server) is an async function. `server.connections` counts accepted connections and
    `server.closed` counts connections the CLIENT closed while the handler was still waiting."""

    def __init__(self, handler, *, tls: bool = False):
        self.handler, self.tls = handler, tls
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

        server = await asyncio.start_server(wrapped, HOST, 0, ssl=server_tls() if self.tls else None)
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
