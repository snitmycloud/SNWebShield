"""The egress proxy: the ONLY network path the Nuclei process has.

One proxy per scan, bound to 127.0.0.1 on a random port, created with the scan's verified host name and its ONE pinned IP.
Rules (owner-approved):
* HTTPS: `CONNECT <verified host>:443` only. HTTP: an absolute-form `GET|HEAD http://<verified host>[:80]/...` only.
* Any other host, any other port, any IP-literal host, any other method: refused with 403 and logged. The proxy never
  resolves a name: it connects to the pinned IP it was given (checked once more against the public-address policy), so DNS
  rebinding, redirects to another host and templates that name other hosts cannot widen what is contacted.
* Every allowed and every refused attempt is logged (time, scan, method, host, port, decision, reason, IP). Paths, headers
  and bodies are never logged. The log goes to a per-scan file and is summarised into the scan result.
* Limits: bytes per connection, connections per scan and idle time, so a template cannot turn the proxy into a pipe.
"""
import asyncio
import ipaddress
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from app.services import ip_policy, netio

MAX_HEAD = 16 * 1024
MAX_BYTES_PER_CONNECTION = 25 * 1024 * 1024
MAX_CONNECTIONS = 3000
IDLE_SECONDS = 30
MAX_LOG_ENTRIES = 5000
REFUSED = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 40\r\nConnection: close\r\n\r\nRefused by the SNWebShield egress policy."


def _normalise_host(host: str) -> str:
    return host.strip().lower().rstrip(".").strip("[]")


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class EgressProxy:
    def __init__(self, *, host: str, ip: str, scan_id: str, log_path: Path | None = None, allow_ip=None, port_map: dict | None = None):
        self.host = _normalise_host(host)
        self.ip = ip
        self.scan_id = scan_id
        self.log_path = Path(log_path) if log_path else None
        self.allow_ip = allow_ip or self._public_only
        self.port_map = port_map or {}   # self-test only: policy port -> local canary port
        self.entries: list[dict] = []
        self.connections = 0
        self.bytes_total = 0
        self.port = 0
        self._server = None
        self._tasks: set[asyncio.Task] = set()
        self._log_file = None

    @staticmethod
    def _public_only(ip: str) -> bool:
        try:
            return ip_policy.refusal_reason(ipaddress.ip_address(ip), ip_policy.server_addresses()) is None
        except Exception:
            return False

    # --- lifecycle ---------------------------------------------------------------------------------------------
    async def start(self) -> int:
        if self.log_path is not None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_file = open(self.log_path, "a", encoding="utf-8")
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
        for task in list(self._tasks):   # cancel open connections FIRST: wait_closed() waits for them (it once blocked ~2 minutes)
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._server is not None:
            try:
                await asyncio.wait_for(self._server.wait_closed(), 5)
            except asyncio.TimeoutError:
                pass
        if self._log_file is not None:
            self._log_file.close()
            self._log_file = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    # --- logging -------------------------------------------------------------------------------------------------
    def _log(self, method, host, port, decision, reason=None, ip=None) -> None:
        entry = {"time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "scan": self.scan_id,
                 "method": method[:12], "host": host[:120], "port": port, "decision": decision, "reason": reason, "ip": ip}
        if len(self.entries) < MAX_LOG_ENTRIES:
            self.entries.append(entry)
        if self._log_file is not None:
            self._log_file.write(json.dumps(entry) + "\n")
            self._log_file.flush()

    def summary(self) -> dict:
        allowed = [e for e in self.entries if e["decision"] == "allowed"]
        refused = [e for e in self.entries if e["decision"] == "refused"]
        reasons: dict = {}
        for e in refused:
            reasons[e["reason"]] = reasons.get(e["reason"], 0) + 1
        return {"allowed": len(allowed), "refused": len(refused), "refused_reasons": reasons,
                "ips_contacted": sorted({e["ip"] for e in allowed if e["ip"]}), "hosts_allowed": sorted({e["host"] for e in allowed}),
                "bytes": self.bytes_total}

    # --- connections ---------------------------------------------------------------------------------------------
    async def _handle(self, reader, writer) -> None:
        task = asyncio.current_task()
        self._tasks.add(task)
        try:
            await self._serve(reader, writer)
        except (asyncio.CancelledError, ConnectionError, OSError, asyncio.TimeoutError):
            pass
        finally:
            self._tasks.discard(task)
            await netio.close(writer)

    async def _read_head(self, reader) -> bytes | None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IDLE_SECONDS)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            return None
        return head if len(head) <= MAX_HEAD else None

    async def _serve(self, reader, writer) -> None:
        head = await self._read_head(reader)
        if head is None:
            return
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3:
            self._log("?", "?", 0, "refused", "bad_request")
            writer.write(REFUSED)
            return
        method, target, version = parts[0].upper(), parts[1], parts[2]
        self.connections += 1
        if self.connections > MAX_CONNECTIONS:
            self._log(method, "?", 0, "refused", "too_many_connections")
            writer.write(REFUSED)
            return
        if method == "CONNECT":
            host, _, port_text = target.rpartition(":")
            host, port = _normalise_host(host), int(port_text) if port_text.isdigit() else 0
            reason = self._refusal(host, port, allowed_port=443)
            if reason:
                self._log(method, host or "?", port, "refused", reason)
                writer.write(REFUSED)
                return
            upstream = await self._open(443, method, host)
            if upstream is None:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await self._relay(reader, writer, *upstream)
            return
        if method in ("GET", "HEAD") and target.lower().startswith("http://"):
            rest = target[7:]
            authority, slash, path = rest.partition("/")
            host, _, port_text = authority.rpartition(":") if ":" in authority and not authority.endswith("]") else (authority, "", "")
            host, port = _normalise_host(host), int(port_text) if port_text.isdigit() else 80
            reason = self._refusal(host, port, allowed_port=80)
            if reason:
                self._log(method, host or "?", port, "refused", reason)
                writer.write(REFUSED)
                return
            upstream = await self._open(80, method, host)
            if upstream is None:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            kept = [line for line in lines[1:] if line and line.split(":", 1)[0].strip().lower()
                    not in ("proxy-connection", "connection", "proxy-authorization", "keep-alive")]
            request = f"{method} /{path} {version}\r\n" + "\r\n".join(kept) + "\r\nConnection: close\r\n\r\n"
            up_reader, up_writer = upstream
            up_writer.write(request.encode("latin-1"))
            await up_writer.drain()
            await self._relay(reader, writer, up_reader, up_writer)
            return
        self._log(method, "?", 0, "refused", "method_or_form_not_allowed")
        writer.write(REFUSED)

    def _refusal(self, host: str, port: int, *, allowed_port: int) -> str | None:
        if not host:
            return "no_host"
        if _is_ip_literal(host):
            return "ip_literal_host"
        if host != self.host:
            return "other_host"
        if port != allowed_port:
            return "port_not_allowed"
        return None

    async def _open(self, port: int, method: str, host: str):
        if not self.allow_ip(self.ip):
            self._log(method, host, port, "refused", "pinned_ip_not_public")
            return None
        try:
            up_reader, up_writer = await netio.open_connection(self.ip, self.port_map.get(port, port), timeout=10)
        except (asyncio.TimeoutError, OSError):
            self._log(method, host, port, "refused", "upstream_unreachable", self.ip)
            return None
        self._log(method, host, port, "allowed", None, self.ip)
        return up_reader, up_writer

    async def _relay(self, c_reader, c_writer, u_reader, u_writer) -> None:
        sent = [0]

        async def pipe(src, dst):
            try:
                while True:
                    data = await asyncio.wait_for(src.read(65536), IDLE_SECONDS)
                    if not data:
                        break
                    sent[0] += len(data)
                    if sent[0] > MAX_BYTES_PER_CONNECTION:
                        break
                    self.bytes_total += len(data)   # only what was actually passed on
                    dst.write(data)
                    await dst.drain()
            except (asyncio.TimeoutError, ConnectionError, OSError):
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        tasks = [asyncio.ensure_future(pipe(c_reader, u_writer)), asyncio.ensure_future(pipe(u_reader, c_writer))]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            await asyncio.wait(tasks, timeout=2)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await netio.close(u_writer)
