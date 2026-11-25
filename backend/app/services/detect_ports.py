"""TCP connect scan with asyncio: open / closed / filtered for each port on the ONE pinned IP.

Limits (all in settings): `scan_connect_concurrency` connections at once, `scan_port_timeout_seconds` per port and
`scan_ports_per_second` new connections per second. A connection that is accepted is closed again at once, and
nothing is sent. Results go into a shared object as they arrive, so a stopped scan keeps what it found.

* open     - the connection was accepted
* closed   - actively refused or reset
* filtered - no answer within the timeout
* error    - something on OUR side or the network path failed (not counted as closed or filtered). If more than half
             of the ports end in errors, the whole step is reported as "could not check", never as "no open ports".
"""
import asyncio
import time
from dataclasses import dataclass, field

from app.core.config import settings
from app.services import netio


@dataclass
class PortResults:
    total: int = 0
    done: int = 0
    open: list[int] = field(default_factory=list)
    closed: int = 0
    filtered: int = 0
    errors: int = 0

    @property
    def could_not_check(self) -> bool:
        return self.done > 0 and self.errors * 2 > self.done

    def summary(self) -> dict:
        return {"scanned": self.done, "planned": self.total, "open": len(self.open), "closed": self.closed,
                "filtered": self.filtered, "errors": self.errors}


class RateLimiter:
    """Spaces connection starts so the average never exceeds `rate` per second."""

    def __init__(self, rate: float):
        self.interval = 1.0 / max(rate, 0.001)
        self._next = time.monotonic()

    async def acquire(self) -> None:
        now = time.monotonic()
        wait = self._next - now
        self._next = max(now, self._next) + self.interval
        if wait > 0:
            await asyncio.sleep(wait)


async def probe_port(ip: str, port: int, timeout: float) -> str:
    try:
        _, writer = await netio.open_connection(ip, port, timeout=timeout)
    except asyncio.TimeoutError:
        return "filtered"
    except (ConnectionRefusedError, ConnectionResetError):
        return "closed"
    except OSError:
        return "error"
    await netio.close(writer)
    return "open"


async def scan_ports(ip: str, ports, results: PortResults, *, guard=None, progress=None,
                     concurrency: int | None = None, timeout: float | None = None, per_second: float | None = None) -> PortResults:
    concurrency = concurrency or settings.scan_connect_concurrency
    timeout = timeout or settings.scan_port_timeout_seconds
    limiter = RateLimiter(per_second or settings.scan_ports_per_second)
    pending = iter(ports)
    results.total = len(ports)
    last_report = [0.0]

    async def worker() -> None:
        for port in pending:  # a shared iterator: each port is taken by exactly one worker
            if guard is not None:
                guard.check()
            await limiter.acquire()
            state = await probe_port(ip, port, timeout)
            results.done += 1
            if state == "open":
                results.open.append(port)
            elif state == "closed":
                results.closed += 1
            elif state == "filtered":
                results.filtered += 1
            else:
                results.errors += 1
            now = time.monotonic()
            if progress is not None and now - last_report[0] >= 0.5:
                last_report[0] = now
                progress(results)

    workers = [asyncio.create_task(worker()) for _ in range(min(concurrency, max(1, len(ports))))]
    try:
        await asyncio.gather(*workers)
    except BaseException:
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)  # connections in flight are closed by the cancellation
        raise
    finally:
        results.open.sort()
        if progress is not None:
            progress(results)
    return results
