"""The engine interface. Every source of findings (built-in configuration checks, NVD/OSV vulnerability matching,
end-of-life lookup, and later Nuclei) is an Engine: it receives the scan facts, returns findings in the common format,
and reports a state. The runner drives engines the same way and merges their findings, so a new engine needs no change
to the runner, the database, the API or the UI.

An engine NEVER decides "safe". If it fails or times out it returns state "could_not_check"; the runner records that
and the UI shows "Could not check". Engines get the ONE pinned IP of the scan and must never resolve names themselves.
"""
import asyncio
import threading
from dataclasses import dataclass, field

from app.services.finding import Finding

STATES = ("ok", "could_not_check", "not_applicable", "skipped", "stopped")


@dataclass
class EngineResult:
    state: str = "ok"
    findings: list = field(default_factory=list)
    detail: dict = field(default_factory=dict)   # shown in the step record (counts, reasons); never secrets


class Engine:
    name = "engine"          # step key, e.g. "configuration"
    label = "Running checks"  # progress text
    title = "Checks"         # plain name for the results panel

    async def run(self, ctx, state, guard) -> EngineResult:  # pragma: no cover - interface
        raise NotImplementedError


_REGISTRY: list[Engine] = []


def register(engine: Engine) -> Engine:
    if any(e.name == engine.name for e in _REGISTRY):
        raise ValueError(f"engine {engine.name!r} already registered")
    _REGISTRY.append(engine)
    return engine


def registered() -> list[Engine]:
    return list(_REGISTRY)


def unregister(name: str) -> None:
    _REGISTRY[:] = [e for e in _REGISTRY if e.name != name]


async def run_engine(engine: Engine, ctx, state, guard, *, timeout: float | None = None) -> EngineResult:
    """Run one engine and never let it raise or hang: a crash or timeout is 'could not check'.

    A stop (ScanStopped / cancellation) is re-raised so the scan guard still ends the scan cleanly.
    """
    from app.services.scan_guard import ScanStopped
    try:
        coro = engine.run(ctx, state, guard)
        result = await (asyncio.wait_for(coro, timeout) if timeout else coro)
    except (ScanStopped, asyncio.CancelledError):
        raise
    except asyncio.TimeoutError:
        return EngineResult("could_not_check", [], {"reason": "timed_out"})
    except Exception:
        return EngineResult("could_not_check", [], {"reason": "unexpected_error"})
    if not isinstance(result, EngineResult) or result.state not in STATES:
        return EngineResult("could_not_check", [], {"reason": "bad_engine_result"})
    result.findings = [f for f in result.findings if isinstance(f, Finding)]
    return result


async def run_blocking(function, *args, **kwargs):
    """Run a blocking function (a database look-up) in a daemon thread and wait for it WITHOUT blocking the scan.

    If the scan is stopped while it waits, the wait is cancelled at once and the thread is simply left to finish by
    itself (it is bounded by the look-up's own timeout and holds no scan data), so a stop is never delayed by a slow
    database and the event loop can close immediately."""
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def deliver(outcome):
        if not future.done():
            if outcome[1] is not None:
                future.set_exception(outcome[1])
            else:
                future.set_result(outcome[0])

    def work():
        try:
            outcome = (function(*args, **kwargs), None)
        except BaseException as error:  # noqa: BLE001 - handed to the waiting scan, never lost
            outcome = (None, error)
        try:
            loop.call_soon_threadsafe(deliver, outcome)
        except RuntimeError:
            pass  # the scan has already ended; nobody is waiting

    threading.Thread(target=work, daemon=True, name="vuln-lookup").start()
    return await future
