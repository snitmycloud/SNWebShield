"""Engines marked `parallel` (Nuclei) run at the same time as the others; their results are merged; a stop cancels them."""
import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import engines, engine_nuclei, nuclei_lock
from app.services.finding import Finding
from app.services.scan_guard import ScanStopped
from netfixtures import BackgroundServer, http_handler
from test_identify_pipeline import fake_databases
from test_robustness_report import scan_site

HTML = {"Content-Type": "text/html"}


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


class Timed(engines.Engine):
    def __init__(self, name, seconds, finding_id, parallel=False, fail=False, stop=False):
        self.name, self.label, self.title, self.parallel = name, f"Running {name}", name, parallel
        self.seconds, self.finding_id, self.fail, self.stop = seconds, finding_id, fail, stop
        self.window = None

    async def run(self, ctx, state, guard):
        started = time.monotonic()
        try:
            await asyncio.sleep(self.seconds)
            if self.fail:
                raise RuntimeError("boom")
            if self.stop:
                raise ScanStopped("website_removed")
            return engines.EngineResult("ok", [Finding(kind="config", check_id=self.finding_id, title=self.finding_id, location="example.com", severity="low",
                                                       confidence="confirmed", sources=["test"])], {"seconds": self.seconds})
        finally:
            self.window = (started, time.monotonic())


@pytest.fixture
def fakes():
    added = []

    def add(engine):
        engines.register(engine)
        added.append(engine.name)
        return engine
    yield add
    for name in added:
        engines.unregister(name)


def scan(client, monkeypatch):
    fake_databases(monkeypatch)
    with BackgroundServer(http_handler({"/": (200, HTML, b"<html>hi</html>")})) as web:
        return scan_site(client, monkeypatch, [web.port])


def test_a_parallel_engine_overlaps_with_the_sequential_ones_and_both_results_are_kept(client, monkeypatch, fakes):
    sequential = fakes(Timed("fake-sequential", 2.0, "test:sequential"))
    parallel = fakes(Timed("fake-parallel", 2.0, "test:parallel", parallel=True))
    status, body, _, _, _ = scan(client, monkeypatch)
    assert status == "completed"
    (p_start, p_end), (s_start, s_end) = parallel.window, sequential.window
    assert p_start < s_end and s_start < p_end                          # their time windows overlap: they ran together
    assert max(p_end, s_end) - min(p_start, s_start) < 3.6              # about 2 s together, not 4 s one after the other
    ids = {f["check_id"] for f in body["findings"]}
    assert {"test:sequential", "test:parallel"} <= ids
    steps = body["scan"]["result"]["steps"]
    assert steps["fake-sequential"]["state"] == "ok" and steps["fake-parallel"]["state"] == "ok"


def test_the_parallel_engine_starts_before_the_sequential_ones_not_after_them(client, monkeypatch, fakes):
    sequential = fakes(Timed("fake-sequential", 1.0, "test:sequential"))
    parallel = fakes(Timed("fake-parallel", 1.0, "test:parallel", parallel=True))
    scan(client, monkeypatch)
    assert parallel.window[0] <= sequential.window[0] + 0.5


def test_a_parallel_engine_that_is_slower_is_waited_for(client, monkeypatch, fakes):
    fakes(Timed("fake-sequential", 0.2, "test:sequential"))
    slow = fakes(Timed("fake-parallel", 2.5, "test:parallel", parallel=True))
    status, body, _, _, _ = scan(client, monkeypatch)
    assert status == "completed" and "test:parallel" in {f["check_id"] for f in body["findings"]}
    assert slow.window[1] - slow.window[0] >= 2.4


def test_a_crashing_parallel_engine_is_could_not_check_and_the_other_results_survive(client, monkeypatch, fakes):
    fakes(Timed("fake-sequential", 0.2, "test:sequential"))
    fakes(Timed("fake-parallel", 0.2, "test:parallel", parallel=True, fail=True))
    status, body, _, _, _ = scan(client, monkeypatch)
    steps = body["scan"]["result"]["steps"]
    assert steps["fake-parallel"]["state"] == "could_not_check" and steps["fake-parallel"]["reason"] == "unexpected_error"
    assert "test:sequential" in {f["check_id"] for f in body["findings"]} and status == "incomplete"


def test_a_stop_while_a_parallel_engine_runs_cancels_it_and_keeps_what_was_found(client, monkeypatch, fakes):
    fakes(Timed("fake-sequential", 0.3, "test:sequential", stop=True))
    parallel = fakes(Timed("fake-parallel", 30.0, "test:parallel", parallel=True))
    started = time.monotonic()
    status, body, took, _, _ = scan(client, monkeypatch)
    assert status == "incomplete" and took < 20 and parallel.window is not None and parallel.window[1] - parallel.window[0] < 15   # cancelled, not waited for
    assert body["scan"]["result"]["steps"]["fake-parallel"]["state"] == "stopped"


def test_only_nuclei_is_parallel():
    from app.services import identify
    identify.register_builtin()
    assert {e.name for e in engines.registered() if e.parallel} == {"nuclei"}


def test_a_missing_nuclei_binary_means_skipped_without_a_note(monkeypatch):
    from app.core.config import settings
    from app.services.detect_runner import ScanContext, ScanState
    from app.services.detect_versions import PortProbe, WebPage
    monkeypatch.setattr(settings, "nuclei_enabled", True)

    def missing():
        raise nuclei_lock.LockError("binary_not_installed")
    monkeypatch.setattr(nuclei_lock, "verified_binary", missing)
    state = ScanState()
    state.probes = [PortProbe(port=80, service="http", http={"status": 200, "over_tls": False, "headers": {}, "cookies": []},
                              web=WebPage(port=80, tls=False, status=200, headers={}, cookies=[], body=""))]

    class Guard:
        def check(self):
            pass
    out = asyncio.run(engines.run_engine(engine_nuclei.NucleiEngine(), ScanContext(scan_id="s", domain="example.com", ip="203.0.113.7"), state, Guard()))
    assert out.state == "skipped" and out.detail == {"reason": "not_installed"}
    state.steps = {"nuclei": {"state": "skipped", "reason": "not_installed"}}
    assert state.optional_notes() == [] and state.incomplete_steps() == []
