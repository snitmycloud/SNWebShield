"""Port scan: the fixed Nmap top-1000 list, open / closed / filtered, the limits, and clean cancellation."""
import asyncio
import errno
import time

import pytest

from app.data.ports import EXTRA_RISKY_PORTS, FULL_PORTS, STANDARD_PORTS, ports_for
from app.data.top_ports import TOP_TCP_PORTS
from app.services import detect_ports, netio
from app.services.scan_guard import ScanStopped
from netfixtures import BackgroundServer, banner_handler, free_port

IP = "127.0.0.1"


def test_the_fixed_port_lists():
    assert len(TOP_TCP_PORTS) == 1000 and len(set(TOP_TCP_PORTS)) == 1000
    assert all(1 <= p <= 65535 for p in TOP_TCP_PORTS)
    assert set(TOP_TCP_PORTS[:10]) == {80, 23, 443, 21, 22, 25, 3389, 110, 445, 139}  # Nmap's ten most common
    assert {22, 80, 443, 3306, 5432, 1433, 9200, 8080, 31337}.issubset(TOP_TCP_PORTS)
    # Risky-service ports that Nmap's default list omits are added, and only those (9200 Elasticsearch is already in it).
    assert EXTRA_RISKY_PORTS == (6379, 27017, 11211, 2375, 2376, 5984, 5601, 2379, 10250, 15672, 9300)
    assert {9200, 3306, 5432, 1433, 23, 21, 3389, 445, 139}.issubset(TOP_TCP_PORTS)
    assert len(STANDARD_PORTS) == 1011 and set(STANDARD_PORTS) == set(TOP_TCP_PORTS) | set(EXTRA_RISKY_PORTS)
    assert len(set(STANDARD_PORTS)) == len(STANDARD_PORTS)
    assert 31337 in STANDARD_PORTS and 9929 in STANDARD_PORTS  # scanme.nmap.org's ports
    assert ports_for("standard") == STANDARD_PORTS
    assert ports_for("full") == FULL_PORTS and len(FULL_PORTS) == 65535 and FULL_PORTS[0] == 1 and FULL_PORTS[-1] == 65535


def scan(ports, **kwargs):
    results = detect_ports.PortResults()
    asyncio.run(detect_ports.scan_ports(IP, ports, results, **kwargs))
    return results


def test_open_closed_and_filtered_ports(monkeypatch):
    with BackgroundServer(banner_handler(b"hello\n")) as server:
        closed, filtered = free_port(), free_port()
        real = netio.open_connection

        async def fake(ip, port, **kwargs):
            if port == closed:  # a real refusal takes ~2 s to be reported on Windows, so it is simulated here
                raise ConnectionRefusedError
            if port == filtered:  # nothing ever answers: a firewall dropping packets
                await asyncio.sleep(kwargs["timeout"])
                raise asyncio.TimeoutError
            return await real(ip, port, **kwargs)

        monkeypatch.setattr(netio, "open_connection", fake)
        result = scan([server.port, closed, filtered], timeout=0.2)
    assert result.open == [server.port] and result.closed == 1 and result.filtered == 1 and result.errors == 0
    assert result.done == 3 and not result.could_not_check


def test_a_reset_counts_as_closed_and_odd_network_errors_are_never_counted_as_closed_or_filtered(monkeypatch):
    async def reset(ip, port, **kwargs):
        raise ConnectionResetError

    monkeypatch.setattr(netio, "open_connection", reset)
    assert scan([1, 2, 3]).closed == 3

    async def unreachable(ip, port, **kwargs):
        raise OSError(errno.ENETUNREACH, "Network is unreachable")

    monkeypatch.setattr(netio, "open_connection", unreachable)
    result = scan(list(range(1, 21)))
    assert result.errors == 20 and result.closed == result.filtered == 0 and result.open == []
    assert result.could_not_check  # never reported as "no open ports"


def test_the_connection_limit_is_respected(monkeypatch):
    state = {"now": 0, "peak": 0}

    async def fake(ip, port, **kwargs):
        state["now"] += 1
        state["peak"] = max(state["peak"], state["now"])
        try:
            await asyncio.sleep(0.01)
            raise ConnectionRefusedError
        finally:
            state["now"] -= 1

    monkeypatch.setattr(netio, "open_connection", fake)
    result = scan(list(range(1, 301)), concurrency=25)
    assert result.done == 300 and 1 < state["peak"] <= 25


def test_the_ports_per_second_limit(monkeypatch):
    async def instant(ip, port, **kwargs):
        raise ConnectionRefusedError

    monkeypatch.setattr(netio, "open_connection", instant)
    started = time.monotonic()
    scan(list(range(1, 101)), per_second=200)
    assert 0.35 <= time.monotonic() - started < 2.0  # 100 ports at 200/s take about half a second


def test_each_port_is_limited_by_the_timeout(monkeypatch):
    async def never(ip, port, **kwargs):
        await asyncio.sleep(kwargs["timeout"])
        raise asyncio.TimeoutError

    monkeypatch.setattr(netio, "open_connection", never)
    started = time.monotonic()
    result = scan(list(range(1, 41)), concurrency=40, timeout=0.3)
    assert result.filtered == 40 and time.monotonic() - started < 1.5


def test_cancelling_keeps_the_partial_results_and_closes_every_connection(monkeypatch):
    state = {"now": 0, "attempts": 0}
    with BackgroundServer(banner_handler(b"x", then_close=False)) as server:
        real = netio.open_connection

        async def fake(ip, port, **kwargs):
            state["attempts"] += 1
            state["now"] += 1
            try:
                if port == 1:
                    return await real(ip, server.port, **kwargs)
                await asyncio.sleep(3600)  # hangs until cancelled
            finally:
                state["now"] -= 1

        monkeypatch.setattr(netio, "open_connection", fake)
        results = detect_ports.PortResults()

        async def main():
            task = asyncio.create_task(detect_ports.scan_ports(IP, list(range(1, 5000)), results, concurrency=50))
            await asyncio.sleep(0.4)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(main())
        after = state["attempts"]
        time.sleep(0.3)
    assert state["now"] == 0  # every connection in flight was cancelled
    assert state["attempts"] == after  # and nothing new was started
    assert results.open == [1] and results.done < results.total  # what was found is kept


def test_a_guard_stop_ends_the_scan_without_further_connections(monkeypatch):
    attempts = []

    async def refuse(ip, port, **kwargs):
        attempts.append(port)
        raise ConnectionRefusedError

    class Guard:
        def check(self):
            if len(attempts) >= 20:
                raise ScanStopped("website_removed")

    monkeypatch.setattr(netio, "open_connection", refuse)
    results = detect_ports.PortResults()
    with pytest.raises(ScanStopped):
        asyncio.run(detect_ports.scan_ports(IP, list(range(1, 3000)), results, guard=Guard(), concurrency=5))
    assert 20 <= len(attempts) < 40 and results.done == len(attempts)


def test_progress_is_reported(monkeypatch):
    async def refuse(ip, port, **kwargs):
        await asyncio.sleep(0.002)
        raise ConnectionRefusedError

    monkeypatch.setattr(netio, "open_connection", refuse)
    seen = []
    scan(list(range(1, 400)), concurrency=5, progress=lambda r: seen.append((r.done, r.total)))
    assert seen and seen[-1] == (399, 399) and all(total == 399 for _, total in seen)


class _Accepted:
    """A connection that was accepted (what an open port looks like to the scanner)."""
    def close(self):
        pass

    async def wait_closed(self):
        pass


def test_a_port_open_like_scanmes_31337_is_reported_by_a_full_standard_scan(monkeypatch):
    open_like_scanme = {22, 80, 9929, 31337}

    async def fake(ip, port, **kwargs):
        if port in open_like_scanme:
            return object(), _Accepted()
        raise ConnectionRefusedError  # everything else is closed

    monkeypatch.setattr(netio, "open_connection", fake)
    result = scan(list(STANDARD_PORTS))
    assert result.open == [22, 80, 9929, 31337]
    assert result.done == result.total == len(STANDARD_PORTS) == 1011 and result.closed == 1007 and result.errors == 0


@pytest.mark.parametrize("port", [31337, 9929, 9200, 6379, 27017, 11211, 2375, 2376, 5984, 5601, 2379, 10250, 15672, 9300])
def test_every_extra_and_unusual_port_is_reported_when_open(monkeypatch, port):
    async def fake(ip, p, **kwargs):
        if p == port:
            return object(), _Accepted()
        raise ConnectionRefusedError

    monkeypatch.setattr(netio, "open_connection", fake)
    assert scan(list(STANDARD_PORTS)).open == [port]


def test_a_port_that_answers_slowly_but_within_the_timeout_is_still_reported(monkeypatch):
    async def fake(ip, p, **kwargs):
        if p == 31337:
            await asyncio.sleep(0.4)  # a distant server
            return object(), _Accepted()
        raise ConnectionRefusedError

    monkeypatch.setattr(netio, "open_connection", fake)
    assert scan(list(STANDARD_PORTS), timeout=1.5).open == [31337]