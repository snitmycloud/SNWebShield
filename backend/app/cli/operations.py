"""Run the scan worker or the monitor. (`python -m app.cli.supervisor` starts both, with the API and web app, and keeps them running.)

    python -m app.cli.operations scan-worker
    python -m app.cli.operations monitor
"""
import argparse
import threading
import time

from app.db.session import SessionLocal
from app.services import job_engine as engine


def should_beat(progress_at, now, limit):
    """A heartbeat is evidence the worker is making progress, not merely that its process exists."""
    return now - progress_at <= limit


def _heartbeat_loop(name, stop, progress, limit, interval=10):
    """Heartbeat independently of the work loop so a long scan is not reported as a dead worker.

    The beat stops once the main loop has made no progress for `limit` seconds (longer than any legitimate round), so a hung worker
    still turns stale instead of being masked by this thread.
    """
    while not stop.wait(interval):
        if not should_beat(progress["at"], time.monotonic(), limit):
            continue
        try:
            with SessionLocal() as db: engine.heartbeat(db, name); db.commit()
        except Exception: pass  # a missed beat is itself the signal; never log details


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["scan-worker", "monitor"])
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    stop = threading.Event()
    progress = {"at": time.monotonic()}
    scan_worker = monitor = None
    if args.role == "scan-worker":
        from app.services import scans
        scan_worker = scans.Worker()
    else:
        from app.services import monitor_role
        monitor = monitor_role.Monitor()
        if not args.once:   # a long uptime round must not make the role look dead
            threading.Thread(target=_heartbeat_loop, args=(monitor_role.NAME, stop, progress, 300), daemon=True).start()
    try:
        while True:
            progress["at"] = time.monotonic()
            try:
                if scan_worker is not None: scan_worker.tick()
                else: monitor.tick()
            except Exception:
                # Never print URLs, credentials or response contents.
                print(f"{args.role}: operation failed; inspect execution history and configuration", flush=True)
                if args.once: raise
            progress["at"] = time.monotonic()
            if args.once: break
            time.sleep(2)
    except KeyboardInterrupt: pass
    finally:
        stop.set()
        if scan_worker is not None: scan_worker.drain()


if __name__ == "__main__": main()
