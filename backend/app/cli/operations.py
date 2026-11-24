"""Run scheduler, monitoring worker or notification dispatcher independently."""
import argparse
from datetime import timedelta
from email.message import EmailMessage
import multiprocessing
import smtplib
import ssl
import threading
import time
from uuid import uuid4
from sqlalchemy import select, update, or_

from app.core.config import settings
from app.core.time import as_utc, utc_now
from app.db.session import SessionLocal
from app.models.jobs import Job
from app.models.monitoring import MonitoringConfig, NotificationDelivery
from app.models.website import Website
from app.services import job_engine as engine
from app.services import monitoring, assessments
from app.services.monitor_probe import probe_child


def permitted(job_id, token, verify_file=False):
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        return bool(job and job.status == "running" and job.claim_token == token and
                    engine.HANDLERS[job.job_type].eligible(db, job, verify_file=verify_file))


def worker_tick():
    with SessionLocal() as db:
        engine.heartbeat(db, "monitoring-worker"); db.commit()
        claimed = engine.claim(db, "monitoring")
    if not claimed: return
    job_id, token = claimed
    if not permitted(job_id, token, verify_file=True):
        payload = {"state": "cancelled", "error": "permission_or_configuration_changed"}
    else:
        with SessionLocal() as db:
            job = db.get(Job, job_id); config = db.get(MonitoringConfig, job.resource_id)
            url, timeout = db.get(Website, job.resource_id).url, config.timeout_seconds
        context = multiprocessing.get_context("spawn")
        receive, send = context.Pipe(duplex=True)
        process = context.Process(target=probe_child, args=(send, url, timeout), daemon=True)
        process.start(); send.close(); deadline = time.monotonic() + timeout + 3
        payload = {"state": "down", "error": "deadline_exceeded", "response_ms": (timeout + 3) * 1000}
        try:
            while time.monotonic() < deadline:
                if not permitted(job_id, token):
                    payload = {"state": "cancelled", "error": "permission_or_configuration_changed"}; break
                if receive.poll(0.25):
                    try:
                        message = receive.recv()
                        if isinstance(message, tuple) and message[0] == "permission":
                            receive.send(permitted(job_id, token)); continue
                        payload = message
                    except EOFError: payload = {"state": "unknown", "error": "probe_process_failed"}
                    break
                if not process.is_alive(): payload = {"state": "unknown", "error": "probe_process_failed"}; break
        finally:
            if process.is_alive(): process.terminate()
            process.join(timeout=2)
            if process.is_alive(): process.kill(); process.join(timeout=2)
            receive.close()
    with SessionLocal() as db: engine.finish(db, job_id, token, payload)


def notification_tick():
    now = utc_now()
    with SessionLocal() as db:
        engine.heartbeat(db, "notification-dispatcher"); db.commit()
        for exhausted in db.scalars(select(NotificationDelivery).where(
            NotificationDelivery.status == "sending", NotificationDelivery.lease_until <= now,
            NotificationDelivery.attempts >= 3)):
            exhausted.status = "failed"; exhausted.claim_token = None; exhausted.lease_until = None
            exhausted.last_error = "delivery_lease_expired"
            engine.event(db, "notification_failed", resource_id=exhausted.website_id,
                detail={"delivery_id": exhausted.id, "reason": "delivery_lease_expired"})
        db.commit()
        row = db.scalar(select(NotificationDelivery).where(or_(
            (NotificationDelivery.status == "pending") & (NotificationDelivery.next_due <= now),
            (NotificationDelivery.status == "sending") & (NotificationDelivery.lease_until <= now)
        )).order_by(NotificationDelivery.next_due).limit(1))
        if not row: return
        token = str(uuid4())
        changed = db.execute(update(NotificationDelivery).where(NotificationDelivery.id == row.id,
            NotificationDelivery.status == row.status,
            NotificationDelivery.claim_token.is_(None) if row.claim_token is None else NotificationDelivery.claim_token == row.claim_token
        ).values(status="sending", claim_token=token, lease_until=now + timedelta(seconds=60),
                 attempts=NotificationDelivery.attempts + 1).execution_options(synchronize_session=False))
        if changed.rowcount != 1: db.rollback(); return
        key, website_id, action = row.id, row.website_id, row.event
        db.commit()
    error = None
    try:
        if settings.notification_channel == "smtp":
            if not settings.smtp_host or not settings.notification_recipient or not settings.smtp_sender:
                raise ValueError("smtp_not_configured")
            message = EmailMessage(); message["From"] = settings.smtp_sender; message["To"] = settings.notification_recipient
            message["Subject"] = f"SNWebShield: {action} — website #{website_id}"
            message["Message-ID"] = f"<{key}@snwebshield.local>"
            message.set_content(f"Monitoring event: {action}\nWebsite ID: {website_id}\nDelivery reference: {key}\nOpen the internal dashboard for details.")
            with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=10, context=ssl.create_default_context()) as smtp:
                if settings.smtp_username: smtp.login(settings.smtp_username, settings.smtp_password.get_secret_value())
                smtp.send_message(message)
        # The dashboard channel is durable in-app notification delivery, not email.
    except Exception:
        error = "notification_delivery_failed"
    with SessionLocal() as db:
        row = db.get(NotificationDelivery, key)
        if row.claim_token != token: return
        row.claim_token = None; row.lease_until = None; row.last_error = error
        row.status = "delivered" if not error else "failed" if row.attempts >= 3 else "pending"
        row.next_due = utc_now() + timedelta(seconds=30 * 2 ** min(row.attempts, 3))
        engine.event(db, "notification_" + row.status, resource_id=website_id, detail={"delivery_id": key, "channel": settings.notification_channel})
        db.commit()


def should_beat(progress_at, now, limit):
    """A heartbeat is evidence the worker is making progress, not merely that its process exists."""
    return now - progress_at <= limit


def _heartbeat_loop(name, stop, progress, limit, interval=10):
    """Heartbeat independently of the job loop so a long scan is not reported as a dead worker.

    The beat stops once the main loop has made no progress for `limit` seconds (longer than any
    legitimate job), so a hung worker still turns stale instead of being masked by this thread.
    """
    while not stop.wait(interval):
        if not should_beat(progress["at"], time.monotonic(), limit):
            continue
        try:
            with SessionLocal() as db: engine.heartbeat(db, name); db.commit()
        except Exception: pass  # a missed beat is itself the signal; never log details


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("role", choices=["scheduler", "worker", "notifications", "assessment-worker"])
    parser.add_argument("--once", action="store_true"); args = parser.parse_args()
    stop = threading.Event()
    progress = {"at": time.monotonic()}
    if args.role == "assessment-worker":
        try: assessments.recover_on_start()  # a crash between a result and its ingestion must not lose it
        except Exception: print("assessment-worker: startup recovery failed; check execution history", flush=True)
        if not args.once:
            limit = engine.lease_seconds("assessment") + 15  # beyond this a tick has overrun its own lease
            threading.Thread(target=_heartbeat_loop, args=("assessment-worker", stop, progress, limit), daemon=True).start()
    try:
        while True:
            progress["at"] = time.monotonic()
            try:
                if args.role == "scheduler":
                    with SessionLocal() as db: engine.scheduler_tick(db)
                elif args.role == "worker": worker_tick()
                elif args.role == "assessment-worker": assessments.worker_tick()
                else: notification_tick()
            except Exception:
                # Never print URLs, credentials or response contents.
                print(f"{args.role}: operation failed; inspect execution history and configuration", flush=True)
                if args.once: raise
            progress["at"] = time.monotonic()
            if args.once: break
            time.sleep(2)
    except KeyboardInterrupt: pass
    finally: stop.set()


if __name__ == "__main__": main()
