"""Local-only browser-test API. Never opens the developer's configured database."""
import os
from pathlib import Path
import secrets
import sys
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    with TemporaryDirectory(prefix="snwebshield-browser-") as directory:
        os.environ["DATABASE_URL"] = f"sqlite:///{(Path(directory) / 'browser.db').as_posix()}"
        os.environ["EVIDENCE_ROOT"] = str(Path(directory) / "evidence")
        os.environ["JWT_SECRET_KEY"] = secrets.token_urlsafe(48)
        os.environ["CORS_ORIGINS"] = "http://127.0.0.1:15173"
        os.environ["JWT_ACCESS_TOKEN_MINUTES"] = "20"
        os.environ["NOTIFICATION_CHANNEL"] = "dashboard"

        from alembic import command
        from alembic.config import Config
        from app.core.security import hash_password
        from app.db.session import SessionLocal, engine
        from app.models import Admin
        import uvicorn

        command.upgrade(Config(str(Path(__file__).resolve().parents[1] / "alembic.ini")), "head")
        with SessionLocal() as db:
            db.add(Admin(
                email="browser-test@example.com", full_name="Browser Test Admin",
                password_hash=hash_password("Synthetic-browser-password-123!"),
                role="admin", is_active=True,
            ))
            db.commit()
        # Test-only transport replacement: exercise the real queue, eligibility,
        # transactions and UI without sending requests to synthetic domains.
        from threading import Event, Thread
        from app.services import monitoring, job_engine, assessments
        from sqlalchemy import select
        from app.models.assessment import AssessmentRequest
        from app.models.jobs import Job
        stopped = Event()
        def fixture_worker():
            while not stopped.wait(.2):
                try:
                    with SessionLocal() as db: job_engine.scheduler_tick(db)
                    with SessionLocal() as db:
                        job_engine.heartbeat(db, "monitoring-worker"); db.commit()
                        claimed = job_engine.claim(db, "monitoring")
                        if claimed:
                            job_engine.finish(db, *claimed, {"state": "up", "http_status": 200,
                                "dns_ok": True, "response_ms": 42.5, "tls_valid": True,
                                "certificate_expires_at": "2030-12-31T00:00:00+00:00",
                                "fixture": True})
                    # Test-only completion fixture. Other browser requests stay
                    # queued for deterministic manual-cancellation coverage.
                    with SessionLocal() as db:
                        first = db.scalar(select(AssessmentRequest).join(Job, Job.id == AssessmentRequest.job_id).where(
                            Job.job_type == "assessment", Job.status == "queued").order_by(Job.created_at).limit(1))
                        run_preflight = first is not None and first.request_note.startswith("BROWSER_COMPLETE")
                    if run_preflight: assessments.worker_tick()
                except Exception:
                    # Dispose the transaction and retry, as the real CLI does.
                    continue
        worker = Thread(target=fixture_worker, daemon=True); worker.start()
        try:
            uvicorn.run("app.main:app", host="127.0.0.1", port=18000, access_log=False, log_level="warning")
        finally:
            stopped.set(); worker.join(timeout=5)
            engine.dispose()


if __name__ == "__main__":
    main()
