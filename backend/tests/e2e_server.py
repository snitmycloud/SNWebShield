"""Local-only browser-test API. Never opens the developer's configured database."""
import os
os.environ["ASSESSMENT_LOCAL_HTTP_ENABLED"] = "true"
os.environ["ASSESSMENT_REMOTE_DOCKER_ENABLED"] = "true"
os.environ["ASSESSMENT_REMOTE_IMAGE_ID"] = "sha256:" + "a" * 64
os.environ["ASSESSMENT_NMAP_ENABLED"] = "true"
os.environ["ASSESSMENT_NMAP_IMAGE_ID"] = "sha256:" + "b" * 64
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
        # This replacement exists only in the disposable browser-test server.
        # The Python analyzer and all permission/queue code remain real.
        from app.services import local_assessment_runtime as local_runtime
        actual_invoke = local_runtime.invoke
        def fixture_invoke(script, payload, permitted, seconds):
            if script == "assessment_broker.py":
                if not permitted(): raise RuntimeError("permission_changed")
                return {"result":{"status":200,"tls_verified":True,"connected_ip":"8.8.8.8",
                    "dns_addresses":["8.8.8.8"],"response_ms":12.5,"header_bytes":100,
                    "certificate_not_after":None,"redirect_followed":False,"facts":{},"tls_version":"TLSv1.3",
                    "redirect":{"is_redirect":False,"location":None,"followed":False},
                    "selected_headers":{"content-security-policy":"default-src 'self'","server":"Synthetic-fixture"}}}
            return actual_invoke(script,payload,permitted,seconds)
        local_runtime.invoke = fixture_invoke
        from app.services import remote_assessment_runtime as remote_runtime
        from app.services.header_analyzer import analyze
        remote_runtime.invoke = fixture_invoke
        def fixture_ssh(operation, payload, permitted, seconds):
            if not permitted(): raise RuntimeError("permission_changed")
            if operation == "check":
                return {"runner": remote_runtime.VERSION, "image_id": os.environ["ASSESSMENT_REMOTE_IMAGE_ID"]}
            if operation == "cleanup": return {"cleanup_confirmed": True}
            return {"analysis": analyze(payload["data"]), "execution": {
                "id": payload["id"], "image_id": os.environ["ASSESSMENT_REMOTE_IMAGE_ID"],
                "cleanup_confirmed": True, "isolation_verified": True, "duration_ms": 50, "container_duration_ms": 40, "analyzer_cpu_seconds": .01,
                "analyzer_peak_rss_bytes": 1000000, "analyzer_duration_ms": 1,
                "limits": {"memory_bytes": 67108864, "cpus": .25, "pids": 16, "timeout_seconds": 8}}}
        remote_runtime.ssh_exchange = fixture_ssh
        from app.services import nmap_runtime, nmap_policy
        from urllib.parse import urlsplit
        def fixture_nmap_broker(script, payload, permitted, seconds):
            if script != "nmap_broker.py" or not permitted(): raise RuntimeError("unexpected_nmap_fixture")
            return {"result": {"host": urlsplit(payload["url"]).hostname, "ip": "8.8.8.8", "dns_addresses": ["8.8.8.8"]}}
        def fixture_nmap_ssh(operation, payload, permitted, seconds):
            if not permitted(): raise RuntimeError("permission_changed")
            image = os.environ["ASSESSMENT_NMAP_IMAGE_ID"]
            if operation == "check": return {"runner": nmap_policy.VERSION, "image_id": image, "ports": [80, 443]}
            if operation == "cleanup": return {"cleanup_confirmed": True}
            states = {"80": "open", "443": "closed"}
            return {"states": states, "analysis": nmap_policy.analysis(states), "execution": {
                "id": payload["id"], "image_id": image, "limits": nmap_policy.LIMITS, "cleanup_confirmed": True,
                "egress_ip": "8.8.8.8", "egress_tcp_ports": [80, 443], "duration_ms": 100,
                "container_duration_ms": 80, "scanner_cpu_seconds": .01, "scanner_peak_rss_bytes": 16000000,
                "scanner_duration_ms": 60}}
        nmap_runtime.invoke = fixture_nmap_broker
        nmap_runtime.exchange = fixture_nmap_ssh
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
                        run_preflight = first is not None and first.request_note.startswith(("BROWSER_COMPLETE", "BROWSER_LOCAL", "BROWSER_REMOTE", "BROWSER_NMAP"))
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
