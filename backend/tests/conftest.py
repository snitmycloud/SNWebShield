import os
os.environ["ASSESSMENT_LOCAL_HTTP_ENABLED"] = "false"
os.environ["ASSESSMENT_REMOTE_DOCKER_ENABLED"] = "false"
os.environ["ASSESSMENT_REMOTE_IMAGE_ID"] = ""
os.environ["ASSESSMENT_NMAP_ENABLED"] = "false"
os.environ["ASSESSMENT_NMAP_IMAGE_ID"] = ""
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

# Configure one isolated SQLite file and a test-only JWT key before app imports.
TEST_DIRECTORY = TemporaryDirectory(prefix="snwebshield-pytest-")
TEST_DB = Path(TEST_DIRECTORY.name) / "test_snwebshield.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"
os.environ["EVIDENCE_ROOT"] = str(Path(TEST_DIRECTORY.name) / "evidence")
os.environ["MAIL_OUTBOX_DIR"] = str(Path(TEST_DIRECTORY.name) / "outbox")
os.environ["SMTP_HOST"] = ""
os.environ["SMTP_SENDER"] = ""
os.environ["NOTIFICATION_CHANNEL"] = "dashboard"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"
os.environ["JWT_SECRET_KEY"] = "test-only-secret-key-not-for-any-real-environment-123456789"

# Legacy analyst-pipeline suites (Phase 1 decision). They exercise the written-permission system that was
# removed (authorisations, evidence uploads, approvals, dual sign-off) and the Docker/Nmap runners, which are
# now read-only. They stay in the repository, unchanged, until Phases 2-4 replace that code and they are
# deleted with it. The read-only behaviour itself is covered by test_legacy_read_only.py.
collect_ignore = [
    "test_assessments.py", "test_authorization_correctness.py", "test_e2e_lifecycle.py", "test_evidence.py",
    "test_findings.py", "test_fix_signoff.py", "test_job_recovery.py", "test_lifecycle.py", "test_local_assessment.py", "test_monitoring.py",
    "test_nmap.py", "test_nmap_inspection.py", "test_observation_reviews.py", "test_one_step_flow.py",
    "test_passive_checks.py", "test_port_watch.py", "test_production_hardening.py", "test_remediation.py",
    "test_remote_assessment.py", "test_reports.py", "test_scanner_hardening.py", "test_unmigrated.py",
    "test_vulnerabilities.py", "test_workbench.py", "test_worker_status.py",
]


@pytest.fixture(autouse=True)
def isolated_database():
    from app.db.base import Base
    from app.db.session import engine
    import app.models  # noqa: F401

    Base.metadata.create_all(engine)
    yield
    # Only this process's disposable database is affected.
    Base.metadata.drop_all(engine)


def pytest_sessionfinish(session, exitstatus):
    from app.db.session import engine
    engine.dispose()
    TEST_DIRECTORY.cleanup()
