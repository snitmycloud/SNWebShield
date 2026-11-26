import os
os.environ["ASSESSMENT_LOCAL_HTTP_ENABLED"] = "false"
os.environ["ASSESSMENT_REMOTE_DOCKER_ENABLED"] = "false"
os.environ["ASSESSMENT_REMOTE_IMAGE_ID"] = ""
os.environ["ASSESSMENT_NMAP_ENABLED"] = "false"
os.environ["ASSESSMENT_NMAP_IMAGE_ID"] = ""
os.environ["NUCLEI_ENABLED"] = "false"   # the development default is ON; tests that need it switch it on themselves
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
def no_internet(monkeypatch):
    """No test may reach the internet: scan connections are limited to loopback test servers, and real DNS and
    crt.sh are replaced by errors (tests that need them install their own fakes)."""
    from app.core.config import settings
    from app.services import detect_dns, detect_subdomains, netio, vuln_sources

    real_open = netio.open_connection

    async def loopback_only(ip, port, **kwargs):
        if ip not in ("127.0.0.1", "::1"):
            raise OSError(f"tests must not use the network (tried {ip}:{port})")
        return await real_open(ip, port, **kwargs)

    async def no_dns(name, rdtype):
        raise OSError("tests must not query real DNS")

    def no_crtsh(domain):
        raise OSError("tests must not reach crt.sh")

    def empty_vuln_databases(source, method, path, **kwargs):
        """Default for tests: databases that know of nothing. Tests of failures or findings install their own fake."""
        return {"vulnerabilities": [], "totalResults": 0} if source == "nvd" else {}

    vuln_sources.reset_state()
    monkeypatch.setattr(vuln_sources, "http_json", empty_vuln_databases)
    monkeypatch.setattr(netio, "open_connection", loopback_only)
    monkeypatch.setattr(detect_dns, "lookup", no_dns)
    monkeypatch.setattr(detect_subdomains, "fetch", no_crtsh)
    monkeypatch.setattr(settings, "scan_ports_per_second", 1_000_000)  # tests are not rate-limited unless they say so
    yield


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
