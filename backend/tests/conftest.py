import os
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
os.environ["SCAN_TLS_HANDSHAKE_TIMEOUT_SECONDS"] = "0.3"   # loopback fixtures: a plain-HTTP fixture never answers a TLS hello, so the 1.2 s production wait only slows tests
os.environ["MONITOR_DOMAIN_ALLOWLIST"] = ""   # the development .env limits the monitor to the test target; tests use their own domains
os.environ["CORS_ORIGINS"] = "http://localhost:5173"
os.environ["JWT_SECRET_KEY"] = "test-only-secret-key-not-for-any-real-environment-123456789"

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


def pytest_collection_modifyitems(config, items):
    """Tests listed in tests/slow_tests.txt (0.8 s or more) get the `slow` marker: `pytest -m "not slow"` is the quick level."""
    listed = {l.strip() for l in (Path(__file__).parent / "slow_tests.txt").read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")}
    slow = pytest.mark.slow
    for item in items:
        if item.nodeid.split("[")[0].replace("tests/", "", 1) in listed:
            item.add_marker(slow)


TEMPLATE_DB = Path(TEST_DIRECTORY.name) / "schema_template.db"


@pytest.fixture(scope="session", autouse=True)
def schema_template():
    """Build the database schema ONCE per test session (per xdist worker) into a template file; each test then starts from a copy of it.
    Creating and dropping ~60 tables for every one of 1,200 tests used to cost about 1.4 s each (most of the suite's run time)."""
    import shutil
    from sqlalchemy import event
    from app.db.base import Base
    from app.db.session import engine
    import app.models  # noqa: F401

    @event.listens_for(engine, "connect")
    def fast_throwaway_database(connection, _record):
        # This file is deleted at the end of the run: no need to wait for the disk to confirm each write.
        cursor = connection.cursor()
        cursor.execute("PRAGMA synchronous=OFF")
        cursor.execute("PRAGMA journal_mode=MEMORY")
        cursor.close()

    Base.metadata.create_all(engine)
    engine.dispose()
    shutil.copyfile(TEST_DB, TEMPLATE_DB)
    yield


@pytest.fixture(autouse=True)
def isolated_database(schema_template):
    """Every test starts with an empty, fully built database (a fresh copy of the template). Only this process's disposable file is touched."""
    import shutil
    import time
    from app.db.session import engine

    for attempt in range(20):
        engine.dispose()   # close every pooled connection so the file can be replaced (Windows keeps open files locked)
        try:
            shutil.copyfile(TEMPLATE_DB, TEST_DB)
            break
        except PermissionError:
            time.sleep(0.1 * (attempt + 1))
    else:
        shutil.copyfile(TEMPLATE_DB, TEST_DB)
    yield
    engine.dispose()


def pytest_sessionfinish(session, exitstatus):
    from app.db.session import engine
    engine.dispose()
    TEST_DIRECTORY.cleanup()
