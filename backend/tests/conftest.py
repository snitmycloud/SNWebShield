import os
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

# Configure one isolated SQLite file and a test-only JWT key before app imports.
TEST_DIRECTORY = TemporaryDirectory(prefix="snwebshield-pytest-")
TEST_DB = Path(TEST_DIRECTORY.name) / "test_snwebshield.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"
os.environ["EVIDENCE_ROOT"] = str(Path(TEST_DIRECTORY.name) / "evidence")
os.environ["CORS_ORIGINS"] = "http://localhost:5173"
os.environ["JWT_SECRET_KEY"] = "test-only-secret-key-not-for-any-real-environment-123456789"


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
