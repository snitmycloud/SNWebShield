import os
from pathlib import Path

# Configure one isolated SQLite file and a test-only JWT key before app imports.
TEST_DB = Path(__file__).with_name("test_snwebshield.db")
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"
os.environ["JWT_SECRET_KEY"] = "test-only-secret-key-not-for-any-real-environment-123456789"
