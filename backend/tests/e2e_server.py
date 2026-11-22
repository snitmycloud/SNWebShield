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
        os.environ["JWT_SECRET_KEY"] = secrets.token_urlsafe(48)
        os.environ["CORS_ORIGINS"] = "http://127.0.0.1:15173"
        os.environ["JWT_ACCESS_TOKEN_MINUTES"] = "20"

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
        try:
            uvicorn.run("app.main:app", host="127.0.0.1", port=18000, access_log=False, log_level="warning")
        finally:
            engine.dispose()


if __name__ == "__main__":
    main()
