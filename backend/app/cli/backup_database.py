"""Make a consistent local SQLite backup without printing records or secrets."""
from datetime import UTC, datetime
from pathlib import Path
import sqlite3

from sqlalchemy.engine import make_url

from app.core.config import settings


def main() -> int:
    url = make_url(settings.database_url)
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        print("This command supports file-based SQLite only; use your database's backup procedure.")
        return 1
    source = Path(url.database).resolve()
    if not source.is_file():
        print("Configured SQLite database does not exist. Check the backend working directory.")
        return 1
    destination_dir = Path.home() / "SNWebShield-Backups"
    destination_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    destination = destination_dir / f"snwebshield-before-auth-correctness-{stamp}.db"
    with sqlite3.connect(source.as_uri() + "?mode=ro", uri=True) as source_db:
        with sqlite3.connect(destination) as backup_db:
            source_db.backup(backup_db)
            if backup_db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("Backup integrity check failed; do not run migrations")
    print(f"Verified SQLite backup: {destination}")
    print("Keep this backup private; it contains application data and password hashes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
