from pathlib import Path
import sqlite3

from app.cli.backup_database import main
from app.core.config import settings


def test_backup_creates_verified_copy_outside_repository(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source.db"
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE sample (value TEXT)")
        db.execute("INSERT INTO sample VALUES ('synthetic private value')")
    monkeypatch.setattr(settings, "database_url", f"sqlite:///{source.as_posix()}")
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    assert main() == 0
    backup, = (tmp_path / "home" / "SNWebShield-Backups").glob("*.db")
    with sqlite3.connect(backup) as db:
        assert db.execute("SELECT value FROM sample").fetchone()[0] == "synthetic private value"
    assert "synthetic private value" not in capsys.readouterr().out
