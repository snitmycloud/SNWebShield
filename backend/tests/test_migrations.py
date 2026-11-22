import os
from pathlib import Path
import sqlite3
import subprocess
import sys


BACKEND = Path(__file__).resolve().parents[1]


def migrate(path, revision="head"):
    environment = {**os.environ, "DATABASE_URL": f"sqlite:///{path.as_posix()}"}
    return subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", revision],
        cwd=BACKEND, env=environment, text=True, capture_output=True, check=True,
    )


def test_new_database_migrates_and_upgrade_is_idempotent(tmp_path):
    path = tmp_path / "fresh.db"
    migrate(path)
    migrate(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0005_assessment_intents"
        columns = {row[1] for row in db.execute("PRAGMA table_info(website_authorizations)")}
        assert "timestamps_verified" in columns
        assert db.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0


def test_adopts_legacy_database_without_resetting_data_or_dates(tmp_path):
    path = tmp_path / "existing.db"
    migrate(path, "0001_foundation")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO admins (id,email,full_name,password_hash,role,is_active) VALUES (7,'test@example.com','Synthetic Admin','preserve-this-synthetic-hash','admin',1)")
        db.execute("INSERT INTO clients (id,company_name,primary_contact_name,email) VALUES (4,'Synthetic Company','Contact','contact@example.com')")
        db.execute("INSERT INTO websites (id,client_id,name,url,environment,authorisation_status) VALUES (5,4,'Synthetic site','https://example.com','staging','approved')")
        db.execute("INSERT INTO website_authorizations (id,website_id,authorization_reference,authorized_by,authorized_domains,permitted_methods,valid_from,valid_until,status) VALUES (9,5,'LEGACY-1','Contact','[\"example.com\"]','[\"passive_reconnaissance\"]','2026-11-22 10:00:00','2026-11-23 10:00:00','approved')")
        db.execute("INSERT INTO authorization_audit_events (authorization_id,admin_id,action,previous_status,new_status,note,evidence_reviewed) VALUES (9,7,'approved','pending','approved','Original synthetic approval retained.',1)")
        # Simulate a pre-Alembic installation, not a stamped database.
        db.execute("DROP TABLE alembic_version")
    migrate(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT id,password_hash,is_active FROM admins").fetchall() == [(7, "preserve-this-synthetic-hash", 1)]
        assert db.execute("SELECT id,valid_from,valid_until,status,timestamps_verified FROM website_authorizations").fetchall() == [(9, "2026-11-22 10:00:00", "2026-11-23 10:00:00", "approved", 0)]
        assert db.execute("SELECT COUNT(*) FROM authorization_audit_events").fetchone()[0] == 1
        assert db.execute("SELECT client_id FROM websites WHERE id=5").fetchone()[0] == 4


def test_partial_schema_is_refused_without_dropping_data(tmp_path):
    path = tmp_path / "partial.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE admins (id INTEGER PRIMARY KEY, marker TEXT)")
        db.execute("INSERT INTO admins VALUES (1,'preserve')")
    try:
        migrate(path)
    except subprocess.CalledProcessError as exc:
        assert "Partial database schema" in exc.stderr
    else:
        raise AssertionError("Partial schema must not be adopted")
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT * FROM admins").fetchall() == [(1, "preserve")]


def test_monitoring_database_upgrade_preserves_all_old_rows(tmp_path):
    path=tmp_path/'evidence-existing.db'
    migrate(path,'0004_monitoring')
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO admins (id,email,full_name,password_hash,role,is_active) VALUES (7,'test@example.com','Synthetic Admin','synthetic-hash','admin',1)")
        db.execute("INSERT INTO clients (id,company_name,primary_contact_name,email) VALUES (4,'Synthetic Company','Contact','contact@example.com')")
        db.execute("INSERT INTO websites (id,client_id,name,url,environment,authorisation_status) VALUES (5,4,'Synthetic site','https://example.com','staging','approved')")
        db.execute("INSERT INTO website_authorizations (id,website_id,authorization_reference,authorized_by,authorized_domains,permitted_methods,valid_from,valid_until,status,evidence_revision,timestamps_verified) VALUES (9,5,'PERMISSION-1','Contact','[\"example.com\"]','[\"passive_reconnaissance\"]','2026-11-22 10:00:00','2026-11-23 10:00:00','approved',1,1)")
        db.execute("INSERT INTO authorization_evidence VALUES ('synthetic-doc',9,5,4,'synthetic.png','image/png',10,?,7,'2026-11-22 10:00:00','2027-11-22 10:00:00',0,'available')",('0'*64,))
        db.execute("INSERT INTO evidence_reviews VALUES ('synthetic-review',9,1,'[\"synthetic-doc\"]',7,'2026-11-22 10:00:00','accepted','Synthetic scope review')")
        db.execute("INSERT INTO jobs (id,job_type,resource_id,revision,status,idempotency_key,due_at,attempts,max_attempts,created_at,completed_at) VALUES ('old-monitor-job','monitoring',5,1,'completed','preserved-monitor-key','2026-11-22 10:00:00',1,2,'2026-11-22 10:00:00','2026-11-22 10:00:01')")
        db.execute("INSERT INTO job_results VALUES ('old-monitor-job','2026-11-22 10:00:01','{\"state\":\"up\"}')")
        tables=[row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('alembic_version','sqlite_sequence')")]
        before={table:db.execute(f'SELECT * FROM "{table}"').fetchall() for table in tables}
    migrate(path)
    with sqlite3.connect(path) as db:
        assert {table:db.execute(f'SELECT * FROM "{table}"').fetchall() for table in tables}==before
        assert db.execute('SELECT COUNT(*) FROM monitoring_configs').fetchone()[0]==0
        assert db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]==1
        assert db.execute('SELECT COUNT(*) FROM assessment_requests').fetchone()[0]==0
