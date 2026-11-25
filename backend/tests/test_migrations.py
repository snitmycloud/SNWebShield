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
        assert db.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0018_detect_results"
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
        after = {table: db.execute(f'SELECT * FROM "{table}"').fetchall() for table in tables}
        # Later migrations append nullable columns; every pre-existing column value must be unchanged.
        assert {t: [row[:len(old[0])] if old else row for row in rows] for (t, rows), old in
                ((item, before[item[0]]) for item in after.items())} == before
        assert db.execute('SELECT COUNT(*) FROM monitoring_configs').fetchone()[0]==0
        assert db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]==1
        assert db.execute('SELECT COUNT(*) FROM assessment_requests').fetchone()[0]==0


def test_stage_one_intents_and_accounts_survive_local_upgrade(tmp_path):
    path=tmp_path/'stage-one.db'
    migrate(path,'0005_assessment_intents')
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO admins (id,email,full_name,password_hash,role,is_active) VALUES (1,'synthetic@example.com','Test Admin','preserved-password-hash','admin',1)")
        db.execute("INSERT INTO clients (id,company_name,primary_contact_name,email) VALUES (1,'Synthetic','Contact','contact@example.com')")
        db.execute("INSERT INTO websites (id,client_id,name,url,environment,authorisation_status) VALUES (1,1,'Synthetic','https://example.com','staging','pending')")
        db.execute("INSERT INTO website_authorizations (id,website_id,authorization_reference,authorized_by,authorized_domains,permitted_methods,valid_from,valid_until,status,evidence_revision,timestamps_verified) VALUES (1,1,'SYNTHETIC','Contact','[\"example.com\"]','[\"automated_non_intrusive_scanning\"]','2026-11-22','2026-11-23','pending',0,1)")
        db.execute("INSERT INTO jobs (id,job_type,resource_id,revision,status,idempotency_key,due_at,attempts,max_attempts,created_at) VALUES ('preserved','assessment',1,1,'queued','key','2026-11-22',0,1,'2026-11-22')")
        db.execute("INSERT INTO assessment_requests VALUES ('intent','preserved',1,1,1,'2026-11-22','authorization-preflight-v1','digest','https://example.com','example.com','permission','{}','Existing explicit preflight')")
        before=db.execute('SELECT * FROM assessment_requests').fetchall()
    migrate(path)
    with sqlite3.connect(path) as db:
        assert [row[:-1] for row in db.execute('SELECT * FROM assessment_requests')]==before
        assert db.execute('SELECT execution_snapshot FROM assessment_requests').fetchone()==(None,)
        assert db.execute('SELECT password_hash FROM admins').fetchone()==('preserved-password-hash',)
        assert db.execute('SELECT COUNT(*) FROM assessment_reports').fetchone()==(0,)


def test_self_service_migration_keeps_every_row_and_marks_the_permission_tables_unused(tmp_path):
    path = tmp_path / "pre-self-service.db"
    migrate(path, "0015_port_watch")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO admins (id,email,full_name,password_hash,role,is_active) VALUES (3,'analyst@example.com','Analyst','hash-a','analyst',1)")
        db.execute("INSERT INTO admins (id,email,full_name,password_hash,role,is_active) VALUES (7,'boss@example.com','Admin','hash-b','admin',1)")
        db.execute("INSERT INTO clients (id,company_name,primary_contact_name,email) VALUES (4,'Synthetic','Contact','c@example.com')")
        for wid, url in ((5, "https://Example.com/shop"), (6, "https://example.com"), (8, "https://10.0.0.1/")):
            db.execute("INSERT INTO websites (id,client_id,name,url,environment,authorisation_status) VALUES (?,4,'Site',?,'production','approved')", (wid, url))
        db.execute("INSERT INTO website_authorizations (id,website_id,authorization_reference,authorized_by,authorized_domains,permitted_methods,valid_from,valid_until,status,evidence_revision,timestamps_verified) VALUES (9,5,'KEEP','Contact','[\"example.com\"]','[\"passive_reconnaissance\"]','2026-11-22','2026-11-23','approved',0,1)")
        db.execute("INSERT INTO auth_events (occurred_at,event_type,email_sha256,admin_id,client_ip,reason,detail) VALUES ('2026-11-22','login_success','x',7,'127.0.0.1','','{}')")
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('alembic_version','sqlite_sequence')")]
        before = {t: db.execute(f'SELECT * FROM "{t}"').fetchall() for t in tables}
    migrate(path)
    migrate(path)  # idempotent
    with sqlite3.connect(path) as db:
        for table, rows in before.items():
            after = db.execute(f'SELECT * FROM "{table}"').fetchall()
            assert [r[:len(rows[0])] for r in after] == rows if rows else after == [], table
        assert db.execute("SELECT id, plan, email_verified_at IS NOT NULL FROM admins ORDER BY id").fetchall() == [(3, "free", 1), (7, "free", 1)]
        websites = db.execute("SELECT id, owner_id, domain, verification_status, length(verification_token), client_id FROM websites ORDER BY id").fetchall()
        # First admin owns the first example.com row; the duplicate and the IP-only row stay staff-only legacy rows.
        assert websites == [(5, 7, "example.com", "unverified", 32, 4), (6, None, None, "unverified", 32, 4),
                            (8, None, None, "unverified", 32, 4)]
        assert {r[0] for r in db.execute("SELECT name FROM retired_tables")} == {
            "website_authorizations", "authorization_audit_events", "authorization_evidence", "evidence_reviews", "evidence_events"}
        db.execute("INSERT INTO admins (email,full_name,password_hash,role,is_active,plan) VALUES ('u@example.com','U','h','user',1,'free')")
        for statement in ("UPDATE auth_events SET reason='x'", "DELETE FROM auth_events"):
            try:
                db.execute(statement)
            except sqlite3.DatabaseError as error:
                assert "append-only" in str(error)
            else:
                raise AssertionError("auth_events must stay append-only")
        db.execute("INSERT INTO auth_events (occurred_at,event_type,email_sha256,client_ip,reason,detail) VALUES ('2026-11-25','signup','y','127.0.0.1','','{}')")


def test_vulnerability_migration_preserves_reports_reviews_and_deadlines(tmp_path):
    path = tmp_path / 'pre-vulnerabilities.db'
    migrate(path, '0008_findings_dashboard')
    tables = ('admins', 'assessment_reports', 'observation_reviews', 'finding_due_dates', 'execution_events')
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO admins (id,email,full_name,password_hash,role,is_active) VALUES (1,'synthetic@example.com','Test Admin','preserved-password-hash','admin',1)")
        before = {table: db.execute(f'SELECT * FROM {table}').fetchall() for table in tables}
    migrate(path)
    migrate(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0018_detect_results"
        after = {table: db.execute(f'SELECT * FROM {table}').fetchall() for table in tables}
        # 0016 appends account columns to admins; every pre-existing value is unchanged.
        after["admins"] = [row[:len(before["admins"][0])] for row in after["admins"]]
        assert after == before
        for table in ('vulnerabilities', 'vulnerability_occurrences', 'vulnerability_events',
                      'vulnerability_suppressions', 'vulnerability_ingestions'):
            assert db.execute(f'SELECT COUNT(*) FROM {table}').fetchone() == (0,)
        checks = db.execute("SELECT sql FROM sqlite_master WHERE name='vulnerabilities'").fetchone()[0]
        assert "ck_vulnerability_state" in checks and "fingerprint" in checks


def test_website_removal_migration_keeps_rows_and_only_limits_the_unique_rule_to_live_websites(tmp_path):
    path = tmp_path / "pre-removal.db"
    migrate(path, "0016_self_service")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO admins (id,email,full_name,password_hash,role,is_active,plan) VALUES (1,'o@example.com','Owner','h','user',1,'free')")
        db.execute("INSERT INTO websites (id,owner_id,name,url,domain,environment,authorisation_status,verification_status) VALUES (1,1,'a.example.com','https://a.example.com/','a.example.com','production','retired','verified')")
        db.execute("INSERT INTO scans (id,website_id,owner_id,scan_type,trigger,status,requested_at) VALUES ('s1',1,1,'standard','first','incomplete','2026-11-25')")
        before = db.execute("SELECT id,owner_id,domain,verification_status FROM websites").fetchall()
    migrate(path)
    migrate(path)  # idempotent
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0018_detect_results"
        assert db.execute("SELECT id,owner_id,domain,verification_status FROM websites").fetchall() == before
        assert db.execute("SELECT removed_at FROM websites WHERE id=1").fetchone() == (None,)
        assert db.execute("SELECT COUNT(*) FROM scans").fetchone() == (1,)
        # A second live website with the same owner and domain is refused...
        try:
            db.execute("INSERT INTO websites (owner_id,name,url,domain,environment,authorisation_status) VALUES (1,'dup','https://a.example.com/','a.example.com','production','retired')")
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("a live duplicate must be refused")
        # ...but once the first one is removed, the domain can be added again.
        db.execute("UPDATE websites SET removed_at='2026-11-25' WHERE id=1")
        db.execute("INSERT INTO websites (owner_id,name,url,domain,environment,authorisation_status) VALUES (1,'again','https://a.example.com/','a.example.com','production','retired')")
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

def test_detect_results_migration_is_additive_and_keeps_scan_history(tmp_path):
    path = tmp_path / "pre-detect.db"
    migrate(path, "0017_website_removal")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO admins (id,email,full_name,password_hash,role,is_active,plan) VALUES (1,'o@example.com','Owner','h','user',1,'free')")
        db.execute("INSERT INTO websites (id,owner_id,name,url,domain,environment,authorisation_status) VALUES (1,1,'a','https://a.example.com/','a.example.com','production','retired')")
        db.execute("INSERT INTO scans (id,website_id,owner_id,scan_type,trigger,status,requested_at,result) VALUES ('s1',1,1,'standard','first','incomplete','2026-11-25','{\"code\":\"checks_not_available\"}')")
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('alembic_version','sqlite_sequence')")]
        before = {t: db.execute(f'SELECT * FROM "{t}"').fetchall() for t in tables}
    migrate(path)
    migrate(path)  # idempotent
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0018_detect_results"
        assert {t: db.execute(f'SELECT * FROM "{t}"').fetchall() for t in tables} == before  # nothing existing changed
        for table in ("scan_ports", "scan_technologies", "scan_observations"):
            assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)
        db.execute("INSERT INTO scan_ports (scan_id,port,state,service) VALUES ('s1',22,'open','ssh')")
        try:
            db.execute("INSERT INTO scan_ports (scan_id,port,state,service) VALUES ('s1',22,'open','ssh')")
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("one row per scan and port")
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"