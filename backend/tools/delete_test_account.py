"""Delete a SYNTHETIC test account's data from the development database, and log exactly what was removed.

    python tools/delete_test_account.py <email> <log-file.md>

Safety:
* only the emails in ALLOWED can be processed (accounts created by the project's own proof runs, never real users);
* it refuses to run if any table other than the ones handled here references the account;
* `auth_events` is append-only (database triggers forbid update and delete) and is never touched, so the account row
  is kept as an anonymized, disabled "tombstone" that those audit rows still point to. Its email, name and password
  are replaced, so nothing identifying remains and nobody can sign in with it.
Back up first: python -m app.cli.backup_database
"""
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete, func, select, text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.security import hash_password  # noqa: E402
from app.core.time import utc_now  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.models.admin import AccountToken, Admin  # noqa: E402
from app.models.jobs import ExecutionEvent  # noqa: E402
from app.models.scan import Scan, ScanObservation, ScanPort, ScanTechnology  # noqa: E402
from app.models.security import AuthEvent, RevokedToken  # noqa: E402
from app.models.website import Website  # noqa: E402
from app.services import job_engine as engine  # noqa: E402

ALLOWED = {"phase1-owner@example.com", "phase2-admin@example.com"}
HANDLED = {"websites", "scans", "execution_events", "account_tokens", "revoked_tokens", "auth_events"}


def references_to_admins(db, account_id):
    """{table: row count} for every table with a foreign key to admins, for this account."""
    found = {}
    for (table,) in db.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall():
        for fk in db.execute(text(f'PRAGMA foreign_key_list("{table}")')).fetchall():
            if fk[2] == "admins":
                n = db.execute(text(f'SELECT COUNT(*) FROM "{table}" WHERE "{fk[3]}" = :id'), {"id": account_id}).scalar()
                if n:
                    found[table] = found.get(table, 0) + n
    return found


def main(email: str, log_file: str) -> int:
    if email not in ALLOWED:
        print("Refused: not an allowed synthetic test account.")
        return 1
    with SessionLocal() as db:
        account = db.scalar(select(Admin).where(Admin.email == email))
        if account is None:
            print("No such account (already removed?).")
            return 0
        if not (account.email.endswith("@example.com") and account.role in ("user", "admin")):
            print("Refused: the account does not look synthetic.")
            return 1
        refs = references_to_admins(db, account.id)
        unexpected = {t: n for t, n in refs.items() if t not in HANDLED}
        if unexpected:
            print("Refused: other tables reference this account:", unexpected)
            return 1

        site_ids = list(db.scalars(select(Website.id).where(Website.owner_id == account.id)))
        domains = sorted(db.scalars(select(Website.domain).where(Website.id.in_(site_ids))))
        scan_ids = list(db.scalars(select(Scan.id).where(Scan.website_id.in_(site_ids)))) if site_ids else []
        removed = {}
        if scan_ids:
            for model, name in ((ScanPort, "scan_ports"), (ScanTechnology, "scan_technologies"), (ScanObservation, "scan_observations")):
                removed[name] = db.execute(delete(model).where(model.scan_id.in_(scan_ids))).rowcount
            removed["scans"] = db.execute(delete(Scan).where(Scan.id.in_(scan_ids))).rowcount
        removed["execution_events"] = db.execute(delete(ExecutionEvent).where(
            (ExecutionEvent.resource_id.in_(site_ids)) | (ExecutionEvent.actor_id == account.id))).rowcount if site_ids else \
            db.execute(delete(ExecutionEvent).where(ExecutionEvent.actor_id == account.id)).rowcount
        removed["websites"] = db.execute(delete(Website).where(Website.id.in_(site_ids))).rowcount if site_ids else 0
        removed["account_tokens"] = db.execute(delete(AccountToken).where(AccountToken.account_id == account.id)).rowcount
        removed["revoked_tokens"] = db.execute(delete(RevokedToken).where(RevokedToken.admin_id == account.id)).rowcount
        audit_rows = db.scalar(select(func.count()).select_from(AuthEvent).where(AuthEvent.admin_id == account.id)) or 0

        account_id, old_role, old_email = account.id, account.role, account.email
        account.email = f"deleted-user-{account_id}@deleted.invalid"
        account.full_name = "Deleted test account"
        account.password_hash = hash_password(secrets.token_urlsafe(48))  # nobody knows it
        account.is_active, account.email_verified_at, account.last_login_at = False, None, None
        engine.event(db, "test_data_cleanup", actor_id=None, detail={
            "account_id": account_id, "role": old_role, "websites_removed": domains, "rows_removed": removed,
            "auth_events_kept": audit_rows})
        db.commit()

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"## {stamp}: synthetic account `{old_email}` (id {account_id}, role {old_role})", "",
             "Removed:", f"- websites: {', '.join(domains) if domains else 'none'}"]
    lines += [f"- {name}: {count}" for name, count in removed.items()]
    lines += ["", f"Kept: the account row as an anonymized, disabled tombstone (email `deleted-user-{account_id}@deleted.invalid`, "
              f"no name, random unknown password, cannot sign in) and its {audit_rows} `auth_events` rows, because that table is "
              "append-only (database triggers forbid update and delete) and the audit log must stay complete.", ""]
    path = Path(log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.exists() else "# Test data cleanup log\n\n"
    path.write_text(existing + "\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
