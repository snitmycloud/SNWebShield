"""Phase 1: self-service accounts, plans, domain ownership verification and scans.

* `admins` becomes the account table: adds `plan` (default free), `email_verified_at`, `password_changed_at`,
  and the `user` role. Existing (staff) accounts are marked email-verified because they were provisioned locally.
* `account_tokens`: hashed, single-use email-verification and password-reset tokens.
* `websites`: `client_id` becomes optional; adds `owner_id`, `domain` and the ownership-verification fields.
  Existing websites are given to the first `admin` account (lowest id) and start `unverified`; a second
  legacy website with the same domain keeps no owner (staff-visible only) so nothing is merged or lost.
* `scans` (one active scan per website, enforced by a partial unique index) and `retired_tables`.
* `auth_events` allows the new account event types.
* The written-permission tables are listed in `retired_tables`: their data is kept, code no longer uses them.

No row is deleted or changed except the additive values above. Back up first: python -m app.cli.backup_database.
SQLite table rebuilds drop triggers, so the append-only auth_events triggers are re-created. Downgrade is refused.
"""
from datetime import UTC, datetime
import secrets

from alembic import op
import sqlalchemy as sa

from app.models.admin import ACCOUNT_ROLES
from app.models.scan import SCAN_STATES, SCAN_TRIGGERS
from app.models.security import AUTH_EVENT_TYPES, trigger_sql as security_triggers

revision = "0016_self_service"
down_revision = "0015_port_watch"
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)
RETIRED = {
    "website_authorizations": "Written-permission records. Replaced by domain ownership verification (Phase 1).",
    "authorization_audit_events": "Approval decisions on written permission. Replaced by ownership verification.",
    "authorization_evidence": "Uploaded permission letters. Evidence uploads were removed in Phase 1.",
    "evidence_reviews": "Human reviews of permission letters. Removed in Phase 1.",
    "evidence_events": "Audit trail of permission-letter handling. Removed in Phase 1.",
}


def _domain_of(url):
    from app.services.domains import DomainError, normalize_domain
    try:
        return normalize_domain(url or "")
    except DomainError:
        return None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    now = datetime.now(UTC)

    # --- accounts ---------------------------------------------------------------------------
    checks = {c.get("name") for c in inspector.get_check_constraints("admins")}
    with op.batch_alter_table("admins", recreate="always") as batch:
        batch.add_column(sa.Column("plan", sa.String(20), nullable=False, server_default="free"))
        batch.add_column(sa.Column("email_verified_at", TZ, nullable=True))
        batch.add_column(sa.Column("password_changed_at", TZ, nullable=True))
        if "ck_admins_role" in checks:
            batch.drop_constraint("ck_admins_role", type_="check")
        batch.create_check_constraint("ck_admins_role", "role IN ('" + "','".join(ACCOUNT_ROLES) + "')")
    bind.execute(sa.text("UPDATE admins SET email_verified_at = :now WHERE email_verified_at IS NULL"), {"now": now})

    op.create_table("account_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("account_id", sa.Integer(), sa.ForeignKey("admins.id", ondelete="CASCADE"), nullable=False),
        sa.Column("purpose", sa.String(20), nullable=False),
        sa.Column("token_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", TZ, nullable=False),
        sa.Column("expires_at", TZ, nullable=False),
        sa.Column("used_at", TZ, nullable=True),
        sa.CheckConstraint("purpose IN ('verify_email','reset_password')", name="ck_account_token_purpose"))
    op.create_index("ix_account_tokens_account_id", "account_tokens", ["account_id"])

    # --- websites ---------------------------------------------------------------------------
    with op.batch_alter_table("websites", recreate="always") as batch:
        batch.alter_column("client_id", existing_type=sa.Integer(), nullable=True)
        batch.add_column(sa.Column("owner_id", sa.Integer(), sa.ForeignKey("admins.id", name="fk_websites_owner_id",
                                                                          ondelete="RESTRICT"), nullable=True))
        batch.add_column(sa.Column("domain", sa.String(253), nullable=True))
        batch.add_column(sa.Column("verification_token", sa.String(64), nullable=True))
        batch.add_column(sa.Column("verification_method", sa.String(10), nullable=True))
        batch.add_column(sa.Column("verification_status", sa.String(20), nullable=False, server_default="unverified"))
        batch.add_column(sa.Column("verified_at", TZ, nullable=True))
        batch.add_column(sa.Column("verification_checked_at", TZ, nullable=True))
        batch.add_column(sa.Column("verification_result", sa.JSON(), nullable=True))
        batch.create_unique_constraint("uq_website_owner_domain", ["owner_id", "domain"])
    op.create_index("ix_websites_owner_id", "websites", ["owner_id"])
    op.create_index("ix_websites_domain", "websites", ["domain"])

    owner = bind.execute(sa.text("SELECT MIN(id) FROM admins WHERE role = 'admin'")).scalar()
    seen = set()
    for website_id, url in bind.execute(sa.text("SELECT id, url FROM websites ORDER BY id")).fetchall():
        domain = _domain_of(url)
        values = {"id": website_id, "token": secrets.token_hex(16), "owner": None, "domain": None}
        if domain and owner is not None and domain not in seen:
            seen.add(domain)
            values.update(owner=owner, domain=domain)
        bind.execute(sa.text("UPDATE websites SET owner_id = :owner, domain = :domain, verification_token = :token, "
                             "verification_status = 'unverified' WHERE id = :id"), values)

    # --- scans ------------------------------------------------------------------------------
    op.create_table("scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("website_id", sa.Integer(), sa.ForeignKey("websites.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("scan_type", sa.String(20), nullable=False),
        sa.Column("trigger", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("requested_at", TZ, nullable=False),
        sa.Column("started_at", TZ, nullable=True),
        sa.Column("ended_at", TZ, nullable=True),
        sa.Column("lease_until", TZ, nullable=True),
        sa.Column("claim_token", sa.String(36), nullable=True),
        sa.Column("resolved_ip", sa.String(45), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("progress", sa.JSON(), nullable=True),
        sa.CheckConstraint("status IN ('" + "','".join(SCAN_STATES) + "')", name="ck_scan_status"),
        sa.CheckConstraint("trigger IN ('" + "','".join(SCAN_TRIGGERS) + "')", name="ck_scan_trigger"))
    for column in ("website_id", "owner_id", "status"):
        op.create_index(f"ix_scans_{column}", "scans", [column])
    op.create_index("uq_active_scan_website", "scans", ["website_id"], unique=True,
                    sqlite_where=sa.text("status IN ('queued', 'running')"),
                    postgresql_where=sa.text("status IN ('queued', 'running')"))

    op.create_table("retired_tables",
        sa.Column("name", sa.String(80), primary_key=True),
        sa.Column("retired_at", TZ, nullable=False),
        sa.Column("reason", sa.Text(), nullable=False))
    existing = set(inspector.get_table_names())
    for name, reason in RETIRED.items():
        if name in existing:
            bind.execute(sa.text("INSERT INTO retired_tables (name, retired_at, reason) VALUES (:n, :t, :r)"),
                         {"n": name, "t": now, "r": reason})

    # --- auth events ------------------------------------------------------------------------
    with op.batch_alter_table("auth_events", recreate="always") as batch:
        batch.drop_constraint("ck_auth_event_type", type_="check")
        batch.create_check_constraint("ck_auth_event_type", "event_type IN ('" + "','".join(AUTH_EVENT_TYPES) + "')")
    if bind.dialect.name == "sqlite":
        for statement in security_triggers():
            op.execute(statement)


def downgrade():
    raise RuntimeError("Preserve accounts, ownership and scan history; restore a reviewed backup/code pair")
