"""Production hardening (Milestone 6).

* `auth_events` (append-only) and `revoked_tokens` - authentication audit log and server-side logout.
* `admins.role` now allows `admin`, `lead_analyst` and `analyst` (existing rows keep `admin`).
* `assessment_closures.generation` replaces the one-closure-per-assessment unique key so a closure can
  be formally reopened (`assessment_closure_reopenings`, append-only) and a later closure recorded.
* `authorization_evidence.purged_at` / `purge_method`, plus immutability triggers for the document's
  identity and hash and for the evidence audit trail.

Existing data is preserved. Back up the database first (see README). SQLite table rebuilds drop
triggers, so the closure triggers are re-created afterwards. Downgrade is refused to preserve history.
"""
from alembic import op
import sqlalchemy as sa

from app.models.admin import ADMIN_ROLES
from app.models.remediation import trigger_sql as remediation_triggers
from app.models.security import AUTH_EVENT_TYPES, trigger_sql as security_triggers

revision = "0013_production_hardening"
down_revision = "0012_remediation_retesting"
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)


def upgrade():
    bind = op.get_bind()
    op.create_table("auth_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("occurred_at", TZ, nullable=False),
        sa.Column("event_type", sa.String(24), nullable=False),
        sa.Column("email_sha256", sa.String(64), nullable=False),
        sa.Column("admin_id", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("client_ip", sa.String(64), nullable=False),
        sa.Column("reason", sa.String(40), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.CheckConstraint("event_type IN ('" + "','".join(AUTH_EVENT_TYPES) + "')", name="ck_auth_event_type"))
    for column in ("occurred_at", "event_type", "email_sha256", "admin_id", "client_ip"):
        op.create_index(f"ix_auth_events_{column}", "auth_events", [column])

    op.create_table("revoked_tokens",
        sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column("admin_id", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("revoked_at", TZ, nullable=False),
        sa.Column("expires_at", TZ, nullable=False))
    op.create_index("ix_revoked_tokens_expires_at", "revoked_tokens", ["expires_at"])

    # Roles: swap the CHECK constraint (SQLite rebuilds the table; data is copied unchanged).
    existing = {c.get("name") for c in sa.inspect(bind).get_check_constraints("admins")}
    with op.batch_alter_table("admins", recreate="always") as batch:
        if "ck_admins_role" in existing:
            batch.drop_constraint("ck_admins_role", type_="check")
        batch.create_check_constraint("ck_admins_role", "role IN ('" + "','".join(ADMIN_ROLES) + "')")

    # Closures: generation number instead of one-per-assessment.
    with op.batch_alter_table("assessment_closures", recreate="always") as batch:
        batch.add_column(sa.Column("generation", sa.Integer(), nullable=False, server_default="1"))
        batch.drop_constraint("uq_assessment_closure", type_="unique")
        batch.create_unique_constraint("uq_assessment_closure_generation", ["assessment_id", "generation"])

    op.create_table("assessment_closure_reopenings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("closure_id", sa.String(36), sa.ForeignKey("assessment_closures.id", ondelete="RESTRICT"), nullable=False, unique=True),
        sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessment_requests.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("reopened_by", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("reopened_at", TZ, nullable=False),
        sa.Column("reason", sa.Text(), nullable=False))
    op.create_index("ix_assessment_closure_reopenings_assessment_id", "assessment_closure_reopenings", ["assessment_id"])

    op.add_column("authorization_evidence", sa.Column("purged_at", TZ, nullable=True))
    op.add_column("authorization_evidence", sa.Column("purge_method", sa.String(40), nullable=True))
    op.execute("UPDATE authorization_evidence SET purge_method = 'legacy_unlink' WHERE state = 'purged'")

    if bind.dialect.name == "sqlite":
        for statement in remediation_triggers() + security_triggers():
            op.execute(statement)


def downgrade():
    raise RuntimeError("Preserve authentication and closure history; restore a reviewed backup/code pair")
