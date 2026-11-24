"""Remediation tracking, scoped retests and assessment closure (Module H).

Additive. Existing data is untouched. Triggers make remediation events and closures append-only,
and freeze a retest request once it is made (its result is written once).
"""
from alembic import op
import sqlalchemy as sa

from app.models.remediation import REMEDIATION_STATUSES, trigger_sql

revision = "0012_remediation_retesting"
down_revision = "0011_vapt_reports"
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)
STATUS_SQL = "('" + "','".join(REMEDIATION_STATUSES) + "')"
ACTIONS = ("status_updated", "retest_requested", "retest_verified_fixed", "retest_still_present",
           "retest_inconclusive", "retest_failed", "reopened", "risk_accepted")


def upgrade():
    op.create_table("vulnerability_remediations",
        sa.Column("vulnerability_id", sa.String(36), sa.ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("client_note", sa.Text(), nullable=False),
        sa.Column("target_date", sa.Date(), nullable=True),
        sa.Column("retest_attempts", sa.Integer(), nullable=False),
        sa.Column("risk_acceptance_reason", sa.Text(), nullable=True),
        sa.Column("risk_accepted_by", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("risk_accepted_at", TZ, nullable=True),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("created_at", TZ, nullable=False),
        sa.Column("updated_at", TZ, nullable=False),
        sa.CheckConstraint(f"status IN {STATUS_SQL}", name="ck_remediation_status"),
        sa.CheckConstraint("version > 0", name="ck_remediation_version"),
        sa.CheckConstraint("retest_attempts >= 0", name="ck_remediation_attempts"))
    op.create_index("ix_vulnerability_remediations_status", "vulnerability_remediations", ["status"])

    op.create_table("remediation_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("vulnerability_id", sa.String(36), sa.ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("action", sa.String(30), nullable=False),
        sa.Column("from_status", sa.String(20), nullable=True),
        sa.Column("to_status", sa.String(20), nullable=True),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("occurred_at", TZ, nullable=False),
        sa.UniqueConstraint("vulnerability_id", "sequence", name="uq_remediation_event_sequence"),
        sa.CheckConstraint("sequence > 0", name="ck_remediation_event_sequence"),
        sa.CheckConstraint("action IN ('" + "','".join(ACTIONS) + "')", name="ck_remediation_event_action"))
    op.create_index("ix_remediation_events_vulnerability_id", "remediation_events", ["vulnerability_id"])

    op.create_table("retest_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("vulnerability_id", sa.String(36), sa.ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("requested_at", TZ, nullable=False),
        sa.Column("authorization_id", sa.Integer(), sa.ForeignKey("website_authorizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessment_requests.id", ondelete="RESTRICT"), nullable=False, unique=True),
        sa.Column("profile_id", sa.String(80), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=True),
        sa.Column("completed_at", TZ, nullable=True),
        sa.Column("occurrence_id", sa.String(36), sa.ForeignKey("vulnerability_occurrences.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("evidence_sha256", sa.String(64), nullable=True),
        sa.Column("failure_code", sa.String(40), nullable=True),
        sa.UniqueConstraint("vulnerability_id", "attempt", name="uq_retest_attempt"),
        sa.CheckConstraint("status IN ('requested','completed','failed')", name="ck_retest_status"),
        sa.CheckConstraint("outcome IS NULL OR outcome IN ('verified_fixed','still_present','inconclusive')", name="ck_retest_outcome"),
        sa.CheckConstraint("attempt > 0", name="ck_retest_attempt"))
    op.create_index("ix_retest_requests_vulnerability_id", "retest_requests", ["vulnerability_id"])
    op.create_index("ix_retest_requests_status", "retest_requests", ["status"])

    op.create_table("assessment_closures",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessment_requests.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("closed_by", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("closed_at", TZ, nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.UniqueConstraint("assessment_id", name="uq_assessment_closure"))
    op.create_index("ix_assessment_closures_assessment_id", "assessment_closures", ["assessment_id"])

    if op.get_bind().dialect.name == "sqlite":
        for statement in trigger_sql():
            op.execute(statement)


def downgrade():
    raise RuntimeError("Preserve remediation and closure history; restore a reviewed backup/code pair")
