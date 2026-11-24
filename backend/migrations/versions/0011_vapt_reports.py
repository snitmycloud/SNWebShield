"""VAPT reports (Module G): report snapshots, PDF artifacts, approval ledger, audit events.

Additive. Existing data is untouched. Triggers make snapshots, artifacts, approvals and events immutable.
"""
from alembic import op
import sqlalchemy as sa

from app.models.report import trigger_sql

revision = "0011_vapt_reports"
down_revision = "0010_analyst_workbench"
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)


def upgrade():
    op.create_table("vapt_reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessment_requests.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("client_id", sa.Integer(), sa.ForeignKey("clients.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("website_id", sa.Integer(), sa.ForeignKey("websites.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("authorization_id", sa.Integer(), sa.ForeignKey("website_authorizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("executive_summary", sa.Text(), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("methodology", sa.JSON(), nullable=False),
        sa.Column("findings", sa.JSON(), nullable=False),
        sa.Column("severity_counts", sa.JSON(), nullable=False),
        sa.Column("eligible_count", sa.Integer(), nullable=False),
        sa.Column("excluded_count", sa.Integer(), nullable=False),
        sa.Column("excluded", sa.JSON(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("draft_pdf_sha256", sa.String(64), nullable=True),
        sa.Column("official_pdf_sha256", sa.String(64), nullable=True),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
        sa.Column("decided_by", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("decided_at", TZ, nullable=True),
        sa.UniqueConstraint("assessment_id", "revision", name="uq_vapt_report_revision"),
        sa.CheckConstraint("status IN ('draft','pending_approval','approved','rejected','superseded')", name="ck_vapt_report_status"),
        sa.CheckConstraint("revision > 0", name="ck_vapt_report_revision"),
        sa.CheckConstraint("eligible_count > 0", name="ck_vapt_report_eligible"))
    op.create_index("ix_vapt_reports_assessment_id", "vapt_reports", ["assessment_id"])
    op.create_index("ix_vapt_reports_status", "vapt_reports", ["status"])

    op.create_table("vapt_report_artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("report_id", sa.String(36), sa.ForeignKey("vapt_reports.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("kind", sa.String(10), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
        sa.UniqueConstraint("report_id", "kind", name="uq_vapt_report_artifact_kind"),
        sa.CheckConstraint("kind IN ('draft','official')", name="ck_vapt_report_artifact_kind"))
    op.create_index("ix_vapt_report_artifacts_report_id", "vapt_report_artifacts", ["report_id"])

    op.create_table("vapt_report_approvals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("report_id", sa.String(36), sa.ForeignKey("vapt_reports.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("decision", sa.String(10), nullable=False),
        sa.Column("analyst_id", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("pdf_sha256", sa.String(64), nullable=True),
        sa.Column("occurred_at", TZ, nullable=False),
        sa.UniqueConstraint("report_id", name="uq_vapt_report_approval_report"),
        sa.CheckConstraint("decision IN ('approved','rejected')", name="ck_vapt_report_approval_decision"))
    op.create_index("ix_vapt_report_approvals_report_id", "vapt_report_approvals", ["report_id"])

    op.create_table("vapt_report_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("report_id", sa.String(36), sa.ForeignKey("vapt_reports.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("action", sa.String(24), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("occurred_at", TZ, nullable=False),
        sa.UniqueConstraint("report_id", "sequence", name="uq_vapt_report_event_sequence"),
        sa.CheckConstraint("action IN ('generated','preview_downloaded','official_downloaded','approved','rejected','superseded')",
                           name="ck_vapt_report_event_action"))
    op.create_index("ix_vapt_report_events_report_id", "vapt_report_events", ["report_id"])

    if op.get_bind().dialect.name == "sqlite":
        for statement in trigger_sql():
            op.execute(statement)


def downgrade():
    raise RuntimeError("Preserve report approval history; restore a reviewed backup/code pair")
