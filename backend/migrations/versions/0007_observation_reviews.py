"""Analyst review revisions and immutable reviewed exports; preserve scanner reports."""
from alembic import op
import sqlalchemy as sa

revision = "0007_observation_reviews"
down_revision = "0006_local_http"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("observation_reviews",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("report_id", sa.String(36), sa.ForeignKey("assessment_reports.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("check_id", sa.String(80), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("reviewer_id", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("disposition", sa.String(30), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("supporting_evidence", sa.Text(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("owner", sa.String(150), nullable=False),
        sa.Column("remediation_status", sa.String(30), nullable=False),
        sa.Column("resolution_notes", sa.Text(), nullable=False),
        sa.Column("retest_assessment_id", sa.String(36), sa.ForeignKey("assessment_requests.id", ondelete="RESTRICT"), nullable=True),
        sa.UniqueConstraint("report_id", "check_id", "revision", name="uq_observation_review_revision"),
        sa.CheckConstraint("revision > 0", name="ck_observation_review_revision"),
        sa.CheckConstraint("disposition IN ('confirmed','not_applicable','dismissed')", name="ck_observation_disposition"),
        sa.CheckConstraint("remediation_status IN ('open','in_progress','ready_for_retest','resolved','not_applicable')", name="ck_observation_remediation"))
    op.create_index("ix_observation_reviews_report_id", "observation_reviews", ["report_id"])
    op.create_table("reviewed_assessment_exports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessment_requests.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False))
    op.create_index("ix_reviewed_assessment_exports_assessment_id", "reviewed_assessment_exports", ["assessment_id"])


def downgrade():
    raise RuntimeError("Preserve analyst review history and exports; restore a reviewed backup/code pair")
