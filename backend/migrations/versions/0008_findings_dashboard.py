"""Finding deadline history; existing analyst reviews remain the source of truth."""
from alembic import op
import sqlalchemy as sa

revision = "0008_findings_dashboard"
down_revision = "0007_observation_reviews"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("finding_due_dates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("report_id", sa.String(36), sa.ForeignKey("assessment_reports.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("check_id", sa.String(80), nullable=False),
        sa.Column("review_id", sa.String(36), sa.ForeignKey("observation_reviews.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("report_id", "check_id", "revision", name="uq_finding_due_date_revision"),
        sa.CheckConstraint("revision > 0", name="ck_finding_due_date_revision"))
    op.create_index("ix_finding_due_dates_report_id", "finding_due_dates", ["report_id"])


def downgrade():
    raise RuntimeError("Preserve finding deadline history; restore a reviewed backup/code pair")
