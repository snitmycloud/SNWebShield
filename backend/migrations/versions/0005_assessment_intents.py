"""Add explicit assessment intents on the shared job engine; preserve old data."""
from alembic import op
import sqlalchemy as sa

revision = "0005_assessment_intents"
down_revision = "0004_monitoring"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("assessment_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("job_id", sa.String(36), sa.ForeignKey("jobs.id", ondelete="RESTRICT"), nullable=False, unique=True),
        sa.Column("website_id", sa.Integer(), sa.ForeignKey("websites.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("authorization_id", sa.Integer(), sa.ForeignKey("website_authorizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("requested_by", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("profile_id", sa.String(80), nullable=False),
        sa.Column("profile_digest", sa.String(64), nullable=False),
        sa.Column("target_url", sa.String(2048), nullable=False),
        sa.Column("target_host", sa.String(253), nullable=False),
        sa.Column("permission_digest", sa.String(64), nullable=False),
        sa.Column("permission_snapshot", sa.JSON(), nullable=False),
        sa.Column("request_note", sa.Text(), nullable=False),
    )
    op.create_index("ix_assessment_requests_website_id", "assessment_requests", ["website_id"])
    op.create_index("ix_assessment_requests_authorization_id", "assessment_requests", ["authorization_id"])
    # This migration has no old assessment jobs to collide with the new index.
    op.create_index("uq_active_assessment_website", "jobs", ["resource_id"], unique=True,
        sqlite_where=sa.text("job_type = 'assessment' AND status IN ('queued', 'running')"),
        postgresql_where=sa.text("job_type = 'assessment' AND status IN ('queued', 'running')"))


def downgrade():
    raise RuntimeError("Preserve assessment/audit history; restore a reviewed backup/code pair")
