"""Port watch (Option A): explicitly enabled recurring TCP 80/443 checks.

Adds `port_watches` and the append-only `port_watch_changes`. Nothing existing is altered and nothing is
enabled by this migration: no website is scanned until an administrator turns port watch on for it.
Back up the database first. Downgrade is refused to preserve history.
"""
from alembic import op
import sqlalchemy as sa

from app.models.port_watch import WATCH_STATES, trigger_sql

revision = "0015_port_watch"
down_revision = "0014_fix_verification_signoff"
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)


def upgrade():
    op.create_table("port_watches",
        sa.Column("website_id", sa.Integer(), sa.ForeignKey("websites.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("enabled_by", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("enabled_at", TZ, nullable=False),
        sa.Column("state", sa.String(10), nullable=False),
        sa.Column("blocked_reason", sa.String(80), nullable=True),
        sa.Column("next_due", TZ, nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("last_requested_at", TZ, nullable=True),
        sa.Column("last_assessment_id", sa.String(36), sa.ForeignKey("assessment_requests.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("last_recorded_assessment_id", sa.String(36), nullable=True),
        sa.Column("last_outcome", sa.String(20), nullable=True),
        sa.Column("last_checked_at", TZ, nullable=True),
        sa.Column("baseline", sa.JSON(), nullable=True),
        sa.CheckConstraint("state IN ('" + "','".join(WATCH_STATES) + "')", name="ck_port_watch_state"),
        sa.CheckConstraint("interval_seconds >= 3600", name="ck_port_watch_interval"))
    op.create_index("ix_port_watches_next_due", "port_watches", ["next_due"])
    op.create_table("port_watch_changes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("website_id", sa.Integer(), sa.ForeignKey("websites.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessment_requests.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("detected_at", TZ, nullable=False),
        sa.Column("previous", sa.JSON(), nullable=False),
        sa.Column("current", sa.JSON(), nullable=False),
        sa.Column("changes", sa.JSON(), nullable=False),
        sa.UniqueConstraint("website_id", "assessment_id", name="uq_port_watch_change"))
    op.create_index("ix_port_watch_changes_website_id", "port_watch_changes", ["website_id"])
    if op.get_bind().dialect.name == "sqlite":
        for statement in trigger_sql():
            op.execute(statement)


def downgrade():
    raise RuntimeError("Preserve port-watch history; restore a reviewed backup/code pair")
