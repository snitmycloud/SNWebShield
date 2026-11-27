"""Phase 5: monitoring.

* `uptime_checks`     - one row per uptime probe (status code, response time, error), kept 30 days.
* `uptime_states`     - one row per website: failures in a row, whether it is down, and the certificate read once a day.
* `score_history`     - the score after each full scan (for the trend chart).
* `alerts`            - every alert that was raised, used to send the same alert at most once per 24 hours.
* `alert_preferences` - an account's on/off choice per alert type.
* `worker_heartbeats.detail` - what the supervisor knows about each role (process id, restarts).

Purely additive. Back up first: python -m app.cli.backup_database. Downgrade is refused to preserve history.
"""
from alembic import op
import sqlalchemy as sa

revision = "0021_monitor"
down_revision = "0020_finding_states"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("uptime_checks",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("website_id", sa.Integer(), sa.ForeignKey("websites.id", ondelete="CASCADE"), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("response_ms", sa.Integer(), nullable=True),
        sa.Column("scheme", sa.String(5), nullable=True),
        sa.Column("error", sa.String(60), nullable=True))
    op.create_index("ix_uptime_checks_site_time", "uptime_checks", ["website_id", "checked_at"])
    op.create_table("uptime_states",
        sa.Column("website_id", sa.Integer(), sa.ForeignKey("websites.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_down", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("down_since", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_ok_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cert_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cert_not_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cert_subject", sa.String(255), nullable=True))
    op.create_table("score_history",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("website_id", sa.Integer(), sa.ForeignKey("websites.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.String(36), nullable=False, unique=True),
        sa.Column("scored_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("grade", sa.String(1), nullable=False),
        sa.Column("counts", sa.JSON(), nullable=False),
        sa.Column("incomplete", sa.Boolean(), nullable=False, server_default=sa.text("0")))
    op.create_index("ix_score_history_site_time", "score_history", ["website_id", "scored_at"])
    op.create_table("alerts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("website_id", sa.Integer(), sa.ForeignKey("websites.id", ondelete="CASCADE"), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=True),
        sa.Column("alert_type", sa.String(40), nullable=False),
        sa.Column("alert_key", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("channel", sa.String(20), nullable=False),
        sa.Column("subject", sa.String(200), nullable=False),
        sa.Column("delivered", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("error", sa.String(80), nullable=True))
    op.create_index("ix_alerts_dedup", "alerts", ["website_id", "alert_type", "alert_key", "created_at"])
    op.create_table("alert_preferences",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("account_id", sa.Integer(), sa.ForeignKey("admins.id", ondelete="CASCADE"), nullable=False),
        sa.Column("alert_type", sa.String(40), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.UniqueConstraint("account_id", "alert_type", name="uq_alert_preference"))
    with op.batch_alter_table("worker_heartbeats") as batch:
        batch.add_column(sa.Column("detail", sa.JSON(), nullable=True))


def downgrade():
    raise RuntimeError("Downgrade is refused: it would delete monitoring history. Restore a database backup instead.")
