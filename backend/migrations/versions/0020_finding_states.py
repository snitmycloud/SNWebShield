"""Phase 4: finding lifecycle.

* `finding_states`   - one row per website and finding fingerprint: open / fixed, how and when it was confirmed fixed, when it was
                       first and last seen, and an optional risk acceptance (reason, who, when, expiry).
* `finding_rechecks` - one row per "Re-scan to confirm fix" request (the focused scan it ran and its outcome).

Purely additive: no existing row or table is changed. Back up first: python -m app.cli.backup_database.
Downgrade is refused to preserve scan history.
"""
from alembic import op
import sqlalchemy as sa

revision = "0020_finding_states"
down_revision = "0019_findings"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("finding_states",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("website_id", sa.Integer(), sa.ForeignKey("websites.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("check_id", sa.String(120), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("location", sa.String(300), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="open"),
        sa.Column("first_seen_scan_id", sa.String(36), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_scan_id", sa.String(36), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fixed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fixed_scan_id", sa.String(36), nullable=True),
        sa.Column("fixed_how", sa.String(12), nullable=True),
        sa.Column("reopened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reopened_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("accepted_reason", sa.Text(), nullable=True),
        sa.Column("accepted_by_id", sa.Integer(), nullable=True),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_days", sa.Integer(), nullable=True),
        sa.Column("accepted_until", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("website_id", "fingerprint", name="uq_finding_state"))
    op.create_index("ix_finding_states_website_id", "finding_states", ["website_id"])
    op.create_index("ix_finding_states_accepted_until", "finding_states", ["accepted_until"])
    op.create_table("finding_rechecks",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False, unique=True),
        sa.Column("website_id", sa.Integer(), sa.ForeignKey("websites.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("check_id", sa.String(120), nullable=False),
        sa.Column("requested_by_id", sa.Integer(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True))
    op.create_index("ix_finding_rechecks_website_id", "finding_rechecks", ["website_id"])
    op.create_index("ix_finding_rechecks_requested_at", "finding_rechecks", ["requested_at"])


def downgrade():
    raise RuntimeError("Preserve scan history; restore a reviewed backup/code pair")
