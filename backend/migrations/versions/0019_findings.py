"""Phase 3A: IDENTIFY findings.

* `scan_findings` - every finding of a scan in one common format (configuration, vulnerability, end-of-life, ...).
* `vuln_cache`    - shared 24-hour cache of NVD / OSV answers (public data only).

Purely additive: no existing row or table is changed. Back up first: python -m app.cli.backup_database.
Downgrade is refused to preserve scan history.
"""
from alembic import op
import sqlalchemy as sa

revision = "0019_findings"
down_revision = "0018_detect_results"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("scan_findings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("check_id", sa.String(120), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("location", sa.String(300), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("confidence", sa.String(10), nullable=False),
        sa.Column("group", sa.String(20), nullable=False),
        sa.Column("you_have", sa.Text(), nullable=True),
        sa.Column("you_should_have", sa.Text(), nullable=True),
        sa.Column("cve_id", sa.String(40), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(120), nullable=True),
        sa.Column("affected_range", sa.Text(), nullable=True),
        sa.Column("first_fixed", sa.Text(), nullable=True),
        sa.Column("why", sa.Text(), nullable=True),
        sa.Column("how_to_fix", sa.Text(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("caveat", sa.Text(), nullable=True),
        sa.Column("sources", sa.JSON(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.UniqueConstraint("scan_id", "fingerprint", name="uq_scan_finding"))
    op.create_index("ix_scan_findings_scan_id", "scan_findings", ["scan_id"])
    op.create_index("ix_scan_findings_severity", "scan_findings", ["severity"])
    op.create_table("vuln_cache",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("source", sa.String(10), nullable=False),
        sa.Column("key", sa.String(200), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(200), nullable=True),
        sa.UniqueConstraint("source", "key", name="uq_vuln_cache"))


def downgrade():
    raise RuntimeError("Preserve scan history; restore a reviewed backup/code pair")
