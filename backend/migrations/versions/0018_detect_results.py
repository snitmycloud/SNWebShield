"""Phase 2: DETECT results.

* `scan_ports`        - the open ports a scan found, with service, product, version, banner and TLS/HTTP details.
* `scan_technologies` - technologies fingerprinted from headers, cookies, meta tags and scripts.
* `scan_observations` - DNS/email records, exposed files and the listed subdomains.

Purely additive: no existing row or table is changed. Back up first: python -m app.cli.backup_database.
Downgrade is refused to preserve scan history.
"""
from alembic import op
import sqlalchemy as sa

revision = "0018_detect_results"
down_revision = "0017_website_removal"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("scan_ports",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(10), nullable=False),
        sa.Column("service", sa.String(60), nullable=True),
        sa.Column("product", sa.String(120), nullable=True),
        sa.Column("version", sa.String(120), nullable=True),
        sa.Column("banner", sa.Text(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.UniqueConstraint("scan_id", "port", name="uq_scan_port"))
    op.create_index("ix_scan_ports_scan_id", "scan_ports", ["scan_id"])
    op.create_table("scan_technologies",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("category", sa.String(60), nullable=False),
        sa.Column("version", sa.String(40), nullable=True),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("evidence", sa.String(200), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.UniqueConstraint("scan_id", "name", name="uq_scan_technology"))
    op.create_index("ix_scan_technologies_scan_id", "scan_technologies", ["scan_id"])
    op.create_table("scan_observations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("key", sa.String(253), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("data", sa.JSON(), nullable=True))
    op.create_index("ix_scan_observations_scan_id", "scan_observations", ["scan_id"])
    op.create_index("ix_scan_observations_kind", "scan_observations", ["kind"])


def downgrade():
    raise RuntimeError("Preserve scan history; restore a reviewed backup/code pair")
