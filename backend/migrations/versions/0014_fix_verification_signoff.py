"""Second-person sign-off on verified fixes.

Adds `fix_verification_signoffs` (append-only, one decision per retest). Nothing existing is altered:
the remediation status machine and its constraints are untouched, so no table is rebuilt. Where
`SEPARATION_OF_DUTIES_ENABLED` is on, closing an assessment additionally needs a confirmed sign-off for
every `verified_fixed` finding. Back up the database first. Downgrade is refused to preserve history.
"""
from alembic import op
import sqlalchemy as sa

from app.models.remediation import signoff_trigger_sql

revision = "0014_fix_verification_signoff"
down_revision = "0013_production_hardening"
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)


def upgrade():
    op.create_table("fix_verification_signoffs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("vulnerability_id", sa.String(36), sa.ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("retest_id", sa.String(36), sa.ForeignKey("retest_requests.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("decision", sa.String(12), nullable=False),
        sa.Column("signed_by", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("signed_at", TZ, nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=True),
        sa.UniqueConstraint("retest_id", name="uq_signoff_retest"),
        sa.CheckConstraint("decision IN ('confirmed','rejected')", name="ck_signoff_decision"))
    op.create_index("ix_fix_verification_signoffs_vulnerability_id", "fix_verification_signoffs", ["vulnerability_id"])
    if op.get_bind().dialect.name == "sqlite":
        for statement in signoff_trigger_sql():
            op.execute(statement)


def downgrade():
    raise RuntimeError("Preserve sign-off history; restore a reviewed backup/code pair")
