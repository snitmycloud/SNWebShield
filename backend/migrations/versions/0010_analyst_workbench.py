"""Analyst workbench (Module F): risk assessments, sign-off ledger, DB-level append-only triggers.

Additive. Existing vulnerabilities, events and suppressions are preserved unchanged.
"""
from alembic import op
import sqlalchemy as sa

revision = "0010_analyst_workbench"
down_revision = "0009_vulnerabilities"
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)
RATINGS = "('informational','low','medium','high','critical')"
IMMUTABLE = ("vulnerability_events", "vulnerability_risk_assessments", "vulnerability_signoffs")


def upgrade():
    op.create_table("vulnerability_risk_assessments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("vulnerability_id", sa.String(36), sa.ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("vulnerability_revision", sa.Integer(), nullable=False),
        sa.Column("author_id", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("likelihood", sa.String(16), nullable=False),
        sa.Column("business_impact", sa.String(16), nullable=False),
        sa.Column("business_context", sa.Text(), nullable=False),
        sa.Column("calculated_rating", sa.String(20), nullable=False),
        sa.Column("risk_rating", sa.String(20), nullable=False),
        sa.Column("override_reason", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("remediation_priority", sa.String(16), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
        sa.UniqueConstraint("vulnerability_id", "version", name="uq_vulnerability_risk_version"),
        sa.CheckConstraint("version > 0", name="ck_vulnerability_risk_version"),
        sa.CheckConstraint("likelihood IN ('rare','unlikely','possible','likely','almost_certain')", name="ck_vulnerability_risk_likelihood"),
        sa.CheckConstraint("business_impact IN ('negligible','minor','moderate','major','severe')", name="ck_vulnerability_risk_impact"),
        sa.CheckConstraint(f"calculated_rating IN {RATINGS}", name="ck_vulnerability_risk_calculated"),
        sa.CheckConstraint(f"risk_rating IN {RATINGS}", name="ck_vulnerability_risk_rating"),
        sa.CheckConstraint("remediation_priority IN ('immediate','short_term','planned','monitor')", name="ck_vulnerability_risk_priority"))
    op.create_index("ix_vulnerability_risk_assessments_vulnerability_id", "vulnerability_risk_assessments", ["vulnerability_id"])

    op.create_table("vulnerability_signoffs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("vulnerability_id", sa.String(36), sa.ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("decision", sa.String(12), nullable=False),
        sa.Column("analyst_id", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("from_state", sa.String(24), nullable=False),
        sa.Column("to_state", sa.String(24), nullable=False),
        sa.Column("vulnerability_revision", sa.Integer(), nullable=False),
        sa.Column("risk_assessment_id", sa.String(36), sa.ForeignKey("vulnerability_risk_assessments.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("occurred_at", TZ, nullable=False),
        sa.UniqueConstraint("vulnerability_id", "sequence", name="uq_vulnerability_signoff_sequence"),
        sa.CheckConstraint("sequence > 0", name="ck_vulnerability_signoff_sequence"),
        sa.CheckConstraint("decision IN ('approved','rejected','reopened')", name="ck_vulnerability_signoff_decision"))
    op.create_index("ix_vulnerability_signoffs_vulnerability_id", "vulnerability_signoffs", ["vulnerability_id"])

    if op.get_bind().dialect.name == "sqlite":
        for table in IMMUTABLE:
            for verb in ("UPDATE", "DELETE"):
                op.execute(f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_{verb.lower()} BEFORE {verb} ON {table} "
                           f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END")


def downgrade():
    raise RuntimeError("Preserve analyst decision history; restore a reviewed backup/code pair")
