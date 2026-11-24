"""Normalised vulnerability records (Module E); additive, preserves all existing data."""
from alembic import op
import sqlalchemy as sa

revision = "0009_vulnerabilities"
down_revision = "0008_findings_dashboard"
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)


def upgrade():
    op.create_table("vulnerabilities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("fingerprint", sa.String(64), nullable=False, unique=True),
        sa.Column("website_id", sa.Integer(), sa.ForeignKey("websites.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("target_url", sa.String(2048), nullable=False),
        sa.Column("target_host", sa.String(253), nullable=False),
        sa.Column("family", sa.String(40), nullable=False),
        sa.Column("check_id", sa.String(80), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("category", sa.String(80), nullable=False),
        sa.Column("scanner_severity", sa.String(20), nullable=False),
        sa.Column("analyst_severity", sa.String(20), nullable=True),
        sa.Column("confidence", sa.String(10), nullable=False),
        sa.Column("confidence_score", sa.Integer(), nullable=False),
        sa.Column("confidence_factors", sa.JSON(), nullable=False),
        sa.Column("validation_state", sa.String(24), nullable=False),
        sa.Column("reproduction_template", sa.JSON(), nullable=False),
        sa.Column("reproduction_steps", sa.Text(), nullable=True),
        sa.Column("detection_count", sa.Integer(), nullable=False),
        sa.Column("not_detected_count", sa.Integer(), nullable=False),
        sa.Column("last_result", sa.String(20), nullable=False),
        sa.Column("first_seen_at", TZ, nullable=False),
        sa.Column("last_seen_at", TZ, nullable=False),
        sa.Column("last_checked_at", TZ, nullable=False),
        sa.Column("first_report_id", sa.String(36), sa.ForeignKey("assessment_reports.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("last_report_id", sa.String(36), sa.ForeignKey("assessment_reports.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
        sa.Column("updated_at", TZ, nullable=False),
        sa.CheckConstraint("validation_state IN ('unconfirmed','confirmed','false_positive','not_applicable')", name="ck_vulnerability_state"),
        sa.CheckConstraint("scanner_severity IN ('informational','low','medium','high','critical')", name="ck_vulnerability_scanner_severity"),
        sa.CheckConstraint("analyst_severity IS NULL OR analyst_severity IN ('informational','low','medium','high','critical')", name="ck_vulnerability_analyst_severity"),
        sa.CheckConstraint("confidence IN ('low','medium','high')", name="ck_vulnerability_confidence"),
        sa.CheckConstraint("confidence_score BETWEEN 0 AND 100", name="ck_vulnerability_confidence_score"),
        sa.CheckConstraint("revision > 0", name="ck_vulnerability_revision"))
    op.create_index("ix_vulnerabilities_website_id", "vulnerabilities", ["website_id"])
    op.create_index("ix_vulnerabilities_validation_state", "vulnerabilities", ["validation_state"])

    op.create_table("vulnerability_occurrences",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("vulnerability_id", sa.String(36), sa.ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("report_id", sa.String(36), sa.ForeignKey("assessment_reports.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessment_requests.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("result", sa.String(20), nullable=False),
        sa.Column("observed_at", TZ, nullable=False),
        sa.Column("suppressed", sa.Boolean(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.UniqueConstraint("vulnerability_id", "report_id", name="uq_vulnerability_occurrence_report"),
        sa.CheckConstraint("result IN ('detected','not_detected')", name="ck_vulnerability_occurrence_result"))
    op.create_index("ix_vulnerability_occurrences_vulnerability_id", "vulnerability_occurrences", ["vulnerability_id"])

    op.create_table("vulnerability_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("vulnerability_id", sa.String(36), sa.ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("from_state", sa.String(24), nullable=True),
        sa.Column("to_state", sa.String(24), nullable=True),
        sa.Column("comment", sa.Text(), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("occurred_at", TZ, nullable=False),
        sa.UniqueConstraint("vulnerability_id", "sequence", name="uq_vulnerability_event_sequence"),
        sa.CheckConstraint("sequence > 0", name="ck_vulnerability_event_sequence"))
    op.create_index("ix_vulnerability_events_vulnerability_id", "vulnerability_events", ["vulnerability_id"])

    op.create_table("vulnerability_suppressions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("vulnerability_id", sa.String(36), sa.ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("decision", sa.String(24), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
        sa.Column("expires_at", TZ, nullable=False),
        sa.Column("revoked_at", TZ, nullable=True),
        sa.Column("revoked_by", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("revoke_reason", sa.Text(), nullable=True))
    op.create_index("ix_vulnerability_suppressions_vulnerability_id", "vulnerability_suppressions", ["vulnerability_id"])

    op.create_table("vulnerability_ingestions",
        sa.Column("report_id", sa.String(36), sa.ForeignKey("assessment_reports.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessment_requests.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("report_sha256", sa.String(64), nullable=False),
        sa.Column("ingested_at", TZ, nullable=False),
        sa.Column("actor_id", sa.Integer(), sa.ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("outcome", sa.JSON(), nullable=False))


def downgrade():
    raise RuntimeError("Preserve vulnerability history; restore a reviewed backup/code pair")
