"""Mark the tables of the removed analyst pipeline as unused.

The earlier analyst pipeline (assessments, observations, vulnerability management, VAPT reports, remediation sign-off, port watch,
monitoring, the job queue) was removed from the code on 2026-11-27. Its tables and ALL their data are kept (nothing is dropped or
changed); they are listed in `retired_tables` like the written-permission tables before them. The audit tables (`execution_events`,
`auth_events`, `authorization_audit_events`, `worker_heartbeats`, `revoked_tokens`) are still in use and are not listed.

Back up first: python -m app.cli.backup_database. Downgrade is refused to keep the register honest.
"""
from alembic import op
import sqlalchemy as sa

revision = "0022_legacy_retired"
down_revision = "0021_monitor"
branch_labels = None
depends_on = None

REASON = "Analyst pipeline removed 2026-11-27. Data kept; no code uses this table."
UNUSED = (
    "assessment_requests", "assessment_reports", "observation_reviews", "reviewed_assessment_exports", "finding_due_dates",
    "vulnerabilities", "vulnerability_occurrences", "vulnerability_events", "vulnerability_suppressions", "vulnerability_ingestions",
    "vulnerability_risk_assessments", "vulnerability_signoffs", "vapt_reports", "vapt_report_artifacts", "vapt_report_approvals",
    "vapt_report_events", "vulnerability_remediations", "remediation_events", "retest_requests", "assessment_closures",
    "fix_verification_signoffs", "assessment_closure_reopenings", "port_watches", "port_watch_changes", "monitoring_consents",
    "monitoring_configs", "monitoring_incidents", "notification_deliveries", "clients", "jobs", "job_attempts", "job_results", "execution_slots",
)


def upgrade():
    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    already = {row[0] for row in bind.execute(sa.text("SELECT name FROM retired_tables"))}
    now = sa.func.now()
    for name in UNUSED:
        if name in existing and name not in already:
            bind.execute(sa.text("INSERT INTO retired_tables (name, retired_at, reason) VALUES (:n, CURRENT_TIMESTAMP, :r)"), {"n": name, "r": REASON})


def downgrade():
    raise RuntimeError("Downgrade is refused: restore a database backup instead.")
