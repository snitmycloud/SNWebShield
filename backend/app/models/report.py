"""UNUSED (the earlier analyst pipeline was removed on 2026-11-27). The tables and all their data are kept in the database and
listed in `retired_tables`; no code reads or writes them. This file only keeps the schema description.

VAPT reports (Module G).

A report row is a frozen snapshot of report-eligible findings. Only `status` and the decision
columns may change after creation (enforced in the ORM and, on SQLite, by triggers); PDF artifacts,
approval decisions and audit events are append-only.
"""
from datetime import datetime

from sqlalchemy import (CheckConstraint, DDL, DateTime, ForeignKey, Integer, JSON, LargeBinary, String, Text,
                        UniqueConstraint, event)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

REPORT_STATUSES = ("draft", "pending_approval", "approved", "rejected", "superseded")
ARTIFACT_KINDS = ("draft", "official")
DECISIONS = ("approved", "rejected")
EVENT_ACTIONS = ("generated", "preview_downloaded", "official_downloaded", "approved", "rejected", "superseded")

# Columns that never change after the report is generated.
FROZEN_COLUMNS = ("id", "assessment_id", "client_id", "website_id", "authorization_id", "revision", "title",
                  "executive_summary", "scope", "methodology", "findings", "severity_counts", "eligible_count",
                  "excluded_count", "excluded", "content_sha256", "created_by", "created_at")


class VaptReport(Base):
    __tablename__ = "vapt_reports"
    __table_args__ = (
        UniqueConstraint("assessment_id", "revision", name="uq_vapt_report_revision"),
        CheckConstraint("status IN ('draft','pending_approval','approved','rejected','superseded')", name="ck_vapt_report_status"),
        CheckConstraint("revision > 0", name="ck_vapt_report_revision"),
        CheckConstraint("eligible_count > 0", name="ck_vapt_report_eligible"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment_requests.id", ondelete="RESTRICT"), index=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="RESTRICT"))
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="RESTRICT"))
    authorization_id: Mapped[int] = mapped_column(ForeignKey("website_authorizations.id", ondelete="RESTRICT"))
    revision: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), index=True)
    title: Mapped[str] = mapped_column(String(300))
    executive_summary: Mapped[str] = mapped_column(Text)
    scope: Mapped[dict] = mapped_column(JSON)
    methodology: Mapped[dict] = mapped_column(JSON)
    findings: Mapped[list] = mapped_column(JSON)
    severity_counts: Mapped[dict] = mapped_column(JSON)
    eligible_count: Mapped[int] = mapped_column(Integer)
    excluded_count: Mapped[int] = mapped_column(Integer)
    excluded: Mapped[list] = mapped_column(JSON)
    content_sha256: Mapped[str] = mapped_column(String(64))
    draft_pdf_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    official_pdf_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_by: Mapped[int | None] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class VaptReportArtifact(Base):
    """A rendered PDF with its SHA-256. Re-verified on every download."""
    __tablename__ = "vapt_report_artifacts"
    __table_args__ = (
        UniqueConstraint("report_id", "kind", name="uq_vapt_report_artifact_kind"),
        CheckConstraint("kind IN ('draft','official')", name="ck_vapt_report_artifact_kind"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("vapt_reports.id", ondelete="RESTRICT"), index=True)
    kind: Mapped[str] = mapped_column(String(10))
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(Integer)
    content: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class VaptReportApproval(Base):
    """Immutable human decision (approval or rejection) with attestation, bound to the content hash."""
    __tablename__ = "vapt_report_approvals"
    __table_args__ = (
        UniqueConstraint("report_id", name="uq_vapt_report_approval_report"),
        CheckConstraint("decision IN ('approved','rejected')", name="ck_vapt_report_approval_decision"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("vapt_reports.id", ondelete="RESTRICT"), index=True)
    decision: Mapped[str] = mapped_column(String(10))
    analyst_id: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    justification: Mapped[str] = mapped_column(Text)
    content_sha256: Mapped[str] = mapped_column(String(64))
    pdf_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class VaptReportEvent(Base):
    __tablename__ = "vapt_report_events"
    __table_args__ = (
        UniqueConstraint("report_id", "sequence", name="uq_vapt_report_event_sequence"),
        CheckConstraint("action IN ('generated','preview_downloaded','official_downloaded','approved','rejected','superseded')",
                        name="ck_vapt_report_event_action"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("vapt_reports.id", ondelete="RESTRICT"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True)
    action: Mapped[str] = mapped_column(String(24))
    detail: Mapped[dict] = mapped_column(JSON)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def _append_only(mapper, connection, target):
    raise ValueError(f"{type(target).__name__} records are append-only")


def _no_delete(mapper, connection, target):
    raise ValueError("VAPT reports can never be deleted")


def _frozen_snapshot(mapper, connection, target):
    from sqlalchemy import inspect
    state = inspect(target)
    for name in FROZEN_COLUMNS:
        if state.attrs[name].history.has_changes():
            raise ValueError(f"VAPT report column '{name}' is frozen after generation")


for _model in (VaptReportArtifact, VaptReportApproval, VaptReportEvent):
    event.listen(_model, "before_update", _append_only)
    event.listen(_model, "before_delete", _append_only)
event.listen(VaptReport, "before_update", _frozen_snapshot)
event.listen(VaptReport, "before_delete", _no_delete)


def trigger_sql():
    """SQLite triggers: raw SQL cannot rewrite a snapshot, history or a finished report's status."""
    frozen = " OR ".join(f"OLD.{c} IS NOT NEW.{c}" for c in FROZEN_COLUMNS)
    statements = [
        f"CREATE TRIGGER IF NOT EXISTS trg_vapt_reports_frozen BEFORE UPDATE ON vapt_reports WHEN {frozen} "
        "BEGIN SELECT RAISE(ABORT, 'vapt_reports snapshot is frozen'); END",
        "CREATE TRIGGER IF NOT EXISTS trg_vapt_reports_no_delete BEFORE DELETE ON vapt_reports "
        "BEGIN SELECT RAISE(ABORT, 'vapt_reports cannot be deleted'); END",
        # Terminal statuses never move, except an approved report being superseded by a newer approval.
        "CREATE TRIGGER IF NOT EXISTS trg_vapt_reports_status BEFORE UPDATE ON vapt_reports "
        "WHEN OLD.status IS NOT NEW.status AND (OLD.status IN ('rejected','superseded') "
        "OR (OLD.status = 'approved' AND NEW.status <> 'superseded')) "
        "BEGIN SELECT RAISE(ABORT, 'vapt_reports status is final'); END",
        # An official PDF hash is written once.
        "CREATE TRIGGER IF NOT EXISTS trg_vapt_reports_official_once BEFORE UPDATE ON vapt_reports "
        "WHEN OLD.official_pdf_sha256 IS NOT NULL AND OLD.official_pdf_sha256 IS NOT NEW.official_pdf_sha256 "
        "BEGIN SELECT RAISE(ABORT, 'official PDF hash is write-once'); END",
    ]
    for table in ("vapt_report_artifacts", "vapt_report_approvals", "vapt_report_events"):
        for verb in ("UPDATE", "DELETE"):
            statements.append(f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_{verb.lower()} BEFORE {verb} ON {table} "
                              f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END")
    return statements


for _table, _prefix in ((VaptReport, "trg_vapt_reports_"), (VaptReportArtifact, "trg_vapt_report_artifacts_"),
                        (VaptReportApproval, "trg_vapt_report_approvals_"), (VaptReportEvent, "trg_vapt_report_events_")):
    for _sql in trigger_sql():
        if f" ON {_table.__tablename__} " in _sql:
            event.listen(_table.__table__, "after_create", DDL(_sql).execute_if(dialect="sqlite"))
