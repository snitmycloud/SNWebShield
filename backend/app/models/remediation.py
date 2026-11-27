"""UNUSED (the earlier analyst pipeline was removed on 2026-11-27). The tables and all their data are kept in the database and
listed in `retired_tables`; no code reads or writes them. This file only keeps the schema description.

Remediation tracking, retests and assessment closure (Module H).

`vulnerability_remediations` holds the current state of one confirmed finding. Everything that
explains how it got there is append-only: `remediation_events`, completed `retest_requests` and
`assessment_closures` (ORM guards plus SQLite triggers, as in Milestones 3 and 4).
"""
from datetime import date, datetime

from sqlalchemy import (CheckConstraint, DDL, Date, DateTime, ForeignKey, Integer, JSON, String, Text,
                        UniqueConstraint, event)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

REMEDIATION_STATUSES = ("open", "in_progress", "fix_submitted", "retest_requested", "verified_fixed", "reopened",
                        "risk_accepted")
BLOCKING_STATUSES = ("open", "in_progress", "fix_submitted", "retest_requested", "reopened")
RETEST_STATUSES = ("requested", "completed", "failed")
RETEST_OUTCOMES = ("verified_fixed", "still_present", "inconclusive")
_STATUS_SQL = "('" + "','".join(REMEDIATION_STATUSES) + "')"
_ACTIONS = ("status_updated", "retest_requested", "retest_verified_fixed", "retest_still_present",
            "retest_inconclusive", "retest_failed", "reopened", "risk_accepted")
_ACTION_SQL = "('" + "','".join(_ACTIONS) + "')"
RETEST_FROZEN = ("id", "vulnerability_id", "attempt", "requested_by", "requested_at", "authorization_id",
                 "assessment_id", "profile_id", "note")


class VulnerabilityRemediation(Base):
    __tablename__ = "vulnerability_remediations"
    __table_args__ = (
        CheckConstraint(f"status IN {_STATUS_SQL}", name="ck_remediation_status"),
        CheckConstraint("version > 0", name="ck_remediation_version"),
        CheckConstraint("retest_attempts >= 0", name="ck_remediation_attempts"),
    )
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), primary_key=True)
    status: Mapped[str] = mapped_column(String(20), index=True)
    version: Mapped[int] = mapped_column(Integer)
    client_note: Mapped[str] = mapped_column(Text)
    target_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    # Completed retests with a conclusive outcome (fixed or still present).
    retest_attempts: Mapped[int] = mapped_column(Integer)
    risk_acceptance_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_accepted_by: Mapped[int | None] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True)
    risk_accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RemediationEvent(Base):
    __tablename__ = "remediation_events"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "sequence", name="uq_remediation_event_sequence"),
        CheckConstraint("sequence > 0", name="ck_remediation_event_sequence"),
        CheckConstraint(f"action IN {_ACTION_SQL}", name="ck_remediation_event_action"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True)  # null = system
    action: Mapped[str] = mapped_column(String(30))
    from_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    note: Mapped[str] = mapped_column(Text)
    detail: Mapped[dict] = mapped_column(JSON)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RetestRequest(Base):
    """One explicit, scoped retest. It is a normal assessment request, so every authorisation, scope
    and method check of the scanner worker applies to it; this row only links it to the finding."""
    __tablename__ = "retest_requests"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "attempt", name="uq_retest_attempt"),
        CheckConstraint("status IN ('requested','completed','failed')", name="ck_retest_status"),
        CheckConstraint("outcome IS NULL OR outcome IN ('verified_fixed','still_present','inconclusive')", name="ck_retest_outcome"),
        CheckConstraint("attempt > 0", name="ck_retest_attempt"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), index=True)
    attempt: Mapped[int] = mapped_column(Integer)
    requested_by: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    authorization_id: Mapped[int] = mapped_column(ForeignKey("website_authorizations.id", ondelete="RESTRICT"))
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment_requests.id", ondelete="RESTRICT"), unique=True)
    profile_id: Mapped[str] = mapped_column(String(80))
    note: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(12), index=True)
    outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    occurrence_id: Mapped[str | None] = mapped_column(ForeignKey("vulnerability_occurrences.id", ondelete="RESTRICT"), nullable=True)
    evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(40), nullable=True)


class AssessmentClosure(Base):
    __tablename__ = "assessment_closures"
    # `generation` numbers successive closures of one assessment (a closure can be formally reopened and
    # a later one made); the unique pair stops two concurrent closers.
    __table_args__ = (UniqueConstraint("assessment_id", "generation", name="uq_assessment_closure_generation"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment_requests.id", ondelete="RESTRICT"), index=True)
    generation: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    closed_by: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    closed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    justification: Mapped[str] = mapped_column(Text)
    summary: Mapped[dict] = mapped_column(JSON)
    content_sha256: Mapped[str] = mapped_column(String(64))


class FixVerificationSignoff(Base):
    """A second person's decision on a retest's `verified_fixed` result. Append-only, one per retest."""
    __tablename__ = "fix_verification_signoffs"
    __table_args__ = (
        UniqueConstraint("retest_id", name="uq_signoff_retest"),
        CheckConstraint("decision IN ('confirmed','rejected')", name="ck_signoff_decision"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), index=True)
    retest_id: Mapped[str] = mapped_column(ForeignKey("retest_requests.id", ondelete="RESTRICT"))
    decision: Mapped[str] = mapped_column(String(12))
    signed_by: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    signed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    note: Mapped[str] = mapped_column(Text)
    evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)


def _append_only(mapper, connection, target):
    raise ValueError(f"{type(target).__name__} records are append-only")


def _no_delete(mapper, connection, target):
    raise ValueError(f"{type(target).__name__} records can never be deleted")


def _retest_frozen(mapper, connection, target):
    from sqlalchemy import inspect
    state = inspect(target)
    for name in RETEST_FROZEN:
        if state.attrs[name].history.has_changes():
            raise ValueError(f"Retest column '{name}' is frozen after the request")


for _model in (RemediationEvent, AssessmentClosure, FixVerificationSignoff):
    event.listen(_model, "before_update", _append_only)
    event.listen(_model, "before_delete", _append_only)
event.listen(VulnerabilityRemediation, "before_delete", _no_delete)
event.listen(RetestRequest, "before_update", _retest_frozen)
event.listen(RetestRequest, "before_delete", _no_delete)


def trigger_sql():
    frozen = " OR ".join(f"OLD.{c} IS NOT NEW.{c}" for c in RETEST_FROZEN)
    statements = [
        "CREATE TRIGGER IF NOT EXISTS trg_vulnerability_remediations_no_delete BEFORE DELETE ON vulnerability_remediations "
        "BEGIN SELECT RAISE(ABORT, 'vulnerability_remediations cannot be deleted'); END",
        "CREATE TRIGGER IF NOT EXISTS trg_retest_requests_no_delete BEFORE DELETE ON retest_requests "
        "BEGIN SELECT RAISE(ABORT, 'retest_requests cannot be deleted'); END",
        f"CREATE TRIGGER IF NOT EXISTS trg_retest_requests_frozen BEFORE UPDATE ON retest_requests WHEN {frozen} "
        "BEGIN SELECT RAISE(ABORT, 'retest_requests request columns are frozen'); END",
        # A finished retest is final, and its outcome is written once.
        "CREATE TRIGGER IF NOT EXISTS trg_retest_requests_final BEFORE UPDATE ON retest_requests "
        "WHEN OLD.status IN ('completed','failed') AND (OLD.status IS NOT NEW.status OR OLD.outcome IS NOT NEW.outcome "
        "OR OLD.completed_at IS NOT NEW.completed_at OR OLD.occurrence_id IS NOT NEW.occurrence_id "
        "OR OLD.evidence_sha256 IS NOT NEW.evidence_sha256) "
        "BEGIN SELECT RAISE(ABORT, 'retest_requests result is final'); END",
    ]
    for table in ("remediation_events", "assessment_closures"):
        for verb in ("UPDATE", "DELETE"):
            statements.append(f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_{verb.lower()} BEFORE {verb} ON {table} "
                              f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END")
    return statements


for _model in (VulnerabilityRemediation, RetestRequest, RemediationEvent, AssessmentClosure):
    for _sql in trigger_sql():
        if f" ON {_model.__tablename__} " in _sql:
            event.listen(_model.__table__, "after_create", DDL(_sql).execute_if(dialect="sqlite"))


def signoff_trigger_sql():
    """Kept apart from trigger_sql(): migration 0013 re-creates that set, before this table exists."""
    return [f"CREATE TRIGGER IF NOT EXISTS trg_fix_verification_signoffs_no_{verb.lower()} BEFORE {verb} ON fix_verification_signoffs "
            f"BEGIN SELECT RAISE(ABORT, 'fix_verification_signoffs is append-only'); END" for verb in ("UPDATE", "DELETE")]


for _sql in signoff_trigger_sql():
    event.listen(FixVerificationSignoff.__table__, "after_create", DDL(_sql).execute_if(dialect="sqlite"))
