"""Immutable assessment intent linked to the shared job queue."""
from datetime import datetime
from sqlalchemy import CheckConstraint, Date, DateTime, ForeignKey, JSON, String, Text, UniqueConstraint
from datetime import date
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class AssessmentRequest(Base):
    __tablename__ = "assessment_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id", ondelete="RESTRICT"), unique=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="RESTRICT"), index=True)
    authorization_id: Mapped[int] = mapped_column(ForeignKey("website_authorizations.id", ondelete="RESTRICT"), index=True)
    requested_by: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    profile_id: Mapped[str] = mapped_column(String(80))
    profile_digest: Mapped[str] = mapped_column(String(64))
    target_url: Mapped[str] = mapped_column(String(2048))
    target_host: Mapped[str] = mapped_column(String(253))
    permission_digest: Mapped[str] = mapped_column(String(64))
    permission_snapshot: Mapped[dict] = mapped_column(JSON)
    request_note: Mapped[str] = mapped_column(Text)
    execution_snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class AssessmentReport(Base):
    __tablename__ = "assessment_reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment_requests.id", ondelete="RESTRICT"), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    content: Mapped[dict] = mapped_column(JSON)
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column()


class ObservationReview(Base):
    """Append-only analyst dispositions; the scanner report is never edited."""
    __tablename__ = "observation_reviews"
    __table_args__ = (
        UniqueConstraint("report_id", "check_id", "revision", name="uq_observation_review_revision"),
        CheckConstraint("revision > 0", name="ck_observation_review_revision"),
        CheckConstraint("disposition IN ('confirmed','not_applicable','dismissed')", name="ck_observation_disposition"),
        CheckConstraint("remediation_status IN ('open','in_progress','ready_for_retest','resolved','not_applicable')", name="ck_observation_remediation"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("assessment_reports.id", ondelete="RESTRICT"), index=True)
    check_id: Mapped[str] = mapped_column(String(80))
    revision: Mapped[int] = mapped_column()
    reviewer_id: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    disposition: Mapped[str] = mapped_column(String(30))
    severity: Mapped[str] = mapped_column(String(20))
    notes: Mapped[str] = mapped_column(Text)
    supporting_evidence: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String(150))
    remediation_status: Mapped[str] = mapped_column(String(30))
    resolution_notes: Mapped[str] = mapped_column(Text)
    retest_assessment_id: Mapped[str | None] = mapped_column(ForeignKey("assessment_requests.id", ondelete="RESTRICT"), nullable=True)


class ReviewedAssessmentExport(Base):
    __tablename__ = "reviewed_assessment_exports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment_requests.id", ondelete="RESTRICT"), index=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    content: Mapped[dict] = mapped_column(JSON)
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column()


class FindingDueDate(Base):
    """Append-only deadline changes for an assessment observation, linked to its review."""
    __tablename__ = "finding_due_dates"
    __table_args__ = (
        UniqueConstraint("report_id", "check_id", "revision", name="uq_finding_due_date_revision"),
        CheckConstraint("revision > 0", name="ck_finding_due_date_revision"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("assessment_reports.id", ondelete="RESTRICT"), index=True)
    check_id: Mapped[str] = mapped_column(String(80))
    review_id: Mapped[str] = mapped_column(ForeignKey("observation_reviews.id", ondelete="RESTRICT"))
    revision: Mapped[int] = mapped_column()
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    note: Mapped[str] = mapped_column(Text)
    updated_by: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
