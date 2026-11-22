"""Immutable assessment intent linked to the shared job queue."""
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
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
