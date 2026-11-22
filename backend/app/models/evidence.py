from datetime import datetime
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class AuthorizationEvidence(Base):
    __tablename__ = "authorization_evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    authorization_id: Mapped[int] = mapped_column(ForeignKey("website_authorizations.id", ondelete="RESTRICT"), index=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="RESTRICT"))
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="RESTRICT"))
    filename: Mapped[str] = mapped_column(String(180))
    media_type: Mapped[str] = mapped_column(String(40))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    uploader_id: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    retain_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False)
    state: Mapped[str] = mapped_column(String(24), default="available")


class EvidenceReview(Base):
    __tablename__ = "evidence_reviews"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    authorization_id: Mapped[int] = mapped_column(ForeignKey("website_authorizations.id", ondelete="RESTRICT"), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON)
    reviewer_id: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decision: Mapped[str] = mapped_column(String(16))
    comment: Mapped[str] = mapped_column(Text)


class EvidenceEvent(Base):
    __tablename__ = "evidence_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    authorization_id: Mapped[int] = mapped_column(ForeignKey("website_authorizations.id", ondelete="RESTRICT"), index=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("authorization_evidence.id", ondelete="RESTRICT"), nullable=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    action: Mapped[str] = mapped_column(String(40))
    comment: Mapped[str] = mapped_column(Text)
