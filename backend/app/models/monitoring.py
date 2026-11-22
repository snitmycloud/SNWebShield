from datetime import datetime
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class MonitoringConsent(Base):
    __tablename__ = "monitoring_consents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="RESTRICT"), index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("authorization_evidence.id", ondelete="RESTRICT"))
    reference: Mapped[str] = mapped_column(String(150))
    url: Mapped[str] = mapped_column(String(2048))
    reviewed_by: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MonitoringConfig(Base):
    __tablename__ = "monitoring_configs"
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="RESTRICT"), primary_key=True)
    consent_id: Mapped[str] = mapped_column(ForeignKey("monitoring_consents.id", ondelete="RESTRICT"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=300)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    failure_threshold: Mapped[int] = mapped_column(Integer, default=2)
    recovery_threshold: Mapped[int] = mapped_column(Integer, default=1)
    next_due: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_enqueued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    state: Mapped[str] = mapped_column(String(24), default="unknown")
    failures: Mapped[int] = mapped_column(Integer, default=0)
    successes: Mapped[int] = mapped_column(Integer, default=0)


class MonitoringIncident(Base):
    __tablename__ = "monitoring_incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="RESTRICT"), index=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    opening_job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id", ondelete="RESTRICT"))
    closing_job_id: Mapped[str | None] = mapped_column(ForeignKey("jobs.id", ondelete="RESTRICT"), nullable=True)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(160), unique=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="RESTRICT"))
    event: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    next_due: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    claim_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(100), nullable=True)
