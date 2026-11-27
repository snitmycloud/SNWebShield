"""Phase 5 monitoring tables: uptime, score history, alerts and alert preferences."""
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class UptimeCheck(Base):
    __tablename__ = "uptime_checks"
    __table_args__ = (Index("ix_uptime_checks_site_time", "website_id", "checked_at"),)
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="CASCADE"))
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)   # None = could not check (blocked address): never counted as down
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scheme: Mapped[str | None] = mapped_column(String(5), nullable=True)
    error: Mapped[str | None] = mapped_column(String(60), nullable=True)


class UptimeState(Base):
    __tablename__ = "uptime_states"
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="CASCADE"), primary_key=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    is_down: Mapped[bool] = mapped_column(Boolean, default=False)
    down_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cert_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cert_not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cert_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ScoreHistory(Base):
    __tablename__ = "score_history"
    __table_args__ = (Index("ix_score_history_site_time", "website_id", "scored_at"),)
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="CASCADE"))
    scan_id: Mapped[str] = mapped_column(String(36), unique=True)
    scored_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    score: Mapped[int] = mapped_column(Integer)
    grade: Mapped[str] = mapped_column(String(1))
    counts: Mapped[dict] = mapped_column(JSON, default=dict)
    incomplete: Mapped[bool] = mapped_column(Boolean, default=False)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_dedup", "website_id", "alert_type", "alert_key", "created_at"),)
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="CASCADE"))
    owner_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    alert_type: Mapped[str] = mapped_column(String(40))
    alert_key: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    channel: Mapped[str] = mapped_column(String(20))   # outbox | smtp
    subject: Mapped[str] = mapped_column(String(200))
    delivered: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(String(80), nullable=True)


class AlertPreference(Base):
    __tablename__ = "alert_preferences"
    __table_args__ = (UniqueConstraint("account_id", "alert_type", name="uq_alert_preference"),)
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="CASCADE"))
    alert_type: Mapped[str] = mapped_column(String(40))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
