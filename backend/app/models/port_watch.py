"""UNUSED (the earlier analyst pipeline was removed on 2026-11-27). The tables and all their data are kept in the database and
listed in `retired_tables`; no code reads or writes them. This file only keeps the schema description.

Explicitly enabled, recurring TCP 80/443 state checks for one website (Option A port watch).

`port_watches` is the current configuration and the last known port state. `port_watch_changes` is an
append-only history of every observed change, so what was seen and when can never be rewritten.
"""
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DDL, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint, event
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

WATCH_STATES = ("active", "blocked", "paused")
_STATE_SQL = "('" + "','".join(WATCH_STATES) + "')"


class PortWatch(Base):
    __tablename__ = "port_watches"
    __table_args__ = (
        CheckConstraint(f"state IN {_STATE_SQL}", name="ck_port_watch_state"),
        CheckConstraint("interval_seconds >= 3600", name="ck_port_watch_interval"),
    )
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="RESTRICT"), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    interval_seconds: Mapped[int] = mapped_column(Integer)
    enabled_by: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    enabled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    state: Mapped[str] = mapped_column(String(10), default="active")
    blocked_reason: Mapped[str | None] = mapped_column(String(80), nullable=True)
    next_due: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    last_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_assessment_id: Mapped[str | None] = mapped_column(ForeignKey("assessment_requests.id", ondelete="RESTRICT"), nullable=True)
    last_recorded_assessment_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_outcome: Mapped[str | None] = mapped_column(String(20), nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    baseline: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class PortWatchChange(Base):
    __tablename__ = "port_watch_changes"
    __table_args__ = (UniqueConstraint("website_id", "assessment_id", name="uq_port_watch_change"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="RESTRICT"), index=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment_requests.id", ondelete="RESTRICT"))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    previous: Mapped[dict] = mapped_column(JSON)
    current: Mapped[dict] = mapped_column(JSON)
    changes: Mapped[list] = mapped_column(JSON)


def _append_only(mapper, connection, target):
    raise ValueError("port_watch_changes records are append-only")


event.listen(PortWatchChange, "before_update", _append_only)
event.listen(PortWatchChange, "before_delete", _append_only)


def trigger_sql():
    return [f"CREATE TRIGGER IF NOT EXISTS trg_port_watch_changes_no_{verb.lower()} BEFORE {verb} ON port_watch_changes "
            f"BEGIN SELECT RAISE(ABORT, 'port_watch_changes is append-only'); END" for verb in ("UPDATE", "DELETE")]


for _sql in trigger_sql():
    event.listen(PortWatchChange.__table__, "after_create", DDL(_sql).execute_if(dialect="sqlite"))
