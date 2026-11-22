"""Shared execution records. Monitoring is the first registered job type."""
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, JSON, String, Integer, UniqueConstraint, Index, text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (Index("uq_active_assessment_website", "resource_id", unique=True,
        sqlite_where=text("job_type = 'assessment' AND status IN ('queued', 'running')"),
        postgresql_where=text("job_type = 'assessment' AND status IN ('queued', 'running')")),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    job_type: Mapped[str] = mapped_column(String(40), index=True)
    resource_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="RESTRICT"), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(160), unique=True)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claim_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=2)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class JobAttempt(Base):
    __tablename__ = "job_attempts"
    __table_args__ = (UniqueConstraint("job_id", "number"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id", ondelete="RESTRICT"), index=True)
    number: Mapped[int] = mapped_column(Integer)
    claim_token: Mapped[str] = mapped_column(String(36))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    outcome: Mapped[str] = mapped_column(String(24), default="running")


class JobResult(Base):
    __tablename__ = "job_results"
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id", ondelete="RESTRICT"), primary_key=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict] = mapped_column(JSON)


class ExecutionEvent(Base):
    __tablename__ = "execution_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    job_id: Mapped[str | None] = mapped_column(ForeignKey("jobs.id", ondelete="RESTRICT"), nullable=True, index=True)
    resource_id: Mapped[int | None] = mapped_column(ForeignKey("websites.id", ondelete="RESTRICT"), nullable=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True)
    action: Mapped[str] = mapped_column(String(60))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeats"
    name: Mapped[str] = mapped_column(String(100), primary_key=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ExecutionSlot(Base):
    __tablename__ = "execution_slots"
    job_type: Mapped[str] = mapped_column(String(40), primary_key=True)
    token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
