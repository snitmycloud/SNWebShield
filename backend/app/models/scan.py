"""Self-service scans and the retired-table register.

A `Scan` row is also the per-scan audit record required by the spec: who (owner), which website, which IP,
scan type, start, end and result. Execution events add the step-by-step trail.
"""
from datetime import datetime

from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

SCAN_STATES = ("queued", "running", "completed", "incomplete", "refused")
SCAN_TRIGGERS = ("first", "manual", "scheduled")
ACTIVE_SCAN_STATES = ("queued", "running")


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("status IN ('" + "','".join(SCAN_STATES) + "')", name="ck_scan_status"),
        CheckConstraint("trigger IN ('" + "','".join(SCAN_TRIGGERS) + "')", name="ck_scan_trigger"),
        # At most one queued or running scan per website, enforced by the database.
        Index("uq_active_scan_website", "website_id", unique=True,
              sqlite_where=text("status IN ('queued', 'running')"),
              postgresql_where=text("status IN ('queued', 'running')")),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="RESTRICT"), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"), index=True)
    scan_type: Mapped[str] = mapped_column(String(20), default="standard")
    trigger: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), index=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claim_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # The single address resolved at the start of the scan. Only this address is ever contacted.
    resolved_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    # Machine-readable outcome (reason codes, step results) and the plain-language message for the owner.
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class ScanPort(Base):
    """One OPEN port found by a scan. Closed and filtered ports are counted in the scan's result, not stored."""
    __tablename__ = "scan_ports"
    __table_args__ = (UniqueConstraint("scan_id", "port", name="uq_scan_port"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(10), default="open")
    service: Mapped[str | None] = mapped_column(String(60), nullable=True)
    product: Mapped[str | None] = mapped_column(String(120), nullable=True)
    version: Mapped[str | None] = mapped_column(String(120), nullable=True)   # None = "not disclosed"
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)          # plain text, cut to 1 KB
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)        # tls, http headers, cookie names and flags


class ScanTechnology(Base):
    __tablename__ = "scan_technologies"
    __table_args__ = (UniqueConstraint("scan_id", "name", name="uq_scan_technology"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    category: Mapped[str] = mapped_column(String(60))
    version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    source: Mapped[str] = mapped_column(String(20))
    evidence: Mapped[str | None] = mapped_column(String(200), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)


class ScanObservation(Base):
    """DNS/email records, exposed files and listed subdomains. `kind` is dns | exposed_file | subdomain."""
    __tablename__ = "scan_observations"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"), index=True)
    kind: Mapped[str] = mapped_column(String(20), index=True)
    key: Mapped[str] = mapped_column(String(253))
    status: Mapped[str] = mapped_column(String(20))
    data: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class RetiredTable(Base):
    """Tables of the removed written-permission system. Kept with their data, no longer used by code."""
    __tablename__ = "retired_tables"
    name: Mapped[str] = mapped_column(String(80), primary_key=True)
    retired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)
