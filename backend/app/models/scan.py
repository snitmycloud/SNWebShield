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


class ScanFinding(Base):
    """One finding of a scan, in the common format (see services/finding.py). Unique per scan and fingerprint."""
    __tablename__ = "scan_findings"
    __table_args__ = (UniqueConstraint("scan_id", "fingerprint", name="uq_scan_finding"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(20))
    check_id: Mapped[str] = mapped_column(String(120))
    title: Mapped[str] = mapped_column(Text)
    location: Mapped[str] = mapped_column(String(300))
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    confidence: Mapped[str] = mapped_column(String(10))
    group: Mapped[str] = mapped_column(String(20))
    you_have: Mapped[str | None] = mapped_column(Text, nullable=True)
    you_should_have: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(120), nullable=True)
    affected_range: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_fixed: Mapped[str | None] = mapped_column(Text, nullable=True)
    why: Mapped[str | None] = mapped_column(Text, nullable=True)
    how_to_fix: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    caveat: Mapped[str | None] = mapped_column(Text, nullable=True)
    sources: Mapped[list | None] = mapped_column(JSON, nullable=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class VulnCache(Base):
    """Shared 24-hour cache of what NVD / OSV said about one product version. Public data, no scan or user data."""
    __tablename__ = "vuln_cache"
    __table_args__ = (UniqueConstraint("source", "key", name="uq_vuln_cache"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(10))
    key: Mapped[str] = mapped_column(String(200))
    payload: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(String(200), nullable=True)


class FindingState(Base):
    """What became of one finding on one website across scans: open or fixed (and how), plus an optional risk acceptance."""
    __tablename__ = "finding_states"
    __table_args__ = (UniqueConstraint("website_id", "fingerprint", name="uq_finding_state"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="RESTRICT"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    check_id: Mapped[str] = mapped_column(String(120))
    title: Mapped[str] = mapped_column(Text)
    location: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(10), default="open", server_default="open")   # open | fixed
    first_seen_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fixed_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    fixed_how: Mapped[str | None] = mapped_column(String(12), nullable=True)     # recheck | full_scan
    reopened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reopened_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    accepted_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    accepted_by_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    accepted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class FindingRecheck(Base):
    """One "Re-scan to confirm fix" request: the focused scan it ran and what it found."""
    __tablename__ = "finding_rechecks"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"), unique=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="RESTRICT"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    check_id: Mapped[str] = mapped_column(String(120))
    requested_by_id: Mapped[int] = mapped_column(Integer)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    outcome: Mapped[str | None] = mapped_column(String(20), nullable=True)      # fixed | still_open | could_not_check
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class RetiredTable(Base):
    """Tables of the removed written-permission system. Kept with their data, no longer used by code."""
    __tablename__ = "retired_tables"
    name: Mapped[str] = mapped_column(String(80), primary_key=True)
    retired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)
