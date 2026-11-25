from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

VERIFICATION_METHODS = ("dns", "file", "meta")
# unverified: never proven. verified: proven (re-checked at most every 24 h before a scan).
# lost: a re-check found the proof gone, so scans are paused until the owner fixes it.
VERIFICATION_STATES = ("unverified", "verified", "lost")


class Website(Base):
    __tablename__ = "websites"
    # One live entry per owner and domain. A removed website keeps its row (past scans and audit records point to it).
    __table_args__ = (Index("uq_website_owner_domain_active", "owner_id", "domain", unique=True,
                            sqlite_where=text("removed_at IS NULL"), postgresql_where=text("removed_at IS NULL")),)

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    # Legacy (analyst era): the client company. Self-service websites have no client.
    client_id: Mapped[int | None] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), index=True, nullable=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"), index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    url: Mapped[str] = mapped_column(String(2048), index=True)
    # Normalised host name (lowercase, no scheme, path or port). The unit of ownership.
    domain: Mapped[str | None] = mapped_column(String(253), index=True, nullable=True)
    platform: Mapped[str | None] = mapped_column(String(100), nullable=True)
    environment: Mapped[str] = mapped_column(String(30), default="production")
    hosting_provider: Mapped[str | None] = mapped_column(String(150), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Retired in Phase 1 (old written-permission system). Kept so existing data is not lost; never read.
    authorisation_status: Mapped[str] = mapped_column(String(30), default="retired")

    verification_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    verification_status: Mapped[str] = mapped_column(String(20), default="unverified", server_default="unverified")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # The last check's plain result: what was expected, what was found, and the advice shown to the owner.
    verification_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Set when the owner removes the website: it leaves their account and frees a plan slot.
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    client: Mapped["Client"] = relationship(back_populates="websites")
    # Keep authorization history: deleting a website must not silently delete its approval records.
    authorizations: Mapped[list["WebsiteAuthorization"]] = relationship(
        back_populates="website"
    )
