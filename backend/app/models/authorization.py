from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, JSON, String, Text, false, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class WebsiteAuthorization(Base):
    """A record of written permission proposed for a website security assessment."""

    __tablename__ = "website_authorizations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired', 'revoked')",
            name="ck_website_authorizations_status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    website_id: Mapped[int] = mapped_column(
        ForeignKey("websites.id", ondelete="RESTRICT"), index=True
    )
    authorization_reference: Mapped[str] = mapped_column(String(120), index=True)
    authorized_by: Mapped[str] = mapped_column(String(150))
    authorized_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    permitted_methods: Mapped[list[str]] = mapped_column(JSON, default=list)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    # Migration marks pre-fix rows false; their original timezone cannot be inferred.
    # Only callers that explicitly normalise the window may set this true.
    timestamps_verified: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false(), nullable=False
    )

    # Reserved for a future private evidence-storage integration. This key is never exposed by API.
    evidence_storage_key: Mapped[str | None] = mapped_column(String(500), nullable=True)
    internal_review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    website: Mapped["Website"] = relationship(back_populates="authorizations")
    review_events: Mapped[list["AuthorizationAuditEvent"]] = relationship(
        back_populates="authorization"
    )
