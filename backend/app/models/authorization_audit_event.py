from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AuthorizationAuditEvent(Base):
    """Append-only record of an administrator's authorization decision."""

    __tablename__ = "authorization_audit_events"
    __table_args__ = (
        CheckConstraint(
            "action IN ('approved', 'rejected', 'revoked')",
            name="ck_authorization_audit_events_action",
        ),
        CheckConstraint(
            "previous_status IN ('pending', 'approved')",
            name="ck_authorization_audit_events_previous_status",
        ),
        CheckConstraint(
            "new_status IN ('approved', 'rejected', 'revoked')",
            name="ck_authorization_audit_events_new_status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    authorization_id: Mapped[int] = mapped_column(
        ForeignKey("website_authorizations.id", ondelete="RESTRICT"), index=True
    )
    admin_id: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"), index=True)
    action: Mapped[str] = mapped_column(String(20))
    previous_status: Mapped[str] = mapped_column(String(20))
    new_status: Mapped[str] = mapped_column(String(20))
    note: Mapped[str] = mapped_column(Text)
    evidence_reviewed: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    authorization: Mapped["WebsiteAuthorization"] = relationship(back_populates="review_events")
    admin: Mapped["Admin"] = relationship(back_populates="authorization_events")
