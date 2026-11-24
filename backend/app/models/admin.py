from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


ADMIN_ROLES = ("admin", "lead_analyst", "analyst")
_ROLE_SQL = "('" + "','".join(ADMIN_ROLES) + "')"


class Admin(Base):
    """An internal administrator account. Accounts are provisioned locally, not publicly."""

    __tablename__ = "admins"
    __table_args__ = (
        CheckConstraint(f"role IN {_ROLE_SQL}", name="ck_admins_role"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(150))
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(20), default="admin")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    authorization_events: Mapped[list["AuthorizationAuditEvent"]] = relationship(
        back_populates="admin"
    )
