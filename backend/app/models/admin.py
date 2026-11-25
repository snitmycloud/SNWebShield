from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


# Staff roles. Only these may use the internal (legacy, read-only) analyst pages.
ADMIN_ROLES = ("admin", "lead_analyst", "analyst")
# Every account role. `user` is a self-service customer who sees only their own websites and scans.
ACCOUNT_ROLES = ADMIN_ROLES + ("user",)
_ROLE_SQL = "('" + "','".join(ACCOUNT_ROLES) + "')"


class Admin(Base):
    """An account: a self-service customer (`user`) or SNWebShield staff. The table name is historical."""

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
    # Plan name from app/plans.json. New accounts are Free until payments exist (Phase 7).
    plan: Mapped[str] = mapped_column(String(20), default="free", server_default="free", nullable=False)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Access tokens issued before this moment are refused (set on password change or reset).
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    authorization_events: Mapped[list["AuthorizationAuditEvent"]] = relationship(
        back_populates="admin"
    )

    @property
    def is_staff(self) -> bool:
        return self.role in ADMIN_ROLES


TOKEN_PURPOSES = ("verify_email", "reset_password")


class AccountToken(Base):
    """Single-use email-verification and password-reset tokens. Only a SHA-256 of the token is stored."""

    __tablename__ = "account_tokens"
    __table_args__ = (
        CheckConstraint("purpose IN ('verify_email','reset_password')", name="ck_account_token_purpose"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="CASCADE"), index=True)
    purpose: Mapped[str] = mapped_column(String(20))
    token_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
