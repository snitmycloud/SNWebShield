"""Milestone 6 production-hardening tables.

* `auth_events` - append-only audit trail of authentication activity (R1). It never stores a
  password, token or raw email: attempts are keyed by a SHA-256 of the normalised email.
* `revoked_tokens` - `jti` denylist so logout is enforced by the server (R3).
* `assessment_closure_reopenings` - append-only record that formally lifts a closure lock.

Also installs database-level immutability for uploaded-authorisation evidence identity (hash, size,
name, owner) and for the evidence audit trail, so purging a document can never rewrite its hash.
"""
from datetime import datetime

from sqlalchemy import CheckConstraint, DDL, DateTime, ForeignKey, Integer, JSON, String, Text, event
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.evidence import AuthorizationEvidence, EvidenceEvent

AUTH_EVENT_TYPES = ("login_success", "login_failure", "login_inactive", "login_throttled", "logout",
                    # Phase 1 self-service accounts
                    "login_unverified", "signup", "signup_throttled", "email_verified", "verification_resent",
                    "password_reset_requested", "password_reset", "password_changed", "account_disabled",
                    "account_enabled", "plan_changed")
_TYPE_SQL = "('" + "','".join(AUTH_EVENT_TYPES) + "')"
EVIDENCE_FROZEN = ("id", "authorization_id", "filename", "media_type", "size", "sha256", "uploader_id", "uploaded_at")


class AuthEvent(Base):
    __tablename__ = "auth_events"
    __table_args__ = (CheckConstraint(f"event_type IN {_TYPE_SQL}", name="ck_auth_event_type"),)
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_type: Mapped[str] = mapped_column(String(24), index=True)
    email_sha256: Mapped[str] = mapped_column(String(64), index=True)
    admin_id: Mapped[int | None] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"), nullable=True, index=True)
    client_ip: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str] = mapped_column(String(40))
    detail: Mapped[dict] = mapped_column(JSON)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    admin_id: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class ClosureReopening(Base):
    __tablename__ = "assessment_closure_reopenings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    closure_id: Mapped[str] = mapped_column(ForeignKey("assessment_closures.id", ondelete="RESTRICT"), unique=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment_requests.id", ondelete="RESTRICT"), index=True)
    reopened_by: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    reopened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)


def _append_only(mapper, connection, target):
    raise ValueError(f"{type(target).__name__} records are append-only")


for _model in (AuthEvent, ClosureReopening, EvidenceEvent):
    event.listen(_model, "before_update", _append_only)
    event.listen(_model, "before_delete", _append_only)


def _evidence_frozen(mapper, connection, target):
    from sqlalchemy import inspect
    state = inspect(target)
    for name in EVIDENCE_FROZEN:
        if state.attrs[name].history.has_changes():
            raise ValueError(f"Evidence column '{name}' is immutable")
    if state.attrs.state.history.has_changes() and state.attrs.state.history.deleted == ["purged"]:
        raise ValueError("A purged document can never be restored")


def _evidence_no_delete(mapper, connection, target):
    raise ValueError("Evidence records can never be deleted; only the stored file is purged")


event.listen(AuthorizationEvidence, "before_update", _evidence_frozen)
event.listen(AuthorizationEvidence, "before_delete", _evidence_no_delete)


def trigger_sql():
    frozen = " OR ".join(f"OLD.{c} IS NOT NEW.{c}" for c in EVIDENCE_FROZEN)
    statements = [
        "CREATE TRIGGER IF NOT EXISTS trg_authorization_evidence_frozen BEFORE UPDATE ON authorization_evidence "
        f"WHEN {frozen} BEGIN SELECT RAISE(ABORT, 'authorization_evidence identity and hash are immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS trg_authorization_evidence_purged_final BEFORE UPDATE ON authorization_evidence "
        "WHEN OLD.state = 'purged' AND NEW.state IS NOT 'purged' "
        "BEGIN SELECT RAISE(ABORT, 'a purged document cannot be restored'); END",
        "CREATE TRIGGER IF NOT EXISTS trg_authorization_evidence_no_delete BEFORE DELETE ON authorization_evidence "
        "BEGIN SELECT RAISE(ABORT, 'authorization_evidence cannot be deleted'); END",
    ]
    for table in ("auth_events", "assessment_closure_reopenings", "evidence_events"):
        for verb in ("UPDATE", "DELETE"):
            statements.append(f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_{verb.lower()} BEFORE {verb} ON {table} "
                              f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END")
    return statements


for _model in (AuthorizationEvidence, EvidenceEvent, AuthEvent, ClosureReopening):
    for _sql in trigger_sql():
        if f" ON {_model.__tablename__} " in _sql:
            event.listen(_model.__table__, "after_create", DDL(_sql).execute_if(dialect="sqlite"))
