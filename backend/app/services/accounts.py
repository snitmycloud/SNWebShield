"""Self-service accounts: sign-up, email verification, password reset and change.

Tokens are 256-bit random values sent only by email; the database keeps their SHA-256. Each token is single
use and expires. Responses to "forgot password" and "resend verification" never reveal whether an email
address has an account.
"""
from datetime import timedelta
from hashlib import sha256
import secrets
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select, update

from app.core.config import settings
from app.core.security import hash_password, validate_password_policy
from app.core.time import as_utc, utc_now
from app.models.admin import AccountToken, Admin
from app.services import auth_audit, mailer, plans


def _digest(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def issue_token(db, account: Admin, purpose: str) -> str:
    now = utc_now()
    lifetime = (timedelta(hours=settings.email_verification_hours) if purpose == "verify_email"
                else timedelta(minutes=settings.password_reset_minutes))
    # Only the newest link of each kind works.
    db.execute(update(AccountToken).where(AccountToken.account_id == account.id, AccountToken.purpose == purpose,
                                          AccountToken.used_at.is_(None)).values(used_at=now))
    token = secrets.token_urlsafe(32)
    db.add(AccountToken(id=str(uuid4()), account_id=account.id, purpose=purpose, token_sha256=_digest(token),
                        created_at=now, expires_at=now + lifetime))
    return token


def consume_token(db, token: str, purpose: str) -> Admin:
    """Mark the token used and return its account, or refuse with one generic message."""
    invalid = HTTPException(400, "This link is invalid or has expired. Request a new one.")
    if not token or len(token) > 200:
        raise invalid
    row = db.scalar(select(AccountToken).where(AccountToken.token_sha256 == _digest(token)))
    now = utc_now()
    if row is None or row.purpose != purpose or row.used_at is not None or as_utc(row.expires_at) <= now:
        raise invalid
    changed = db.execute(update(AccountToken).where(AccountToken.id == row.id, AccountToken.used_at.is_(None))
                         .values(used_at=now).execution_options(synchronize_session=False))
    if changed.rowcount != 1:
        raise invalid
    account = db.get(Admin, row.account_id)
    if account is None:
        raise invalid
    return account


def _link(path: str, token: str) -> str:
    return f"{settings.frontend_base_url.rstrip('/')}/{path}?token={token}"


def _deliver(*args) -> None:
    try:
        mailer.send(*args)
    except Exception:  # the message body holds a token: never include it in an error
        raise HTTPException(503, "We could not send the email right now. Please try again in a few minutes.") from None


def send_verification(account: Admin, token: str) -> None:
    _deliver(account.email, "Confirm your SNwebshield email address",
                "Welcome to SNwebshield.\n\n"
                "Confirm your email address to finish creating your account:\n\n"
                f"{_link('verify-email', token)}\n\n"
                f"This link works once and expires in {settings.email_verification_hours} hours.\n"
                "If you did not sign up, you can ignore this email.\n")


def send_reset(account: Admin, token: str) -> None:
    _deliver(account.email, "Reset your SNwebshield password",
                "Someone (hopefully you) asked to reset your SNwebshield password.\n\n"
                f"Choose a new password here:\n\n{_link('reset-password', token)}\n\n"
                f"This link works once and expires in {settings.password_reset_minutes} minutes.\n"
                "If you did not ask for this, ignore this email; your password stays the same.\n")


def check_password(password: str, email: str) -> None:
    problems = validate_password_policy(password, email)
    if problems:
        raise HTTPException(422, "Password " + "; ".join(problems) + ".")


def sign_up(db, email: str, password: str, full_name: str, ip: str) -> None:
    if auth_audit.recent_count(db, ("signup", "signup_throttled"), ip=ip) >= settings.signup_max_per_ip:
        auth_audit.record(db, "signup_throttled", email, ip, reason="too_many_signups")
        db.commit()
        raise HTTPException(429, "Too many sign-ups from your network. Please try again in an hour.")
    check_password(password, email)
    existing = db.scalar(select(Admin).where(Admin.email == email))
    auth_audit.record(db, "signup", email, ip, admin_id=existing.id if existing else None,
                      reason="existing_account" if existing else "created")
    if existing is not None:
        # Same answer as a new sign-up so the form cannot be used to discover who has an account.
        # An unverified account gets a fresh link; a verified one gets nothing.
        if existing.email_verified_at is None and existing.is_active:
            token = issue_token(db, existing, "verify_email")
            db.commit()
            send_verification(existing, token)
        else:
            db.commit()
        return
    account = Admin(email=email, full_name=full_name or email.split("@")[0][:150],
                    password_hash=hash_password(password), role="user", is_active=True, plan=plans.default_plan())
    db.add(account)
    db.flush()
    token = issue_token(db, account, "verify_email")
    db.commit()
    send_verification(account, token)


def verify_email(db, token: str, ip: str) -> Admin:
    account = consume_token(db, token, "verify_email")
    if account.email_verified_at is None:
        account.email_verified_at = utc_now()
    auth_audit.record(db, "email_verified", account.email, ip, admin_id=account.id)
    db.commit()
    return account


def _email_request_allowed(db, email: str, ip: str, event: str) -> bool:
    if auth_audit.recent_count(db, ("verification_resent", "password_reset_requested"), ip=ip) >= settings.account_email_max_per_ip:
        raise HTTPException(429, "Too many requests from your network. Please try again later.")
    # At most three emails of this kind per address per window, silently.
    return auth_audit.recent_count(db, (event,), email=email) < 3


def resend_verification(db, email: str, ip: str) -> None:
    allowed = _email_request_allowed(db, email, ip, "verification_resent")
    account = db.scalar(select(Admin).where(Admin.email == email))
    auth_audit.record(db, "verification_resent", email, ip, admin_id=account.id if account else None,
                      reason="sent" if allowed and account and account.email_verified_at is None else "not_sent")
    token = None
    if allowed and account is not None and account.is_active and account.email_verified_at is None:
        token = issue_token(db, account, "verify_email")
    db.commit()
    if token:
        send_verification(account, token)


def request_reset(db, email: str, ip: str) -> None:
    allowed = _email_request_allowed(db, email, ip, "password_reset_requested")
    account = db.scalar(select(Admin).where(Admin.email == email))
    auth_audit.record(db, "password_reset_requested", email, ip, admin_id=account.id if account else None,
                      reason="sent" if allowed and account and account.is_active else "not_sent")
    token = None
    if allowed and account is not None and account.is_active:
        token = issue_token(db, account, "reset_password")
    db.commit()
    if token:
        send_reset(account, token)


def reset_password(db, token: str, new_password: str, ip: str) -> None:
    account = consume_token(db, token, "reset_password")
    if not account.is_active:
        db.rollback()
        raise HTTPException(400, "This link is invalid or has expired. Request a new one.")
    check_password(new_password, account.email)
    account.password_hash = hash_password(new_password)
    account.password_changed_at = utc_now()
    # Following the emailed link proves control of the address.
    account.email_verified_at = account.email_verified_at or utc_now()
    auth_audit.record(db, "password_reset", account.email, ip, admin_id=account.id)
    db.commit()


def change_password(db, account: Admin, current: str, new_password: str, ip: str) -> None:
    from app.core.security import verify_password
    if not verify_password(current, account.password_hash):
        raise HTTPException(400, "Your current password is not correct.")
    if current == new_password:
        raise HTTPException(422, "Choose a password different from your current one.")
    check_password(new_password, account.email)
    account.password_hash = hash_password(new_password)
    account.password_changed_at = utc_now()
    auth_audit.record(db, "password_changed", account.email, ip, admin_id=account.id)
    db.commit()
