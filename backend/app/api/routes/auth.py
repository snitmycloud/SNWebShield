from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import (
    create_access_token,
    get_current_admin,
    get_current_session,
    hash_password,
    password_needs_rehash,
    verify_password,
    verify_unknown_user_password,
)
from app.core.time import utc_now
from app.db.session import get_db
from app.models.admin import Admin
from app.models.security import RevokedToken
from app.schemas.auth import AdminLogin, AdminRead, TokenRead
from app.services import auth_audit

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _bad_credentials() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/login", response_model=TokenRead)
def admin_login(payload: AdminLogin, request: Request, db: Session = Depends(get_db)) -> TokenRead:
    email = str(payload.email).strip().lower()
    ip = auth_audit.client_ip(request)

    wait = auth_audit.retry_after_seconds(db, email, ip)
    if wait:
        auth_audit.record(db, "login_throttled", email, ip, reason="too_many_failures", detail={"retry_after": wait})
        db.commit()
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Too many failed sign-in attempts; try again later",
                            headers={"Retry-After": str(wait)})

    admin = db.scalar(select(Admin).where(Admin.email == email))

    if admin is None:
        verify_unknown_user_password(payload.password)
        auth_audit.record(db, "login_failure", email, ip, reason="unknown_account")
        db.commit()
        raise _bad_credentials()

    if not verify_password(payload.password, admin.password_hash):
        auth_audit.record(db, "login_failure", email, ip, admin_id=admin.id, reason="bad_password")
        db.commit()
        raise _bad_credentials()

    if not admin.is_active:
        auth_audit.record(db, "login_inactive", email, ip, admin_id=admin.id, reason="inactive_account")
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator account is inactive",
        )

    try:
        access_token, expires_in = create_access_token(admin)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if password_needs_rehash(admin.password_hash):
        admin.password_hash = hash_password(payload.password)
    admin.last_login_at = datetime.now(UTC)
    auth_audit.record(db, "login_success", email, ip, admin_id=admin.id, detail={"role": admin.role})
    db.commit()
    db.refresh(admin)
    return TokenRead(access_token=access_token, expires_in=expires_in, admin=admin)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def admin_logout(request: Request, session: tuple[Admin, dict] = Depends(get_current_session),
                 db: Session = Depends(get_db)) -> Response:
    """Revoke the presented token server-side (its `jti` is denied until it would have expired anyway)."""
    admin, claims = session
    now = utc_now()
    expires = datetime.fromtimestamp(int(claims["exp"]), UTC)
    try:
        db.add(RevokedToken(jti=str(claims["jti"]), admin_id=admin.id, revoked_at=now, expires_at=expires))
        db.flush()
    except IntegrityError:
        db.rollback()  # two logouts raced; the token is revoked either way
    # Entries past their natural expiry (plus the 15-second validation leeway) can never be replayed.
    db.execute(delete(RevokedToken).where(RevokedToken.expires_at < now - timedelta(minutes=1)))
    auth_audit.record(db, "logout", admin.email, auth_audit.client_ip(request), admin_id=admin.id, reason="logout")
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=AdminRead)
def get_admin_profile(current_admin: Admin = Depends(get_current_admin)) -> Admin:
    return current_admin
