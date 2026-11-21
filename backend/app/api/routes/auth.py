from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    create_access_token,
    get_current_admin,
    verify_password,
    verify_unknown_user_password,
)
from app.db.session import get_db
from app.models.admin import Admin
from app.schemas.auth import AdminLogin, AdminRead, TokenRead

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenRead)
def admin_login(payload: AdminLogin, db: Session = Depends(get_db)) -> TokenRead:
    email = str(payload.email).strip().lower()
    admin = db.scalar(select(Admin).where(Admin.email == email))

    if admin is None:
        verify_unknown_user_password(payload.password)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(payload.password, admin.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not admin.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator account is inactive",
        )

    try:
        access_token, expires_in = create_access_token(admin)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    admin.last_login_at = datetime.now(UTC)
    db.commit()
    db.refresh(admin)
    return TokenRead(access_token=access_token, expires_in=expires_in, admin=admin)


@router.get("/me", response_model=AdminRead)
def get_admin_profile(current_admin: Admin = Depends(get_current_admin)) -> Admin:
    return current_admin
