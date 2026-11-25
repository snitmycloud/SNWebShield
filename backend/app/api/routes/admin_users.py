"""Admin: list accounts, change a plan, disable or enable an account. Every change is audited."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import require_platform_admin
from app.core.time import as_utc
from app.db.session import get_db
from app.models.admin import Admin
from app.models.website import Website
from app.services import auth_audit, plans

router = APIRouter(prefix="/admin/users", tags=["Admin"])


class PlanChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plan: str


def _read(db, account: Admin) -> dict:
    websites = db.scalar(select(func.count()).select_from(Website).where(
        Website.owner_id == account.id, Website.removed_at.is_(None))) or 0
    iso = lambda v: as_utc(v).isoformat() if v else None
    return {"id": account.id, "email": account.email, "full_name": account.full_name, "role": account.role,
            "plan": account.plan, "is_active": account.is_active, "email_verified": account.email_verified_at is not None,
            "websites": websites, "created_at": iso(account.created_at), "last_login_at": iso(account.last_login_at)}


def _target(db, user_id: int) -> Admin:
    account = db.get(Admin, user_id)
    if account is None:
        raise HTTPException(404, "User not found")
    return account


@router.get("")
def list_users(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0),
               admin: Admin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    rows = db.scalars(select(Admin).order_by(Admin.id.desc()).offset(offset).limit(limit))
    return {"plans": plans.names(), "users": [_read(db, row) for row in rows]}


@router.post("/{user_id}/plan")
def change_plan(user_id: int, payload: PlanChange, request: Request, admin: Admin = Depends(require_platform_admin),
                db: Session = Depends(get_db)):
    if payload.plan not in plans.names():
        raise HTTPException(422, "Unknown plan")
    account = _target(db, user_id)
    previous, account.plan = account.plan, payload.plan
    auth_audit.record(db, "plan_changed", account.email, auth_audit.client_ip(request), admin_id=account.id,
                      reason="admin_change", detail={"by_admin_id": admin.id, "from": previous, "to": payload.plan})
    db.commit()
    return _read(db, account)


@router.post("/{user_id}/{action}")
def set_active(user_id: int, action: str, request: Request, admin: Admin = Depends(require_platform_admin),
               db: Session = Depends(get_db)):
    if action not in ("disable", "enable"):
        raise HTTPException(404, "Not found")
    account = _target(db, user_id)
    if action == "disable" and account.id == admin.id:
        raise HTTPException(409, "You cannot disable your own account.")
    account.is_active = action == "enable"
    auth_audit.record(db, "account_disabled" if action == "disable" else "account_enabled", account.email,
                      auth_audit.client_ip(request), admin_id=account.id, reason="admin_change",
                      detail={"by_admin_id": admin.id})
    db.commit()
    return _read(db, account)
