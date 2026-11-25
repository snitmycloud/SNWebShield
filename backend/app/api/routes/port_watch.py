"""Port watch API. Enabling is the explicit, audited act that permits recurring TCP 80/443 checks.

Reading is open to any signed-in administrator. Enabling and disabling need an infrastructure role
(admin or lead analyst). No route here contacts a target: scans are requested by the scheduler through the
ordinary assessment path and executed by the assessment worker after its own permission re-check.
"""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.core import rbac
from app.core.security import get_current_admin
from app.db.session import get_db
from app.models.admin import Admin
from app.services import port_watch as service

def _migrated(call):
    """Port watch needs migration 0015. Until it is applied, say so plainly rather than failing with a server error."""
    try:
        return call()
    except OperationalError as error:
        raise HTTPException(503, "Port watch needs the latest database migration: run python -m alembic upgrade head from backend") from error


router = APIRouter(prefix="/port-watch", tags=["Port watch"], dependencies=[Depends(get_current_admin)])


class EnablePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    interval_seconds: int = Field(strict=True, ge=service.MIN_INTERVAL_SECONDS, le=service.MAX_INTERVAL_SECONDS)
    network_permission_confirmed: Literal[True]  # "I inspected genuine written permission for recurring TCP 80/443 checks"
    human_validation_confirmed: Literal[True]    # a person, not a script, enabled this


class DisablePayload(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    reason: str = Field(min_length=10, max_length=500)


@router.get("/{website_id}")
def read(website_id: int = Path(gt=0), db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    return _migrated(lambda: service.describe(db, website_id, admin.id))


@router.post("/{website_id}/enable")
def enable(payload: EnablePayload, website_id: int = Path(gt=0), db: Session = Depends(get_db),
           admin: Admin = Depends(rbac.require_infrastructure_role)):
    return _migrated(lambda: service.enable(db, admin.id, website_id, payload.interval_seconds))


@router.post("/{website_id}/disable")
def disable(payload: DisablePayload, website_id: int = Path(gt=0), db: Session = Depends(get_db),
            admin: Admin = Depends(rbac.require_infrastructure_role)):
    return _migrated(lambda: service.disable(db, admin.id, website_id, payload.reason))
