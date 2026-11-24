"""Module H API: remediation tracking and scoped retests for confirmed findings.

Every route requires an authenticated, active administrator with a remediation role. A retest is
an ordinary assessment request, so the scanner worker revalidates the live written authorisation,
exact scope and methods; nothing here contacts a target.
"""
from datetime import date
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core import rbac
from app.core.rbac import require_remediation_role
from app.db.session import get_db
from app.models.admin import Admin
from app.services import remediation as service

router = APIRouter(prefix="/remediation", tags=["Remediation and retesting"], dependencies=[Depends(require_remediation_role)])

Status = Literal["open", "in_progress", "fix_submitted", "retest_requested", "verified_fixed", "reopened", "risk_accepted"]


class StatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    expected_version: int = Field(ge=0, strict=True)
    status: Literal["open", "in_progress", "fix_submitted", "risk_accepted"]
    note: str = Field(min_length=10, max_length=4000)
    target_date: date | None = None
    human_validation_confirmed: bool = False


class Reopen(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    expected_version: int = Field(ge=0, strict=True)
    reason: str = Field(min_length=20, max_length=4000)


class RetestPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    expected_version: int = Field(ge=0, strict=True)
    authorization_id: int = Field(gt=0)
    note: str = Field(min_length=20, max_length=1500)
    explicitly_requested: Literal[True]
    network_permission_confirmed: Literal[True]


@router.get("")
def listing(status: Status | None = None, website_id: int | None = Query(None, gt=0),
            assessment_id: UUID | None = None, search: str = Query("", max_length=200),
            limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    return service.listing(db, status=status, website_id=website_id,
                           assessment_id=str(assessment_id) if assessment_id else None, search=search.strip(),
                           limit=limit, offset=offset)


@router.get("/{vulnerability_id}")
def detail(vulnerability_id: UUID, db: Session = Depends(get_db)):
    return service.detail_of(db, str(vulnerability_id))


@router.post("/{vulnerability_id}/update")
def update(vulnerability_id: UUID, payload: StatusUpdate, db: Session = Depends(get_db),
           admin: Admin = Depends(require_remediation_role)):
    if payload.status == "risk_accepted":
        rbac.ensure_risk_acceptor(admin)
    return service.update_status(db, str(vulnerability_id), admin.id, payload)


@router.post("/{vulnerability_id}/reopen")
def reopen(vulnerability_id: UUID, payload: Reopen, db: Session = Depends(get_db),
           admin: Admin = Depends(require_remediation_role)):
    return service.reopen(db, str(vulnerability_id), admin.id, payload)


@router.get("/{vulnerability_id}/retests")
def retests(vulnerability_id: UUID, db: Session = Depends(get_db)):
    return service.retests(db, str(vulnerability_id))


@router.post("/{vulnerability_id}/retests", status_code=201)
def request_retest(vulnerability_id: UUID, payload: RetestPayload, db: Session = Depends(get_db),
                   admin: Admin = Depends(require_remediation_role)):
    return service.request_retest(db, str(vulnerability_id), admin.id, payload)
