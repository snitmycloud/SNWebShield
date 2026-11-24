"""Module G API: VAPT report generation, human approval and authenticated PDF download.

Every route requires an authenticated, active administrator with a report role. Generating a report
never contacts a target. A report cannot be released until a human approves it.
"""
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.rbac import require_report_approver, require_report_role
from app.db.session import get_db
from app.models.admin import Admin
from app.services import reports as service

router = APIRouter(prefix="/reports", tags=["VAPT reports"], dependencies=[Depends(require_report_role)])

Status = Literal["draft", "pending_approval", "approved", "rejected", "superseded"]


class Generate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_id: UUID


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    human_validation_confirmed: Literal[True]
    justification: str = Field(min_length=20, max_length=4000)


def pdf_response(data, digest, official):
    return Response(content=data, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="{"vapt-report" if official else "vapt-report-DRAFT"}.pdf"',
        "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", "X-Report-SHA256": digest,
        "X-Report-Release": "official" if official else "draft-not-for-release"})


@router.get("")
def listing(status: Status | None = None, assessment_id: UUID | None = None, limit: int = Query(50, ge=1, le=100),
            offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    return service.listing(db, status=status, assessment_id=str(assessment_id) if assessment_id else None,
                           limit=limit, offset=offset)


@router.get("/eligibility")
def eligibility(assessment_id: UUID, db: Session = Depends(get_db)):
    return service.eligibility(db, str(assessment_id))


@router.post("", status_code=201)
def generate(payload: Generate, db: Session = Depends(get_db), admin: Admin = Depends(require_report_role)):
    return service.generate(db, str(payload.assessment_id), admin.id)


@router.get("/{report_id}")
def detail(report_id: UUID, db: Session = Depends(get_db)):
    return service.detail(db, str(report_id))


@router.get("/{report_id}/events")
def events(report_id: UUID, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    return service.events(db, str(report_id), limit, offset)


@router.get("/{report_id}/preview")
def preview(report_id: UUID, db: Session = Depends(get_db), admin: Admin = Depends(require_report_role)):
    data, digest = service.download(db, str(report_id), admin.id, "draft")
    return pdf_response(data, digest, official=False)


@router.get("/{report_id}/pdf")
def official_pdf(report_id: UUID, db: Session = Depends(get_db), admin: Admin = Depends(require_report_role)):
    data, digest = service.download(db, str(report_id), admin.id, "official")
    return pdf_response(data, digest, official=True)


@router.post("/{report_id}/approve")
def approve(report_id: UUID, payload: Decision, db: Session = Depends(get_db),
            admin: Admin = Depends(require_report_approver)):
    return service.decide(db, str(report_id), admin.id, "approved", payload.justification)


@router.post("/{report_id}/reject")
def reject(report_id: UUID, payload: Decision, db: Session = Depends(get_db),
           admin: Admin = Depends(require_report_approver)):
    return service.decide(db, str(report_id), admin.id, "rejected", payload.justification)
