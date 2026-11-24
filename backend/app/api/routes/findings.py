from datetime import date
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import get_current_admin
from app.db.session import get_db
from app.models.admin import Admin
from app.models.assessment import FindingDueDate
from app.services import findings

router = APIRouter(prefix="/findings", tags=["Findings"], dependencies=[Depends(get_current_admin)])


class Deadline(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    expected_revision: int = Field(ge=0, strict=True)
    expected_review_revision: int = Field(gt=0, strict=True)
    due_date: date | None
    note: str = Field(min_length=10, max_length=2000)


@router.get("")
def listing(client_id: int | None = Query(None, gt=0), website_id: int | None = Query(None, gt=0),
            severity: Literal["informational", "low", "medium", "high", "critical"] | None = None,
            status: Literal["open", "in_progress", "ready_for_retest", "resolved"] | None = None,
            owner: str = Query("", max_length=150), search: str = Query("", max_length=200), overdue_only: bool = False,
            limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    return findings.listing(db, client_id=client_id, website_id=website_id, severity=severity, status=status,
        owner=owner.strip(), search=search.strip(), overdue_only=overdue_only, limit=limit, offset=offset)


@router.get("/{assessment_id}/{check_id}")
def detail(assessment_id: UUID, check_id: str, db: Session = Depends(get_db)):
    return findings.detail(db, str(assessment_id), check_id)


@router.post("/{assessment_id}/{check_id}/deadline", status_code=201)
def deadline(assessment_id: UUID, check_id: str, payload: Deadline, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    return findings.save_deadline(db, str(assessment_id), check_id, admin.id, payload)


@router.get("/{assessment_id}/{check_id}/deadline-history")
def deadline_history(assessment_id: UUID, check_id: str, limit: int = Query(50, ge=1, le=100),
                     offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    _, report = findings.observation_reviews.verified_report(db, str(assessment_id))
    if check_id not in findings.observation_reviews.observations(report):
        from fastapi import HTTPException
        raise HTTPException(404, "Observation not found")
    rows = db.scalars(select(FindingDueDate).where(FindingDueDate.report_id == report.id,
        FindingDueDate.check_id == check_id).order_by(FindingDueDate.revision.desc()).offset(offset).limit(limit))
    return [findings.deadline_serial(row) for row in rows]
