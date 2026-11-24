"""Module E API: normalised vulnerabilities, evidence, validation and suppression."""
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.orm import Session

from app.core.security import get_current_admin
from app.db.session import get_db
from app.models.admin import Admin
from app.services import vulnerabilities as service

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"], dependencies=[Depends(get_current_admin)])

Severity = Literal["informational", "low", "medium", "high", "critical"]
State = Literal["unconfirmed", "confirmed", "false_positive", "not_applicable"]


class Ingest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_id: UUID | None = None


class Comment(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    comment: str = Field(min_length=5, max_length=4000)


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    expected_revision: int = Field(gt=0, strict=True)
    decision: State
    human_validation_confirmed: Literal[True]
    justification: str = Field(min_length=20, max_length=4000)
    severity: Severity | None = None
    reproduction_steps: str | None = Field(default=None, min_length=20, max_length=8000)
    suppress_until: AwareDatetime | None = None

    @model_validator(mode="after")
    def requirements(self):
        if self.decision == "confirmed":
            if not self.severity or not self.reproduction_steps or self.suppress_until:
                raise ValueError("Confirmation requires analyst severity and reproduction steps, and no suppression")
        elif self.decision in ("false_positive", "not_applicable"):
            if not self.suppress_until or self.severity or self.reproduction_steps:
                raise ValueError("Dismissal requires a suppression expiry and no severity or reproduction steps")
        elif self.severity or self.reproduction_steps or self.suppress_until:
            raise ValueError("Reopening takes only a justification")
        return self


@router.get("")
def listing(state: State | None = None, severity: Severity | None = None,
            confidence: Literal["low", "medium", "high"] | None = None,
            website_id: int | None = Query(None, gt=0), client_id: int | None = Query(None, gt=0),
            suppressed: bool | None = None, search: str = Query("", max_length=200),
            limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    return service.listing(db, state=state, severity=severity, confidence=confidence, website_id=website_id,
                           client_id=client_id, suppressed=suppressed, search=search.strip(), limit=limit, offset=offset)


@router.post("/ingest")
def ingest(payload: Ingest, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    # Processes stored, integrity-checked reports only; never contacts a target.
    return service.ingest_pending(db, admin.id, str(payload.assessment_id) if payload.assessment_id else None)


@router.get("/{vulnerability_id}")
def detail(vulnerability_id: UUID, db: Session = Depends(get_db)):
    return service.detail(db, str(vulnerability_id))


@router.get("/{vulnerability_id}/occurrences")
def occurrences(vulnerability_id: UUID, limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0),
                db: Session = Depends(get_db)):
    return service.occurrences(db, str(vulnerability_id), limit, offset)


@router.get("/{vulnerability_id}/events")
def events(vulnerability_id: UUID, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
           db: Session = Depends(get_db)):
    return service.events(db, str(vulnerability_id), limit, offset)


@router.post("/{vulnerability_id}/comments", status_code=201)
def comment(vulnerability_id: UUID, payload: Comment, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    return service.comment(db, str(vulnerability_id), admin.id, payload.comment)


@router.post("/{vulnerability_id}/validation")
def validation(vulnerability_id: UUID, payload: Decision, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    return service.decide(db, str(vulnerability_id), admin.id, payload)
