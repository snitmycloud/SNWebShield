"""Module F API: the human security analyst workbench.

Every route requires an authenticated, active administrator holding an analyst role
(`require_analyst`). Nothing here contacts a target; it only reads stored, integrity-checked
evidence and records attested human decisions.
"""
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.orm import Session

from app.core.rbac import require_analyst
from app.db.session import get_db
from app.models.admin import Admin
from app.services import vulnerabilities as service

router = APIRouter(prefix="/workbench", tags=["Analyst workbench"], dependencies=[Depends(require_analyst)])

Severity = Literal["informational", "low", "medium", "high", "critical"]
Likelihood = Literal["rare", "unlikely", "possible", "likely", "almost_certain"]
Impact = Literal["negligible", "minor", "moderate", "major", "severe"]
Priority = Literal["immediate", "short_term", "planned", "monitor"]
Stage = Literal["needs_assessment", "ready_for_signoff", "report_eligible", "dismissed", "all"]


class Assessment(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    expected_revision: int = Field(gt=0, strict=True)
    likelihood: Likelihood
    business_impact: Impact
    business_context: str = Field(min_length=20, max_length=4000)
    risk_rating: Severity
    override_reason: str | None = Field(default=None, min_length=20, max_length=2000)
    remediation: str = Field(min_length=20, max_length=8000)
    remediation_priority: Priority


class Signoff(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    expected_revision: int = Field(gt=0, strict=True)
    decision: Literal["approve", "reject", "reopen"]
    human_validation_confirmed: Literal[True]
    justification: str = Field(min_length=20, max_length=4000)
    reproduction_steps: str | None = Field(default=None, min_length=20, max_length=8000)
    rejection_outcome: Literal["false_positive", "not_applicable"] | None = None
    suppress_until: AwareDatetime | None = None

    @model_validator(mode="after")
    def requirements(self):
        if self.decision == "approve":
            if not self.reproduction_steps or self.rejection_outcome or self.suppress_until:
                raise ValueError("Approval requires reproduction steps and nothing else")
        elif self.decision == "reject":
            if not self.rejection_outcome or not self.suppress_until or self.reproduction_steps:
                raise ValueError("Rejection requires an outcome and suppression expiry, and no reproduction steps")
        elif self.reproduction_steps or self.rejection_outcome or self.suppress_until:
            raise ValueError("Reopening takes only a justification")
        return self


@router.get("/queue")
def queue(stage: Stage = "needs_assessment", severity: Severity | None = None,
          website_id: int | None = Query(None, gt=0), search: str = Query("", max_length=200),
          limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    return service.queue(db, stage=stage, severity=severity, website_id=website_id, search=search.strip(),
                         limit=limit, offset=offset)


@router.get("/{vulnerability_id}")
def detail(vulnerability_id: UUID, db: Session = Depends(get_db)):
    return service.workbench_detail(db, str(vulnerability_id))


@router.post("/{vulnerability_id}/assessment", status_code=201)
def save_assessment(vulnerability_id: UUID, payload: Assessment, db: Session = Depends(get_db),
                    admin: Admin = Depends(require_analyst)):
    return service.save_assessment(db, str(vulnerability_id), admin.id, payload)


@router.post("/{vulnerability_id}/signoff")
def signoff(vulnerability_id: UUID, payload: Signoff, db: Session = Depends(get_db),
            admin: Admin = Depends(require_analyst)):
    return service.signoff(db, str(vulnerability_id), admin.id, payload)


@router.get("/{vulnerability_id}/signoffs")
def signoffs(vulnerability_id: UUID, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
             db: Session = Depends(get_db)):
    return service.signoffs(db, str(vulnerability_id), limit, offset)


@router.get("/{vulnerability_id}/audit")
def audit(vulnerability_id: UUID, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
          db: Session = Depends(get_db)):
    return service.audit(db, str(vulnerability_id), limit, offset)
