"""Assessment lifecycle API for fixed local profiles."""
from datetime import datetime
from typing import Literal
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.rbac import require_closure_reopen_role, require_closure_role, require_remediation_role
from app.core.security import get_current_admin
from app.core.time import as_utc, utc_now
from app.db.session import get_db
from app.models.admin import Admin
from app.models.assessment import AssessmentRequest
from app.models.jobs import Job, JobResult, JobAttempt, ExecutionEvent, WorkerHeartbeat
from app.services import assessments as service
from app.services import remediation as remediation_service

WORKER_STALE_SECONDS = 45  # worker heartbeats every ~10 s from a dedicated thread

router = APIRouter(prefix="/assessments", tags=["Assessments"], dependencies=[Depends(get_current_admin)])


class CreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    website_id: int = Field(gt=0)
    authorization_id: int = Field(gt=0)
    profile_id: str = Field(min_length=1, max_length=80)
    idempotency_key: UUID
    explicitly_requested: Literal[True]
    network_permission_confirmed: bool = False
    note: str = Field(min_length=20, max_length=2000)


class Cancellation(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    reason: str = Field(min_length=10, max_length=1000)


class ObservationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    expected_revision: int = Field(ge=0, strict=True)
    human_validation_confirmed: Literal[True]
    disposition: Literal["confirmed", "not_applicable", "dismissed"]
    severity: Literal["informational", "low", "medium", "high", "critical"] = "informational"
    notes: str = Field(min_length=20, max_length=4000)
    supporting_evidence: str = Field(min_length=20, max_length=8000)
    recommendation: str = Field(default="", max_length=4000)
    owner: str = Field(default="", max_length=150)
    remediation_status: Literal["open", "in_progress", "ready_for_retest", "resolved", "not_applicable"]
    resolution_notes: str = Field(default="", max_length=4000)
    retest_assessment_id: UUID | None = None

    @model_validator(mode="after")
    def decision_requirements(self):
        if self.disposition == "confirmed":
            if len(self.recommendation) < 20 or not self.owner or self.remediation_status == "not_applicable":
                raise ValueError("Confirmed issues require a recommended fix, owner and remediation status")
            if self.remediation_status == "resolved" and (len(self.resolution_notes) < 20 or not self.retest_assessment_id):
                raise ValueError("Resolution requires notes and a later completed retest")
        elif self.remediation_status != "not_applicable" or self.severity != "informational" or self.retest_assessment_id:
            raise ValueError("Non-confirmed observations use informational severity and not-applicable remediation")
        return self


def serial(row):
    return {c.name: as_utc(value).isoformat() if isinstance(value, datetime) else value
            for c in row.__table__.columns if c.name != "claim_token" for value in [getattr(row, c.name)]}


def read(db, row):
    job = db.get(Job, row.job_id)
    result = db.get(JobResult, row.job_id)
    return {**serial(row), "mode": (row.execution_snapshot or {}).get("mode", "policy_only"), "job": serial(job),
            "result": serial(result) if result else None}


@router.get("/profiles")
def profiles():
    from app.core.config import settings
    return [{**p, "digest": service.digest(p), "available": service.profile_available(p)} for p in service.PROFILES.values()]


@router.get("/worker-status")
def worker_status(db: Session = Depends(get_db)):
    row = db.get(WorkerHeartbeat, "assessment-worker")
    # The server clock decides health; the browser clock is never trusted.
    age = None if row is None else max(0, int((utc_now() - as_utc(row.seen_at)).total_seconds()))
    state = "not_started" if row is None else "running" if age <= WORKER_STALE_SECONDS else "stale"
    return {"worker": serial(row) if row else None, "state": state, "age_seconds": age,
            "stale_after_seconds": WORKER_STALE_SECONDS,
            "start_command": r".\.venv\Scripts\python.exe -m app.cli.operations assessment-worker",
            "mode": "profile_controlled",
            "scanner_tools_enabled": service.profile_available(service.PROFILES[service.NMAP_PROFILE_ID])}


@router.post("", status_code=201)
def create(payload: CreateRequest, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    return read(db, service.create_request(db, admin.id, payload))


@router.get("")
def listing(website_id: int | None = Query(default=None, gt=0), limit: int = Query(default=50, ge=1, le=100),
            offset: int = Query(default=0, ge=0), db: Session = Depends(get_db)):
    statement = select(AssessmentRequest).order_by(AssessmentRequest.requested_at.desc(), AssessmentRequest.id)
    if website_id is not None:
        statement = statement.where(AssessmentRequest.website_id == website_id)
    return [read(db, row) for row in db.scalars(statement.offset(offset).limit(limit))]


@router.get("/{assessment_id}")
def detail(assessment_id: UUID, db: Session = Depends(get_db)):
    return read(db, service.get_request(db, str(assessment_id)))


class Closure(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    human_validation_confirmed: Literal[True]
    justification: str = Field(min_length=20, max_length=4000)


@router.get("/{assessment_id}/closure")
def closure(assessment_id: UUID, db: Session = Depends(get_db), admin: Admin = Depends(require_remediation_role)):
    return remediation_service.closure_state(db, str(assessment_id))


@router.post("/{assessment_id}/close")
def close(assessment_id: UUID, payload: Closure, db: Session = Depends(get_db), admin: Admin = Depends(require_closure_role)):
    return remediation_service.close_assessment(db, str(assessment_id), admin.id, payload.justification)


@router.get("/{assessment_id}/reviews")
def review_summary(assessment_id: UUID, db: Session = Depends(get_db)):
    from app.services import observation_reviews
    return observation_reviews.summary(db, str(assessment_id))


@router.post("/{assessment_id}/reviews/{check_id}", status_code=201)
def review_observation(assessment_id: UUID, check_id: str, payload: ObservationDecision,
                       db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    from app.services import observation_reviews
    return observation_reviews.save(db, str(assessment_id), check_id, admin.id, payload)


@router.get("/{assessment_id}/reviews/{check_id}/history")
def review_history(assessment_id: UUID, check_id: str,
                   limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0),
                   db: Session = Depends(get_db)):
    from app.services import observation_reviews
    from app.models.assessment import ObservationReview
    _, report = observation_reviews.verified_report(db, str(assessment_id))
    if check_id not in observation_reviews.observations(report):
        raise HTTPException(404, "Observation not found in this assessment")
    rows = db.scalars(select(ObservationReview).where(ObservationReview.report_id == report.id,
        ObservationReview.check_id == check_id).order_by(ObservationReview.revision.desc()).offset(offset).limit(limit))
    return [observation_reviews.serial(row) for row in rows]


@router.post("/{assessment_id}/reviewed-reports", status_code=201)
def create_reviewed_report(assessment_id: UUID, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    from app.services import observation_reviews
    return observation_reviews.create_export(db, str(assessment_id), admin.id)


@router.get("/{assessment_id}/reviewed-reports/{export_id}/download")
def download_reviewed_report(assessment_id: UUID, export_id: UUID,
                            db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    from app.models.assessment import ReviewedAssessmentExport
    row = service.get_request(db, str(assessment_id))
    export = db.get(ReviewedAssessmentExport, str(export_id))
    if not export or export.assessment_id != row.id:
        raise HTTPException(404, "Reviewed report not found for this assessment")
    data = service.report_bytes(export.content)
    from hashlib import sha256
    if len(data) != export.size or sha256(data).hexdigest() != export.sha256:
        raise HTTPException(409, "Reviewed report integrity check failed")
    service.engine.event(db, "reviewed_assessment_export_downloaded", db.get(Job, row.job_id), actor_id=admin.id,
                         detail={"export_id": export.id, "sha256": export.sha256})
    db.commit()
    from fastapi.responses import Response
    return Response(data, media_type="application/json", headers={"Cache-Control": "no-store, private",
        "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; sandbox",
        "Content-Disposition": f'attachment; filename="reviewed-assessment-{export.id}.json"'})


@router.get("/{assessment_id}/{collection}")
def history(assessment_id: UUID, collection: Literal["attempts", "events"],
            limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0),
            db: Session = Depends(get_db)):
    row = service.get_request(db, str(assessment_id))
    model = JobAttempt if collection == "attempts" else ExecutionEvent
    order = JobAttempt.started_at if collection == "attempts" else ExecutionEvent.occurred_at
    statement = select(model).where(model.job_id == row.job_id).order_by(order.desc(), model.id)
    return [serial(x) for x in db.scalars(statement.offset(offset).limit(limit))]


@router.post("/{assessment_id}/cancel")
def cancel(assessment_id: UUID, payload: Cancellation, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    row = service.get_request(db, str(assessment_id))
    if not service.cancel(db, row, admin.id, payload.reason):
        db.rollback()
        raise HTTPException(409, "Only queued or running assessments can be cancelled")
    db.commit()
    return read(db, row)


@router.get("/{assessment_id}/report/download")
def report_download(assessment_id: UUID, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    from app.models.assessment import AssessmentReport
    from fastapi.responses import Response
    from hashlib import sha256
    row = service.get_request(db, str(assessment_id))
    report = db.scalar(select(AssessmentReport).where(AssessmentReport.assessment_id == row.id))
    if report is None: raise HTTPException(404, "No successful assessment report")
    data = service.report_bytes(report.content)
    if len(data) != report.size or sha256(data).hexdigest() != report.sha256:
        raise HTTPException(409, "Report integrity check failed")
    service.engine.event(db, "assessment_report_downloaded", resource_id=row.website_id,
        actor_id=admin.id, detail={"report_id":report.id})
    db.commit()
    return Response(data, media_type="application/json", headers={"Cache-Control":"no-store, private",
        "X-Content-Type-Options":"nosniff", "Content-Security-Policy":"default-src 'none'; sandbox",
        "Content-Disposition":f'attachment; filename="assessment-{row.id}.json"'})


@router.post("/{assessment_id}/reopen-closure")
def reopen_closure(assessment_id: UUID, payload: Closure, db: Session = Depends(get_db),
                   admin: Admin = Depends(require_closure_reopen_role)):
    """Formally lift the closed-assessment lock (audited, reason required)."""
    return remediation_service.reopen_closure(db, str(assessment_id), admin.id, payload.justification)
