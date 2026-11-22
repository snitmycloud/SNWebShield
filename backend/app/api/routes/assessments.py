"""Assessment lifecycle API. Stage one enables permission preflight only."""
from datetime import datetime
from typing import Literal
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.security import get_current_admin
from app.core.time import as_utc
from app.db.session import get_db
from app.models.admin import Admin
from app.models.assessment import AssessmentRequest
from app.models.jobs import Job, JobResult, JobAttempt, ExecutionEvent, WorkerHeartbeat
from app.services import assessments as service

router = APIRouter(prefix="/assessments", tags=["Assessments"], dependencies=[Depends(get_current_admin)])


class CreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    website_id: int = Field(gt=0)
    authorization_id: int = Field(gt=0)
    profile_id: str = Field(min_length=1, max_length=80)
    idempotency_key: UUID
    explicitly_requested: Literal[True]
    note: str = Field(min_length=20, max_length=2000)


class Cancellation(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    reason: str = Field(min_length=10, max_length=1000)


def serial(row):
    return {c.name: as_utc(value).isoformat() if isinstance(value, datetime) else value
            for c in row.__table__.columns if c.name != "claim_token" for value in [getattr(row, c.name)]}


def read(db, row):
    job = db.get(Job, row.job_id)
    result = db.get(JobResult, row.job_id)
    return {**serial(row), "mode": "policy_only", "job": serial(job),
            "result": serial(result) if result else None}


@router.get("/profiles")
def profiles():
    return [{**p, "digest": service.digest(p)} for p in service.PROFILES.values()]


@router.get("/worker-status")
def worker_status(db: Session = Depends(get_db)):
    row = db.get(WorkerHeartbeat, "assessment-worker")
    return {"worker": serial(row) if row else None, "mode": "policy_only", "scanner_tools_enabled": False}


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
