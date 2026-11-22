from datetime import timedelta
from pathlib import Path
from urllib.parse import unquote, quote
from uuid import uuid4
from hashlib import sha256
import os

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.core.config import settings
from app.core.security import get_current_admin
from app.core.time import as_utc, utc_now
from app.db.session import get_db
from app.models.admin import Admin
from app.models.website import Website
from app.models.evidence import AuthorizationEvidence, EvidenceEvent, EvidenceReview
from app.services.authorizations import get_authorization
from app.services import evidence as service

router = APIRouter(tags=["Authorization evidence"], dependencies=[Depends(get_current_admin)])


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    revision: int = Field(ge=0)
    decision: Literal["accepted", "rejected"]
    inspected: Literal[True]
    comment: str = Field(min_length=20, max_length=2000)


class Reason(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    reason: str = Field(min_length=10, max_length=2000)


class HoldRequest(Reason):
    legal_hold: bool


def metadata(row):
    return {key: (as_utc(value).isoformat() if key in {"uploaded_at", "retain_until", "reviewed_at", "occurred_at"} else value)
            for key, value in {column.name: getattr(row, column.name) for column in row.__table__.columns}.items()}


def get_document(db, key):
    service.stored_path(key)  # UUID syntax check; never accept caller paths.
    row = db.get(AuthorizationEvidence, key)
    if row is None: raise HTTPException(404, "Evidence not found")
    return row


@router.get("/authorizations/{authorization_id}/evidence")
def listing(authorization_id: int, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    record = get_authorization(db, authorization_id)
    rows = db.scalars(select(AuthorizationEvidence).where(AuthorizationEvidence.authorization_id == record.id).order_by(AuthorizationEvidence.uploaded_at))
    reviews = db.scalars(select(EvidenceReview).where(EvidenceReview.authorization_id == record.id).order_by(EvidenceReview.reviewed_at.desc()))
    return {"revision": record.evidence_revision, "documents": [metadata(row) for row in rows], "reviews": [metadata(row) for row in reviews]}


@router.post("/authorizations/{authorization_id}/evidence", status_code=201)
async def upload(authorization_id: int, request: Request, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    record = get_authorization(db, authorization_id)
    if record.status != "pending": raise HTTPException(409, "Upload evidence only to pending authorizations")
    filename = unquote(request.headers.get("X-Evidence-Filename", ""))
    if not filename or len(filename) > 180 or any(c in filename for c in '/\\\r\n\x00') or any(ord(c) < 32 for c in filename):
        raise HTTPException(422, "Use a simple document filename without paths")
    if Path(filename).suffix.lower() not in {".pdf", ".png", ".jpg", ".jpeg"}:
        raise HTTPException(422, "Only PDF, PNG and JPEG are allowed")
    key = str(uuid4()); path = service.stored_path(key); size = 0; digest = sha256(); committed = False; created = False
    try:
        with path.open("xb") as file:
            created = True
            os.chmod(path, 0o600)
            async for chunk in request.stream():
                size += len(chunk)
                if size > settings.evidence_max_bytes: raise HTTPException(413, "Document exceeds the configured size limit")
                file.write(chunk); digest.update(chunk)
        if not size: raise HTTPException(422, "The document is empty")
        media = await run_in_threadpool(service.validate_file, path, filename)
        service.lock_revision(db, record, increment=True)
        website = db.get(Website, record.website_id)
        if website is None: raise HTTPException(409, "Linked website is unavailable")
        now = utc_now()
        row = AuthorizationEvidence(id=key, authorization_id=record.id, website_id=website.id,
            client_id=website.client_id, filename=filename, media_type=media, size=size,
            sha256=digest.hexdigest(), uploader_id=admin.id, uploaded_at=now,
            retain_until=max(now, as_utc(record.valid_until)) + timedelta(days=settings.evidence_retention_days),
            state="available", legal_hold=False)
        db.add(row); db.flush()
        service.event(db, record.id, admin.id, "uploaded", key)
        db.commit(); committed = True; db.refresh(row)
        return metadata(row)
    except Exception:
        db.rollback()
        if created and not committed: path.unlink(missing_ok=True)
        raise


@router.get("/authorizations/{authorization_id}/evidence/events")
def history(authorization_id: int, db: Session = Depends(get_db)):
    get_authorization(db, authorization_id)
    return [metadata(row) for row in db.scalars(select(EvidenceEvent).where(
        EvidenceEvent.authorization_id == authorization_id).order_by(EvidenceEvent.occurred_at, EvidenceEvent.id))]


@router.get("/evidence/{key}/{operation}")
def retrieve(key: str, operation: Literal["download", "preview"], db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    row = get_document(db, key)
    if row.state != "available": raise HTTPException(410, "Evidence is withdrawn or deleted")
    content = service.verified_bytes(row)
    media = row.media_type
    if operation == "preview":
        if media == "application/pdf": raise HTTPException(422, "Download the PDF for inspection; inline PDF preview is disabled")
        content = service.image_preview(content); media = "image/png"
    service.event(db, row.authorization_id, admin.id, "opened", key, operation)
    db.commit()
    return Response(content, media_type=media, headers={
        "Content-Disposition": "attachment; filename*=UTF-8''" + quote(row.filename if operation == "download" else key + ".png", safe=""),
        "Cache-Control": "no-store, private", "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; sandbox",
    })


@router.post("/authorizations/{authorization_id}/evidence/reviews", status_code=201)
def review(authorization_id: int, payload: ReviewRequest, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    record = get_authorization(db, authorization_id)
    if record.evidence_revision != payload.revision: raise HTTPException(409, "Evidence changed; inspect the current revision")
    service.lock_revision(db, record, increment=True)
    documents = service.available(db, record.id)
    if not documents: raise HTTPException(409, "Upload a document before reviewing")
    for document in documents:
        service.verified_bytes(document)
        opened = db.scalar(select(EvidenceEvent.id).where(EvidenceEvent.evidence_id == document.id,
            EvidenceEvent.actor_id == admin.id, EvidenceEvent.action == "opened").limit(1))
        if not opened: raise HTTPException(409, "Open every current document before recording a human review")
    row = EvidenceReview(id=str(uuid4()), authorization_id=record.id, revision=record.evidence_revision + 1,
        evidence_ids=[d.id for d in documents], reviewer_id=admin.id, reviewed_at=utc_now(),
        decision=payload.decision, comment=payload.comment)
    db.add(row); service.event(db, record.id, admin.id, "review_" + payload.decision, comment=payload.comment)
    db.commit(); return metadata(row)


@router.post("/evidence/{key}/withdraw")
def withdraw(key: str, payload: Reason, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    row = get_document(db, key); record = get_authorization(db, row.authorization_id)
    if row.state != "available": raise HTTPException(409, "Document is already unavailable")
    if record.status == "approved": raise HTTPException(409, "Revoke approval before withdrawing its supporting evidence")
    service.lock_revision(db, record, increment=True, pending=False)
    row.state = "withdrawn"
    service.event(db, record.id, admin.id, "withdrawn", key, payload.reason)
    db.commit(); return metadata(row)


@router.post("/evidence/{key}/hold")
def hold(key: str, payload: HoldRequest, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    row = get_document(db, key); record = get_authorization(db, row.authorization_id)
    service.lock_revision(db, record, pending=False)
    if row.state in {"purged", "deletion_pending"}: raise HTTPException(409, "Deletion has already started")
    row.legal_hold = payload.legal_hold
    service.event(db, record.id, admin.id, "hold_changed", key, payload.reason + f"; legal_hold={payload.legal_hold}")
    db.commit(); return metadata(row)


@router.post("/evidence/{key}/purge")
def purge(key: str, payload: Reason, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    row = get_document(db, key); record = get_authorization(db, row.authorization_id)
    service.lock_revision(db, record, pending=False)
    if row.state == "purged": return metadata(row)
    if row.legal_hold or record.status == "approved" or as_utc(row.retain_until) > utc_now():
        raise HTTPException(409, "Retention, legal hold or an approved authorization prevents deletion")
    if row.state not in {"withdrawn", "deletion_pending"}: raise HTTPException(409, "Withdraw the document first")
    row.state = "deletion_pending"
    service.event(db, record.id, admin.id, "purge_requested", key, payload.reason); db.commit()
    path = service.stored_path(key)
    if path.is_symlink(): raise HTTPException(409, "Storage integrity error")
    path.unlink(missing_ok=True)
    row.state = "purged"; service.event(db, record.id, admin.id, "purged", key, payload.reason)
    db.commit(); return metadata(row)
