from datetime import UTC, datetime
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import get_current_admin
from app.db.session import get_db
from app.models.admin import Admin
from app.models.authorization import WebsiteAuthorization
from app.models.authorization_audit_event import AuthorizationAuditEvent
from app.models.website import Website
from app.schemas.authorization import AuthorizationCreate, AuthorizationRead
from app.schemas.authorization_review import (
    AuthorizationApprovalRequest,
    AuthorizationAuditEventRead,
    AuthorizationDecisionRequest,
)

router = APIRouter(prefix="/authorizations", tags=["Authorizations"])


def _as_utc(value: datetime) -> datetime:
    """SQLite may return naive datetimes; stored authorization timestamps are UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _get_authorization_or_404(db: Session, authorization_id: int) -> WebsiteAuthorization:
    authorization = db.get(WebsiteAuthorization, authorization_id)
    if authorization is None:
        raise HTTPException(status_code=404, detail="Authorization record not found")
    return authorization


def _sync_website_authorisation_status(
    db: Session, website_id: int, fallback_status: str
) -> None:
    website = db.get(Website, website_id)
    if website is None:
        return
    another_approved = db.scalar(
        select(WebsiteAuthorization.id)
        .where(
            WebsiteAuthorization.website_id == website_id,
            WebsiteAuthorization.status == "approved",
        )
        .limit(1)
    )
    website.authorisation_status = "approved" if another_approved is not None else fallback_status


@router.post("", response_model=AuthorizationRead, status_code=status.HTTP_201_CREATED)
def create_authorization(
    payload: AuthorizationCreate,
    db: Session = Depends(get_db),
    _admin: Admin = Depends(get_current_admin),
) -> WebsiteAuthorization:
    website = db.get(Website, payload.website_id)
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")

    registered_host = (urlsplit(website.url).hostname or "").lower().rstrip(".")
    if registered_host not in payload.authorized_domains:
        raise HTTPException(
            status_code=422,
            detail=(
                "authorized_domains must explicitly include the registered website hostname: "
                f"{registered_host}"
            ),
        )

    authorization = WebsiteAuthorization(**payload.model_dump(), status="pending")
    db.add(authorization)
    db.commit()
    db.refresh(authorization)
    return authorization


@router.get("", response_model=list[AuthorizationRead])
def list_authorizations(
    website_id: int | None = Query(default=None, gt=0),
    record_status: str | None = Query(
        default=None, alias="status", pattern="^(pending|approved|rejected|expired|revoked)$"
    ),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _admin: Admin = Depends(get_current_admin),
) -> list[WebsiteAuthorization]:
    statement = select(WebsiteAuthorization).order_by(WebsiteAuthorization.id.desc())
    if website_id is not None:
        statement = statement.where(WebsiteAuthorization.website_id == website_id)
    if record_status is not None:
        statement = statement.where(WebsiteAuthorization.status == record_status)
    statement = statement.offset(offset).limit(limit)
    return list(db.scalars(statement).all())


@router.get("/{authorization_id}/events", response_model=list[AuthorizationAuditEventRead])
def list_authorization_events(
    authorization_id: int,
    db: Session = Depends(get_db),
    _admin: Admin = Depends(get_current_admin),
) -> list[AuthorizationAuditEvent]:
    _get_authorization_or_404(db, authorization_id)
    statement = (
        select(AuthorizationAuditEvent)
        .where(AuthorizationAuditEvent.authorization_id == authorization_id)
        .order_by(AuthorizationAuditEvent.id.asc())
    )
    return list(db.scalars(statement).all())


@router.get("/{authorization_id}", response_model=AuthorizationRead)
def get_authorization(
    authorization_id: int,
    db: Session = Depends(get_db),
    _admin: Admin = Depends(get_current_admin),
) -> WebsiteAuthorization:
    return _get_authorization_or_404(db, authorization_id)


@router.post("/{authorization_id}/approve", response_model=AuthorizationRead)
def approve_authorization(
    authorization_id: int,
    payload: AuthorizationApprovalRequest,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin),
) -> WebsiteAuthorization:
    authorization = _get_authorization_or_404(db, authorization_id)
    if authorization.status != "pending":
        raise HTTPException(status_code=409, detail="Only pending authorizations can be approved")

    now = datetime.now(UTC)
    if _as_utc(authorization.valid_until) <= now:
        raise HTTPException(status_code=409, detail="Authorization validity period has expired")

    website = db.get(Website, authorization.website_id)
    if website is None:
        raise HTTPException(status_code=409, detail="Linked website no longer exists")
    registered_host = (urlsplit(website.url).hostname or "").lower().rstrip(".")
    if registered_host not in authorization.authorized_domains:
        raise HTTPException(status_code=409, detail="Authorization scope no longer matches the website")

    previous_status = authorization.status
    authorization.status = "approved"
    authorization.internal_review_notes = payload.review_note
    _sync_website_authorisation_status(db, authorization.website_id, "approved")
    db.add(
        AuthorizationAuditEvent(
            authorization_id=authorization.id,
            admin_id=current_admin.id,
            action="approved",
            previous_status=previous_status,
            new_status="approved",
            note=payload.review_note,
            evidence_reviewed=True,
        )
    )
    db.commit()
    db.refresh(authorization)
    return authorization


@router.post("/{authorization_id}/reject", response_model=AuthorizationRead)
def reject_authorization(
    authorization_id: int,
    payload: AuthorizationDecisionRequest,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin),
) -> WebsiteAuthorization:
    authorization = _get_authorization_or_404(db, authorization_id)
    if authorization.status != "pending":
        raise HTTPException(status_code=409, detail="Only pending authorizations can be rejected")

    previous_status = authorization.status
    authorization.status = "rejected"
    authorization.internal_review_notes = payload.reason
    _sync_website_authorisation_status(db, authorization.website_id, "rejected")
    db.add(
        AuthorizationAuditEvent(
            authorization_id=authorization.id,
            admin_id=current_admin.id,
            action="rejected",
            previous_status=previous_status,
            new_status="rejected",
            note=payload.reason,
            evidence_reviewed=False,
        )
    )
    db.commit()
    db.refresh(authorization)
    return authorization


@router.post("/{authorization_id}/revoke", response_model=AuthorizationRead)
def revoke_authorization(
    authorization_id: int,
    payload: AuthorizationDecisionRequest,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin),
) -> WebsiteAuthorization:
    authorization = _get_authorization_or_404(db, authorization_id)
    if authorization.status != "approved":
        raise HTTPException(status_code=409, detail="Only approved authorizations can be revoked")

    previous_status = authorization.status
    authorization.status = "revoked"
    authorization.internal_review_notes = payload.reason
    _sync_website_authorisation_status(db, authorization.website_id, "revoked")
    db.add(
        AuthorizationAuditEvent(
            authorization_id=authorization.id,
            admin_id=current_admin.id,
            action="revoked",
            previous_status=previous_status,
            new_status="revoked",
            note=payload.reason,
            evidence_reviewed=False,
        )
    )
    db.commit()
    db.refresh(authorization)
    return authorization
