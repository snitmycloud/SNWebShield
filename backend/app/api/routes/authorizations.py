from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import get_current_admin
from app.db.session import get_db
from app.models.admin import Admin
from app.models.authorization import WebsiteAuthorization
from app.models.authorization_audit_event import AuthorizationAuditEvent
from app.core.time import utc_now
from app.services.authorizations import (
    decide_authorization, effective_status_expression, get_authorization as get_record,
    read_authorization,
)
from app.models.website import Website
from app.schemas.authorization import (
    AuthorizationCreate, AuthorizationRead, AuthorizationSummary, EffectiveAuthorizationStatus,
)
from app.schemas.authorization_review import (
    AuthorizationApprovalRequest,
    AuthorizationAuditEventRead,
    AuthorizationDecisionRequest,
)

router = APIRouter(prefix="/authorizations", tags=["Authorizations"])


@router.post("", response_model=AuthorizationRead, status_code=status.HTTP_201_CREATED)
def create_authorization(
    payload: AuthorizationCreate,
    db: Session = Depends(get_db),
    _admin: Admin = Depends(get_current_admin),
) -> AuthorizationRead:
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

    authorization = WebsiteAuthorization(**payload.model_dump(), status="pending", timestamps_verified=True)
    db.add(authorization)
    db.commit()
    db.refresh(authorization)
    return read_authorization(authorization, utc_now())


@router.get("", response_model=list[AuthorizationRead])
def list_authorizations(
    website_id: int | None = Query(default=None, gt=0),
    record_status: str | None = Query(
        default=None, alias="status", pattern="^(pending|approved|rejected|expired|revoked)$"
    ),
    effective_status: EffectiveAuthorizationStatus | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _admin: Admin = Depends(get_current_admin),
) -> list[AuthorizationRead]:
    now = utc_now()
    statement = select(WebsiteAuthorization).order_by(WebsiteAuthorization.id.desc())
    if website_id is not None:
        statement = statement.where(WebsiteAuthorization.website_id == website_id)
    if record_status is not None:
        statement = statement.where(WebsiteAuthorization.status == record_status)
    if effective_status is not None:
        statement = statement.where(effective_status_expression(now) == effective_status)
    statement = statement.offset(offset).limit(limit)
    return [read_authorization(row, now) for row in db.scalars(statement)]


@router.get("/summary", response_model=AuthorizationSummary)
def authorization_summary(
    website_id: int | None = Query(default=None, gt=0),
    db: Session = Depends(get_db),
    _admin: Admin = Depends(get_current_admin),
) -> AuthorizationSummary:
    now = utc_now()
    predicate = [] if website_id is None else [WebsiteAuthorization.website_id == website_id]
    state = effective_status_expression(now)
    decisions, effective = {}, {}
    # One grouped query gives both totals from the same database snapshot.
    for decision, current, count in db.execute(select(
        WebsiteAuthorization.status, state, func.count()
    ).where(*predicate).group_by(WebsiteAuthorization.status, state)):
        decisions[decision] = decisions.get(decision, 0) + count
        effective[current] = effective.get(current, 0) + count
    return AuthorizationSummary(
        as_of=now, total=sum(decisions.values()),
        decision_counts={key: decisions.get(key, 0) for key in ["pending", "approved", "rejected", "revoked", "expired"]},
        effective_counts={key: effective.get(key, 0) for key in [
            "pending", "active", "scheduled", "expired", "rejected", "revoked", "needs_date_review"
        ]},
    )


@router.get("/{authorization_id}/events", response_model=list[AuthorizationAuditEventRead])
def list_authorization_events(
    authorization_id: int,
    db: Session = Depends(get_db),
    _admin: Admin = Depends(get_current_admin),
) -> list[AuthorizationAuditEvent]:
    get_record(db, authorization_id)
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
) -> AuthorizationRead:
    return read_authorization(get_record(db, authorization_id), utc_now())


@router.post("/{authorization_id}/approve", response_model=AuthorizationRead)
def approve_authorization(
    authorization_id: int,
    payload: AuthorizationApprovalRequest,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin),
) -> AuthorizationRead:
    record = decide_authorization(
        db, authorization_id, current_admin.id, "approved", payload.review_note
    )
    return read_authorization(record, utc_now())


@router.post("/{authorization_id}/reject", response_model=AuthorizationRead)
def reject_authorization(
    authorization_id: int,
    payload: AuthorizationDecisionRequest,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin),
) -> AuthorizationRead:
    record = decide_authorization(
        db, authorization_id, current_admin.id, "rejected", payload.reason
    )
    return read_authorization(record, utc_now())


@router.post("/{authorization_id}/revoke", response_model=AuthorizationRead)
def revoke_authorization(
    authorization_id: int,
    payload: AuthorizationDecisionRequest,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin),
) -> AuthorizationRead:
    record = decide_authorization(
        db, authorization_id, current_admin.id, "revoked", payload.reason
    )
    return read_authorization(record, utc_now())
