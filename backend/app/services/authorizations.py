from datetime import datetime
from urllib.parse import urlsplit

from fastapi import HTTPException
from sqlalchemy import and_, case, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.core.time import as_utc, utc_now
from app.models.authorization import WebsiteAuthorization as Authorization
from app.models.authorization_audit_event import AuthorizationAuditEvent
from app.models.website import Website
from app.schemas.authorization import AuthorizationRead


def effective_status(record: Authorization, now: datetime) -> str:
    if record.status in {"rejected", "revoked", "expired"}:
        return record.status
    if not record.timestamps_verified:
        return "needs_date_review"
    if as_utc(record.valid_until) <= now:
        return "expired"
    if record.status == "pending":
        return "pending"
    return "scheduled" if as_utc(record.valid_from) > now else "active"


def effective_status_expression(now: datetime):
    """SQL equivalent used for filtering/counts before pagination."""
    return case(
        (Authorization.status.in_(["rejected", "revoked", "expired"]), Authorization.status),
        (Authorization.timestamps_verified.is_(False), "needs_date_review"),
        (Authorization.valid_until <= now, "expired"),
        (Authorization.status == "pending", "pending"),
        (Authorization.valid_from > now, "scheduled"),
        else_="active",
    )


def read_authorization(record: Authorization, now: datetime) -> AuthorizationRead:
    # Keep ambiguous legacy wall times timezone-free instead of claiming they are UTC.
    values = {field: getattr(record, field) for field in AuthorizationRead.model_fields
              if field != "effective_status"}
    if record.timestamps_verified:
        for field in ("valid_from", "valid_until"):
            values[field] = as_utc(values[field])
    return AuthorizationRead(**values, effective_status=effective_status(record, now))


def get_authorization(db: Session, authorization_id: int) -> Authorization:
    record = db.get(Authorization, authorization_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Authorization record not found")
    return record


def website_statuses(db: Session, website_ids: list[int], now: datetime) -> dict[int, str]:
    """Current validity, never a persisted website approval flag.

    Prefer a currently valid approval, then a scheduled approval, then a pending
    review. Other outcomes use the newest record. Unverified legacy windows do
    not override a verified current approval and never grant current validity.
    """
    grouped: dict[int, list[Authorization]] = {key: [] for key in website_ids}
    if not website_ids:
        return {}
    for record in db.scalars(select(Authorization).where(
        Authorization.website_id.in_(website_ids)
    ).order_by(Authorization.id.desc())):
        grouped[record.website_id].append(record)
    result = {}
    for website_id, records in grouped.items():
        states = [effective_status(record, now) for record in records]
        result[website_id] = next(
            (state for state in ["active", "scheduled", "pending", "needs_date_review"] if state in states),
            states[0] if states else "not_requested",
        )
    return result


def decide_authorization(
    db: Session, authorization_id: int, admin_id: int, action: str, note: str,
    *, now: datetime | None = None,
) -> Authorization:
    now = as_utc(now) if now is not None else utc_now()
    expected = "approved" if action == "revoked" else "pending"
    try:
        record = get_authorization(db, authorization_id)
        if record.status != expected:
            raise HTTPException(status_code=409, detail=f"Only {expected} authorizations can be {action}")
        predicates = [Authorization.id == authorization_id, Authorization.status == expected]
        if action == "approved":
            if not record.timestamps_verified:
                raise HTTPException(status_code=409, detail=(
                    "Legacy authorization dates need review. Create a replacement record from the original written permission."
                ))
            if as_utc(record.valid_until) <= now:
                raise HTTPException(status_code=409, detail="Authorization validity period has expired")
            if as_utc(record.valid_until) <= as_utc(record.valid_from):
                raise HTTPException(status_code=409, detail="Invalid authorization validity period")
            website = db.get(Website, record.website_id)
            if website is None:
                raise HTTPException(status_code=409, detail="Linked website no longer exists")
            host = (urlsplit(website.url).hostname or "").lower().rstrip(".")
            if host not in record.authorized_domains:
                raise HTTPException(status_code=409, detail="Authorization scope no longer matches the website")
            predicates.extend([
                Authorization.timestamps_verified.is_(True),
                Authorization.valid_until > now,
                Authorization.valid_until > Authorization.valid_from,
            ])

        accepted_review_id = None
        if action == "approved":
            from app.services.evidence import accepted_review
            accepted_review_id = accepted_review(db, record, admin_id).id
            predicates.append(Authorization.evidence_revision == record.evidence_revision)

        # Compare-and-set is the concurrency boundary, including on SQLite.
        # UPDATE plus INSERT are in the same transaction; a failed event flush
        # rolls the decision back. No cached website flag is used for validity.
        changed = db.execute(update(Authorization).where(and_(*predicates)).values(
            status=action, internal_review_notes=note, updated_at=now
        ).execution_options(synchronize_session=False))
        if changed.rowcount != 1:
            raise HTTPException(status_code=409, detail="Authorization changed; refresh before making another decision")
        db.add(AuthorizationAuditEvent(
            authorization_id=authorization_id, admin_id=admin_id, action=action,
            evidence_review_id=accepted_review_id,
            previous_status=expected, new_status=action, note=note,
            evidence_reviewed=action == "approved", created_at=now,
        ))
        db.commit()
        db.refresh(record)
        return record
    except OperationalError as exc:
        db.rollback()
        # SQLite may reject a competing snapshot upgrade before the CAS runs.
        if db.bind.dialect.name == "sqlite" and "locked" in str(exc).lower():
            raise HTTPException(status_code=409, detail="Authorization is being updated; refresh and retry") from exc
        raise
    except Exception:
        db.rollback()
        raise
