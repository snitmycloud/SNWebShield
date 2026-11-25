"""Websites: add, list, verify ownership. Customers see only their own; staff can see all (read-only)."""
import secrets

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_current_account, get_current_admin
from app.core.time import as_utc, utc_now
from app.db.session import get_db
from app.models.admin import Admin
from app.models.scan import Scan
from app.models.website import Website
from app.schemas.website import RemoveRequest, VerifyRequest, WebsiteCreate
from app.services import job_engine as engine
from app.services import lifecycle, ownership, plans, scans
from app.services.domains import DomainError, normalize_domain

router = APIRouter(prefix="/websites", tags=["Websites"])


def _iso(value):
    return as_utc(value).isoformat() if value else None


def read_website(db: Session, website: Website, *, with_instructions=False) -> dict:
    latest = scans.latest_scan(db, website.id)
    data = {
        "id": website.id, "domain": website.domain, "name": website.name, "url": website.url,
        "owner_id": website.owner_id, "legacy": website.owner_id is None or website.domain is None,
        "verification_status": website.verification_status, "verification_method": website.verification_method,
        "verified_at": _iso(website.verified_at), "verification_checked_at": _iso(website.verification_checked_at),
        "verification_result": website.verification_result, "created_at": _iso(website.created_at),
        "removed_at": _iso(website.removed_at), "test_target": scans.is_test_target(website),
        "scans_paused": website.verification_status == "lost",
        "latest_scan": scans.serial(latest) if latest else None,
    }
    if with_instructions and website.verification_token and website.domain:
        data["verification_code"] = website.verification_token
        data["instructions"] = ownership.instructions(website)
    return data


def _visible(db: Session, account: Admin, website_id: int) -> Website:
    """The owner's website; staff may read any. Others get 404 so ids cannot be probed."""
    website = db.get(Website, website_id)
    if website is None or (website.owner_id != account.id and not account.is_staff):
        raise HTTPException(404, "Website not found")
    if website.removed_at is not None and not account.is_staff:
        raise HTTPException(404, "Website not found")
    return website


def _owned(db: Session, account: Admin, website_id: int) -> Website:
    """Only the owner may change a website or start work on it. A removed website no longer exists for them."""
    website = db.get(Website, website_id)
    if website is None or website.owner_id != account.id or website.removed_at is not None:
        raise HTTPException(404, "Website not found")
    return website


@router.post("", status_code=status.HTTP_201_CREATED)
def create_website(payload: WebsiteCreate, account: Admin = Depends(get_current_account), db: Session = Depends(get_db)):
    try:
        domain = normalize_domain(payload.domain)
    except DomainError as error:
        raise HTTPException(422, str(error)) from error
    test_target = domain in settings.approved_test_targets
    if test_target and account.role != "admin":
        # Approved test targets are for SNWebShield's own testing; they are never available to customers or analysts.
        raise HTTPException(403, "That address is reserved for SNWebShield's own testing and cannot be added.")
    plan = plans.get(account.plan)
    used = db.scalar(select(func.count()).select_from(Website).where(
        Website.owner_id == account.id, Website.removed_at.is_(None))) or 0
    if used >= plan["max_websites"]:
        raise plans.limit_reached(plan, "websites", plan["max_websites"])
    if db.scalar(select(Website.id).where(Website.owner_id == account.id, Website.domain == domain,
                                          Website.removed_at.is_(None))):
        raise HTTPException(409, f"You have already added {domain}.")
    website = Website(owner_id=account.id, client_id=None, domain=domain, name=domain, url=f"https://{domain}/",
                      environment="production", authorisation_status="retired",
                      verification_token=None if test_target else secrets.token_hex(16),
                      verification_status="unverified")
    db.add(website)
    try:
        db.flush()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(409, f"You have already added {domain}.") from error
    engine.event(db, "website_added", resource_id=website.id, actor_id=account.id,
                 detail={"domain": domain, "test_target": test_target})
    if test_target:
        now = utc_now()
        website.verification_status, website.verification_method = "verified", "test_target"
        website.verified_at = website.verification_checked_at = now
        website.verification_result = {"ok": True, "method": "test_target", "state": "verified", "expected": "", "found": [],
                                       "message": "Approved SNWebShield test target (admin accounts only).",
                                       "checked_at": now.isoformat()}
        engine.event(db, "ownership_verified", resource_id=website.id, actor_id=account.id,
                     detail={"method": "test_target", "domain": domain})
        try:
            scans.request_scan(db, website, "first")
        except HTTPException as limit:
            if limit.status_code != 429:  # the daily test-target limit may already be used; the website is still added
                raise
    parent = None if test_target else ownership.covering_website(db, website)
    if parent is not None:
        # example.com is already verified, so shop.example.com is covered and its first scan starts now.
        ownership.mark_covered(website, parent)
        engine.event(db, "ownership_verified", resource_id=website.id, actor_id=account.id,
                     detail={"method": "parent", "parent_domain": parent.domain})
        scans.request_scan(db, website, "first")
    db.commit()
    db.refresh(website)
    return read_website(db, website, with_instructions=True)


@router.get("")
def list_websites(
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    all_accounts: bool = Query(default=False, description="Staff only: include every account's websites"),
    account: Admin = Depends(get_current_account),
    db: Session = Depends(get_db),
):
    statement = select(Website).order_by(Website.id.desc())
    if not (all_accounts and account.is_staff):
        statement = statement.where(Website.owner_id == account.id, Website.removed_at.is_(None))
    rows = db.scalars(statement.offset(offset).limit(limit)).all()
    return [read_website(db, row) for row in rows]


@router.get("/{website_id}")
def get_website(website_id: int, account: Admin = Depends(get_current_account), db: Session = Depends(get_db)):
    website = _visible(db, account, website_id)
    return read_website(db, website, with_instructions=website.owner_id == account.id)


@router.post("/{website_id}/verify")
def verify_website(website_id: int, payload: VerifyRequest, account: Admin = Depends(get_current_account),
                   db: Session = Depends(get_db)):
    """Check ownership now with the chosen method. On success the first scan starts automatically."""
    website = _owned(db, account, website_id)
    if website.verification_method == "test_target":  # approved by the fixed list, nothing to prove
        return {"website": read_website(db, website), "check": website.verification_result, "scan": None}
    parent = ownership.covering_website(db, website)
    if parent is not None:
        ownership.mark_covered(website, parent)
        result = {**website.verification_result}
    else:
        check = ownership.run_check(website, payload.method)
        ownership.record(website, check)
        if not check.ok and website.verification_status == "verified" and website.verification_method == payload.method:
            # The owner re-checked the method that verified this site and the proof is gone.
            website.verification_status = "lost"
        result = website.verification_result
    engine.event(db, "ownership_check", resource_id=website.id, actor_id=account.id,
                 detail={"method": result.get("method"), "state": result.get("state")})
    scan = None
    if website.verification_status == "verified":
        if scans.latest_scan(db, website.id) is None:
            scan = scans.request_scan(db, website, "first")
    db.commit()
    db.refresh(website)
    return {"website": read_website(db, website, with_instructions=True), "check": result,
            "scan": scans.serial(scan) if scan else None}


@router.post("/{website_id}/remove")
def remove_website(website_id: int, payload: RemoveRequest, account: Admin = Depends(get_current_account),
                   db: Session = Depends(get_db)):
    """Remove a website from the account (owner only; the owner must type its domain).

    Clears its verification, deletes its queued scans and ends a running one, and frees a plan slot. Finished scan
    records, execution events and the audit log are kept, and the removal itself is written to the audit log.
    """
    website = _owned(db, account, website_id)
    if payload.confirm_domain.strip().lower().rstrip(".") != (website.domain or website.name).lower():
        raise HTTPException(422, f"To remove this website, type its domain exactly: {website.domain or website.name}")
    now = utc_now()
    was = website.verification_status
    stopped = scans.discard_for_removal(db, website)
    website.verification_status = "unverified"
    website.verification_method = None
    website.verification_token = None
    website.verification_result = None
    website.verified_at = None
    website.verification_checked_at = None
    website.removed_at = now
    engine.event(db, "website_removed", resource_id=website.id, actor_id=account.id, detail={
        "domain": website.domain, "user_id": account.id, "removed_at": now.isoformat(),
        "verification_was": was, **stopped})
    db.commit()
    return {"status": "removed", "domain": website.domain, **stopped,
            "message": f"{website.domain} was removed. Your past scan records are kept."}


@router.get("/{website_id}/scans")
def website_scans(website_id: int, limit: int = Query(default=20, ge=1, le=100),
                  account: Admin = Depends(get_current_account), db: Session = Depends(get_db)):
    website = _visible(db, account, website_id)
    rows = db.scalars(select(Scan).where(Scan.website_id == website.id).order_by(Scan.requested_at.desc()).limit(limit))
    return [scans.serial(row) for row in rows]


@router.get("/{website_id}/lifecycle")
def website_lifecycle(website_id: int, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    """Legacy (staff, read-only) monitor / detect / validate / protect summary. No network, no writes."""
    return lifecycle.website_lifecycle(db, admin.id, website_id)
