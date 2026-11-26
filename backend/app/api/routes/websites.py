"""Websites: add, list, verify ownership. Customers see only their own; staff can see all (read-only)."""
import secrets

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_current_account, get_current_admin
from app.core.time import as_utc, utc_now
from app.db.session import get_db
from app.models.admin import Admin
from app.models.scan import Scan, ScanFinding, ScanObservation, ScanPort, ScanTechnology
from app.models.website import Website
from app.schemas.website import AcceptRiskRequest, ManualVerifyRequest, RemoveRequest, ScanRequest, VerifyRequest, WebsiteCreate
from app.services import job_engine as engine
from app.services import comparison, finding_states, lifecycle, ownership, plans, scans, scoring
from app.services.domains import DomainError, normalize_domain

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
router = APIRouter(prefix="/websites", tags=["Websites"])


def _iso(value):
    return as_utc(value).isoformat() if value else None


def scan_summary(db: Session, scan: Scan | None) -> dict | None:
    """Score, grade, counts by severity, certificate expiry, CDN and notes of one finished (or stopped) scan."""
    if scan is None or scan.status not in ("completed", "incomplete"):
        return None
    rows = db.execute(select(ScanFinding.severity, ScanFinding.confidence, ScanFinding.group, ScanFinding.fingerprint)
                      .where(ScanFinding.scan_id == scan.id)).all()
    result = scan.result or {}
    # Fixed and accepted findings stay listed but are not counted - only on the website's latest scan (older scans stay as they were).
    states = {}
    if scan.scan_type != "recheck" and (latest := scans.latest_scan(db, scan.website_id)) is not None and latest.id == scan.id:
        states = finding_states.states_for(db, scan.website_id)
    now = utc_now()

    def set_aside(item):
        state = states.get(item["fingerprint"])
        return bool(state and (state.status == "fixed" or finding_states.accepted_active(state, now)))
    summary = scoring.summarize([{"severity": r[0], "confidence": r[1], "group": r[2], "fingerprint": r[3]} for r in rows],
                                incomplete=scan.status == "incomplete", excluded=set_aside)
    summary["accepted"] = sum(1 for r in rows if finding_states.accepted_active(states.get(r[3]), now))
    summary["fixed"] = sum(1 for r in rows if (states.get(r[3]) is not None and states[r[3]].status == "fixed"))
    summary["changes"] = comparison.compare(db, scan)["counts"] if scan.status in ("completed", "incomplete") else None
    certificate = None
    for port in db.scalars(select(ScanPort).where(ScanPort.scan_id == scan.id)):
        cert = ((port.details or {}).get("tls") or {}).get("certificate") or {}
        try:
            expires = as_utc(datetime.fromisoformat(cert.get("not_after")))
        except (TypeError, ValueError):
            continue
        days = (expires - utc_now()).days
        if certificate is None or days < certificate["days_left"]:
            certificate = {"port": port.port, "expires_at": expires.isoformat(), "days_left": days, "subject": cert.get("subject_cn")}
    summary.update(scan_id=scan.id, scanned_at=_iso(scan.ended_at or scan.requested_at), certificate=certificate,
                   cdn=result.get("cdn"), notes=result.get("notes") or [])
    return summary


def read_website(db: Session, website: Website, *, with_instructions=False, account: Admin | None = None) -> dict:
    if ownership.expire_manual(website):   # a manual verification lasts 24 hours, then scans pause
        db.commit()
    if finding_states.expire_due(db, website_id=website.id):   # accepted risks that ran out go back to Open
        db.commit()
    latest = scans.latest_scan(db, website.id)
    data = {
        "id": website.id, "domain": website.domain, "name": website.name, "url": website.url,
        "owner_id": website.owner_id, "legacy": website.owner_id is None or website.domain is None,
        "verification_status": website.verification_status, "verification_method": website.verification_method,
        "verified_at": _iso(website.verified_at), "verification_checked_at": _iso(website.verification_checked_at),
        "verification_result": website.verification_result, "created_at": _iso(website.created_at),
        "removed_at": _iso(website.removed_at), "test_target": scans.is_test_target(website),
        "scans_paused": website.verification_status == "lost",
        "manual_verification": ({"label": ownership.MANUAL_LABEL, "reason": (website.verification_result or {}).get("reason"),
                                 "granted_by": (website.verification_result or {}).get("granted_by"),
                                 "granted_at": (website.verification_result or {}).get("granted_at"),
                                 "expires_at": (website.verification_result or {}).get("expires_at")}
                                if website.verification_method == "manual" and website.verification_status == "verified" else None),
        "can_verify_manually": bool(account is not None and account.role == "admin" and website.owner_id is not None
                                    and website.removed_at is None and website.verification_method != "test_target"
                                    and website.verification_status != "verified"),
        "latest_scan": scans.serial(latest) if latest else None,
        "summary": scan_summary(db, latest),
    }
    if (account is not None and account.id == website.owner_id and website.removed_at is None
            and website.verification_status == "verified"):
        data["scan_now"] = scans.scan_now_status(db, website, account)  # what the Scan now button shows
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
    return read_website(db, website, with_instructions=True, account=account)


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
    return [read_website(db, row, account=account) for row in rows]


@router.get("/{website_id}")
def get_website(website_id: int, account: Admin = Depends(get_current_account), db: Session = Depends(get_db)):
    website = _visible(db, account, website_id)
    return read_website(db, website, with_instructions=website.owner_id == account.id, account=account)


@router.post("/{website_id}/verify")
def verify_website(website_id: int, payload: VerifyRequest, account: Admin = Depends(get_current_account),
                   db: Session = Depends(get_db)):
    """Check ownership now with the chosen method. On success the first scan starts automatically."""
    website = _owned(db, account, website_id)
    if website.verification_method == "test_target":  # approved by the fixed list, nothing to prove
        return {"website": read_website(db, website, account=account), "check": website.verification_result, "scan": None}
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
    return {"website": read_website(db, website, with_instructions=True, account=account), "check": result,
            "scan": scans.serial(scan) if scan else None}


@router.post("/{website_id}/verify-manual")
def verify_manually(website_id: int, payload: ManualVerifyRequest, account: Admin = Depends(get_current_account),
                    db: Session = Depends(get_db)):
    """ADMIN ONLY (demo backup): mark a website verified by hand for 24 hours. Needs a typed reason and is audit-logged.

    Normal users get 403 whatever they send. A website that is already verified by DNS, file or meta is never downgraded.
    """
    if account.role != "admin" or not account.is_active:
        raise HTTPException(403, "Only an administrator can verify a website manually.")
    website = db.get(Website, website_id)
    if website is None or website.removed_at is not None or website.owner_id is None or not website.domain:
        raise HTTPException(404, "Website not found")
    if website.verification_method == "test_target":
        raise HTTPException(409, "This is an approved test target; it needs no verification.")
    ownership.expire_manual(website)
    if website.verification_status == "verified" and website.verification_method != "manual":
        raise HTTPException(409, "This website is already verified.")
    result = ownership.grant_manual(website, account, payload.reason)
    engine.event(db, "manual_verification", resource_id=website.id, actor_id=account.id, detail={
        "admin_id": account.id, "admin": account.email, "domain": website.domain, "owner_id": website.owner_id, "reason": result["reason"],
        "granted_at": result["granted_at"], "expires_at": result["expires_at"]})
    scan = None
    if scans.latest_scan(db, website.id) is None:
        scan = scans.request_scan(db, website, "first")
    db.commit()
    db.refresh(website)
    return {"website": read_website(db, website, with_instructions=website.owner_id == account.id, account=account), "check": result,
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


@router.post("/{website_id}/scan")
def scan_now(website_id: int, payload: ScanRequest, account: Admin = Depends(get_current_account),
             db: Session = Depends(get_db)):
    """The Scan now button. Owner only. Limits (per website or per account, per day) come from plans.json; a test
    target also has its own stricter limit. Asking while a scan is running returns that scan and uses nothing up."""
    website = _owned(db, account, website_id)
    scan, status, already_running = scans.request_manual_scan(db, website, account, payload.scan_type)
    db.commit()
    return {"scan": scans.serial(scan), "scan_now": status, "already_running": already_running}


@router.get("/{website_id}/scans/{scan_id}")
def scan_detail(website_id: int, scan_id: str, account: Admin = Depends(get_current_account),
                db: Session = Depends(get_db)):
    """One scan with everything it found. Partial results of an incomplete scan are included and marked by its status."""
    website = _visible(db, account, website_id)
    scan = db.get(Scan, scan_id)
    if scan is None or scan.website_id != website.id:
        raise HTTPException(404, "Scan not found")
    ports = db.scalars(select(ScanPort).where(ScanPort.scan_id == scan.id).order_by(ScanPort.port)).all()
    technologies = db.scalars(select(ScanTechnology).where(ScanTechnology.scan_id == scan.id)
                              .order_by(ScanTechnology.name)).all()
    observations = db.scalars(select(ScanObservation).where(ScanObservation.scan_id == scan.id)
                              .order_by(ScanObservation.kind, ScanObservation.key)).all()
    stored = db.scalars(select(ScanFinding).where(ScanFinding.scan_id == scan.id)).all()
    if finding_states.expire_due(db, website_id=website.id):
        db.commit()
    latest = scans.latest_scan(db, website.id)
    is_latest = latest is not None and latest.id == scan.id
    states = finding_states.states_for(db, website.id) if is_latest else {}
    now = utc_now()
    findings = sorted(({"id": f.id, "fingerprint": f.fingerprint, "kind": f.kind, "check_id": f.check_id, "title": f.title,
                        "location": f.location, "port": f.port, "severity": f.severity, "confidence": f.confidence, "group": f.group,
                        "scored": f.confidence == "confirmed" and f.severity != "info" and (f.fingerprint not in states or finding_states.view(states[f.fingerprint], now)["status"] == "open"),
                        "state": finding_states.view(states.get(f.fingerprint), now) if is_latest else {"status": "open"},
                        "recheckable": is_latest and finding_states.recheckable(f.check_id), "you_have": f.you_have,
                        "you_should_have": f.you_should_have, "cve_id": f.cve_id, "cvss_score": f.cvss_score,
                        "cvss_vector": f.cvss_vector, "affected_range": f.affected_range, "first_fixed": f.first_fixed,
                        "why": f.why, "how_to_fix": f.how_to_fix, "evidence": f.evidence, "caveat": f.caveat,
                        "sources": f.sources or [], "details": f.details or {}} for f in stored),
                      key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["group"] != "findings", -(f["cvss_score"] or 0), f["title"]))
    return {
        "scan": scans.serial(scan), "domain": website.domain, "findings": findings, "summary": scan_summary(db, scan), "test_target": scans.is_test_target(website),
        "ports": [{"port": p.port, "state": p.state, "service": p.service, "product": p.product, "version": p.version,
                   "banner": p.banner, **{k: (p.details or {}).get(k) for k in ("tls", "http", "service_guess", "notes")}}
                  for p in ports],
        "technologies": [{"name": t.name, "category": t.category, "version": t.version, "source": t.source,
                          "evidence": t.evidence, "port": t.port} for t in technologies],
        "dns": [{"key": o.key, "status": o.status, "data": o.data} for o in observations if o.kind == "dns"],
        "exposed": [{"path": o.key, "status": o.status, **(o.data or {})} for o in observations if o.kind == "exposed_file"],
        "subdomains": [o.key for o in observations if o.kind == "subdomain"],
    }


@router.get("/{website_id}/scans")
def website_scans(website_id: int, limit: int = Query(default=20, ge=1, le=100),
                  account: Admin = Depends(get_current_account), db: Session = Depends(get_db)):
    website = _visible(db, account, website_id)
    rows = db.scalars(select(Scan).where(Scan.website_id == website.id, Scan.scan_type != "recheck").order_by(Scan.requested_at.desc()).limit(limit))
    return [scans.serial(row) for row in rows]


@router.get("/{website_id}/scans/{scan_id}/comparison")
def scan_comparison(website_id: int, scan_id: str, account: Admin = Depends(get_current_account), db: Session = Depends(get_db)):
    """What is new, fixed and unchanged compared with the scan before this one."""
    website = _visible(db, account, website_id)
    scan = db.get(Scan, scan_id)
    if scan is None or scan.website_id != website.id:
        raise HTTPException(404, "Scan not found")
    return comparison.compare(db, scan)


def _state_error(error: finding_states.StateError):
    status_code = 403 if error.code == "not_owner" else 404 if error.code == "finding_not_found" else 422 if error.code in ("bad_reason", "bad_days") else 409
    return HTTPException(status_code, {"code": error.code, "message": error.message})


@router.post("/{website_id}/findings/{fingerprint}/accept")
def accept_risk(website_id: int, fingerprint: str, payload: AcceptRiskRequest, account: Admin = Depends(get_current_account),
                db: Session = Depends(get_db)):
    """Accept a risk with a typed reason for 30, 90, 180 or 365 days. Owner only (staff and analysts cannot)."""
    website = _owned(db, account, website_id)
    try:
        state = finding_states.accept(db, website, account, fingerprint, payload.reason, payload.days)
    except finding_states.StateError as error:
        raise _state_error(error) from error
    db.commit()
    return finding_states.view(state)


@router.delete("/{website_id}/findings/{fingerprint}/accept")
def stop_accepting_risk(website_id: int, fingerprint: str, account: Admin = Depends(get_current_account), db: Session = Depends(get_db)):
    website = _owned(db, account, website_id)
    try:
        state = finding_states.unaccept(db, website, account, fingerprint)
    except finding_states.StateError as error:
        raise _state_error(error) from error
    db.commit()
    return finding_states.view(state)


@router.post("/{website_id}/findings/{fingerprint}/recheck")
def recheck_finding(website_id: int, fingerprint: str, account: Admin = Depends(get_current_account), db: Session = Depends(get_db)):
    """Re-scan to confirm a fix: queues a short scan of this one finding. Owner only; uses the separate re-check allowance."""
    website = _owned(db, account, website_id)
    scan, _ = scans.request_recheck(db, website, account, fingerprint)
    db.commit()
    return {"scan": scans.serial(scan)}


@router.get("/{website_id}/lifecycle")
def website_lifecycle(website_id: int, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    """Legacy (staff, read-only) monitor / detect / validate / protect summary. No network, no writes."""
    return lifecycle.website_lifecycle(db, admin.id, website_id)
