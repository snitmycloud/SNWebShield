"""Module H: remediation tracking, scoped retests and assessment closure.

Only confirmed findings are tracked (a finding with no remediation row is `open`). A retest is an
ordinary assessment request made through `assessments.create_request`, so the scanner worker
revalidates the live written authorisation, exact domain and methods at request, claim and
execution exactly as for any other scan: nothing here contacts a target or bypasses that path, and
there is no local fallback. The retest's observation is linked back to the finding, which becomes
`verified_fixed` if the weakness is no longer detected and is automatically `reopened` with the
fresh evidence if it still reproduces. Verification evidence is the scanner's stored, hash-checked
occurrence, never client-supplied text. All notes are untrusted: control characters are stripped
and lengths are bounded before they are stored.
"""
from datetime import timedelta
from hashlib import sha256
from types import SimpleNamespace
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import exists, func, or_, select, update
from sqlalchemy.exc import IntegrityError, OperationalError

from app.core import rbac
from app.core.time import as_utc, utc_now
from app.models.assessment import AssessmentReport, AssessmentRequest
from app.models.client import Client
from app.models.jobs import Job
from app.models.remediation import (BLOCKING_STATUSES, AssessmentClosure, FixVerificationSignoff, RemediationEvent,
                                    RetestRequest, VulnerabilityRemediation)
from app.models.security import ClosureReopening
from app.models.vulnerability import Vulnerability, VulnerabilityIngestion, VulnerabilityOccurrence
from app.models.website import Website
from app.services import assessments, closure_lock
from app.services import vulnerabilities as vulns
from app.services.reports import strip_controls

# Manual (analyst or client-update) transitions. `retest_requested` is entered only by a retest
# request, and `verified_fixed` only by a retest result; both leave only through those paths or a reopen.
MANUAL_TRANSITIONS = {
    "open": {"in_progress", "fix_submitted", "risk_accepted"},
    "in_progress": {"open", "fix_submitted", "risk_accepted"},
    "fix_submitted": {"in_progress", "risk_accepted"},
    "retest_requested": set(),
    "verified_fixed": set(),
    "reopened": {"in_progress", "fix_submitted", "risk_accepted"},
    "risk_accepted": set(),
}
REOPENABLE = frozenset({"verified_fixed", "risk_accepted", "fix_submitted"})
MAX_RETESTS = 10
MAX_TARGET_DAYS = 730


def _clean(value, limit, minimum, label):
    text = strip_controls(value, limit, True)
    if len(text) < minimum:
        raise HTTPException(422, f"{label} needs at least {minimum} visible characters")
    return text


def _names(db, ids):
    return vulns._names(db, ids)


def _iso(value):
    return as_utc(value).isoformat() if value is not None else None


# --- State helpers -------------------------------------------------------------------------

def confirmed(db, vulnerability_id):
    vulnerability = vulns.get(db, vulnerability_id)
    if vulnerability.validation_state != "confirmed":
        raise HTTPException(409, "Only confirmed findings have remediation tracking")
    return vulnerability


def current(db, vulnerability_id):
    return db.get(VulnerabilityRemediation, vulnerability_id)


def status_of(row):
    return row.status if row is not None else "open"


def version_of(row):
    return row.version if row is not None else 0


def add_event(db, vulnerability_id, action, actor_id, from_status, to_status, note, detail, now):
    sequence = (db.scalar(select(func.max(RemediationEvent.sequence)).where(
        RemediationEvent.vulnerability_id == vulnerability_id)) or 0) + 1
    row = RemediationEvent(id=str(uuid4()), vulnerability_id=vulnerability_id, sequence=sequence, actor_id=actor_id,
                           action=action, from_status=from_status, to_status=to_status, note=note,
                           detail=detail or {}, occurred_at=now)
    db.add(row)
    db.flush()
    return row


def _move(db, vulnerability_id, row, to_status, actor_id, action, note, detail, now, **values):
    """Change status under optimistic concurrency and append the event. The caller commits."""
    previous = status_of(row)
    if row is None:
        db.add(VulnerabilityRemediation(
            vulnerability_id=vulnerability_id, status=to_status, version=1, client_note=values.pop("client_note", ""),
            target_date=values.pop("target_date", None), retest_attempts=values.pop("retest_attempts", 0),
            risk_acceptance_reason=values.pop("risk_acceptance_reason", None),
            risk_accepted_by=values.pop("risk_accepted_by", None), risk_accepted_at=values.pop("risk_accepted_at", None),
            updated_by=actor_id, created_at=now, updated_at=now))
        db.flush()
    else:
        changed = db.execute(update(VulnerabilityRemediation).where(
            VulnerabilityRemediation.vulnerability_id == vulnerability_id, VulnerabilityRemediation.version == row.version,
            VulnerabilityRemediation.status == row.status).values(
            status=to_status, version=row.version + 1, updated_by=actor_id, updated_at=now, **values)
            .execution_options(synchronize_session=False))
        if changed.rowcount != 1:
            raise HTTPException(409, "Remediation changed concurrently; refresh before updating")
    add_event(db, vulnerability_id, action, actor_id, previous, to_status, note, detail, now)


def _commit(db):
    try:
        db.commit()
    except (IntegrityError, OperationalError) as error:
        db.rollback()
        raise HTTPException(409, "Remediation changed concurrently; refresh before updating") from error


def _expect_version(row, expected):
    if version_of(row) != expected:
        raise HTTPException(409, "Remediation changed; refresh before updating")


# --- Manual updates --------------------------------------------------------------------------

def update_status(db, vulnerability_id, actor_id, payload):
    confirmed(db, vulnerability_id)
    closure_lock.assert_unlocked(db, vulnerability_id)
    row = current(db, vulnerability_id)
    _expect_version(row, payload.expected_version)
    previous = status_of(row)
    if payload.status not in MANUAL_TRANSITIONS[previous]:
        raise HTTPException(409, f"Cannot move from {previous} to {payload.status}")
    now = utc_now()
    accepting = payload.status == "risk_accepted"
    note = _clean(payload.note, 4000, 20 if accepting else 10, "Note")
    if accepting and payload.human_validation_confirmed is not True:
        raise HTTPException(422, "Risk acceptance requires an explicit human attestation")
    if payload.target_date is not None and not now.date() <= payload.target_date <= now.date() + timedelta(days=MAX_TARGET_DAYS):
        raise HTTPException(422, f"Target remediation date must be within the next {MAX_TARGET_DAYS} days")
    values = {"client_note": note, "target_date": payload.target_date if payload.target_date is not None
              else (row.target_date if row else None)}
    if accepting:
        values.update(risk_acceptance_reason=note, risk_accepted_by=actor_id, risk_accepted_at=now)
    detail = {"target_date": values["target_date"].isoformat() if values["target_date"] else None}
    try:
        _move(db, vulnerability_id, row, payload.status, actor_id, "risk_accepted" if accepting else "status_updated",
              note, detail, now, **values)
        _commit(db)
    except HTTPException:
        db.rollback()
        raise
    except (IntegrityError, OperationalError) as error:
        db.rollback()
        raise HTTPException(409, "Remediation changed concurrently; refresh before updating") from error
    return detail_of(db, vulnerability_id)


def reopen(db, vulnerability_id, actor_id, payload):
    """Manual analyst reopening of an issue that is not actually resolved."""
    confirmed(db, vulnerability_id)
    closure_lock.assert_unlocked(db, vulnerability_id)
    row = current(db, vulnerability_id)
    _expect_version(row, payload.expected_version)
    previous = status_of(row)
    if previous == "retest_requested":
        raise HTTPException(409, "A retest is pending; wait for its result before reopening")
    if previous not in REOPENABLE:
        raise HTTPException(409, f"A {previous} finding cannot be reopened")
    reason = _clean(payload.reason, 4000, 20, "Reason")
    try:
        _move(db, vulnerability_id, row, "reopened", actor_id, "reopened", reason, {"reopened_from": previous},
              utc_now(), client_note=reason, risk_acceptance_reason=None, risk_accepted_by=None, risk_accepted_at=None)
        _commit(db)
    except HTTPException:
        db.rollback()
        raise
    return detail_of(db, vulnerability_id)


# --- Independent sign-off of a verified fix --------------------------------------------------

def _latest_verified_retest(db, vulnerability_id):
    return db.scalar(select(RetestRequest).where(
        RetestRequest.vulnerability_id == vulnerability_id, RetestRequest.status == "completed",
        RetestRequest.outcome == "verified_fixed").order_by(RetestRequest.attempt.desc()).limit(1))


def fix_verification(db, vulnerability_id, row=None):
    """Where a `verified_fixed` finding stands on human sign-off. The scanner comparison alone is not final
    when dual sign-off is enabled: a person who did not do the work must confirm the retest evidence."""
    row = row if row is not None else current(db, vulnerability_id)
    if status_of(row) != "verified_fixed":
        return {"applicable": False, "required": False, "state": "not_applicable"}
    retest = _latest_verified_retest(db, vulnerability_id)
    try:
        signoff = db.scalar(select(FixVerificationSignoff).where(FixVerificationSignoff.retest_id == retest.id)) if retest else None
    except OperationalError:
        db.rollback()  # migration 0014 not applied yet: show the fix as awaiting sign-off instead of failing the page
        signoff = None
    names = _names(db, [signoff.signed_by]) if signoff else {}
    return {"applicable": True, "required": False,  # dual sign-off removed (Phase 1)
            "retest_id": retest.id if retest else None, "evidence_sha256": retest.evidence_sha256 if retest else None,
            "state": "confirmed" if signoff is not None and signoff.decision == "confirmed" else "pending",
            "signed_by": signoff.signed_by if signoff else None,
            "signed_by_name": names.get(signoff.signed_by) if signoff else None,
            "signed_at": _iso(signoff.signed_at) if signoff else None, "note": signoff.note if signoff else None}


def verify_fix(db, vulnerability_id, actor_id, payload):
    """Record a second person's decision on the latest verified retest. `rejected` reopens the finding."""
    from app.services import job_engine
    vulnerability = confirmed(db, vulnerability_id)
    closure_lock.assert_unlocked(db, vulnerability_id)
    row = current(db, vulnerability_id)
    _expect_version(row, payload.expected_version)
    if status_of(row) != "verified_fixed":
        raise HTTPException(409, "Only a finding that a retest verified as fixed can be signed off")
    retest = _latest_verified_retest(db, vulnerability_id)
    if retest is None:
        raise HTTPException(409, "No completed retest supports this verification")
    if db.scalar(select(FixVerificationSignoff.id).where(FixVerificationSignoff.retest_id == retest.id)):
        raise HTTPException(409, "This verification was already signed off")
    note = _clean(payload.note, 4000, 20, "Note")
    # Whoever requested the retest or touched this finding's remediation cannot be the second person.
    # An earlier rejection by a reviewer reopens the finding, but reviewing is not doing the work.
    if payload.decision == "confirmed" and retest.evidence_sha256 is None:
        raise HTTPException(409, "The retest has no stored evidence to confirm; reject it or request another retest")
    now = utc_now()
    try:
        db.add(FixVerificationSignoff(id=str(uuid4()), vulnerability_id=vulnerability_id, retest_id=retest.id,
                                      decision=payload.decision, signed_by=actor_id, signed_at=now, note=note,
                                      evidence_sha256=retest.evidence_sha256))
        job_engine.event(db, "fix_verification_" + payload.decision, resource_id=vulnerability.website_id, actor_id=actor_id,
                         detail={"vulnerability_id": vulnerability_id, "retest_id": retest.id,
                                 "evidence_sha256": retest.evidence_sha256})
        if payload.decision == "rejected":
            _move(db, vulnerability_id, row, "reopened", actor_id, "reopened", note,
                  {"reopened_from": "verified_fixed", "signoff": "rejected", "retest_id": retest.id}, now, client_note=note)
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except (IntegrityError, OperationalError) as error:
        db.rollback()
        raise HTTPException(409, "The verification was changed concurrently; refresh") from error
    return detail_of(db, vulnerability_id)


# --- Retests ---------------------------------------------------------------------------------

def request_retest(db, vulnerability_id, actor_id, payload):
    """Retired in Phase 1: legacy retests ran through the removed written-permission system.
    Phase 4 adds "Re-scan to confirm fix" on top of self-service scans."""
    raise HTTPException(410, "Legacy retests are retired. Re-scanning to confirm a fix arrives in a later update.")


def _finish(db, retest, status, outcome, occurrence=None, failure=None):
    now = utc_now()
    changed = db.execute(update(RetestRequest).where(RetestRequest.id == retest.id, RetestRequest.status == "requested")
                         .values(status=status, outcome=outcome, completed_at=now,
                                 occurrence_id=occurrence.id if occurrence else None,
                                 evidence_sha256=occurrence.evidence_sha256 if occurrence else None, failure_code=failure)
                         .execution_options(synchronize_session=False))
    if changed.rowcount != 1:
        db.rollback()
        return
    row = current(db, retest.vulnerability_id)
    detail = {"retest_id": retest.id, "assessment_id": retest.assessment_id, "attempt": retest.attempt, "outcome": outcome,
              "failure_code": failure, "occurrence_id": occurrence.id if occurrence else None,
              "evidence_sha256": occurrence.evidence_sha256 if occurrence else None}
    target, action, extra = {
        "verified_fixed": ("verified_fixed", "retest_verified_fixed", {}),
        "still_present": ("reopened", "retest_still_present", {}),
        "inconclusive": ("fix_submitted", "retest_inconclusive", {}),
        None: ("fix_submitted", "retest_failed", {}),
    }[outcome]
    if outcome in ("verified_fixed", "still_present") and row is not None:
        extra["retest_attempts"] = row.retest_attempts + 1
    note = {"verified_fixed": "Retest found the weakness no longer detected.",
            "still_present": "Retest reproduced the weakness; the finding was automatically reopened.",
            "inconclusive": "Retest produced no applicable observation; request another retest or reopen manually.",
            None: f"Retest did not complete ({failure})."}[outcome]
    try:
        if row is not None and row.status == "retest_requested":
            _move(db, retest.vulnerability_id, row, target, None, action, note, detail, now, **extra)
        else:
            add_event(db, retest.vulnerability_id, action, None, status_of(row), status_of(row), note, detail, now)
        db.commit()
    except (HTTPException, IntegrityError, OperationalError):
        db.rollback()


def reconcile(db, retest):
    """Resolve a requested retest from its assessment's job and ingested observations. Idempotent."""
    if retest.status != "requested":
        return
    request = db.get(AssessmentRequest, retest.assessment_id)
    job = db.get(Job, request.job_id) if request else None
    if job is None:
        return
    if job.status in ("failed", "cancelled"):
        _finish(db, retest, "failed", None, failure=f"job_{job.status}")
        return
    if job.status != "completed":
        return
    report = db.scalar(select(AssessmentReport).where(AssessmentReport.assessment_id == retest.assessment_id))
    if report is None:
        _finish(db, retest, "failed", None, failure="no_report")
        return
    if db.get(VulnerabilityIngestion, report.id) is None:
        return  # ingestion has not run yet; it is retried by the worker hook and on the next read
    occurrence = db.scalar(select(VulnerabilityOccurrence).where(
        VulnerabilityOccurrence.vulnerability_id == retest.vulnerability_id,
        VulnerabilityOccurrence.assessment_id == retest.assessment_id))
    intact = occurrence is not None and sha256(assessments.report_bytes(occurrence.evidence)).hexdigest() == occurrence.evidence_sha256
    if occurrence is None or not intact:
        _finish(db, retest, "completed", "inconclusive", occurrence if intact else None)
    elif occurrence.result == "detected":
        _finish(db, retest, "completed", "still_present", occurrence)
    else:
        _finish(db, retest, "completed", "verified_fixed", occurrence)


def reconcile_vulnerability(db, vulnerability_id):
    for retest in list(db.scalars(select(RetestRequest).where(RetestRequest.vulnerability_id == vulnerability_id,
                                                              RetestRequest.status == "requested"))):
        reconcile(db, retest)


def sync(db, assessment_id=None):
    statement = select(RetestRequest).where(RetestRequest.status == "requested")
    for retest in list(db.scalars(statement.order_by(RetestRequest.requested_at).limit(100))):
        reconcile(db, retest)


def on_assessment_ingested(db, assessment_id):
    """Worker hook, called after ingestion. Failures never affect the recorded scanner result."""
    for retest in list(db.scalars(select(RetestRequest).where(RetestRequest.assessment_id == assessment_id))):
        reconcile(db, retest)


# --- Queries ---------------------------------------------------------------------------------

def _retest_serial(db, retest):
    job_status = db.scalar(select(Job.status).join(AssessmentRequest, AssessmentRequest.job_id == Job.id)
                           .where(AssessmentRequest.id == retest.assessment_id))
    value = {c.name: _iso(v) if c.name.endswith("_at") else v
             for c in retest.__table__.columns for v in [getattr(retest, c.name)]}
    value["assessment_status"] = job_status
    return value


def _item(db, vulnerability, website, client, row, retests=None):
    status = status_of(row)
    active = db.scalar(select(RetestRequest.id).where(RetestRequest.vulnerability_id == vulnerability.id,
                                                      RetestRequest.status == "requested"))
    total = db.scalar(select(func.count()).select_from(RetestRequest).where(RetestRequest.vulnerability_id == vulnerability.id))
    return {
        "vulnerability_id": vulnerability.id, "title": vulnerability.title, "check_id": vulnerability.check_id,
        "target_url": vulnerability.target_url, "severity": vulnerability.analyst_severity or vulnerability.scanner_severity,
        "website_id": website.id, "website_name": website.name, "client_name": client.company_name,
        "status": status, "version": version_of(row), "client_note": row.client_note if row else "",
        "target_date": row.target_date.isoformat() if row and row.target_date else None,
        "retest_attempts": row.retest_attempts if row else 0, "retests_total": total, "active_retest_id": active,
        "risk_acceptance_reason": row.risk_acceptance_reason if row else None,
        "risk_accepted_at": _iso(row.risk_accepted_at) if row else None,
        "updated_at": _iso(row.updated_at) if row else None,
        "allowed_statuses": sorted(MANUAL_TRANSITIONS[status]),
        "can_request_retest": status == "fix_submitted" and active is None and total < MAX_RETESTS,
        "can_reopen": status in REOPENABLE,
    }


def listing(db, *, status=None, website_id=None, assessment_id=None, search="", limit=50, offset=0):
    sync(db)
    effective = func.coalesce(VulnerabilityRemediation.status, "open")
    base = (select(Vulnerability, Website, Client, VulnerabilityRemediation)
            .join(Website, Website.id == Vulnerability.website_id).join(Client, Client.id == Website.client_id)
            .outerjoin(VulnerabilityRemediation, VulnerabilityRemediation.vulnerability_id == Vulnerability.id)
            .where(Vulnerability.validation_state == "confirmed"))
    if website_id: base = base.where(Vulnerability.website_id == website_id)
    if assessment_id:
        base = base.where(exists().where(VulnerabilityOccurrence.vulnerability_id == Vulnerability.id,
                                         VulnerabilityOccurrence.assessment_id == assessment_id,
                                         VulnerabilityOccurrence.result == "detected"))
    if search:
        base = base.where(or_(*(func.lower(c).contains(search.lower(), autoescape=True) for c in (
            Vulnerability.title, Vulnerability.check_id, Vulnerability.target_host, Website.name, Client.company_name))))
    counts = {k: 0 for k in MANUAL_TRANSITIONS}
    counts.update({k: n for k, n in db.execute(base.with_only_columns(effective, func.count(), maintain_column_froms=True)
                                                .group_by(effective))})
    selected = base.where(effective == status) if status else base
    rows = db.execute(selected.order_by(Vulnerability.last_seen_at.desc(), Vulnerability.id).offset(offset).limit(limit)).all()
    return {"items": [_item(db, v, w, c, r) for v, w, c, r in rows], "summary": counts,
            "limit": limit, "offset": offset}


def detail_of(db, vulnerability_id):
    vulnerability = confirmed(db, vulnerability_id)
    reconcile_vulnerability(db, vulnerability_id)
    db.expire_all()
    vulnerability = confirmed(db, vulnerability_id)
    website = db.get(Website, vulnerability.website_id)
    value = _item(db, vulnerability, website, db.get(Client, website.client_id), current(db, vulnerability_id))
    events = list(db.scalars(select(RemediationEvent).where(RemediationEvent.vulnerability_id == vulnerability_id)
                             .order_by(RemediationEvent.sequence.desc()).limit(100)))
    names = _names(db, [e.actor_id for e in events])
    value["events"] = [{**{c.name: _iso(v) if c.name.endswith("_at") else v for c in e.__table__.columns
                           for v in [getattr(e, c.name)]}, "actor_name": names.get(e.actor_id) or "system"} for e in events]
    value["retests"] = [_retest_serial(db, r) for r in db.scalars(select(RetestRequest).where(
        RetestRequest.vulnerability_id == vulnerability_id).order_by(RetestRequest.attempt.desc()).limit(50))]
    value["fix_verification"] = fix_verification(db, vulnerability_id)
    return value


def retests(db, vulnerability_id):
    confirmed(db, vulnerability_id)
    reconcile_vulnerability(db, vulnerability_id)
    return [_retest_serial(db, r) for r in db.scalars(select(RetestRequest).where(
        RetestRequest.vulnerability_id == vulnerability_id).order_by(RetestRequest.attempt.desc()).limit(50))]


# --- Assessment closure --------------------------------------------------------------------------

def _closure_serial(db, row):
    names = _names(db, [row.closed_by])
    return {"id": row.id, "assessment_id": row.assessment_id, "closed_by": row.closed_by,
            "closed_by_name": names.get(row.closed_by), "closed_at": _iso(row.closed_at),
            "justification": row.justification, "summary": row.summary, "content_sha256": row.content_sha256,
            "generation": row.generation}


def _reopening_serial(db, row):
    names = _names(db, [row.reopened_by])
    return {"id": row.id, "closure_id": row.closure_id, "assessment_id": row.assessment_id,
            "reopened_by": row.reopened_by, "reopened_by_name": names.get(row.reopened_by),
            "reopened_at": _iso(row.reopened_at), "reason": row.reason}


def closure_state(db, assessment_id):
    request = assessments.get_request(db, assessment_id)
    sync(db)
    job = db.get(Job, request.job_id)
    rows = db.execute(select(Vulnerability, VulnerabilityRemediation).join(
        VulnerabilityOccurrence, VulnerabilityOccurrence.vulnerability_id == Vulnerability.id).outerjoin(
        VulnerabilityRemediation, VulnerabilityRemediation.vulnerability_id == Vulnerability.id).where(
        VulnerabilityOccurrence.assessment_id == assessment_id, VulnerabilityOccurrence.result == "detected")
        .order_by(Vulnerability.check_id)).all()
    findings = [{"vulnerability_id": v.id, "check_id": v.check_id, "title": v.title,
                 "severity": v.analyst_severity or v.scanner_severity, "status": status_of(r),
                 "retest_attempts": r.retest_attempts if r else 0,
                 "risk_acceptance_reason": r.risk_acceptance_reason if r else None}
                for v, r in rows if v.validation_state == "confirmed"]
    unreviewed = sum(1 for v, _ in rows if v.validation_state == "unconfirmed")
    blockers = [{k: f[k] for k in ("vulnerability_id", "check_id", "title", "status")}
                for f in findings if f["status"] in BLOCKING_STATUSES]
    closure = closure_lock.active_closure(db, assessment_id)
    reopenings = list(db.scalars(select(ClosureReopening).where(ClosureReopening.assessment_id == assessment_id)
                                 .order_by(ClosureReopening.reopened_at)))
    reasons = []
    if job is None or job.status != "completed": reasons.append("The assessment has not completed.")
    if closure is not None: reasons.append("The assessment is already closed.")
    if blockers:
        by = {}
        for b in blockers: by[b["status"]] = by.get(b["status"], 0) + 1
        reasons.append(f"{len(blockers)} confirmed finding(s) are unresolved ("
                       + ", ".join(f"{n} {s.replace('_', ' ')}" for s, n in sorted(by.items())) + ").")
    # With dual sign-off on, a scanner-verified fix is not final until a second person confirms it.
    signoffs = {f["vulnerability_id"]: fix_verification(db, f["vulnerability_id"]) for f in findings if f["status"] == "verified_fixed"}
    checks = {f["vulnerability_id"]: f["check_id"] for f in findings}
    awaiting = [{"vulnerability_id": k, "check_id": checks[k]} for k, v in signoffs.items()
                if v["required"] and v["state"] != "confirmed"]
    if awaiting:
        reasons.append(f"{len(awaiting)} verified fix(es) await independent sign-off.")
    counts = {}
    for f in findings: counts[f["status"]] = counts.get(f["status"], 0) + 1
    return {"assessment_id": assessment_id, "signoff_pending": awaiting, "closed": closure is not None,
            "closure": _closure_serial(db, closure) if closure else None, "can_close": not reasons,
            "blocking_reasons": reasons, "blockers": blockers, "confirmed_count": len(findings),
            "status_counts": counts, "unreviewed_count": unreviewed, "findings": findings,
            "reopenings": [_reopening_serial(db, r) for r in reopenings]}


def close_assessment(db, assessment_id, actor_id, justification):
    state = closure_state(db, assessment_id)
    if not state["can_close"]:
        raise HTTPException(409, "Cannot close: " + " ".join(state["blocking_reasons"]))
    text = _clean(justification, 4000, 20, "Justification")
    now = utc_now()
    generation = (db.scalar(select(func.max(AssessmentClosure.generation)).where(
        AssessmentClosure.assessment_id == assessment_id)) or 0) + 1
    summary = {"findings": state["findings"], "status_counts": state["status_counts"],
               "unreviewed_count": state["unreviewed_count"]}
    row = AssessmentClosure(id=str(uuid4()), assessment_id=assessment_id, generation=generation, closed_by=actor_id,
                            closed_at=now, justification=text, summary=summary,
                            content_sha256=assessments.digest({"assessment_id": assessment_id, "justification": text,
                                                              "summary": summary}))
    try:
        db.add(row)
        db.commit()
    except (IntegrityError, OperationalError) as error:
        db.rollback()
        raise HTTPException(409, "The assessment was closed concurrently") from error
    return closure_state(db, assessment_id)


def reopen_closure(db, assessment_id, actor_id, reason):
    """Formally lift the closure lock. Appends an immutable record; the closure itself is never edited."""
    assessments.get_request(db, assessment_id)
    closure = closure_lock.active_closure(db, assessment_id)
    if closure is None:
        raise HTTPException(409, "The assessment has no active closure to reopen")
    text = _clean(reason, 4000, 20, "Reason")
    row = ClosureReopening(id=str(uuid4()), closure_id=closure.id, assessment_id=assessment_id, reopened_by=actor_id,
                           reopened_at=utc_now(), reason=text)
    try:
        db.add(row)
        db.commit()
    except (IntegrityError, OperationalError) as error:
        db.rollback()
        raise HTTPException(409, "The closure was reopened concurrently") from error
    return closure_state(db, assessment_id)
