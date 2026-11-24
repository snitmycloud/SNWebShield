"""Module E: normalise scanner observations into deduplicated, human-validated records.

Inputs are stored scanner reports, which contain data derived from untrusted target
responses. Every observation is re-validated against a fixed vocabulary before use,
the source report's SHA-256 is re-checked, and the scanner can never confirm a
vulnerability: only an attested analyst decision moves a record out of `unconfirmed`.
No network operation happens here.
"""
from datetime import timedelta
from hashlib import sha256
from urllib.parse import quote, unquote, urlsplit
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import and_, case, exists, func, or_, select, update
from sqlalchemy.exc import IntegrityError, OperationalError

from app.core.time import as_utc, utc_now
from app.models.assessment import AssessmentReport, AssessmentRequest
from app.models.client import Client
from app.models.jobs import Job
from app.models.vulnerability import (SEVERITIES, Vulnerability, VulnerabilityEvent, VulnerabilityIngestion,
                                      VulnerabilityOccurrence, VulnerabilitySuppression)
from app.models.website import Website
from app.services import assessments, job_engine

FAMILY = "http_security_headers"
HEADER_PROFILES = frozenset({assessments.HTTP_PROFILE_ID, assessments.REMOTE_PROFILE_ID})
SUPPRESSION_MAX_DAYS = 365
MAX_OBSERVATIONS = 64

# Fixed check vocabulary. `reliability` is the base confidence that a failed check
# reflects a real weakness rather than an artefact of one HEAD request.
CHECKS = {
    "csp": {"title": "Content-Security-Policy header missing", "header": "Content-Security-Policy",
            "reliability": 70, "expect": "a Content-Security-Policy header that restricts script, object and frame sources"},
    "hsts": {"title": "HSTS missing or without a positive max-age", "header": "Strict-Transport-Security",
             "reliability": 80, "expect": "Strict-Transport-Security with max-age greater than zero (commonly 31536000)"},
    "x_frame_options": {"title": "X-Frame-Options missing or not DENY/SAMEORIGIN", "header": "X-Frame-Options",
                        "reliability": 60, "expect": "DENY or SAMEORIGIN, or an equivalent CSP frame-ancestors directive"},
    "csp_frame_ancestors": {"title": "CSP frame-ancestors directive missing", "header": "Content-Security-Policy",
                            "reliability": 50, "expect": "a frame-ancestors directive listing only trusted origins"},
    "x_content_type_options": {"title": "X-Content-Type-Options nosniff missing", "header": "X-Content-Type-Options",
                               "reliability": 80, "expect": "the value nosniff"},
    "referrer_policy": {"title": "Referrer-Policy missing or unrecognised", "header": "Referrer-Policy",
                        "reliability": 60, "expect": "a recognised value such as strict-origin-when-cross-origin"},
    "permissions_policy": {"title": "Permissions-Policy header missing", "header": "Permissions-Policy",
                           "reliability": 50, "expect": "a policy that disables browser features the site does not use"},
    "server_disclosure": {"title": "Server software disclosed in response headers", "header": "Server and X-Powered-By",
                          "reliability": 70, "expect": "no Server or X-Powered-By header, or a generic value without versions"},
}
TRANSITIONS = {
    "unconfirmed": {"confirmed", "false_positive", "not_applicable"},
    "confirmed": {"unconfirmed"},
    "false_positive": {"unconfirmed"},
    "not_applicable": {"unconfirmed"},
}
TRANSPORT_EVIDENCE = ("status", "tls_verified", "tls_version", "connected_ip", "response_ms", "headers_sha256", "redirect")


class IngestionRejected(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


# --- Normalisation helpers ----------------------------------------------------------------

def fingerprint(website_id, target_url, family, check):
    """Stable identity: the same check on the same exact target is one vulnerability."""
    return assessments.digest({"v": 1, "website_id": website_id, "target_url": target_url,
                               "family": family, "check": check})


def safe_url(target_url):
    """Re-encode a validated target URL so it is inert inside single-quoted shell text."""
    parts = urlsplit(target_url)
    path = quote(unquote(parts.path or "/"), safe="/-._~")
    query = ("?" + quote(unquote(parts.query), safe="=&-._~")) if parts.query else ""
    return f"{parts.scheme}://{parts.hostname}{path}{query}"


def reproduction(check, target_url):
    meta = CHECKS[check]
    return [
        "Confirm the written authorisation for this exact domain is approved and inside its validity window before sending any request.",
        f"Send one HEAD request without following redirects: curl -sS -I --max-redirs 0 '{safe_url(target_url)}'",
        f"Inspect the {meta['header']} response header in the output.",
        f"Expected secure configuration: {meta['expect']}.",
        "Record the response status and exact header value as analyst evidence. Do not test outside the authorised scope.",
    ]


def parse_observation(item):
    """Return (check, result, severity) for a well-formed observation, else None."""
    if not isinstance(item, dict):
        return None
    check, observed, severity = item.get("check"), item.get("observed"), item.get("severity_suggestion")
    if (check not in CHECKS or severity not in SEVERITIES
            or item.get("requires_human_validation") is not True
            or item.get("confirmed_vulnerability") is not False):
        return None
    # Identity checks: 0/1 must not be accepted as booleans.
    if observed is False:
        return check, "detected", severity
    if observed is True:
        return check, "not_detected", severity
    return None  # Not applicable to this response (e.g. HSTS over HTTP).


def score(check, results):
    """Deterministic, explainable confidence from check reliability and history."""
    factors = [{"factor": "check_reliability", "effect": CHECKS[check]["reliability"]}]
    detections = results.count("detected")
    if detections > 1:
        factors.append({"factor": "repeated_detection", "effect": min(15, 5 * (detections - 1))})
    flips = sum(1 for a, b in zip(results, results[1:]) if a != b)
    if flips:
        factors.append({"factor": "inconsistent_results", "effect": -min(30, 15 * flips)})
    if results and results[-1] == "not_detected":
        factors.append({"factor": "not_detected_in_latest_assessment", "effect": -20})
    total = max(5, min(95, sum(f["effect"] for f in factors)))
    return total, ("high" if total >= 75 else "medium" if total >= 50 else "low"), factors


def report_intact(report):
    data = assessments.report_bytes(report.content)
    return len(data) == report.size and sha256(data).hexdigest() == report.sha256


def evidence(request, report, item):
    transport = report.content.get("transport") if isinstance(report.content.get("transport"), dict) else {}
    value = {"schema_version": 1, "assessment_id": request.id, "report_id": report.id, "report_sha256": report.sha256,
             "profile_id": request.profile_id, "adapter": report.content.get("adapter"),
             "recorded_at": report.content.get("recorded_at"),
             "observation": dict(item),
             "transport": {k: transport[k] for k in TRANSPORT_EVIDENCE if k in transport}}
    return value, sha256(assessments.report_bytes(value)).hexdigest()


def active_suppression(db, vulnerability_id, now):
    return db.scalar(select(VulnerabilitySuppression).where(
        VulnerabilitySuppression.vulnerability_id == vulnerability_id, VulnerabilitySuppression.revoked_at.is_(None),
        VulnerabilitySuppression.expires_at > now).order_by(VulnerabilitySuppression.created_at.desc()).limit(1))


def add_event(db, vulnerability, action, *, actor_id=None, from_state=None, to_state=None, comment="", detail=None, now=None):
    sequence = (db.scalar(select(func.max(VulnerabilityEvent.sequence)).where(
        VulnerabilityEvent.vulnerability_id == vulnerability.id)) or 0) + 1
    row = VulnerabilityEvent(id=str(uuid4()), vulnerability_id=vulnerability.id, sequence=sequence, actor_id=actor_id,
                             action=action, from_state=from_state, to_state=to_state, comment=comment,
                             detail=detail or {}, occurred_at=now or utc_now())
    db.add(row)
    db.flush()
    return row


# --- Ingestion ---------------------------------------------------------------------------

def _record(db, request, report, item, check, result, severity, now, outcome):
    key = fingerprint(request.website_id, request.target_url, FAMILY, check)
    vulnerability = db.scalar(select(Vulnerability).where(Vulnerability.fingerprint == key))
    observed_at = as_utc(report.created_at)
    if vulnerability is None:
        if result == "not_detected":
            outcome["passed_without_record"] += 1
            return
        vulnerability = Vulnerability(
            id=str(uuid4()), fingerprint=key, website_id=request.website_id, target_url=request.target_url,
            target_host=request.target_host, family=FAMILY, check_id=check, title=CHECKS[check]["title"],
            category="security_headers", scanner_severity=severity, analyst_severity=None,
            confidence="low", confidence_score=0, confidence_factors=[], validation_state="unconfirmed",
            reproduction_template=reproduction(check, request.target_url), reproduction_steps=None,
            detection_count=0, not_detected_count=0, last_result=result, first_seen_at=observed_at,
            last_seen_at=observed_at, last_checked_at=observed_at, first_report_id=report.id,
            last_report_id=report.id, revision=1, created_at=now, updated_at=now)
        db.add(vulnerability)
        db.flush()
        add_event(db, vulnerability, "detected_new", to_state="unconfirmed", now=now,
                  detail={"report_id": report.id, "assessment_id": request.id, "fingerprint": key})
        outcome["created"] += 1
    suppression = active_suppression(db, vulnerability.id, now)
    value, digest = evidence(request, report, item)
    db.add(VulnerabilityOccurrence(id=str(uuid4()), vulnerability_id=vulnerability.id, report_id=report.id,
        assessment_id=request.id, result=result, observed_at=observed_at,
        suppressed=result == "detected" and suppression is not None, evidence=value, evidence_sha256=digest))
    if result == "detected":
        vulnerability.detection_count += 1
        outcome["detected"] += 1
        if observed_at >= as_utc(vulnerability.last_seen_at):
            vulnerability.last_seen_at, vulnerability.last_report_id = observed_at, report.id
            vulnerability.scanner_severity = severity
        vulnerability.first_seen_at = min(as_utc(vulnerability.first_seen_at), observed_at)
    else:
        vulnerability.not_detected_count += 1
        outcome["not_detected"] += 1
    if observed_at >= as_utc(vulnerability.last_checked_at):
        vulnerability.last_checked_at, vulnerability.last_result = observed_at, result
    db.flush()
    history = list(db.scalars(select(VulnerabilityOccurrence.result).where(
        VulnerabilityOccurrence.vulnerability_id == vulnerability.id).order_by(
        VulnerabilityOccurrence.observed_at, VulnerabilityOccurrence.id)))
    vulnerability.confidence_score, vulnerability.confidence, vulnerability.confidence_factors = score(check, history)
    vulnerability.updated_at = now
    add_event(db, vulnerability, "occurrence_recorded", now=now, detail={
        "report_id": report.id, "assessment_id": request.id, "result": result,
        "suppressed": result == "detected" and suppression is not None, "evidence_sha256": digest})
    state = vulnerability.validation_state
    if result == "detected" and state in ("false_positive", "not_applicable"):
        if suppression is None:
            # Dismissals only carry forward while their suppression is active.
            vulnerability.validation_state, vulnerability.analyst_severity = "unconfirmed", None
            vulnerability.revision += 1
            add_event(db, vulnerability, "reopened_redetected", from_state=state, to_state="unconfirmed", now=now,
                      detail={"report_id": report.id, "reason": "suppression_expired_or_absent"})
            outcome["reopened"] += 1
        else:
            outcome["suppressed"] += 1


def ingest_report(db, report, actor_id=None):
    """Ingest one report inside the caller's transaction. Raises IngestionRejected."""
    now = utc_now()
    request = db.get(AssessmentRequest, report.assessment_id)
    job = db.get(Job, request.job_id) if request else None
    if not job or job.status != "completed":
        raise IngestionRejected("assessment_not_completed")
    if not report_intact(report):
        raise IngestionRejected("report_integrity_failed")
    outcome = {"family": None, "created": 0, "detected": 0, "not_detected": 0, "passed_without_record": 0,
               "skipped": 0, "reopened": 0, "suppressed": 0}
    if request.profile_id in HEADER_PROFILES:
        outcome["family"] = FAMILY
        analysis = report.content.get("analysis")
        items = analysis.get("observations") if isinstance(analysis, dict) else None
        if not isinstance(items, list) or len(items) > MAX_OBSERVATIONS:
            raise IngestionRejected("report_schema_invalid")
        seen = set()
        for item in items:
            parsed = parse_observation(item)
            if parsed is None or parsed[0] in seen:
                outcome["skipped"] += 1
                continue
            seen.add(parsed[0])
            _record(db, request, report, item, *parsed, now, outcome)
    else:
        # Port-state results are exposure inventory reviewed in the assessment workbench.
        outcome["reason"] = "profile_not_ingested_inventory_only"
    db.add(VulnerabilityIngestion(report_id=report.id, assessment_id=request.id, report_sha256=report.sha256,
                                  ingested_at=now, actor_id=actor_id, outcome=outcome))
    job_engine.event(db, "vulnerabilities_ingested", job, actor_id=actor_id, detail={"report_id": report.id, **outcome})
    return outcome


def ingest_one(db, report_id, actor_id=None):
    if db.get(VulnerabilityIngestion, report_id):
        return {"report_id": report_id, "status": "already_ingested"}
    report = db.get(AssessmentReport, report_id)
    if report is None:
        raise HTTPException(404, "Assessment report not found")
    try:
        outcome = ingest_report(db, report, actor_id)
        db.commit()
        return {"report_id": report_id, "status": "ingested", **outcome}
    except IngestionRejected as rejected:
        db.rollback()
        request = db.get(AssessmentRequest, report.assessment_id)
        job = db.get(Job, request.job_id) if request else None
        job_engine.event(db, "vulnerability_ingestion_rejected", job, actor_id=actor_id,
                         detail={"report_id": report_id, "reason": rejected.code})
        db.commit()
        return {"report_id": report_id, "status": "rejected", "reason": rejected.code}
    except (IntegrityError, OperationalError):
        db.rollback()
        if db.get(VulnerabilityIngestion, report_id):
            return {"report_id": report_id, "status": "already_ingested"}
        raise HTTPException(409, "Ingestion changed concurrently; retry")


def pending_reports(db, assessment_id=None, limit=200):
    statement = (select(AssessmentReport.id).join(AssessmentRequest, AssessmentRequest.id == AssessmentReport.assessment_id)
                 .join(Job, Job.id == AssessmentRequest.job_id)
                 .where(Job.status == "completed", ~exists().where(VulnerabilityIngestion.report_id == AssessmentReport.id))
                 .order_by(AssessmentReport.created_at, AssessmentReport.id))
    if assessment_id:
        statement = statement.where(AssessmentReport.assessment_id == assessment_id)
    return list(db.scalars(statement.limit(limit)))


def ingest_pending(db, actor_id=None, assessment_id=None):
    # Chronological order makes confidence and last-seen deterministic for backfills.
    results = [ingest_one(db, report_id, actor_id) for report_id in pending_reports(db, assessment_id)]
    return {"processed": len(results), "results": results, "remaining": len(pending_reports(db, assessment_id, 1))}


def ingest_after_assessment(assessment_id):
    """Worker hook: failures never affect the already-recorded scanner result."""
    from app.db.session import SessionLocal
    with SessionLocal() as db:
        try:
            for report_id in pending_reports(db, assessment_id, 1):
                ingest_one(db, report_id)
        except Exception:
            db.rollback()
            request = db.get(AssessmentRequest, assessment_id)
            job_engine.event(db, "vulnerability_ingestion_failed", db.get(Job, request.job_id) if request else None,
                             detail={"assessment_id": assessment_id})
            db.commit()


# --- Queries -----------------------------------------------------------------------------

def effective_severity():
    return case((and_(Vulnerability.validation_state == "confirmed", Vulnerability.analyst_severity.is_not(None)),
                 Vulnerability.analyst_severity), else_=Vulnerability.scanner_severity)


def suppression_serial(row, now):
    if row is None:
        return None
    status = "revoked" if row.revoked_at else "active" if as_utc(row.expires_at) > now else "expired"
    return {"id": row.id, "decision": row.decision, "reason": row.reason, "created_by": row.created_by,
            "created_at": as_utc(row.created_at).isoformat(), "expires_at": as_utc(row.expires_at).isoformat(),
            "revoked_at": as_utc(row.revoked_at).isoformat() if row.revoked_at else None,
            "revoked_by": row.revoked_by, "revoke_reason": row.revoke_reason, "status": status}


def serial(db, vulnerability, website=None, client=None, now=None):
    now = now or utc_now()
    value = {c.name: as_utc(v).isoformat() if c.name.endswith("_at") and v is not None else v
             for c in vulnerability.__table__.columns for v in [getattr(vulnerability, c.name)]}
    value["effective_severity"] = (vulnerability.analyst_severity if vulnerability.validation_state == "confirmed"
                                   and vulnerability.analyst_severity else vulnerability.scanner_severity)
    latest = db.scalar(select(VulnerabilitySuppression).where(VulnerabilitySuppression.vulnerability_id == vulnerability.id)
                       .order_by(VulnerabilitySuppression.created_at.desc()).limit(1))
    value["suppression"] = suppression_serial(latest, now)
    if website is not None:
        value.update(website_name=website.name, client_id=client.id, client_name=client.company_name)
    return value


def listing(db, *, state=None, severity=None, confidence=None, website_id=None, client_id=None,
            suppressed=None, search="", limit=50, offset=0):
    now = utc_now()
    active = exists().where(VulnerabilitySuppression.vulnerability_id == Vulnerability.id,
                            VulnerabilitySuppression.revoked_at.is_(None), VulnerabilitySuppression.expires_at > now)
    statement = (select(Vulnerability, Website, Client).join(Website, Website.id == Vulnerability.website_id)
                 .join(Client, Client.id == Website.client_id))
    if state: statement = statement.where(Vulnerability.validation_state == state)
    if severity: statement = statement.where(effective_severity() == severity)
    if confidence: statement = statement.where(Vulnerability.confidence == confidence)
    if website_id: statement = statement.where(Vulnerability.website_id == website_id)
    if client_id: statement = statement.where(Client.id == client_id)
    if suppressed is not None: statement = statement.where(active if suppressed else ~active)
    if search:
        statement = statement.where(or_(*(func.lower(column).contains(search.lower(), autoescape=True) for column in (
            Vulnerability.title, Vulnerability.check_id, Vulnerability.target_host, Website.name, Client.company_name))))
    counts = db.execute(statement.with_only_columns(func.count().label("total"), *[
        func.sum(case((Vulnerability.validation_state == value, 1), else_=0)).label(value)
        for value in ("unconfirmed", "confirmed", "false_positive", "not_applicable")],
        maintain_column_froms=True)).mappings().one()
    priority = case({"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}, value=effective_severity(), else_=5)
    rows = db.execute(statement.order_by(priority, Vulnerability.confidence_score.desc(),
                                         Vulnerability.last_seen_at.desc(), Vulnerability.id).offset(offset).limit(limit))
    return {"items": [serial(db, v, w, c, now) for v, w, c in rows],
            "summary": {k: int(v or 0) for k, v in counts.items()},
            "pending_ingestion": len(pending_reports(db, limit=201)), "limit": limit, "offset": offset}


def get(db, vulnerability_id):
    row = db.get(Vulnerability, vulnerability_id)
    if row is None:
        raise HTTPException(404, "Vulnerability not found")
    return row


def detail(db, vulnerability_id):
    vulnerability = get(db, vulnerability_id)
    website = db.get(Website, vulnerability.website_id)
    value = serial(db, vulnerability, website, db.get(Client, website.client_id))
    value["suppressions"] = [suppression_serial(row, utc_now()) for row in db.scalars(
        select(VulnerabilitySuppression).where(VulnerabilitySuppression.vulnerability_id == vulnerability.id)
        .order_by(VulnerabilitySuppression.created_at.desc()))]
    value["allowed_decisions"] = sorted(TRANSITIONS[vulnerability.validation_state])
    return value


def occurrences(db, vulnerability_id, limit, offset):
    get(db, vulnerability_id)
    rows = db.scalars(select(VulnerabilityOccurrence).where(VulnerabilityOccurrence.vulnerability_id == vulnerability_id)
                      .order_by(VulnerabilityOccurrence.observed_at.desc(), VulnerabilityOccurrence.id).offset(offset).limit(limit))
    return [{c.name: as_utc(v).isoformat() if c.name == "observed_at" else v
             for c in row.__table__.columns for v in [getattr(row, c.name)]} for row in rows]


def events(db, vulnerability_id, limit, offset):
    get(db, vulnerability_id)
    rows = db.scalars(select(VulnerabilityEvent).where(VulnerabilityEvent.vulnerability_id == vulnerability_id)
                      .order_by(VulnerabilityEvent.sequence.desc()).offset(offset).limit(limit))
    return [{c.name: as_utc(v).isoformat() if c.name == "occurred_at" else v
             for c in row.__table__.columns for v in [getattr(row, c.name)]} for row in rows]


# --- Analyst actions ---------------------------------------------------------------------

def comment(db, vulnerability_id, actor_id, text):
    vulnerability = get(db, vulnerability_id)
    try:
        row = add_event(db, vulnerability, "comment", actor_id=actor_id, from_state=vulnerability.validation_state,
                        to_state=vulnerability.validation_state, comment=text)
        db.commit()
    except (IntegrityError, OperationalError) as error:
        db.rollback()
        raise HTTPException(409, "History changed concurrently; retry the comment") from error
    return {"id": row.id, "sequence": row.sequence}


def decide(db, vulnerability_id, actor_id, payload):
    vulnerability = get(db, vulnerability_id)
    now = utc_now()
    current, target = vulnerability.validation_state, payload.decision
    if vulnerability.revision != payload.expected_revision:
        raise HTTPException(409, "Vulnerability changed; refresh before deciding")
    if target not in TRANSITIONS[current]:
        raise HTTPException(409, f"Cannot move from {current} to {target}")
    detail = {"human_validation_confirmed": True, "revision": vulnerability.revision + 1}
    values = {"validation_state": target, "revision": vulnerability.revision + 1, "updated_at": now}
    if target == "confirmed":
        source = db.scalar(select(AssessmentReport).join(VulnerabilityOccurrence,
            VulnerabilityOccurrence.report_id == AssessmentReport.id).where(
            VulnerabilityOccurrence.vulnerability_id == vulnerability.id, VulnerabilityOccurrence.result == "detected")
            .order_by(VulnerabilityOccurrence.observed_at.desc()).limit(1))
        if source is None or not report_intact(source):
            raise HTTPException(409, "Source evidence is missing or failed its integrity check")
        values.update(analyst_severity=payload.severity, reproduction_steps=payload.reproduction_steps)
        detail.update(severity=payload.severity, evidence_report_id=source.id, evidence_report_sha256=source.sha256)
    else:
        values["analyst_severity"] = None
    suppression = None
    if target in ("false_positive", "not_applicable"):
        expires = as_utc(payload.suppress_until)
        if not now < expires <= now + timedelta(days=SUPPRESSION_MAX_DAYS):
            raise HTTPException(422, f"Suppression must expire in the future and within {SUPPRESSION_MAX_DAYS} days")
        suppression = VulnerabilitySuppression(id=str(uuid4()), vulnerability_id=vulnerability.id, decision=target,
            reason=payload.justification, created_by=actor_id, created_at=now, expires_at=expires)
        detail.update(suppression_id=suppression.id, suppress_until=expires.isoformat())
    try:
        changed = db.execute(update(Vulnerability).where(Vulnerability.id == vulnerability.id,
            Vulnerability.revision == payload.expected_revision, Vulnerability.validation_state == current)
            .values(**values).execution_options(synchronize_session=False))
        if changed.rowcount != 1:
            raise HTTPException(409, "Vulnerability changed concurrently; refresh before deciding")
        if target == "unconfirmed":
            revoked = db.execute(update(VulnerabilitySuppression).where(
                VulnerabilitySuppression.vulnerability_id == vulnerability.id, VulnerabilitySuppression.revoked_at.is_(None))
                .values(revoked_at=now, revoked_by=actor_id, revoke_reason=payload.justification)
                .execution_options(synchronize_session=False))
            detail["suppressions_revoked"] = revoked.rowcount
        if suppression:
            db.add(suppression)
        add_event(db, vulnerability, "validation_changed", actor_id=actor_id, from_state=current, to_state=target,
                  comment=payload.justification, detail=detail, now=now)
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except (IntegrityError, OperationalError) as error:
        db.rollback()
        raise HTTPException(409, "Vulnerability changed concurrently; refresh before deciding") from error
    db.refresh(vulnerability)
    return detail_after(db, vulnerability.id)


def detail_after(db, vulnerability_id):
    db.expire_all()
    return detail(db, vulnerability_id)
