"""Module G: professional VAPT reports.

A report is a frozen snapshot of findings that satisfy Milestone 3's eligibility rule
(`vulnerabilities.report_eligible`: confirmed AND the latest sign-off is an approval for the current
revision with a risk assessment). Nothing else can enter a report. A human must approve the report
before an official PDF exists. Every value that originates from a target, a client record or an
analyst is treated as untrusted: it is stripped of control characters at snapshot time and escaped
(plus transcoded to the PDF's Latin-1 font) when rendered. No network operation happens here.
"""
import json
import unicodedata
from hashlib import sha256
from io import BytesIO
from uuid import uuid4
from xml.sax.saxutils import escape

from fastapi import HTTPException
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError, OperationalError

from app.core.time import as_utc, utc_now
from app.models.admin import Admin
from app.models.assessment import AssessmentReport, AssessmentRequest
from app.models.client import Client
from app.models.jobs import Job
from app.models.report import VaptReport, VaptReportApproval, VaptReportArtifact, VaptReportEvent
from app.models.vulnerability import (Vulnerability, VulnerabilityOccurrence, VulnerabilityRiskAssessment,
                                      VulnerabilitySignoff)
from app.models.website import Website
from app.services import assessments
from app.services import vulnerabilities as vulns

SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
PRIORITY_ORDER = ("immediate", "short_term", "planned", "monitor")
PRIORITY_LABEL = {"immediate": "Immediate", "short_term": "Short term", "planned": "Planned", "monitor": "Monitor"}
OPEN_STATUSES = ("draft", "pending_approval")
MAX_EVIDENCE_LINES = 40
MAX_LINE = 300
SEVERITY_COLOR = {"critical": "#8b0000", "high": "#c0392b", "medium": "#d68910", "low": "#2471a3", "informational": "#5d6d7e"}


# --- Untrusted text handling -------------------------------------------------------------

def strip_controls(value, limit=4000, multiline=False):
    """Remove control, format (incl. bidi), surrogate and private-use characters; bound the length."""
    text = "" if value is None else str(value)
    out = []
    for ch in text[:limit]:
        category = unicodedata.category(ch)
        if ch in "\n\t" and multiline:
            out.append(ch if ch == "\n" else " ")
        elif ch in "\r\n\t":
            out.append(" ")
        elif category[0] == "C":
            continue
        else:
            out.append(ch)
    return "".join(out).strip()


def pdf_text(value, limit=4000, multiline=False):
    """Escape for reportlab's mini-markup and transcode to what the built-in Helvetica can encode."""
    text = strip_controls(value, limit, multiline)
    text = "".join(ch if ord(ch) <= 0xFF else "?" for ch in text)
    return escape(text).replace("\n", "<br/>")


def evidence_lines(value, prefix=""):
    """Flatten evidence into bounded `path: value` lines. Values are data, never markup."""
    lines = []
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            lines += evidence_lines(value[key], f"{prefix}{strip_controls(key, 60)}.")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value[:20]):
            lines += evidence_lines(item, f"{prefix}{index}.")
    else:
        rendered = json.dumps(value, ensure_ascii=True)
        lines.append(f"{prefix.rstrip('.')}: {rendered}"[:MAX_LINE])
    return lines[:MAX_EVIDENCE_LINES]


# --- Gathering eligible findings ---------------------------------------------------------

def _names(db, ids):
    return vulns._names(db, ids)


def gather(db, assessment_id):
    """Split the findings detected in one assessment into report-eligible and excluded."""
    request = db.get(AssessmentRequest, assessment_id)
    if request is None:
        raise HTTPException(404, "Assessment not found")
    job = db.get(Job, request.job_id)
    if job is None or job.status != "completed":
        raise HTTPException(409, "Only completed assessments can be reported")
    rows = db.execute(select(Vulnerability, VulnerabilityOccurrence)
                      .join(VulnerabilityOccurrence, VulnerabilityOccurrence.vulnerability_id == Vulnerability.id)
                      .where(VulnerabilityOccurrence.assessment_id == assessment_id,
                             VulnerabilityOccurrence.result == "detected")
                      .order_by(Vulnerability.check_id)).all()
    eligible, excluded = [], []
    for vulnerability, occurrence in rows:
        intact = sha256(assessments.report_bytes(occurrence.evidence)).hexdigest() == occurrence.evidence_sha256
        if vulns.report_eligible(db, vulnerability) and intact:
            eligible.append((vulnerability, occurrence))
        elif not intact:
            excluded.append({"vulnerability_id": vulnerability.id, "check_id": vulnerability.check_id,
                             "validation_state": vulnerability.validation_state, "reason": "evidence_integrity_failed"})
        else:
            state = vulnerability.validation_state
            reason = ("dismissed" if state in ("false_positive", "not_applicable")
                      else "stale_or_missing_signoff" if state == "confirmed"
                      else "unconfirmed" if vulns.current_assessment(db, vulnerability) else "unassessed")
            excluded.append({"vulnerability_id": vulnerability.id, "check_id": vulnerability.check_id,
                             "validation_state": state, "reason": reason})
    return request, eligible, excluded


def eligibility(db, assessment_id):
    request, eligible, excluded = gather(db, assessment_id)
    reasons = {}
    for item in excluded:
        reasons[item["reason"]] = reasons.get(item["reason"], 0) + 1
    return {"assessment_id": request.id, "eligible_count": len(eligible), "excluded_count": len(excluded),
            "excluded": excluded, "excluded_reasons": reasons,
            "can_generate": bool(eligible)}


def _finding(db, vulnerability, occurrence):
    signoff = db.scalar(select(VulnerabilitySignoff).where(VulnerabilitySignoff.vulnerability_id == vulnerability.id)
                        .order_by(VulnerabilitySignoff.sequence.desc()).limit(1))
    assessment = db.get(VulnerabilityRiskAssessment, signoff.risk_assessment_id)
    names = _names(db, [signoff.analyst_id, assessment.author_id])
    return {
        "vulnerability_id": vulnerability.id, "revision": vulnerability.revision, "check_id": vulnerability.check_id,
        "title": strip_controls(vulnerability.title, 200), "category": strip_controls(vulnerability.category, 80),
        "target_url": strip_controls(vulnerability.target_url, 2048),
        "severity": assessment.risk_rating, "likelihood": assessment.likelihood,
        "business_impact": assessment.business_impact,
        "business_context": strip_controls(assessment.business_context, 4000, True),
        "remediation": strip_controls(assessment.remediation, 8000, True),
        "remediation_priority": assessment.remediation_priority,
        "reproduction_steps": strip_controls(vulnerability.reproduction_steps, 8000, True),
        "evidence": occurrence.evidence, "evidence_sha256": occurrence.evidence_sha256,
        "risk_assessment_id": assessment.id, "risk_assessment_version": assessment.version,
        "signoff_id": signoff.id, "signoff_analyst": strip_controls(names.get(signoff.analyst_id), 150),
        "signoff_at": as_utc(signoff.occurred_at).isoformat(),
        "signoff_justification": strip_controls(signoff.justification, 4000, True),
    }


def _methodology(db, request):
    profile = assessments.PROFILES.get(request.profile_id, {})
    stored = db.scalar(select(AssessmentReport).where(AssessmentReport.assessment_id == request.id))
    content = stored.content if stored is not None and isinstance(stored.content, dict) else {}
    execution = content.get("execution") if isinstance(content.get("execution"), dict) else {}
    transport = content.get("transport") if isinstance(content.get("transport"), dict) else {}
    remote = profile.get("mode") == "remote_docker"
    duration = execution.get("duration_ms")
    return {
        "profile_id": request.profile_id, "profile_name": strip_controls(profile.get("name", request.profile_id), 120),
        "profile_version": profile.get("version"), "mode": profile.get("mode"), "adapter": profile.get("adapter"),
        "request_budget": profile.get("request_budget"), "redirect_budget": profile.get("redirect_budget"),
        "body_byte_limit": profile.get("body_byte_limit"),
        "tls_version": strip_controls(transport.get("tls_version"), 20) or None,
        "isolation": {
            "applicable": remote,
            "attested": remote and execution.get("isolation_attested") is True,
            "cleanup_confirmed": remote and execution.get("cleanup_confirmed") is True,
            "duration_ms": duration if type(duration) in (int, float) else None,
        },
        "source_report_sha256": stored.sha256 if stored is not None else None,
        "assessment_requested_at": as_utc(request.requested_at).isoformat(),
    }


def _scope(db, request):
    website = db.get(Website, request.website_id)
    client = db.get(Client, website.client_id)
    snapshot = request.permission_snapshot if isinstance(request.permission_snapshot, dict) else {}
    return {
        "client_id": client.id, "client_name": strip_controls(client.company_name, 200),
        "website_id": website.id, "website_name": strip_controls(website.name, 200),
        "website_url": strip_controls(website.url, 2048), "target_url": strip_controls(request.target_url, 2048),
        "target_host": strip_controls(request.target_host, 253), "authorization_id": request.authorization_id,
        "authorized_domains": [strip_controls(d, 253) for d in snapshot.get("authorized_domains", [])],
        "permitted_methods": [strip_controls(m, 80) for m in snapshot.get("permitted_methods", [])],
        "valid_from": snapshot.get("valid_from"), "valid_until": snapshot.get("valid_until"),
        "assessment_id": request.id,
    }


def summarise(scope, counts, total, excluded_count, findings):
    highest = next((s for s in SEVERITY_ORDER if counts[s]), "informational")
    immediate = sum(1 for f in findings if f["remediation_priority"] == "immediate")
    breakdown = ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s])
    text = (f"SNWebShield performed an authorised, non-intrusive HTTP security header assessment of "
            f"{scope['website_name']} ({scope['target_host']}) for {scope['client_name']}. "
            f"{total} finding{'s' if total != 1 else ''} ({breakdown}) {'were' if total != 1 else 'was'} confirmed by a "
            f"human security analyst and {'are' if total != 1 else 'is'} reported here. The highest assessed risk is "
            f"{highest}. ")
    if immediate:
        text += f"{immediate} item{'s' if immediate != 1 else ''} require{'' if immediate != 1 else 's'} immediate remediation. "
    text += (f"{excluded_count} further automated observation{'s' if excluded_count != 1 else ''} did not meet the "
             f"analyst-validation requirement and {'are' if excluded_count != 1 else 'is'} excluded from this report.")
    return text


def content_digest(report):
    """Hash of every frozen content column; recomputed before approval and download."""
    return assessments.digest({
        "title": report.title, "executive_summary": report.executive_summary, "scope": report.scope,
        "methodology": report.methodology, "findings": report.findings, "severity_counts": report.severity_counts,
        "eligible_count": report.eligible_count, "excluded_count": report.excluded_count, "excluded": report.excluded,
        "assessment_id": report.assessment_id, "revision": report.revision})


# --- PDF rendering -----------------------------------------------------------------------

def _styles():
    base = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=base["BodyText"], fontName="Helvetica", fontSize=9.5, leading=13,
                          alignment=TA_LEFT, wordWrap="CJK")
    return {
        "title": ParagraphStyle("title", parent=base["Title"], fontName="Helvetica-Bold", fontSize=22, leading=26, alignment=TA_LEFT),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=14, leading=18, spaceBefore=14, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=11, leading=14, spaceBefore=10, spaceAfter=4, wordWrap="CJK"),
        "body": body,
        "small": ParagraphStyle("small", parent=body, fontSize=8, leading=10.5, textColor=colors.HexColor("#444444")),
        "evidence": ParagraphStyle("evidence", parent=body, fontName="Courier", fontSize=7.5, leading=9.5,
                                   backColor=colors.HexColor("#f2f2f2"), borderPadding=3, leftIndent=4),
        "warn": ParagraphStyle("warn", parent=body, fontName="Helvetica-Bold", textColor=colors.HexColor("#8b0000")),
    }


def _p(text, style, limit=4000, multiline=False):
    return Paragraph(pdf_text(text, limit, multiline), style)


def _table(rows, widths, styles, header=True):
    cells = [[Paragraph(pdf_text(c, 600, True) if not isinstance(c, Paragraph) else c, styles["body"]) for c in row] for row in rows]
    table = Table(cells, colWidths=widths, repeatRows=1 if header else 0)
    commands = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b0b0b0")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
    if header:
        commands.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e3e8ee")))
    table.setStyle(TableStyle(commands))
    return table


def render_pdf(report, creator_name, approval=None, approver_name=None):
    """Render a PDF. Official output exists only for an approved report (`approval` given)."""
    official = approval is not None
    s = _styles()
    buffer = BytesIO()
    width = A4[0] - 40 * mm

    def decorate(canvas, doc):
        canvas.saveState()
        if not official:
            canvas.setFont("Helvetica-Bold", 54)
            canvas.setFillColor(colors.Color(0.85, 0.2, 0.2, alpha=0.12))
            canvas.translate(A4[0] / 2, A4[1] / 2)
            canvas.rotate(45)
            canvas.drawCentredString(0, 0, "DRAFT - NOT APPROVED")
            canvas.rotate(-45)
            canvas.translate(-A4[0] / 2, -A4[1] / 2)
        canvas.setFillColor(colors.HexColor("#555555"))
        canvas.setFont("Helvetica", 7.5)
        status = "OFFICIAL - APPROVED" if official else "DRAFT - NOT FOR RELEASE"
        canvas.drawString(20 * mm, 11 * mm, f"SNWebShield VAPT report {report.id} rev {report.revision} | {status} | Confidential")
        canvas.drawRightString(A4[0] - 20 * mm, 11 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm,
                            bottomMargin=20 * mm, invariant=1, title=pdf_text(report.title, 200).replace("&amp;", "&")[:200],
                            author="SNWebShield", subject="VAPT report", creator="SNWebShield")
    scope, method, findings = report.scope, report.methodology, report.findings
    story = [Paragraph("SNWebShield", s["small"]), _p(report.title, s["title"], 300),
             _p(f"Client: {scope['client_name']}  |  Target: {scope['target_host']}  |  Revision {report.revision}", s["body"]),
             _p(f"Generated {as_utc(report.created_at).isoformat()} (UTC)", s["small"])]
    if not official:
        story += [Spacer(1, 6), _p("DRAFT. This document has not been approved by a human analyst and must not be released.", s["warn"])]

    story += [_p("1. Executive summary", s["h1"]), _p(report.executive_summary, s["body"])]

    story += [_p("2. Client and domain scope", s["h1"]),
              _table([["Item", "Value"], ["Client", scope["client_name"]], ["Website", f"{scope['website_name']} ({scope['website_url']})"],
                      ["Assessed target", scope["target_url"]], ["Authorised domains", ", ".join(scope["authorized_domains"])],
                      ["Permitted methods", ", ".join(scope["permitted_methods"])],
                      ["Authorisation window (UTC)", f"{scope.get('valid_from')} to {scope.get('valid_until')}"],
                      ["Authorisation / assessment", f"{scope['authorization_id']} / {scope['assessment_id']}"]],
                     [45 * mm, width - 45 * mm], s)]

    iso = method["isolation"]
    if not iso["applicable"]:
        isolation = ("Not applicable. This profile sends one HEAD request from the trusted local broker and analyses the "
                     "stored headers in-process; no container is used.")
    elif iso["attested"]:
        isolation = ("Attested. The header analysis ran in a disposable container on the remote Docker host with networking "
                     "disabled, a non-root user, a read-only root filesystem and CPU, memory, process and time limits. The "
                     "runner inspected the created container and refused to start it on any mismatch. "
                     f"Cleanup confirmed: {'yes' if iso['cleanup_confirmed'] else 'no'}.")
    else:
        isolation = ("Not attested. The installed remote runner predates per-run isolation inspection, so isolation is "
                     "not claimed for this run. "
                     f"Cleanup confirmed: {'yes' if iso['cleanup_confirmed'] else 'no'}.")
    story += [_p("3. Assessment methodology and isolation attestation", s["h1"]),
              _p(f"Profile: {method['profile_name']} (v{method.get('profile_version')}, {method.get('mode')}). "
                 f"Request budget: {method.get('request_budget')} HEAD request, redirects followed: "
                 f"{method.get('redirect_budget')}, response body bytes read: {method.get('body_byte_limit')}. "
                 f"TLS version observed: {method.get('tls_version') or 'n/a'}.", s["body"]),
              Spacer(1, 3), _p(f"Isolation: {isolation}", s["body"]), Spacer(1, 3),
              _p("Only non-intrusive checks were performed within the written authorisation. All scanner output and target "
                 "responses were treated as untrusted data, and every finding below was validated and signed off by a human "
                 "security analyst. No exploitation was attempted.", s["body"]),
              _p(f"Source scanner report SHA-256: {method.get('source_report_sha256')}", s["small"])]

    counts = report.severity_counts
    story += [_p("4. Severity breakdown", s["h1"]),
              _table([["Severity"] + [x.capitalize() for x in SEVERITY_ORDER] + ["Total"],
                      ["Validated findings"] + [str(counts[x]) for x in SEVERITY_ORDER] + [str(report.eligible_count)]],
                     [34 * mm] + [(width - 34 * mm - 16 * mm) / 5] * 5 + [16 * mm], s)]

    story.append(_p("5. Validated technical findings", s["h1"]))
    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["title"]))
    for number, f in enumerate(ordered, 1):
        color = SEVERITY_COLOR[f["severity"]]
        block = [Paragraph(f'5.{number} {pdf_text(f["title"], 200)} <font color="{color}">[{f["severity"].upper()}]</font>', s["h2"]),
                 _table([["Assessed risk", f"{f['severity']} (likelihood: {f['likelihood']}, business impact: {f['business_impact']})"],
                         ["Target", f["target_url"]], ["Category / check", f"{f['category']} / {f['check_id']}"],
                         ["Business context", f["business_context"]]], [38 * mm, width - 38 * mm], s, header=False),
                 Spacer(1, 3), _p("Evidence (untrusted target data, shown as inert text)", s["small"])]
        lines = evidence_lines({"observation": f["evidence"].get("observation"), "transport": f["evidence"].get("transport")})
        block.append(Paragraph("<br/>".join(pdf_text(line, MAX_LINE) for line in lines) or "No evidence recorded.", s["evidence"]))
        block += [Paragraph(f"Evidence SHA-256: {pdf_text(f['evidence_sha256'], 64)}", s["small"]), Spacer(1, 3),
                  _p("Reproduction steps", s["small"]), _p(f["reproduction_steps"], s["body"], 8000, True)]
        story += [KeepTogether(block[:2]), *block[2:]]

    story.append(_p("6. Remediation recommendations", s["h1"]))
    for priority in PRIORITY_ORDER:
        group = [f for f in ordered if f["remediation_priority"] == priority]
        if not group:
            continue
        story.append(_p(f"{PRIORITY_LABEL[priority]} priority", s["h2"]))
        for f in group:
            story += [Paragraph(f"<b>{pdf_text(f['title'], 200)}</b> ({pdf_text(f['severity'])})", s["body"]),
                      _p(f["remediation"], s["body"], 8000, True), Spacer(1, 4)]

    rows = [["Finding", "Signed off by (UTC)"]] + [[f["title"], f"{f['signoff_analyst']} at {f['signoff_at']}"] for f in ordered]
    story += [_p("7. Analyst approval and sign-off", s["h1"]),
              _p("Finding-level sign-offs", s["h2"]), _table(rows, [width * 0.55, width * 0.45], s),
              _p("Report approval", s["h2"])]
    if official:
        story += [_table([["Decision", "Approved for release"], ["Approved by", approver_name or "analyst"],
                          ["Approved at (UTC)", as_utc(approval.occurred_at).isoformat()],
                          ["Justification", approval.justification],
                          ["Report content SHA-256", approval.content_sha256], ["Prepared by", creator_name]],
                         [45 * mm, width - 45 * mm], s, header=False)]
    else:
        story += [_p("PENDING. No analyst has approved this report. Prepared by "
                     f"{creator_name}. It must not be shared with the client until approved.", s["warn"])]
    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    data = buffer.getvalue()
    if not data.startswith(b"%PDF-"):
        raise RuntimeError("PDF renderer produced invalid output")
    return data


# --- Persistence and workflow -----------------------------------------------------------

def add_event(db, report_id, action, actor_id, detail=None, now=None):
    sequence = (db.scalar(select(func.max(VaptReportEvent.sequence)).where(VaptReportEvent.report_id == report_id)) or 0) + 1
    row = VaptReportEvent(id=str(uuid4()), report_id=report_id, sequence=sequence, actor_id=actor_id, action=action,
                          detail=detail or {}, occurred_at=now or utc_now())
    db.add(row)
    db.flush()
    return row


def _artifact(report_id, kind, data, now):
    return VaptReportArtifact(id=str(uuid4()), report_id=report_id, kind=kind, sha256=sha256(data).hexdigest(),
                              size=len(data), content=data, created_at=now)


def serial(db, report, names=None):
    names = names or _names(db, [report.created_by, report.decided_by])
    approval = db.scalar(select(VaptReportApproval).where(VaptReportApproval.report_id == report.id))
    value = {c.name: as_utc(v).isoformat() if c.name.endswith("_at") and v is not None else v
             for c in report.__table__.columns for v in [getattr(report, c.name)]}
    value.update(created_by_name=names.get(report.created_by), decided_by_name=names.get(report.decided_by),
                 can_download_official=report.status == "approved" and report.official_pdf_sha256 is not None,
                 can_decide=report.status in OPEN_STATUSES,
                 approval=None if approval is None else {
                     "decision": approval.decision, "analyst_id": approval.analyst_id,
                     "justification": approval.justification, "content_sha256": approval.content_sha256,
                     "pdf_sha256": approval.pdf_sha256, "occurred_at": as_utc(approval.occurred_at).isoformat()})
    return value


def listing(db, *, status=None, assessment_id=None, limit=50, offset=0):
    statement = select(VaptReport)
    if status: statement = statement.where(VaptReport.status == status)
    if assessment_id: statement = statement.where(VaptReport.assessment_id == assessment_id)
    total = db.scalar(select(func.count()).select_from(statement.subquery()))
    rows = list(db.scalars(statement.order_by(VaptReport.created_at.desc(), VaptReport.id).offset(offset).limit(limit)))
    names = _names(db, [r.created_by for r in rows] + [r.decided_by for r in rows])
    items = [{k: v for k, v in serial(db, r, names).items() if k not in ("findings", "scope", "methodology", "excluded")}
             for r in rows]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def get(db, report_id):
    row = db.get(VaptReport, report_id)
    if row is None:
        raise HTTPException(404, "Report not found")
    return row


def detail(db, report_id):
    return serial(db, get(db, report_id))


def generate(db, assessment_id, actor_id):
    request, eligible, excluded = gather(db, assessment_id)
    if not eligible:
        raise HTTPException(409, "No report-eligible findings: findings must be confirmed with a current analyst sign-off")
    now = utc_now()
    findings = [_finding(db, v, o) for v, o in eligible]
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    scope = _scope(db, request)
    previous = db.scalar(select(func.max(VaptReport.revision)).where(VaptReport.assessment_id == assessment_id)) or 0
    report = VaptReport(
        id=str(uuid4()), assessment_id=assessment_id, client_id=scope["client_id"], website_id=scope["website_id"],
        authorization_id=request.authorization_id, revision=previous + 1, status="draft",
        title=strip_controls(f"VAPT report: {scope['website_name']}", 300),
        executive_summary=summarise(scope, counts, len(findings), len(excluded), findings),
        scope=scope, methodology=_methodology(db, request), findings=findings, severity_counts=counts,
        eligible_count=len(findings), excluded_count=len(excluded), excluded=excluded, content_sha256="",
        created_by=actor_id, created_at=now)
    report.content_sha256 = content_digest(report)
    names = _names(db, [actor_id])
    pdf = render_pdf(report, names.get(actor_id) or "analyst")
    report.draft_pdf_sha256 = sha256(pdf).hexdigest()
    try:
        # A newer draft replaces older open drafts of the same assessment; approved reports stay in force.
        for old in db.scalars(select(VaptReport).where(VaptReport.assessment_id == assessment_id,
                                                         VaptReport.status.in_(OPEN_STATUSES))):
            old.status = "superseded"
            add_event(db, old.id, "superseded", actor_id, {"superseded_by_revision": report.revision}, now)
        db.add(report)
        db.flush()
        db.add(_artifact(report.id, "draft", pdf, now))
        add_event(db, report.id, "generated", actor_id, {
            "revision": report.revision, "eligible_count": report.eligible_count, "excluded_count": report.excluded_count,
            "content_sha256": report.content_sha256, "draft_pdf_sha256": report.draft_pdf_sha256}, now)
        db.commit()
    except (IntegrityError, OperationalError) as error:
        db.rollback()
        raise HTTPException(409, "Another report was generated concurrently; retry") from error
    return detail(db, report.id)


def _verify_content(report):
    if content_digest(report) != report.content_sha256:
        raise HTTPException(409, "Report content failed its integrity check; generate a new revision")


def _still_eligible(db, report):
    stale = []
    for f in report.findings:
        vulnerability = db.get(Vulnerability, f["vulnerability_id"])
        last = vulnerability and db.scalar(select(VulnerabilitySignoff).where(
            VulnerabilitySignoff.vulnerability_id == vulnerability.id).order_by(VulnerabilitySignoff.sequence.desc()).limit(1))
        if (vulnerability is None or not vulns.report_eligible(db, vulnerability)
                or vulnerability.revision != f["revision"] or last.id != f["signoff_id"]):
            stale.append(f["check_id"])
    return stale


def decide(db, report_id, actor_id, decision, justification):
    report = get(db, report_id)
    if report.status not in OPEN_STATUSES:
        raise HTTPException(409, f"A {report.status} report cannot be decided")
    now = utc_now()
    _verify_content(report)
    approval_pdf = None
    approval = VaptReportApproval(id=str(uuid4()), report_id=report.id, decision=decision, analyst_id=actor_id,
                                  justification=strip_controls(justification, 4000, True),
                                  content_sha256=report.content_sha256, pdf_sha256=None, occurred_at=now)
    artifact = None
    if decision == "approved":
        stale = _still_eligible(db, report)
        if stale:
            raise HTTPException(409, "Findings changed since this report was generated (" + ", ".join(stale)
                                + "); generate a new revision")
        names = _names(db, [actor_id, report.created_by])
        approval_pdf = render_pdf(report, names.get(report.created_by) or "analyst", approval, names.get(actor_id) or "analyst")
        artifact = _artifact(report.id, "official", approval_pdf, now)
        approval.pdf_sha256 = artifact.sha256
    try:
        values = {"status": decision, "decided_by": actor_id, "decided_at": now}
        if artifact:
            values["official_pdf_sha256"] = artifact.sha256
        changed = db.execute(update(VaptReport).where(VaptReport.id == report.id, VaptReport.status.in_(OPEN_STATUSES))
                             .values(**values).execution_options(synchronize_session=False))
        if changed.rowcount != 1:
            raise HTTPException(409, "Report was decided concurrently; refresh")
        db.add(approval)
        if artifact:
            db.add(artifact)
            for old in db.scalars(select(VaptReport).where(VaptReport.assessment_id == report.assessment_id,
                                                             VaptReport.status == "approved", VaptReport.id != report.id)):
                db.execute(update(VaptReport).where(VaptReport.id == old.id).values(status="superseded")
                           .execution_options(synchronize_session=False))
                add_event(db, old.id, "superseded", actor_id, {"superseded_by_report": report.id}, now)
        add_event(db, report.id, decision, actor_id,
                  {"content_sha256": report.content_sha256, "official_pdf_sha256": artifact.sha256 if artifact else None}, now)
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except (IntegrityError, OperationalError) as error:
        db.rollback()
        raise HTTPException(409, "Report changed concurrently; refresh") from error
    db.expire_all()
    return detail(db, report.id)


def events(db, report_id, limit, offset):
    get(db, report_id)
    rows = list(db.scalars(select(VaptReportEvent).where(VaptReportEvent.report_id == report_id)
                           .order_by(VaptReportEvent.sequence.desc()).offset(offset).limit(limit)))
    names = _names(db, [r.actor_id for r in rows])
    return [{**{c.name: as_utc(v).isoformat() if c.name.endswith("_at") else v
                for c in r.__table__.columns for v in [getattr(r, c.name)]}, "actor_name": names.get(r.actor_id)} for r in rows]


def download(db, report_id, actor_id, kind):
    """Return verified PDF bytes. `official` is available only for an approved report."""
    report = get(db, report_id)
    if kind == "official" and (report.status != "approved" or not report.official_pdf_sha256):
        raise HTTPException(409, "Only an approved report can be downloaded as an official PDF")
    expected = report.official_pdf_sha256 if kind == "official" else report.draft_pdf_sha256
    artifact = db.scalar(select(VaptReportArtifact).where(VaptReportArtifact.report_id == report.id,
                                                           VaptReportArtifact.kind == kind))
    if (artifact is None or sha256(artifact.content).hexdigest() != artifact.sha256 or artifact.sha256 != expected
            or len(artifact.content) != artifact.size or not artifact.content.startswith(b"%PDF-")):
        raise HTTPException(409, "PDF artifact failed its integrity check")
    add_event(db, report.id, "official_downloaded" if kind == "official" else "preview_downloaded", actor_id,
              {"pdf_sha256": artifact.sha256})
    db.commit()
    return artifact.content, artifact.sha256
