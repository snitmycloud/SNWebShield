"""Historical analyst review and immutable export; never performs network operations."""
from copy import deepcopy
from hashlib import sha256
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, OperationalError

from app.core.time import as_utc, utc_now
from app.models.assessment import AssessmentRequest, AssessmentReport, ObservationReview, ReviewedAssessmentExport
from app.models.jobs import Job
from app.services import assessments, job_engine


def verified_report(db, assessment_id):
    request = assessments.get_request(db, assessment_id)
    job = db.get(Job, request.job_id)
    report = db.scalar(select(AssessmentReport).where(AssessmentReport.assessment_id == request.id))
    if not report or not job or job.status != "completed":
        raise HTTPException(409, "A completed assessment report is required")
    data = assessments.report_bytes(report.content)
    if len(data) != report.size or sha256(data).hexdigest() != report.sha256:
        raise HTTPException(409, "Source report integrity check failed")
    return request, report


def observations(report):
    return {item["check"]: item for item in report.content["analysis"]["observations"]}


def serial(review):
    return {column.name: as_utc(value).isoformat() if column.name == "reviewed_at" else value
            for column in review.__table__.columns for value in [getattr(review, column.name)]}


def latest_reviews(db, report_id):
    latest = select(ObservationReview.check_id, func.max(ObservationReview.revision).label("revision")).where(
        ObservationReview.report_id == report_id).group_by(ObservationReview.check_id).subquery()
    rows = db.scalars(select(ObservationReview).join(latest,
        (ObservationReview.check_id == latest.c.check_id) & (ObservationReview.revision == latest.c.revision))
        .where(ObservationReview.report_id == report_id))
    return {row.check_id: row for row in rows}


def summary(db, assessment_id):
    request, report = verified_report(db, assessment_id)
    latest = latest_reviews(db, report.id)
    items = [{"observation": item, "review": serial(latest[check]) if check in latest else None}
             for check, item in observations(report).items()]
    exports = db.scalars(select(ReviewedAssessmentExport).where(ReviewedAssessmentExport.assessment_id == request.id)
                        .order_by(ReviewedAssessmentExport.created_at.desc(), ReviewedAssessmentExport.id).limit(20))
    return {"source_report_id": report.id, "source_report_sha256": report.sha256,
            "total": len(items), "reviewed": sum(item["review"] is not None for item in items),
            "observations": items, "exports": [{"id": e.id, "created_at": as_utc(e.created_at).isoformat(),
                "created_by": e.created_by, "sha256": e.sha256, "size": e.size} for e in exports]}


def validate_retest(db, original, check, payload):
    if not payload.retest_assessment_id:
        if payload.remediation_status == "resolved":
            raise HTTPException(422, "Resolution requires a later successful retest and resolution notes")
        return
    retest, report = verified_report(db, str(payload.retest_assessment_id))
    original_job, retest_job = db.get(Job, original.job_id), db.get(Job, retest.job_id)
    if (retest.id == original.id or retest.website_id != original.website_id or retest.target_url != original.target_url
            or not original_job.completed_at or as_utc(retest.requested_at) <= as_utc(original_job.completed_at)
            or not retest_job.completed_at or check not in observations(report)):
        raise HTTPException(422, "Retest must be a later completed assessment of the same website and exact target")


def save(db, assessment_id, check, actor_id, payload):
    request, report = verified_report(db, assessment_id)
    if check not in observations(report):
        raise HTTPException(404, "Observation not found in this assessment")
    current = db.scalar(select(ObservationReview).where(ObservationReview.report_id == report.id,
        ObservationReview.check_id == check).order_by(ObservationReview.revision.desc()).limit(1))
    if (current.revision if current else 0) != payload.expected_revision:
        raise HTTPException(409, "Review changed; refresh before saving")
    validate_retest(db, request, check, payload)
    values = payload.model_dump(exclude={"expected_revision", "human_validation_confirmed"})
    if values["retest_assessment_id"] is not None:
        values["retest_assessment_id"] = str(values["retest_assessment_id"])
    review = ObservationReview(id=str(uuid4()), report_id=report.id, check_id=check,
        revision=payload.expected_revision + 1, reviewer_id=actor_id, reviewed_at=utc_now(), **values)
    try:
        db.add(review)
        job_engine.event(db, "observation_review_recorded", db.get(Job, request.job_id), actor_id=actor_id,
            detail={"review_id": review.id, "check_id": check, "revision": review.revision,
                    "disposition": review.disposition, "remediation_status": review.remediation_status,
                    "source_report_sha256": report.sha256})
        db.commit()
    except (IntegrityError, OperationalError) as error:
        db.rollback()
        raise HTTPException(409, "Review changed concurrently; refresh before saving") from error
    return serial(review)


def create_export(db, assessment_id, actor_id):
    request, report = verified_report(db, assessment_id)
    latest = latest_reviews(db, report.id)
    checks = observations(report)
    if not checks or any(check not in latest for check in checks):
        raise HTTPException(409, "Review every observation before exporting a reviewed report")
    export_id, now = str(uuid4()), utc_now()
    reviews = [serial(latest[check]) for check in checks]
    content = {"schema_version": 1, "report_type": "analyst_reviewed_tcp_port_assessment" if request.profile_id == assessments.NMAP_PROFILE_ID else "analyst_reviewed_header_assessment",
        "id": export_id, "assessment_id": request.id, "website_id": request.website_id,
        "target_url": request.target_url, "created_at": as_utc(now).isoformat(), "created_by": actor_id,
        "source_report": {"id": report.id, "sha256": report.sha256, "size": report.size, "content": deepcopy(report.content)},
        "analyst_reviews": reviews,
        "summary": {"total": len(checks), "reviewed": len(reviews),
            "analyst_confirmed": sum(r["disposition"] == "confirmed" for r in reviews),
            "unresolved_confirmed": sum(r["disposition"] == "confirmed" and r["remediation_status"] != "resolved" for r in reviews),
            "resolved": sum(r["remediation_status"] == "resolved" for r in reviews)},
        "limitations": ["Analyst decisions are separate from immutable scanner observations.",
            "Resolved means analyst-reviewed remediation with a linked retest; no automatic security certification.",
            "This snapshot does not change when later review revisions are recorded."]}
    data = assessments.report_bytes(content)
    if len(data) > 2097152:
        raise HTTPException(413, "Reviewed report exceeds export size limit")
    export = ReviewedAssessmentExport(id=export_id, assessment_id=request.id, created_by=actor_id,
        created_at=now, content=content, sha256=sha256(data).hexdigest(), size=len(data))
    db.add(export)
    job_engine.event(db, "reviewed_assessment_export_created", db.get(Job, request.job_id), actor_id=actor_id,
                     detail={"export_id": export.id, "sha256": export.sha256,
                             "review_revisions": {check: latest[check].revision for check in checks}})
    db.commit()
    return {"id": export.id, "sha256": export.sha256, "size": export.size, "created_at": as_utc(now).isoformat()}
