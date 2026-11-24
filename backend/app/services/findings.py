"""Central work queue derived from latest analyst decisions. No scan execution."""
from datetime import timedelta, timezone
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import case, func, or_, select
from sqlalchemy.exc import IntegrityError, OperationalError

from app.core.time import as_utc, utc_now
from app.models.assessment import AssessmentReport, AssessmentRequest, FindingDueDate, ObservationReview
from app.models.client import Client
from app.models.website import Website
from app.models.jobs import Job
from app.services import job_engine, observation_reviews


def today():
    # Due dates are calendar dates in the user's business timezone (no DST).
    return utc_now().astimezone(timezone(timedelta(hours=5, minutes=30))).date()


def latest(table):
    return select(table.report_id, table.check_id, func.max(table.revision).label("revision")).group_by(
        table.report_id, table.check_id).subquery()


def join_latest(table, subquery):
    return (table.report_id == subquery.c.report_id) & (table.check_id == subquery.c.check_id) & (table.revision == subquery.c.revision)


def deadline_serial(row):
    return {"id": row.id, "revision": row.revision, "review_id": row.review_id,
            "due_date": row.due_date.isoformat() if row.due_date else None, "note": row.note,
            "updated_by": row.updated_by, "updated_at": as_utc(row.updated_at).isoformat()}


def query():
    reviews, dates = latest(ObservationReview), latest(FindingDueDate)
    return select(ObservationReview, AssessmentRequest, AssessmentReport, Website, Client, FindingDueDate).select_from(ObservationReview).join(
        reviews, join_latest(ObservationReview, reviews)).join(AssessmentReport, AssessmentReport.id == ObservationReview.report_id).join(
        AssessmentRequest, AssessmentRequest.id == AssessmentReport.assessment_id).join(Job, Job.id == AssessmentRequest.job_id).join(
        Website, Website.id == AssessmentRequest.website_id).join(Client, Client.id == Website.client_id).outerjoin(
        dates, (dates.c.report_id == ObservationReview.report_id) & (dates.c.check_id == ObservationReview.check_id)).outerjoin(
        FindingDueDate, join_latest(FindingDueDate, dates)).where(ObservationReview.disposition == "confirmed", Job.status == "completed")


def listing(db, *, client_id=None, website_id=None, severity=None, status=None, owner="", search="", overdue_only=False, limit=50, offset=0):
    day = today()
    overdue = (FindingDueDate.due_date < day) & (ObservationReview.remediation_status != "resolved")
    statement = query()
    if client_id: statement = statement.where(Client.id == client_id)
    if website_id: statement = statement.where(Website.id == website_id)
    if severity: statement = statement.where(ObservationReview.severity == severity)
    if status: statement = statement.where(ObservationReview.remediation_status == status)
    if owner: statement = statement.where(func.lower(ObservationReview.owner).contains(owner.lower(), autoescape=True))
    if search:
        statement = statement.where(or_(*(func.lower(column).contains(search.lower(), autoescape=True)
            for column in (Client.company_name, Website.name, AssessmentRequest.target_host, ObservationReview.check_id))))
    if overdue_only: statement = statement.where(overdue)
    counts = db.execute(statement.with_only_columns(
        func.count().label("total"),
        *[func.sum(case((ObservationReview.remediation_status == value, 1), else_=0)).label(value)
          for value in ("open", "in_progress", "ready_for_retest", "resolved")],
        func.sum(case((overdue, 1), else_=0)).label("overdue"), maintain_column_froms=True)).mappings().one()
    priority = case({"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}, value=ObservationReview.severity, else_=5)
    rows = db.execute(statement.order_by(priority, FindingDueDate.due_date.asc().nulls_last(),
        ObservationReview.reviewed_at.desc(), ObservationReview.id).offset(offset).limit(limit))
    items = []
    for review, request, report, website, client, date in rows:
        items.append({"assessment_id": request.id, "check_id": review.check_id,
            "client_id": client.id, "client_name": client.company_name, "website_id": website.id, "website_name": website.name,
            "target_url": request.target_url, "source_report_sha256": report.sha256,
            "review": observation_reviews.serial(review), "deadline": deadline_serial(date) if date else None,
            "overdue": bool(date and date.due_date and date.due_date < day and review.remediation_status != "resolved")})
    return {"items": items, "summary": {k: int(v or 0) for k, v in counts.items()},
            "limit": limit, "offset": offset, "today": day.isoformat(), "timezone": "Asia/Kolkata"}


def current(db, assessment_id, check):
    request, report = observation_reviews.verified_report(db, assessment_id)
    if check not in observation_reviews.observations(report):
        raise HTTPException(404, "Observation not found")
    review = db.scalar(select(ObservationReview).where(ObservationReview.report_id == report.id,
        ObservationReview.check_id == check).order_by(ObservationReview.revision.desc()).limit(1))
    if not review or review.disposition != "confirmed":
        raise HTTPException(409, "This observation is not currently analyst-confirmed; refresh the findings list")
    date = db.scalar(select(FindingDueDate).where(FindingDueDate.report_id == report.id,
        FindingDueDate.check_id == check).order_by(FindingDueDate.revision.desc()).limit(1))
    return request, report, review, date


def detail(db, assessment_id, check):
    request, report, review, date = current(db, assessment_id, check)
    return {"assessment_id": request.id, "check_id": check, "target_url": request.target_url,
            "source_report_sha256": report.sha256,
            "observation": observation_reviews.observations(report)[check], "review": observation_reviews.serial(review),
            "deadline": deadline_serial(date) if date else None}


def save_deadline(db, assessment_id, check, actor_id, payload):
    request, report, review, date = current(db, assessment_id, check)
    if review.revision != payload.expected_review_revision or (date.revision if date else 0) != payload.expected_revision:
        raise HTTPException(409, "Finding changed; refresh before saving its deadline")
    row = FindingDueDate(id=str(uuid4()), report_id=report.id, check_id=check, review_id=review.id,
        revision=payload.expected_revision + 1, due_date=payload.due_date, note=payload.note,
        updated_by=actor_id, updated_at=utc_now())
    try:
        db.add(row)
        job_engine.event(db, "finding_deadline_recorded", db.get(Job, request.job_id), actor_id=actor_id,
            detail={"deadline_id": row.id, "check_id": check, "revision": row.revision,
                    "due_date": row.due_date.isoformat() if row.due_date else None, "review_id": review.id})
        db.commit()
    except (IntegrityError, OperationalError) as error:
        db.rollback()
        raise HTTPException(409, "Finding deadline changed concurrently; refresh before saving") from error
    return deadline_serial(row)
