"""Closed-assessment lock.

While an assessment has an *active* closure (a closure with no reopening record), every finding that
was detected in it is frozen: its sign-off, risk assessment and remediation state cannot change, and no
retest can be requested. A closure is lifted only by `remediation.reopen_closure`, which appends an
immutable reopening record with an actor and a reason. Comments stay allowed (they are append-only
notes and never change a state).
"""
from fastapi import HTTPException
from sqlalchemy import exists, select

from app.models.remediation import AssessmentClosure
from app.models.security import ClosureReopening
from app.models.vulnerability import VulnerabilityOccurrence


def active_closure(db, assessment_id):
    return db.scalar(select(AssessmentClosure).where(
        AssessmentClosure.assessment_id == assessment_id,
        ~exists().where(ClosureReopening.closure_id == AssessmentClosure.id))
        .order_by(AssessmentClosure.generation.desc()).limit(1))


def locking_closure(db, vulnerability_id):
    """The active closure of any assessment in which this finding was detected, if one exists."""
    return db.scalar(select(AssessmentClosure).join(
        VulnerabilityOccurrence, VulnerabilityOccurrence.assessment_id == AssessmentClosure.assessment_id).where(
        VulnerabilityOccurrence.vulnerability_id == vulnerability_id, VulnerabilityOccurrence.result == "detected",
        ~exists().where(ClosureReopening.closure_id == AssessmentClosure.id))
        .order_by(AssessmentClosure.closed_at.desc()).limit(1))


def assert_unlocked(db, vulnerability_id):
    closure = locking_closure(db, vulnerability_id)
    if closure is not None:
        raise HTTPException(409, "This finding belongs to a closed assessment and is locked; "
                                 "formally reopen the assessment closure first")
