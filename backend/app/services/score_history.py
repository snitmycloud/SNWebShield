"""The score after each finished full scan, for the trend chart.

A point is stored when a full scan finishes (after its finding states are updated, so accepted and fixed findings are already set
aside). Scans from before this existed are filled in the first time the trend is read (from the findings stored with each scan).
"""
from sqlalchemy import select

from app.core.time import as_utc, utc_now
from app.models.scan import FindingState, Scan, ScanFinding
from app.models.watch import ScoreHistory
from app.services import finding_states, scoring

FINISHED = ("completed", "incomplete")


def _score(db, scan: Scan, states: dict) -> dict:
    now = utc_now()
    rows = list(db.scalars(select(ScanFinding).where(ScanFinding.scan_id == scan.id)))

    def set_aside(item):
        state = states.get(item["fingerprint"])
        return bool(state and (state.status == "fixed" or finding_states.accepted_active(state, now)))
    return scoring.summarize([{"severity": r.severity, "confidence": r.confidence, "group": r.group, "fingerprint": r.fingerprint} for r in rows],
                             incomplete=scan.status == "incomplete", excluded=set_aside)


def record(db, scan: Scan, *, use_states: bool = True) -> ScoreHistory | None:
    if scan.scan_type == "recheck" or scan.status not in FINISHED:
        return None
    existing = db.scalar(select(ScoreHistory).where(ScoreHistory.scan_id == scan.id))
    if existing is not None:
        return existing
    states = finding_states.states_for(db, scan.website_id) if use_states else {}
    summary = _score(db, scan, states)
    row = ScoreHistory(website_id=scan.website_id, scan_id=scan.id, scored_at=as_utc(scan.ended_at or scan.requested_at), score=summary["score"],
                       grade=summary["grade"], counts=summary["counts"], incomplete=scan.status == "incomplete")
    db.add(row)
    db.flush()
    return row


def trend(db, website_id: int, limit: int = 60) -> list[dict]:
    """Oldest first. Fills in finished scans that have no point yet (older scans are scored as they were, without later accept/fix choices)."""
    have = set(db.scalars(select(ScoreHistory.scan_id).where(ScoreHistory.website_id == website_id)))
    missing = [s for s in db.scalars(select(Scan).where(Scan.website_id == website_id, Scan.scan_type != "recheck", Scan.status.in_(FINISHED)))
               if s.id not in have]
    for scan in missing:
        record(db, scan, use_states=False)
    if missing:
        db.commit()
    rows = list(db.scalars(select(ScoreHistory).where(ScoreHistory.website_id == website_id).order_by(ScoreHistory.scored_at.desc()).limit(limit)))
    return [{"scan_id": r.scan_id, "at": as_utc(r.scored_at).isoformat(), "score": r.score, "grade": r.grade, "incomplete": r.incomplete,
             "counts": r.counts} for r in reversed(rows)]
