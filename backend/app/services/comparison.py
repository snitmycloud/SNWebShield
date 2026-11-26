"""Scan comparison: what is NEW, FIXED, UNCHANGED (or could not be confirmed) since the previous scan of the same website.

Baseline (owner-approved): the previous full scan, completed or incomplete. A finding counts as FIXED only if the step that produces
it finished OK in the newer scan; otherwise it is "could not confirm" and is never called fixed. Rechecks are not scans of the whole
website and are never used as a baseline.
"""
from sqlalchemy import select

from app.core.time import as_utc
from app.models.scan import Scan, ScanFinding
from app.services import finding_states

FINISHED = ("completed", "incomplete")
MAX_LISTED = 100


def previous_scan(db, scan: Scan) -> Scan | None:
    return db.scalar(select(Scan).where(Scan.website_id == scan.website_id, Scan.id != scan.id, Scan.scan_type != "recheck",
                                        Scan.status.in_(FINISHED), Scan.requested_at < scan.requested_at)
                     .order_by(Scan.requested_at.desc()).limit(1))


def _brief(row) -> dict:
    return {"fingerprint": row.fingerprint, "title": row.title, "severity": row.severity, "location": row.location, "check_id": row.check_id,
            "confidence": row.confidence}


def compare(db, scan: Scan) -> dict:
    if scan.scan_type == "recheck" or scan.status not in FINISHED:
        return {"previous": None, "counts": {"new": 0, "fixed": 0, "unchanged": 0, "could_not_confirm": 0}, "new": [], "fixed": [], "unchanged": [],
                "could_not_confirm": []}
    before = previous_scan(db, scan)
    now_rows = {r.fingerprint: r for r in db.scalars(select(ScanFinding).where(ScanFinding.scan_id == scan.id))}
    if before is None:
        return {"previous": None, "counts": {"new": 0, "fixed": 0, "unchanged": len(now_rows), "could_not_confirm": 0}, "new": [], "fixed": [],
                "unchanged": [_brief(r) for r in list(now_rows.values())[:MAX_LISTED]], "could_not_confirm": [], "first_scan": True}
    old_rows = {r.fingerprint: r for r in db.scalars(select(ScanFinding).where(ScanFinding.scan_id == before.id))}
    steps = (scan.result or {}).get("steps") or {}
    new = [_brief(r) for fp, r in now_rows.items() if fp not in old_rows]
    unchanged = [_brief(r) for fp, r in now_rows.items() if fp in old_rows]
    fixed, unsure = [], []
    for fp, row in old_rows.items():
        if fp in now_rows:
            continue
        (fixed if finding_states.step_finished_ok(steps, row.check_id) else unsure).append(_brief(row))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for group in (new, fixed, unchanged, unsure):
        group.sort(key=lambda f: (order.get(f["severity"], 9), f["title"]))
    return {
        "previous": {"scan_id": before.id, "scanned_at": as_utc(before.ended_at or before.requested_at).isoformat(), "status": before.status},
        "counts": {"new": len(new), "fixed": len(fixed), "unchanged": len(unchanged), "could_not_confirm": len(unsure)},
        "new": new[:MAX_LISTED], "fixed": fixed[:MAX_LISTED], "unchanged": unchanged[:MAX_LISTED], "could_not_confirm": unsure[:MAX_LISTED],
    }
