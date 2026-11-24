"""Report-only retention sweep for uploaded written-authorisation documents (risk R9).

Lists documents whose retention period has ended and what still blocks their deletion. It deletes
nothing: a human withdraws and purges each one with a recorded reason (`POST /evidence/{key}/purge`).
Prints identifiers and hashes only, never file contents.
"""
from app.db.session import SessionLocal
from app.services import evidence


def main() -> int:
    with SessionLocal() as db:
        rows = evidence.retention_report(db)
    if not rows:
        print("No evidence documents are past their retention date.")
        return 0
    print(f"{len(rows)} document(s) are past retention (nothing was deleted):")
    for row in rows:
        blockers = ",".join(row["blockers"]) or "none - eligible to purge"
        print(f"  {row['evidence_id']} auth={row['authorization_id']} state={row['state']} "
              f"retain_until={row['retain_until']} blockers={blockers}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
