# Findings and remediation dashboard

Open **Findings** in the sidebar to manage analyst-confirmed observations across clients and websites. The dashboard reads existing reports/reviews and never queues a scan, sends a website request or starts a container.

## What appears in the queue

An item appears only when its latest analyst review is **Confirmed** and its source assessment completed. Earlier confirmations superseded by **Dismissed** or **Not applicable** do not appear. Resolved confirmations remain visible with their resolved status. Original automatic observations are never promoted without a human decision.

The identity of an item is its assessment report and observation check. Repeated checks from different assessments remain separate items, including retests; there is no automatic merging, deduplication or copying of old decisions to a newer scan.

If the dashboard is empty, open a completed assessment in **Assessments**, inspect the evidence and record an appropriate confirmed decision. Tests use disposable synthetic data and do not populate real findings.

## Filters, counts and detail

Use client, website, severity, status, owner substring, search and **Overdue findings only**, then select **Apply finding filters**. Search matches client/website name, target hostname or observation check. Owner/search filters treat wildcard characters literally. Clear filters restores the full queue.

Counts cover the entire filtered result set, not only the current page. The list shows 50 items per page, ordered by severity, then due date and review time. Open, in-progress, ready-for-retest, resolved and overdue counts come from the latest decisions/deadlines. Overdue overlaps unresolved status counts rather than being a separate resolution state.

**Open finding** shows evidence notes, recommended fix and source checksum. Expand the review to update its owner, severity, notes, recommendation or status; the same attestation, concurrency, retest and revision-history rules apply as in the assessment screen. Dismissing or marking a finding not applicable removes it from the current queue while retaining its history.

Use **Open source assessment and reports** to open the exact completed assessment, including its original report, analyst review history and reviewed snapshots. If a retest is linked, **Open linked retest** opens that assessment. Navigation never creates a new job. The application retains its existing active-administrator access model; this increment does not add tenant isolation or client logins.

## Due dates

Set a calendar due date and a change note of at least 10 characters. Leave the date empty to clear it. Changes are append-only, recording actor, timestamp, revision, source review ID and note; paginated history remains available even when an item later leaves the queue.

Overdue means the due date is before today's calendar date in **Asia/Kolkata** and the latest confirmed review is unresolved. Due today is not overdue. Resolved items are excluded; reopening one reuses its existing deadline and may make it overdue again. Due dates remain associated with the original assessment observation when its owner/status changes. There are no automatic notifications, calendar integrations or new background processes.

The deadline form binds both its expected deadline revision and review revision. Stale or competing edits return 409; refresh and reconcile instead of overwriting. Deadline changes do not modify original scanner reports, review decisions or already-created reviewed snapshots. Existing reviewed exports contain review/remediation data; deadline history is a separate tracking record and is not retroactively inserted into exports.

## API

All routes require the existing active-administrator authentication:

- `GET /api/v1/findings`: optional `client_id`, `website_id`, `severity`, `status`, `owner`, `search`, `overdue_only`, `limit` (1–100) and `offset`. Returns bounded items, full filtered counts, business date and timezone.
- `GET /api/v1/findings/{assessment_id}/{check_id}`: current confirmed review and integrity-checked source context. Non-confirmed/latest-dismissed items return 409.
- `POST /api/v1/findings/{assessment_id}/{check_id}/deadline`: `expected_revision` (0 for first change), `expected_review_revision`, ISO `due_date` or null, and `note`. Actor/time are assigned server-side; arbitrary additional fields are rejected.
- `GET /api/v1/findings/{assessment_id}/{check_id}/deadline-history?limit=50&offset=0`: date-change history. Historical dates remain readable after dismissal, subject to source-report integrity and administrator authentication.

Review edits reuse `POST /api/v1/assessments/{id}/reviews/{check}`. Confirmed issues cannot be resolved without analyst resolution notes and a later successful, separately authorised same-target retest. See [Analyst review](ANALYST_REVIEW.md).

## Migration and validation

Migration `0008_findings_dashboard` follows `0007_observation_reviews` and adds only `finding_due_dates`, with indexes, revision uniqueness and references to source reports/reviews. It preserves existing records. Startup requires the new table; destructive downgrades are refused.

For another installation, make a private backup and apply the migration from `backend`:

```powershell
.\.venv\Scripts\python.exe -m app.cli.backup_database
.\.venv\Scripts\python.exe -m alembic upgrade head
```

Restart the API and refresh the browser. No Azure or scanner-image changes are needed. Tests cover latest decisions, empty/filtered queues, whole-result counts, pagination, deadline history/clearing, time-zone date boundaries, resolved/reopened status, distinct retest findings, concurrency, authentication and input validation. Browser acceptance covers filters, evidence detail, deadline history, owner/status changes and navigation back to the source review. No actual website is contacted by these test fixtures.

Validated on Windows on 2026-11-24: all 274 backend tests, 14 frontend helper tests, 16 Chromium browser scenarios and the Vite production build passed; Git whitespace checks passed. Backend tests emit one existing Starlette/httpx deprecation warning. A verified private SQLite backup was made before applying the migration locally. The database is now at `0008_findings_dashboard`. Accounts, clients, websites, authorisations, evidence, assessment requests/reports, analyst reviews and reviewed exports matched the backup exactly after migration. The real work queue was checked and contained zero confirmed findings; no review decisions were entered on the user's behalf. No Azure changes, real target requests or real assessment jobs were created for this increment.
