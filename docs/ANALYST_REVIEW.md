# Analyst review and remediation

Completed local and Azure header assessments now support analyst dispositions, remediation tracking, revision history and private reviewed JSON snapshots. This workflow runs entirely on Windows; reviewing and exporting never sends HTTP requests or runs a container.

Latest confirmed decisions also appear in the [central Findings dashboard](FINDINGS_DASHBOARD.md), where analysts can filter work across clients/websites, manage due dates and open source assessments. Owner/status edits use this same review history rather than creating a competing finding record.

## Use in the dashboard

Open **Assessments**, open a completed HTTP assessment and scroll to **Analyst review and remediation**. Existing reports work immediately after migration; no rescan is required to start a review. Expand an observation and choose:

- **Confirmed**: you validated an issue in its application context. Select analyst severity, explain your reasoning and supporting evidence, recommend a fix and record an owner. Remediation can be open, in progress, ready for retest or resolved.
- **Not applicable**: document why the control does not apply to this application.
- **Dismissed**: document why the observation does not establish an issue.

Every decision requires at least 20 characters of review notes and supporting evidence, plus an explicit human-review attestation. Supporting evidence is analyst-entered text and references to inspected configuration/documents; this increment does not add finding-evidence file uploads. Avoid secrets in notes. The source report ID and checksum establish provenance. Owner is a free-text person/team name; this does not send notifications or create user accounts.

Save records the authenticated reviewer, timestamp and next revision. Use **Show … review history** for earlier notes, evidence, fixes, owners and statuses; history is paginated in groups of 50. Conflicting edits receive HTTP 409; refresh and reconcile your changes instead of overwriting another analyst's decision. An old authorisation expiring or being revoked does not prevent reviewing an already completed historical report, but all future network operations still require current permission.

## Retest and resolution

Queue a new assessment using the existing request form after fixes. Select genuine current authorisation, an appropriate HTTP profile, a request note and both explicit permission checkboxes. Run the assessment worker normally. There is no automatic retest or reuse of old consent; the existing permission checks, one-request budget and cooldown remain in force.

To mark a confirmed issue **resolved**, supply at least 20 characters of resolution notes and the UUID of a later successful HTTP assessment. The backend verifies the retest was requested after the original job completed, uses the same website and exact target URL, has a completed job and integrity-checked report, and includes this observation. Self-links, queued/failed jobs and different targets are rejected. The analyst must assess the retest evidence: a linked report is not automatic proof that a policy is effective. A resolved item can be reopened through a new review revision; earlier resolution history remains.

## Reviewed exports

After every observation has a decision, **Export reviewed report** creates and downloads an authenticated JSON snapshot. It includes the original scanner report and checksum, current review revisions, evidence notes, remediation fields, reviewer/creator identities and summary counts. Original automatic observations retain `confirmed_findings: 0`; analyst confirmations are counted separately under the reviewed report summary. A report can be fully reviewed while still containing unresolved confirmed issues; their statuses and counts remain visible in the export.

Each export has its own UUID, timestamp, SHA-256 and size. Later decisions do not change previously exported content. The dashboard lists the latest 20 snapshots; existing snapshot download URLs remain valid with administrator authentication. Downloads check integrity, use private/no-store headers, and are audited. Exports are JSON rather than PDF, are not digital signatures or security certifications, and are not public links. Client publication, email, ticket integration, due-date scheduling and cross-assessment findings deduplication are outside this increment.

## API

All routes require the existing active administrator authentication:

- `GET /api/v1/assessments/{id}/reviews`: observation/current-review summary, source checksum and latest export metadata.
- `POST /api/v1/assessments/{id}/reviews/{check}`: append a review with `expected_revision` (0 for first review), `human_validation_confirmed: true`, disposition, severity, notes, supporting_evidence, recommendation, owner, remediation_status, resolution_notes and optional retest_assessment_id. Reviewer and timestamps are assigned server-side. Unknown fields/checks and invalid decision combinations are rejected.
- `GET /api/v1/assessments/{id}/reviews/{check}/history?limit=50&offset=0`: revision history.
- `POST /api/v1/assessments/{id}/reviewed-reports`: create a completed-review snapshot, returning its ID, checksum, size and creation timestamp. Incomplete reviews return 409.
- `GET /api/v1/assessments/{id}/reviewed-reports/{export_id}/download`: private, hash-checked snapshot download; assessment/export association is enforced.

The original raw assessment-report download remains available. API reviews cannot edit scanner reports or previously saved revisions/exports. The application audit records review creation, revision, disposition, remediation status, source checksum and export creation/download.

## Migration and validation

Migration `0007_observation_reviews`, following `0006_local_http`, adds only `observation_reviews` and `reviewed_assessment_exports` plus their indexes/constraints. It preserves existing requests, reports, accounts, evidence and jobs. A unique `(report_id, check_id, revision)` prevents concurrent saves from silently replacing one another. Startup requires the new tables; destructive downgrades are refused.

For another installation, back up its database privately before migrating. From `backend`:

```powershell
.\.venv\Scripts\python.exe -m app.cli.backup_database
.\.venv\Scripts\python.exe -m alembic upgrade head
```

Restart the API and refresh the browser after upgrading. No Azure changes, image rebuilds or scanner configuration changes are needed.

Automated acceptance covers dispositions, attestation and field validation, stale/concurrent edits, immutable source reports, report/export integrity, authenticated access, assessment/export association, complete-review requirements, immutable export revisions, historical review after revocation, retest validation and migration preservation. Browser acceptance exercises confirmation with owner/status, revision history, dismissal of remaining observations and reviewed JSON download through the actual API and disposable database. Test scanner transport uses synthetic data and does not contact real targets.

Validated on Windows on 2026-11-24: 261 backend tests, 13 frontend helper tests and all 15 Chromium browser journeys passed; the Vite production build and Git whitespace checks passed. Backend tests emit one existing Starlette/httpx deprecation warning. A verified SQLite backup was saved privately under the Windows user's `SNWebShield-Backups` directory before applying the local migration. The local database is now at `0007_observation_reviews`. Protected account, client, website, authorisation, evidence, assessment-request and source-report tables were compared against the backup and matched exactly. The user's existing completed assessment was verified as reviewable with zero of eight observations reviewed; no decisions were entered on the user's behalf. No VM changes or target requests were performed for this increment.
