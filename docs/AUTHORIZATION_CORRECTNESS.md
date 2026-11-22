# Authentication and authorisation correctness

Baseline: `50b0f0e`. Implementation branch: `fix/auth-authorization-stability`.

## Scope and verified status

This change addresses the five reviewed defects: timezone handling, effective validity, concurrent decisions/audit writes, frontend session expiry, and authorisation summaries/status labels. The existing React/FastAPI/SQLAlchemy architecture is retained. It adds no monitoring, scanner, worker, finding, signed-document upload or automatic assessment execution.

The user's Windows checkout was confirmed clean on main at `50b0f0e`. Implementation was prepared separately; it has not changed their Windows database or GitHub main. The historical baseline review is in [FOUNDATION_ASSESSMENT.md](FOUNDATION_ASSESSMENT.md).

Automated backend, migration and frontend helper results are recorded in `VALIDATION.md` in the delivery package. Browser tests must run on Windows before this milestone is accepted or merged. The review environment could not launch a local browser or reach the app through its cloud browser. Do not equate the frontend build or Playwright test discovery with browser verification.

## Decisions, dates and current validity

`status` remains the recorded decision: pending, approved, rejected, revoked or legacy expired. Read operations do not overwrite the decision or invent audit events.

`effective_status` is calculated at read time using a server UTC timestamp:

| Effective state | Meaning |
|---|---|
| `pending` | Verified window has not expired; review decision is pending |
| `active` | Approved and `valid_from <= now < valid_until` |
| `scheduled` | Approved but valid_from is still in the future |
| `expired` | Verified window has ended, or the historical stored status is expired |
| `rejected` / `revoked` | Administrative outcome takes precedence over date validity |
| `needs_date_review` | A pending/approved legacy window has no reliable timezone provenance |

Future administrative approval is allowed; it becomes scheduled, never active before its start. End boundaries are exclusive. Date order and explicit input timezone remain mandatory. Every newly created window is normalised to UTC before SQLite writes it; verified windows and audit timestamps are returned with explicit UTC offsets. `timestamps_verified` means UTC storage provenance, not verification of the signatory or signed document.

The approval endpoint still requires evidence attestation and at least 20 trimmed note characters. Rejection/revocation require at least 10 trimmed reason characters. Repeated/conflicting transitions return 409. A conditional UPDATE restricts the transition to the expected existing state; one transaction commits the decision and its audit event. Failure to insert the event rolls back the decision. Concurrent SQLite lock conflicts return a retryable 409; no uncontrolled automatic retry is introduced.

Website reads add `effective_authorisation_status`. Current approvals take precedence, followed by scheduled approvals, pending requests and dates needing review. Otherwise the latest record's outcome is shown; no records yields `not_requested`. The old persisted `authorisation_status` field is retained for compatibility and is not a validity authority. The frontend uses the new computed field.

## Migration and existing data

Alembic revision `0001_foundation` creates the frozen five-table baseline for an empty database or adopts an existing baseline after checking its table/column names. Partial or unexpected schemas stop migration for review. It does not reset existing tables.

Revision `0002_authorization_utc` adds the non-null `timestamps_verified` boolean with false as its database default. Existing authorisation dates, statuses, IDs, administrators, password hashes, clients, websites and audit events remain unchanged. No timezone is guessed and no old timestamp is bulk-shifted.

Existing pending/approved records consequently show Dates need review. They do not contribute to Currently valid counts. Re-establish each permission by inspecting its original written document, creating a replacement through the existing POST authorisation API with explicit offsets, then reviewing/approving the replacement normally. Keep old history; reject superseded pending records or revoke old approvals with a replacement reference in the reason. Do not flip the provenance flag through SQL to bypass this review. There is no new evidence or authorisation-creation UI in this change.

Both API startup and administrator provisioning require the migrated schema. Schema creation has moved out of application startup. Downgrade commands deliberately refuse to discard tables/provenance; rollback means stopping the updated application and restoring a reviewed backup together with its matching application revision. Keep any post-migration writes before considering a restore; restoring a backup discards subsequent changes.

## API changes

| Method/path under `/api/v1` | Change |
|---|---|
| `GET /authorizations` | Adds effective_status and timestamps_verified to each record; optional `effective_status` filter applied before pagination |
| `GET /authorizations/{id}` | Same additive fields; stored decision retained |
| `GET /authorizations/summary` | New protected whole-dataset counts; optional website_id; as_of UTC, total, decision_counts and effective_counts from one grouped query |
| `POST /authorizations/{id}/approve` | Normalised-window checks, legacy-date refusal, conditional transition and transactional event |
| `POST /authorizations/{id}/reject` and `/revoke` | Conditional transition and transactional event |
| Website create/list/detail | Adds effective_authorisation_status; original field retained |

The original `status` list filter still filters recorded decisions for API compatibility. Use `effective_status=expired` for approvals whose windows ended. No new scan endpoints exist.

## Frontend changes

The API helper now signals expiry when local expiry is reached, a protected request has no usable token, or a protected 401 is returned. Login failures remain login errors. A timer expires idle sessions; focus/visibility changes re-check background tabs. A stale successful response cannot repopulate data after logout/session change. SessionStorage remains a development mechanism; secure cookies, CSRF architecture and MFA remain future production work.

Overview pending counts use actual unexpired pending authorisation records from the summary endpoint. Summary cards are not calculated from website flags or a truncated first page. The local UI helper retrieves all pages of existing list APIs; server-side UI pagination remains future scaling work. Authorisation/website labels distinguish scheduled, expired, rejected, revoked, not requested and dates needing review. Decisions refresh website and summary data. Older detail responses are ignored after closing/changing the selected record. Periodic refresh runs every 60 seconds; summary displays its as_of time, and the backend remains the validity authority.

## Windows implementation order (PowerShell)

Stop both existing development servers with Ctrl+C in their own terminals. Keep the existing `.env` and administrator. Do not copy environment examples over configured files. Stop at any failed command and inspect the error before continuing.

### 1. Apply the reviewed patch on a branch

Download `SNWebShield_Auth_Correctness.zip` to Downloads, then:

```powershell
Expand-Archive -Path "$HOME\Downloads\SNWebShield_Auth_Correctness.zip" -DestinationPath "$HOME\Downloads\SNWebShield_Auth_Correctness"
Set-Location C:\SNWebShield-Local
git status --short --branch
git log -1 --oneline
git switch -c fix/auth-authorization-stability
$patchPath = "$HOME\Downloads\SNWebShield_Auth_Correctness\snwebshield-auth-correctness.patch"
git apply --check $patchPath
```

Only after the check succeeds:

```powershell
git apply $patchPath
git diff --check
git diff --stat
```

The ZIP contains a patch, not a replacement repository, database or environment. It includes the baseline documentation corrections and assessment. If paths/branch already exist, stop and inspect rather than overwriting them.

### 2. Install backend dependencies, back up, then migrate

```powershell
Set-Location C:\SNWebShield-Local\backend
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m app.cli.backup_database
```

The backup command reads the configured SQLite database, creates a consistent copy under `$HOME\SNWebShield-Backups`, checks integrity and prints its location without printing records or secrets. Confirm it succeeds before migration. For a new installation with no database, migrations create it; for an existing installation, do not continue if the configured file is unexpectedly missing. The helper supports file-based SQLite only.

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m alembic current
.\.venv\Scripts\python.exe -m pytest -q
```

Expected migration revision: `0002_authorization_utc (head)`. Tests use a separate temporary database and synthetic users; they do not recreate the application database or reset your admin. `JWT_SECRET_KEY` must remain your locally configured value. The updated example intentionally leaves it empty.

### 3. Frontend tests and browser journeys

```powershell
Set-Location C:\SNWebShield-Local\frontend
npm ci
npm test
npm run build
npx playwright install chromium
npm run test:e2e
```

The six browser journeys use only synthetic records, their own temporary database, API port 18000 and frontend port 15173. They refuse to reuse already-running servers on those ports. They do not touch the application database or start any website assessment. Request tracing, screenshots and video are disabled to avoid capturing bearer tokens. If a browser test fails, keep the textual failure output and stop before pushing/merging.

### 4. Verify your existing local application

Backend terminal:

```powershell
Set-Location C:\SNWebShield-Local\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Frontend terminal:

```powershell
Set-Location C:\SNWebShield-Local\frontend
npm run dev
```

Sign in with your existing admin. Verify existing clients/websites/history remain, legacy permissions show Dates need review, and pending/currently-valid counts reflect actual permissions. Do not approve a real permission merely to test the UI. Use the isolated browser suite for state-changing test decisions. Check the browser console for unexpected errors and test logout/session expiry. Record browser and API results before accepting the milestone.

### 5. Review, commit and push a feature branch

After local checks succeed, inspect the changed paths:

```powershell
Set-Location C:\SNWebShield-Local
git status --short
git diff --check
git diff
```

`CHANGED_FILES.txt` in the package is the exact allowlist for staging. It deliberately excludes `.env`, databases, backups, node_modules, build/test output and `authorization-ui-review.txt`.

```powershell
$changedFiles = Get-Content "$HOME\Downloads\SNWebShield_Auth_Correctness\CHANGED_FILES.txt"
git add -- $changedFiles
git diff --cached --stat
git diff --cached
git commit -m "Fix authentication and authorization correctness"
git push -u origin fix/auth-authorization-stability
```

Review the staged diff before committing. Open a pull request from the feature branch into main and include actual Windows pytest, frontend helper/build and six browser-test results. Use `PR_DESCRIPTION.md` in the package as a template, replacing pending validation fields with observed results. Review before merging; do not push these changes directly to main. No GitHub push, PR or merge was performed by the agent.

## Remaining limitations

PostgreSQL execution/concurrency, deployed session controls, authorisation creation UI, secure evidence upload, general audit immutability, client/website deactivation and scanner enforcement are outside this patch. SQLite foreign-key enforcement and client-email database uniqueness remain separately identified foundation work. Browser verification must be completed on Windows. Do not call the platform production-ready or the milestone fully verified until its acceptance checks pass.
