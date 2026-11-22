# SNWebShield foundation assessment

Reviewed 22 November 2026. Baseline: `50b0f0e2824078e517a3013e15c2fe780ce9b573` (`Add admin authentication and authorization management`).

This is the historical baseline assessment. For subsequent changes and remaining validation, see [the correctness implementation guide](AUTHORIZATION_CORRECTNESS.md).

## Review boundary and conclusion

The GitHub remote's HEAD and main both resolve to the supplied commit. A fresh clone was clean on main before review. This verifies the remote baseline, not the working tree, environment, administrator or database at `C:\SNWebShield-Local`. The older project path in the handover is historical and was not accessed. The intentionally excluded `authorization-ui-review.txt` was not added.

The foundation exists and should be preserved. The next milestone is **authentication and authorisation correctness**, before evidence uploads, monitoring or scanner execution. This review changes documentation only, on local branch `review/foundation-assessment`; it does not change application behaviour, user data or GitHub main.

## Verification performed

| Check | Result and boundary |
|---|---|
| Backend installation | Installed the existing requirements into an isolated virtual environment; no dependency file changed |
| Backend baseline | `python -m pytest -q`: **19 passed, 1 warning**, 3.28 seconds |
| Warning | Starlette TestClient deprecates its current httpx integration; record and resolve through tested dependency compatibility |
| Frontend installation | `npm ci` succeeded without changing the lockfile |
| Frontend build | `npm run build`: Vite 6.4.6, 1,575 modules, successful |
| Additional API probes | Disposable SQLite database and synthetic administrator; no network assessments |
| Authentication probes | Missing token on profile/client/website/authorisation lists: 401; invalid, expired, wrong-issuer, wrong-audience and wrong-role tokens: 401; existing token after admin deactivation: 401 |
| Time and status probes | Reproduced offset loss, approval of an already expired offset-based record, stale expired approvals, and premature website-approved presentation |
| SQLite integrity | `PRAGMA foreign_keys` returned 0 in the review environment |
| Frontend helper probe | Exercised `api.js` in Node with synthetic storage/fetch: locally expired token is removed, but the resulting 401 does not dispatch the session-expired event |
| Browser workflows | **Incomplete.** Local Chromium could not launch because socket creation was denied; the cloud browser could not reach the app. Rendering, interactions, console errors and complete user journeys are not verified |

Review runtime: Python 3.12.14, Node 24.22.3, npm 11.19.1. Backend requirements use broad version ranges, so this installation is not evidence of identical dependency versions on Windows. Key resolved versions: FastAPI 0.165.0, Starlette 1.10.0, SQLAlchemy 2.1.9, Pydantic 2.14.4, PyJWT 2.15.1 and httpx 0.28.1. Frontend dependencies came from the committed lockfile. No vulnerability audit was performed.

## Actual implementation

| Area | Verified state |
|---|---|
| Admin identity | Argon2 hashing; local provisioning CLI; HS256 JWT with issuer, audience, required claims and a 20-minute default lifetime; active administrator lookup on protected requests |
| Client and website APIs | Authenticated create/list/detail; client relationship check; HTTP(S) URL validation and embedded-credential rejection |
| Client and website UI | List, local search and creation forms; no edit/deactivate lifecycle |
| Authorisation APIs | Create/list/detail, website/status filters, approval/rejection/revocation and decision event history |
| Authorisation validation | Explicit registered-host scope inclusion, allowed method enum, timezone-required input, date order, pending-only approval, evidence attestation and note/reason lengths |
| Authorisation UI | List/search/status filter/details, decision forms and event history exist in source; no creation form |
| Evidence | Reserved private storage key and review attestation only; no uploaded signed documents or identity verification |
| Persistence | Five models: Admin, Client, Website, WebsiteAuthorization, AuthorizationAuditEvent; SQLite locally, startup create_all, no migration framework |
| Testing | 19 backend tests; no committed frontend/browser suite |
| Workers and analyst operations | No monitoring worker, scheduler, scanner, assessment job, findings workflow, analyst workbench, report generation or retesting implementation |

Website registration and approval have no scanner invocation path. This confirms separation in the current source; it is not an execution policy for future workers. All administrators currently share access: there is no multi-role or tenant-isolated service.

## Prioritised defects and gaps

### P1: fix before a worker can consume authorisations

1. **Timezone offset loss permits an expired record to be approved.** `backend/app/schemas/authorization.py` requires aware input but does not normalise it to UTC. SQLite removes offsets from stored DateTime values. `_as_utc` in `backend/app/api/routes/authorizations.py` then treats the stored wall-clock value as UTC. Reproduction: create a record with `valid_until` ten minutes in the past expressed as `+05:30`; creation returns 201 with a naive date and approval returns 200/approved. The same instant expressed as UTC must have the same decision. Return explicit UTC timestamps. Existing naive rows cannot safely be bulk-corrected without identifying their original timezone provenance.

2. **Recorded approval and current validity are conflated.** List/detail/filter operate on stored status. There is no expiry transition or computed effective state; an expired approved record remains approved and `?status=expired` returns none for it. `_sync_website_authorisation_status` considers any approved record without checking dates. A future-dated approved record also labels the website approved immediately. Advance administrative approval may be legitimate, but it must be distinct from permission that is currently valid. Define one central policy for effective state; preserve the recorded decision and audit history.

3. **Decision transitions are vulnerable to concurrent updates by code inspection.** Routes read status, change the object and append an event without a conditional update/version check. Competing approval/rejection/revocation requests can both pass the initial read. This was not reproduced under concurrent load. Add a database-enforced transition pattern and verify it against the chosen database; do not assume row locks work identically in SQLite and PostgreSQL.

### P2: complete in the next stabilisation milestone

4. **Session-expiry notification has a gap.** `getAccessToken()` clears an expired local session before `request()` handles a 401. The event dispatch requires a truthy token, so that branch does not notify App. The helper probe reproduced zero events for this case, compared with an event for an unexpired stored token receiving 401. App has no expiry timer. The resulting dashboard behaviour is inferred from source and still needs browser confirmation; backend authentication remains enforced.

5. **Dashboard authorisation figures are not record counts.** `OverviewPage` counts every website whose cached status is not approved. A website with no request contributes to pending; multiple requests for one website contribute only one. Lists are capped at 100 without pagination or exact totals, so searches and counts can omit older records.

6. **Website status presentation can contradict the authorisation page.** `StatusPill` renders every non-approved status as Pending, including rejected/revoked. Decision callbacks refresh authorisations but not Dashboard's website collection. The overview API card always says Online once loading ends, even after failure. These are source findings requiring browser reproduction.

7. **Fresh-checkout setup omits the signing key.** `backend/.env.example` has no JWT settings; the root example's `SECRET_KEY` is ignored by current Settings. With no configured JWT key, otherwise valid login fails with 503. READMEs previously denied that login/audits existed. Review changes reconcile those claims and explain setup; updating configuration examples remains a small follow-up.

### P3: required before lifecycle expansion or deployment

8. **Database integrity/migration gaps.** SQLite foreign keys are off; declaration of `ondelete=RESTRICT` does not enforce it in this connection configuration. Client email uniqueness is checked in application code but lacks a database unique constraint, allowing a race. There are no migrations. Inventory and back up existing data before constraint changes; report inconsistent rows instead of deleting them.

9. **Audit coverage is partial.** Decision events include actor, note, timestamps and transitions. Creation is not audited; the model's append-only docstring is not a database immutability control. Client/website actions and authentication have no general audit trail.

10. **Production controls remain absent.** Login throttling, MFA, secure cookies/CSRF architecture, tenant isolation, general RBAC, refresh/revocation policy, backups, CI and worker isolation need later milestones. Current bearer-token logout clears browser storage only. Database status and domain registration are never sufficient permission to run a future worker.

## Exact next milestone: authentication and authorisation correctness

Suggested implementation branch: `fix/auth-authorization-stability`, based on the reviewed commit and preserving the stack and existing data.

**Objective:** make recorded decisions, effective date validity, API responses, dashboard presentation and session behaviour consistent, with regression tests and real browser verification. Do not add network workers in this milestone.

| Area | Concrete changes |
|---|---|
| Backend services | Extract date normalisation, effective-state calculation, website aggregate status and decision transitions from routes into a focused authorisation service; inject an explicit UTC clock for tests |
| Date policy | Normalise all new inputs to UTC; return explicit UTC offsets; distinguish pending review, approved but not yet valid, currently valid, expired, rejected and revoked; rejected/revoked decisions keep their precedence |
| Decisions | Preserve evidence/note requirements and atomic decision/event writes; use conditional transitions so only one conflicting decision succeeds |
| APIs | Retain all existing URLs. Add effective-state fields to authorisation/website reads without silently redefining stored decision status. Add protected `GET /api/v1/authorizations/summary` for whole-dataset counts and an explicit effective-state filter; register the static route before `/{authorization_id}` |
| Summary semantics | Return recorded-decision counts separately from currently-valid/future/expired counts, with an `as_of` UTC timestamp. Website-without-request is not a pending authorisation |
| Frontend | Handle expiry and every protected 401 consistently; clear sensitive views on expiry; show exact status labels; refresh website/summary data after decisions; cancel/ignore stale detail requests; show real connectivity state; paginate lists and searches |
| Creation workflow | Add one focused authorisation form using the existing POST endpoint: website, reference, signatory name, exact domains, permitted methods and timezone-aware validity window. Clearly label the current evidence-review attestation process |
| Configuration/docs | Add placeholder JWT settings to the backend example, document supported setup and update the assessment when defects are fixed; record a tested backend dependency set |
| Database | First inventory date provenance and orphan rows. No automatic timestamp rewrite, table recreation, admin reset or schema migration is needed for computed effective-state fields. Any constraint or transition-version column requires a separately reviewed migration with backup and rollback |

API surface retained: `POST /auth/login`, `GET /auth/me`, client/website create/list/detail, authorisation create/list/detail/events and POST approve/reject/revoke, all under `/api/v1`. Monitoring/assessment/scanner endpoints remain absent. This milestone does not grant approval to execute a scan or test a third-party target.

### Acceptance and tests

1. Preserve all 19 baseline tests. Add parametrised UTC, `+05:30` and negative-offset cases for identical instants, future windows, exact expiry boundaries, invalid order and timezone-free input. Test SQLite round trips and explicit UTC responses. Keep the existing JWT validation leeway explicit and test outside it.
2. Verify unknown email, wrong password, missing/malformed/expired/wrong-claim token, inactive account, account deactivation after login and unauthenticated reads/writes. No password hash or JWT appears in logs, reports or screenshots.
3. Exercise creation, filters, pagination, detail, audit history and all decision transitions; verify nonexistent IDs, scope mismatch, missing evidence, short/whitespace-only notes, forbidden transitions and concurrent decisions. Failed actions produce no decision event; the successful transition has exactly one event.
4. Confirm currently expired/future records cannot be presented as currently valid. Revoking one of several approvals retains a website's currently-valid state only if another matching approval is currently valid. Legacy ambiguous timestamps are flagged for review rather than silently changed.
5. Browser-test login success/failure, restoration, logout, expiry during a form and idle expiry, authorisation creation, filtering, details, approve/reject/revoke, audit refresh, stale-response handling and API failure/retry. Inspect console errors. Use only synthetic records in an isolated local database.
6. With zero, one, multiple and more than 100 requests, compare summary values with the whole database. Confirm websites with no requests do not inflate pending counts and rejected/revoked statuses display accurately across pages.
7. Confirm registration and approval produce no assessment jobs, subprocesses, worker calls or outbound target traffic. Run the full backend suite and frontend build after changes. Completion requires the browser journeys as well as those checks.

## Documentation and handoff

This review reconciles the root/backend/frontend READMEs, Windows setup guide and architecture status note. The broader workflow and security documents remain target requirements. API/database/deployment documentation and a changelog should grow with implemented milestones; they should not claim the future subsystems already exist.

Before applying implementation changes to Windows, confirm `git status --short --branch` and `git log -1 --oneline` in the user's actual checkout. A clean remote clone cannot detect local uncommitted changes. Keep `authorization-ui-review.txt`, `.env`, databases, dependencies and generated output excluded from commits. No push, merge, deployment or scan was performed during this review.
