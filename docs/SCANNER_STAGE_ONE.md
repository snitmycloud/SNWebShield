# Security Scanner Worker — stage one: assessment jobs and permission enforcement

## Audit boundary

The user verified a clean Windows checkout at `C:\SNWebShield-Local`, branch `feature/website-monitoring`, commit `b7749f1`, parent `99221a9`. This runtime cannot access that Windows filesystem. Its available copy contains the reviewed monitoring implementation and the corrected zero-duration fixture assertion, with different local Git hashes. Before editing, that copy passed 142 backend tests, 10 frontend helper tests and the Vite production build. The user's eight Windows browser journeys previously passed; that is prior evidence, not a result for the new scanner stage. Use `git apply --check` on the actual Windows checkout before applying the incremental patch.

Reviewed current models, routes, authentication, authorisation/evidence policy, migrations, tests, React navigation and shared worker code. `FOUNDATION_ASSESSMENT.md` remains a historical review of `50b0f0e`, not a current feature inventory.

| Existing component | Reuse and limits |
| --- | --- |
| JWT/Argon2 and active administrator lookup | Protect all assessment endpoints; one administrator role, no tenant isolation |
| Website/client relationships | Resolve target from the registered website, never an arbitrary request URL; existing models lack deactivate/delete lifecycle fields |
| Authorisation service | Explicit approved status, verified UTC dates, exact domains and method enum; website cached approval flag grants nothing |
| Private evidence | Verify current accepted review linked to the approval audit event, exact document set, relationship and hashes; no cryptographic verification of a signature/person |
| Job engine | Same jobs, attempts, results, idempotency, pool slots, claims, leases, fenced results and transactional execution events |
| Scheduler | Same registered-handler dispatcher; assessments queue only through explicit requests, not periodic scheduling |
| Monitoring probe | Reuse static URL validation; do not reuse monitoring consent or treat a monitoring result as scan permission |
| React/API helpers | Existing session expiry, navigation, authenticated requests, paginated history and styling conventions |

Missing before this stage: assessment intent, binding to a selected authorisation/profile/evidence snapshot, assessment policy handler, assessment APIs, worker role and dashboard. Still missing afterward: real scanner adapters, OS/container isolation, restricted network execution, output evidence/findings and analyst review workflow.

## Implemented architecture

Explicit administrator request → locked live permission check → immutable assessment intent plus shared queued job → assessment pool claim → locked live permission/snapshot recheck → policy-only result plus audit event in one transaction.

The independent `assessment-worker` role executes no subprocess, DNS query, HTTP request or scanner tool. The current fixed catalogue has one versioned profile, `authorization-preflight-v1`, requiring `automated_non_intrusive_scanning`. This is a code-reviewed preflight policy, **not** a completed human scan-profile approval manager. It deliberately does not accept `passive_reconnaissance` as permission for a future automated profile. Its description, method requirements and mode are hashed; changes invalidate queued requests. No commands, scripts, templates, tool options, target overrides, uploaded profiles or credential inputs are accepted.

A completed result says `permission_preflight_passed`, `mode=policy_only`, `network_execution=false`, `findings_created=0` and `destination_resolution=not_performed`. It grants no durable execution token and is not proof that DNS, egress or a scanner adapter is safe. A future adapter must revalidate everything immediately before launch and during execution.

## Database and lifecycle

Migration `0005_assessment_intents` adds `assessment_requests`, with UUID ID, unique job ID, website/authorisation/requester relationships, timestamp, profile ID/digest, target URL/host, permission snapshot/digest and request note. Existing shared jobs provide state, attempts, lease, timestamps and final result. No old IDs or data are rewritten. Migration coverage upgrades a populated 0004 database and compares every existing table's rows, including private evidence, reviews and monitoring results.

A partial unique index on existing `jobs.resource_id` for active assessment jobs prevents multiple queued/running assessment requests per website, even using different authorisations. It does not restrict monitoring jobs. The index is defined for SQLite/PostgreSQL; only SQLite is functionally tested. Existing SQLite connections still have foreign keys disabled, a historical integrity gap; service relationship checks and effective unique indexes should not be confused with a broader database-integrity repair.

| Job state | Meaning in this stage |
| --- | --- |
| queued | Explicit preflight intent accepted; no assessment operation performed |
| running | Claimed by the assessment pool |
| completed | Permission preflight finished, **not a security scan** |
| cancelled | Administrator cancellation, revocation or live permission/snapshot denial |
| failed | Execution lease expired or operational failure; no successful preflight implied |

No automatic security-job retry: `max_attempts=1`. A new explicit request is needed after a failure. The pool inherits the shared one-active-job slot, 60-second lease and five-second release pacing. Expired leases are recovered by the next assessment worker claim; history is retained. Idempotency keys are scoped to the requester and bound to the complete request fields; replay returns the same request without requeueing. A different request with a reused key is rejected. Queued/running jobs can be cancelled; late results cannot replace their state.

Revocation calls assessment cancellation before the existing decision transaction commits. If its audit write fails, the revocation and cancellations roll back together. Monitoring consents remain separate and are not modified. Cancellation may retain a pool lease until the old worker releases it or the lease expires; new work waits safely.

## Permission policy

Require an active administrator requester, existing matching client/website/authorisation, recorded approved status, verified timestamps, `valid_from <= now < valid_until`, an exact canonical hostname and all profile-required methods. Reject wildcard/suffix-only matches, IP literals, local/internal names, nonstandard ports, URL credentials and unsupported schemes. Targets come exclusively from the registered website.

Require the latest authorisation audit decision to be an evidence-reviewed approval, pointing to an accepted review by that approver at the current revision. The current available document IDs must exactly match the review, belong to the same website/client and pass file hash/size checks. Snapshot includes target, domains, methods, validity, approval/review IDs, evidence revision and document hashes. Any snapshot/target/profile change invalidates pending execution. Permission is checked after acquiring the authorisation lock and again for expiry after reading evidence. Evidence storage integrity failures fail closed.

The service serializes with the existing authorisation/evidence conditional-update lock; the job's CAS claim token fences completion. Request/policy denials have coarse audit reasons, without documents, credentials, commands or claim tokens. Validation/authentication errors handled before the service are not a general security-audit middleware; production audit coverage remains future work.

DNS is deliberately not resolved in this stage. A publicly shaped name might resolve privately or change later. No network adapter is enabled, so it cannot become SSRF through this worker. Do not remove this prohibition merely because preflight completed. No production bypass/private-target flag is added.

## APIs and UI

All paths below are under `/api/v1`, protected by existing active-admin authentication.

| Method/path | Behaviour |
| --- | --- |
| GET `/assessments/profiles` | Fixed versioned policy-only catalogue and digest |
| POST `/assessments` | Explicit request, live permission enforcement, idempotent queueing |
| GET `/assessments` | History; optional website_id, limit 1–100, offset >=0 |
| GET `/assessments/worker-status` | Worker heartbeat and explicit tools-disabled mode |
| GET `/assessments/{id}` | Intent, snapshot, shared job and policy result |
| GET `/assessments/{id}/events` | Paginated execution/audit events |
| GET `/assessments/{id}/attempts` | Paginated attempts without claim tokens |
| POST `/assessments/{id}/cancel` | Reason required, 10–1000 trimmed characters |

Request fields: positive `website_id`, `authorization_id`, available `profile_id`, UUID `idempotency_key`, `explicitly_requested: true`, and trimmed `note` of 20–2000 characters. Unknown fields are rejected. Permission/profile conflicts return 409; malformed requests return 422; authentication follows existing behaviour.

The Assessments page selects website, current authorisation and profile, requires an explicit request checkbox/note, lists paginated history and displays detail, attempts and audit events. Completed is labelled **Preflight completed**. Pending requests support cancellation. All selected approvals are revalidated by the backend; a visible UI option does not itself grant permission. Details show the latest 50 attempts/events; full pagination remains available in the API.

## Windows migration and operation

Stop API/operational processes before applying. Preserve `.env`, administrator accounts, SQLite database and evidence root. Back up database with the existing CLI and separately copy private evidence; database backup alone does not include files. Never delete the DB or reset users to repair a migration.

```powershell
Set-Location C:\SNWebShield-Local\backend
.\.venv\Scripts\python.exe -m app.cli.backup_database
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m alembic current
.\.venv\Scripts\python.exe -m pytest -q

Set-Location C:\SNWebShield-Local\frontend
npm test
npm run build
npm run test:e2e
```

Expected head: `0005_assessment_intents`. Existing dependencies are reused; no scanner installation is required. Keep the API and Vite in their usual terminals. To execute one queued preflight, use a separate PowerShell terminal:

```powershell
Set-Location C:\SNWebShield-Local\backend
.\.venv\Scripts\python.exe -m app.cli.operations assessment-worker --once
```

Omit `--once` to poll continuously. The monitoring scheduler/worker/notification roles keep their existing names and behaviour; no second scheduler or queue is created. They are not required for this network-free preflight. Assessment operation remains a separate process, **not an OS security sandbox**.

Use synthetic local records and a permission document clearly marked for testing. An authorisation with `automated_non_intrusive_scanning`, current dates, an accepted human evidence review and an approval is required. Existing authorisation creation remains API-only. Select it in Assessments, enter a synthetic request note, attest and queue. Before running the worker, cancel a request and inspect its event. Queue another, execute `assessment-worker --once`, refresh and expect **Preflight completed** with no scanner output. Queue another, revoke its authorisation, and confirm cancellation. No stage-one action contacts the registered website.

## Validation and remaining limits

Tests cover baseline regressions, exact dates/domains/methods, missing/unreviewed/withdrawn/mismatched/tampered evidence, changed target/profile/requester/snapshot, idempotency, competing requests and claims, independent pools, cancellation/revocation fencing, expired leases, audit rollback and preservation of populated migration data. A network/subprocess tripwire verifies that permission preflight never calls DNS or launches tools. An independent CLI subprocess also claims and completes a durable preflight request against the disposable database. Three new Playwright journeys cover explicit request/cancel, insufficient methods and preflight result display. They use a test-only completion fixture in the disposable browser server; no production test-control endpoint or bypass flag exists.

Browser execution here was blocked at Chromium launch by the environment's socket restriction, before any journey ran. Eleven browser journeys are defined; Windows acceptance is required. A production build and API tests are not a replacement for that acceptance. PostgreSQL, Windows worker execution and production concurrency/load are unverified in this runtime.

## Subsequent phases and acceptance gates

1. **This stage:** assessment intent and live permission enforcement. Gate: backend/unit/build checks plus Windows browser and CLI preflight acceptance; no network/tool invocation.
2. **Isolated low-impact adapter:** a narrowly bounded public-destination check, with validated/pinned DNS per connection, redirect checks, explicit egress gateway/allowlist, resource/child-process bounds, cancellation and no raw command interface. Gate: controlled lab, private/mixed/rebinding DNS and redirect denial, timeouts, output bounds and revocation during execution.
3. **Approved tool profiles:** separate reviewed, immutable/versioned profiles for Nmap, Nuclei and ZAP. Review and approval identity, exact tool/version, permitted methods, ports, request budgets, signed/pinned template policy, credentials handling and isolation are required before enabling adapters. Passive ZAP analysis requires supplied/captured traffic; crawling/spidering is not silently treated as passive. Nuclei tags alone cannot prove a template low-impact. Tools that perform their own DNS/networking need enforced network isolation; validating a hostname once and then invoking a tool is insufficient.
4. **Results/evidence/findings:** private bounded output collection, hashes, parser/version provenance, untrusted candidate findings, deduplication and human analyst disposition. No confirmed vulnerability is created solely from raw scanner output.
5. **Operational acceptance:** controlled downtime/cancellation/crash tests, resource/egress enforcement, tested PostgreSQL migration/concurrency, service supervision, backups/retention, deployment review. Only then consider larger or more intrusive profiles with separately approved scope.

This stage does not install/invoke Nmap, Nuclei or ZAP, publish a PR, push commits, implement findings or claim production readiness.

### Recorded preparation checks

191 backend tests passed with the existing Starlette/httpx warning; 11 frontend helper tests and the production build passed. Eleven browser journeys were discovered, but Chromium failed at launch before any journey ran. An independent CLI worker and controlled policy/concurrency/migration tests passed. These are preparation-workspace results, not acceptance of the patched Windows checkout.

## Windows validation - 22 November 2026

- Migration: 0005_assessment_intents.
- Backend: 191 passed, one existing deprecation warning.
- Frontend helpers: 11 passed.
- Browser regression suite: 12 passed.
- Production build and git diff --check passed.
- Manual checks demonstrated method rejection, queued cancellation and independent CLI preflight completion.
- Revocation and refresh behaviour passed browser regression coverage.
- Windows test server emitted WinError 10054 connection-close callback messages; all tests passed. Root cause remains unconfirmed.
- This stage performs permission preflight only; no scanner tools or target traffic.
