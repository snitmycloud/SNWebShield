# Changelog

## Unreleased — restricted Docker Nmap profile

- Add fixed non-root TCP connect discovery on ports 80/443 behind a dedicated default-DROP container network policy; no scripts, banners, OS detection, custom ports or local fallback.
- Require separate TCP-discovery approval and both hostname and numeric public-IP scope, with fresh DNS matching, pre-launch permission handshake and shared assessment throttles.
- Integrate structured port observations, usage, cleanup, analyst review, reviewed exports and Findings. Preserve existing header profiles and authorisations.
- Add live namespace isolation/timeout/cancellation checks, a fixed VM self-test and successful/denied API/browser coverage. No new Azure resources or schema migration.

## Unreleased — central Findings dashboard

- Aggregate latest analyst-confirmed observations across clients/websites with severity, owner, status, search and overdue filters, full filtered counts and pagination.
- Add calendar due dates with append-only actor/revision history, stale/concurrent-edit checks and Asia/Kolkata overdue rules excluding resolved items.
- Reuse the assessment review workflow for remediation edits and link directly to source assessments/reports and retests. Keep repeated assessments separate and never trigger scans from Findings.
- Add the additive `0008_findings_dashboard` migration and API/browser coverage.

## Unreleased — analyst review and remediation

- Add per-observation human dispositions, severity, evidence notes, recommended fixes, owners and remediation status with append-only revision history and concurrency checks.
- Require a later successful assessment of the same target and analyst resolution notes to resolve confirmed issues.
- Add private, integrity-checked reviewed JSON snapshots that preserve source observations and review revisions, plus authenticated download audit history.
- Add an additive review/export migration, dashboard controls and API/browser regression coverage. No new scanner or Azure resources are involved.

## Unreleased — existing Azure Docker scanner host

- Add a default-off remote header-analysis profile using fixed SSH commands, an approved immutable image and the existing VM only.
- Keep the authorised HEAD broker and all application data on Windows; enforce non-root, networkless, read-only and resource-limited analysis containers.
- Add independent container deadlines, targeted cleanup, cancellation audit telemetry and dashboard duration/CPU/peak analyser memory.
- Validate Windows SSH and live synthetic analysis, kernel isolation, resource configuration, timeout, cancellation and cleanup on the existing VM; preserve the three pre-existing containers.
- Preserve required Windows OpenSSH profile paths while excluding application secrets and retaining process limits. Document setup, cleanup uncertainty, verification commands and deallocation costs.

## Unreleased — authentication and authorisation correctness

- Normalise new permission windows to UTC and preserve original decision history separately from effective validity.
- Add Alembic baseline adoption and a provenance flag; preserve legacy dates and require their review instead of guessing timezone offsets.
- Enforce conditional decision transitions and transactional audit-event writes.
- Add whole-dataset authorisation summaries and computed website validity states.
- Fix idle/request-time session expiry, stale responses after logout, dashboard counts and status labels.
- Add isolated backend, migration, frontend helper and Windows browser regression suites, plus a verified SQLite backup command.
- Reconcile setup documentation. Browser acceptance and PostgreSQL verification remain pending.

## Unreleased — authorisation evidence

- Private UUID-addressed PDF/image uploads, content validation, SHA-256 verification and authenticated downloads/previews.
- Human evidence reviews tied to actor and revision; approval requires current accepted evidence.
- Evidence metadata/history, legal holds and retention-checked deletion with retryable tombstones.
- Additive migration 0003_evidence; existing data preserved.
- Local implementation prepared; updated Windows browser verification and PostgreSQL integration remain pending.

## Unreleased — monitoring operational engine

- Add a shared durable job engine with registered handlers, scheduler dispatch, atomic claims, pool leases, attempts, execution events and fenced final results. Monitoring is its first handler; scanners remain unimplemented.
- Add explicit reviewed monitoring consent, disabled-by-default configuration, activation/revocation controls and additive migration `0004_monitoring`.
- Add bounded public-destination HTTP/DNS/TLS probes with pinned addresses, same-origin redirect validation and independent child-process deadlines.
- Add historical metrics, failure/recovery incidents, a durable dashboard/optional SMTP notification outbox and the monitoring dashboard.
- Add controlled HTTP fixture, concurrency, cancellation, subprocess, SSRF, notification and browser journey coverage. Browser launch is blocked in this environment; Windows acceptance remains required.

## Unreleased — assessment job manager and permission engine

- Add explicit, idempotent assessment requests on the shared queue, a separate assessment pool and network-free worker role.
- Require current audited authorisation, exact domain/method scope, accepted current evidence, hash integrity and bound snapshots before request/execution.
- Add transactional revocation cancellation, request/attempt/audit history and a policy-only profile catalogue/dashboard.
- Add additive migration `0005_assessment_intents` and backend/browser/helper regression coverage.
- Real scanner integration, profile approval management, findings and network isolation remain unimplemented. Windows browser acceptance is pending for this stage.

## Local Python HTTP assessments

- Add an explicitly consented single-HEAD profile, live scope checks, bounded local Python execution, private reports and reviewable header observations.
- Reuse existing jobs, audit/cancellation/history and preserve SQLite data with additive migration 0006_local_http.
- Add security, transport, process, migration and browser tests. No Docker/cloud/tool dependency.
