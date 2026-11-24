# SNWebShield

**Website Security Assessment & Vulnerability Management Platform**

Tagline: **Identify. Analyse. Secure.**

SNWebShield is an internal platform under development for a website cybersecurity services team. The implemented foundation manages administrator login, clients, websites and authorisation review. Private authorisation evidence and reviewed monitoring consent are supported. Assessment execution, findings, reports, remediation and retesting remain planned.

> Safety principle: SNWebShield must only support assessments that have been explicitly authorised in writing by a person with authority over the target assets. A website URL submitted to the platform is not, by itself, permission to test it.

## Initial product goals

1. Manage clients, contacts and website assets.
2. Record signed authorisation, scope, rules of engagement and exclusions.
3. Support analyst-led manual website assessments.
4. Record test coverage, limitations, evidence and validated vulnerabilities.
5. Apply consistent severity and business-priority ratings.
6. Generate separate executive and technical PDF reports.
7. Give each client a tenant-isolated portal to view its own assessments and reports.
8. Track remediation and retest outcomes.
9. Add controlled scanner integrations only after the manual workflow is proven.

## Current stack and future direction

- Frontend: React 18 + Vite 6, JavaScript and CSS
- Backend: Python + FastAPI, SQLAlchemy and Pydantic
- Authentication: Argon2 password hashing and HS256 JWTs; browser sessionStorage for development
- Current database: SQLite with additive Alembic migrations; PostgreSQL deployment is unverified
- Background jobs: shared durable SQLAlchemy job engine with separate scheduler, monitoring worker and notification dispatcher
- Evidence: private local files with authenticated retrieval; encrypted object storage is future work
- Reports: HTML templates rendered to PDF
- Development: Git + GitHub

Monitoring jobs and private local evidence storage are implemented; report rendering remains planned. The current application is for local development and is not production-ready.

## Local setup and verified review

Use [backend setup](backend/README.md) and [frontend setup](frontend/README.md). Configure `JWT_SECRET_KEY` in `backend/.env` and provision an administrator with `python -m app.cli.create_admin` before signing in. The root environment example is an older planning example; runtime backend settings are defined in `backend/app/core/config.py` and read from the backend working directory.

The [authentication and authorisation implementation guide](docs/AUTHORIZATION_CORRECTNESS.md) covers the current fixes, migration, Windows checks and review workflow. Browser verification remains pending.

The [foundation assessment](docs/FOUNDATION_ASSESSMENT.md) records the review of commit `50b0f0e`, baseline checks, reproduced defects and the next milestone. The architecture and workflow documents describe future requirements as well as implemented features; they are not a feature-completion checklist.

## Repository map

```text
SNWebShield/
├── README.md
├── .gitignore
├── .env.example
├── docs/
│   ├── PROJECT_REQUIREMENTS.md
│   ├── PROJECT_ARCHITECTURE.md
│   ├── ASSESSMENT_WORKFLOW.md
│   └── SECURITY_GUARDRAILS.md
├── backend/
│   └── app/
├── frontend/
│   └── src/
├── assessment/
│   ├── checklists/
│   └── methodologies/
├── reporting/
│   └── templates/
├── database/
│   └── schema/
└── tests/
```

## Development phases

1. Requirements, governance and assessment SOP.
2. Manual assessment checklist and controlled lab validation.
3. Executive and technical report templates.
4. Database schema and authentication/authorisation.
5. Client and admin dashboard MVP.
6. Findings, evidence and PDF report workflow.
7. Security review and pilot with owned or explicitly authorised sites.
8. Controlled scanner integration and automation.

## Non-goals for the first release

- Unrestricted public URL scanning.
- Automatically exploiting vulnerabilities.
- Denial-of-service or stress testing.
- Persistence, lateral movement or data exfiltration.
- Scanning third-party services outside the approved scope.
- Claiming that a site is completely secure based only on automated checks.

## Status

**Application foundation and authorisation review implemented; stabilisation required.** Administrator login and protected client, website and authorisation APIs exist. The React UI supports client/website creation and authorisation review decisions with audit history. Authorisation creation currently has an API but no UI form. UTC normalisation, computed validity states, atomic decisions, session expiry and exact authorisation summaries now have regression coverage. Alembic migrations are included. The monitoring engine is implemented for local validation; scanner execution, analyst workflows, reporting and production hardening remain planned. Neither website registration nor authorisation approval starts a scan.

## Milestone 1: scanner worker hardening (Module D)

The scanner worker now uses one fixed, hardened SSH transport for both remote profiles: the Windows OpenSSH client is pinned by absolute path, and command-line options override any `ssh_config` that would enable agent/X11/port forwarding, proxies, passwords or session reuse. A missing client, an unreachable VM, an unavailable Docker daemon or the wrong runner/image fails the job with a specific audited error, with no local fallback. Assessment jobs hold a 120-second lease that exceeds every bounded remote stage budget. The HEAD broker requires TLS 1.2 or later, records the negotiated version, and classifies redirects into fixed categories without following them or storing the `Location` value. The VM runner can now inspect each created container and refuse to start it unless network, user, filesystem, capability, resource, IPC, mount and port settings match policy. This only takes effect after the runner is redeployed manually.

The full audit, risk register, test evidence, manual VM steps and remaining roadmap are in [docs/AUDIT_MATRIX.md](docs/AUDIT_MATRIX.md). No schema migration was added.

## Milestone 2: vulnerability management (Module E)

Migration `0009_vulnerabilities` adds a normalised `Vulnerability` entity, per-assessment `VulnerabilityOccurrence` records and an append-only event history. Repeated detections of the same check on the same website and target share a fingerprint, so they are deduplicated across assessments while each occurrence keeps its own evidence hash. Each vulnerability carries scanner and analyst severity, a confidence score with its factors, reproduction steps, and a validation state. Nothing becomes confirmed without an explicit human analyst validation, and analyst comments are recorded in the audit history. The API is under `/api/v1/vulnerabilities` and the dashboard has a new Vulnerabilities page. Verified with 430 backend tests, 22 frontend tests and a passing production build. Back up the database before running `alembic upgrade head`.

## Milestone 3: analyst workbench (Module F)

Migration `0010_analyst_workbench` adds versioned risk assessments (likelihood x business impact with a reasoned override, business context, tailored remediation and priority) and an immutable sign-off ledger, and installs SQLite triggers that make vulnerability events, assessments and sign-offs append-only even against raw SQL. The `/api/v1/workbench` API provides a review queue, assessment authoring, approve/reject/reopen sign-off and an audit trail with analyst identity, all behind an analyst role check. A finding can only be confirmed after a human saves a risk assessment for its current revision and signs off with attestation; only then is it report eligible. The dashboard has a new Analyst workbench page that shows scanner evidence as escaped plain text only. Verified with 470 backend tests, 31 frontend tests and a passing production build. Back up the database, then run `alembic upgrade head` from `backend`. Vulnerabilities confirmed before this milestone must be re-approved in the workbench to become report eligible.

## Local authorisation evidence milestone

Private document upload, authenticated retrieval, human reviews, retention/holds and the approval evidence gate are implemented for local testing. Follow [the evidence guide](docs/AUTHORIZATION_EVIDENCE.md) for migration `0003_evidence`, configuration, API details, backup limitations and Windows validation. See the monitoring guide for current validation limits; no GitHub push is required.

## Website monitoring milestone

The first operational handler uses a shared job engine with atomic claims, leases, attempts, fenced results and execution events. Separate reviewed monitoring consent and explicit activation are required. The dashboard provides HTTP/DNS/TLS metrics, response-time history, incidents and notification delivery history. Migration `0004_monitoring` preserves existing data.

Follow [monitoring setup, APIs and validation](docs/MONITORING.md) for the five local processes, Windows commands and remaining acceptance checks. Browser execution was blocked by the implementation environment, so Windows browser acceptance remains required. Scanners are not implemented and cannot inherit monitoring permission.

## Security Scanner Worker: stage one

Explicit assessment requests, a versioned policy-only profile, live authorisation/evidence enforcement and an independent `assessment-worker` role now use the existing shared job engine. The Assessments dashboard supports request history, detail and cancellation. Migration `0005_assessment_intents` preserves existing monitoring data. No network check, Nmap, Nuclei or ZAP adapter is enabled; completed means permission preflight only.

See [the assessment audit, design, API and Windows acceptance guide](docs/SCANNER_STAGE_ONE.md). Keep existing accounts, configuration and data; back up before migrating. New browser acceptance remains pending on Windows.

## Local Python assessment worker

The [restricted Nmap profile](docs/NMAP_SCANNER.md) adds isolated TCP connect discovery for ports 80/443 only, with a dedicated container firewall, explicit hostname + public-IP scope and separate `tcp_port_discovery` permission. It reuses reports, analyst review and Findings; web-only approvals are insufficient.

The [Findings dashboard](docs/FINDINGS_DASHBOARD.md) provides a central queue of current analyst-confirmed issues, client/website/owner/severity/status filters, due dates, overdue counts and source-assessment navigation. It reuses the same review history and does not trigger scans. Migration: `0008_findings_dashboard`.

Completed header assessments support [analyst review, remediation tracking and reviewed report exports](docs/ANALYST_REVIEW.md). Migration `0007_observation_reviews` preserves existing reports and adds human decisions with revision history; no rescan is needed to review an existing assessment.

For the existing Azure VM integration, see [Remote Docker scanner setup and acceptance](docs/REMOTE_DOCKER_SCANNER.md). The default-off remote profile keeps the application/data on Windows and sends selected headers to a fixed networkless analyser. Windows SSH and live isolation, timeout, cancellation and cleanup checks passed. Real target assessments still require explicit, current written authorisation.

A default-off fixed HTTP profile reuses assessment jobs and live authorisation/evidence checks. It performs one HEAD and runs a network-free header analysis program in a bounded local Python process. No Docker or cloud service is required. Migration: `0006_local_http`; setting: `ASSESSMENT_LOCAL_HTTP_ENABLED=false`. See `docs/LOCAL_HTTP_ASSESSMENTS.md` (repository root) for setup, execution limits, acceptance steps and trust-boundary limitations.
