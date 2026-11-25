# SNWebShield

**Self-service website security scanner — MONITORS. DETECTS. VALIDATES. PROTECTS.**

SNWebShield is a self-service website security scanner for website owners. A user signs up, adds their websites, proves they own each one (DNS TXT record, uploaded file or homepage meta tag), and SNWebShield scans it automatically. The product spec and build phases are in [docs/SNWEBSHIELD_SPEC.md](docs/SNWEBSHIELD_SPEC.md).

> Safety principle: domain ownership verification is the only approval step, and nothing is scanned without it. Ownership is re-checked before every scan, only the single public IP resolved at the start of a scan is contacted, private and cloud-internal addresses are refused, and a check that cannot finish is reported as "incomplete", never as "safe".

### Phase 1 (self-service accounts and ownership): what changed

- **Accounts:** sign up with email and password, confirm the email, sign in and out, forgot/reset password, change password. Passwords use Argon2 and the existing policy; sign-up, login and reset emails are rate-limited. Roles are `user` (customer) and `admin`; the older staff roles `lead_analyst` and `analyst` remain for the read-only legacy pages. Customers see only their own websites and scans and are refused by every staff route.
- **Plans:** limits live in one file, [backend/app/plans.json](backend/app/plans.json) (Free = 5 websites, Pro = 25, Business = 100), re-read when it changes. New accounts are Free; an admin changes plans on the Admin page. Adding a website past the limit shows a friendly message with an **Upgrade** button.
- **Websites and verification:** the domain is cleaned up (scheme, path, port, case) and IP addresses, `localhost` and internal names are refused. Each website gets its own random code. "Verify now" checks at once and shows what was found against what was expected; if the file/meta method fails because the site has no valid HTTPS, it points to the DNS TXT method. Verifying `example.com` covers its subdomains; verifying `www.example.com` covers only that host.
- **Remove website:** the owner can remove a website from its page or the list. They must type the domain to confirm. Removal deletes the website's verification code, deletes its queued scans, ends a running scan, and frees a plan slot. The website row, finished scan records, execution events and the audit log are kept, and `website_removed` (user, domain, time, what was cancelled) is written to the audit log (migration `0017_website_removal`). The same domain can be added again later with a new code.
- **Approved test targets (for Phase 2 testing):** a fixed list in code (`APPROVED_TEST_TARGETS` in `backend/app/core/config.py`) containing only `scanme.nmap.org`, which the Nmap project publicly allows scanning for tests. Only `admin` accounts can add it (everyone else gets "reserved"); it needs no DNS proof, is labelled **Test target** in the app, is limited to **2 scans per day** (UTC, shared by all admins, not resettable by removing and re-adding), and every scan is audited with `test_target: true`. It cannot be read or changed from the app, the API or `.env`, and it never covers subdomains.
- **Automatic first scan:** as soon as verification succeeds, the first scan is queued and run by the new `scan-worker`. In Phase 1 a scan re-checks ownership, resolves and pins one public IP, records the audit entry and ends as **incomplete**; the port, version and technology checks arrive in Phase 2.
- **Removed:** written authorisations, evidence uploads, approval states, attestation checkboxes, the assessment profile picker and dual sign-off. Their tables and data are kept and listed in `retired_tables` (migration `0016_self_service`). The earlier analyst pipeline (assessments, Docker/Nmap profiles, workbench, VAPT reports, remediation, port watch, monitoring set-up) is **read-only**: staff can still read past data, only "stop" actions work, and it will be deleted after Phases 2–4 replace it.

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
- Reports: PDFs rendered locally with `reportlab`, released only after human approval
- Development: Git + GitHub

The application runs locally on Windows (React frontend, FastAPI backend, workers); only the isolated scanner container runs on the Azure VM. It has been hardened for single-team production use behind HTTPS but has not been independently penetration tested; see the open items in [docs/AUDIT_MATRIX.md](docs/AUDIT_MATRIX.md).

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

**Phase 1 of the self-service spec is implemented on branch `feat/phase1-self-service`** (see the Phase 1 section above and [docs/AUDIT_MATRIX.md](docs/AUDIT_MATRIX.md)). The milestone notes below describe the earlier analyst workflow, which is now read-only.

Earlier status — **Milestones 1 to 6 complete (Modules A to H plus production hardening).** Authentication, authorisation evidence, monitoring, the scanner worker, vulnerability management, the analyst workbench, VAPT reporting, remediation and closure are implemented and tested, with an end-to-end lifecycle test. Open items are manual user steps (VM runner redeploy, real-target acceptance) and the risks listed as open in the audit matrix. Authorisation creation has an API but no UI form. Neither website registration nor authorisation approval starts a scan.

## Milestone 1: scanner worker hardening (Module D)

The scanner worker now uses one fixed, hardened SSH transport for both remote profiles: the Windows OpenSSH client is pinned by absolute path, and command-line options override any `ssh_config` that would enable agent/X11/port forwarding, proxies, passwords or session reuse. A missing client, an unreachable VM, an unavailable Docker daemon or the wrong runner/image fails the job with a specific audited error, with no local fallback. Assessment jobs hold a 120-second lease that exceeds every bounded remote stage budget. The HEAD broker requires TLS 1.2 or later, records the negotiated version, and classifies redirects into fixed categories without following them or storing the `Location` value. The VM runner can now inspect each created container and refuse to start it unless network, user, filesystem, capability, resource, IPC, mount and port settings match policy. This only takes effect after the runner is redeployed manually.

The full audit, risk register, test evidence, manual VM steps and remaining roadmap are in [docs/AUDIT_MATRIX.md](docs/AUDIT_MATRIX.md). No schema migration was added.

## Milestone 2: vulnerability management (Module E)

Migration `0009_vulnerabilities` adds a normalised `Vulnerability` entity, per-assessment `VulnerabilityOccurrence` records and an append-only event history. Repeated detections of the same check on the same website and target share a fingerprint, so they are deduplicated across assessments while each occurrence keeps its own evidence hash. Each vulnerability carries scanner and analyst severity, a confidence score with its factors, reproduction steps, and a validation state. Nothing becomes confirmed without an explicit human analyst validation, and analyst comments are recorded in the audit history. The API is under `/api/v1/vulnerabilities` and the dashboard has a new Vulnerabilities page. Verified with 430 backend tests, 22 frontend tests and a passing production build. Back up the database before running `alembic upgrade head`.

## Milestone 3: analyst workbench (Module F)

Migration `0010_analyst_workbench` adds versioned risk assessments (likelihood x business impact with a reasoned override, business context, tailored remediation and priority) and an immutable sign-off ledger, and installs SQLite triggers that make vulnerability events, assessments and sign-offs append-only even against raw SQL. The `/api/v1/workbench` API provides a review queue, assessment authoring, approve/reject/reopen sign-off and an audit trail with analyst identity, all behind an analyst role check. A finding can only be confirmed after a human saves a risk assessment for its current revision and signs off with attestation; only then is it report eligible. The dashboard has a new Analyst workbench page that shows scanner evidence as escaped plain text only. Verified with 470 backend tests, 31 frontend tests and a passing production build. Back up the database, then run `alembic upgrade head` from `backend`. Vulnerabilities confirmed before this milestone must be re-approved in the workbench to become report eligible.

## Milestone 4: VAPT reporting (Module G)

Migration `0011_vapt_reports` adds report snapshots, PDF artifacts with SHA-256 hashes, an immutable approval ledger and an audit event log, with SQLite triggers that block rewriting them. The `/api/v1/reports` API generates a draft from one completed assessment, including only findings that an analyst confirmed and signed off against their current revision (everything else is counted and excluded), and renders a PDF locally with `reportlab` (no external binaries): executive summary, client and domain scope, methodology and isolation attestation, severity breakdown, validated findings with escaped evidence and reproduction steps, remediation by priority, and the analyst sign-off block. All client, target and evidence text is treated as untrusted and escaped. A report stays a draft until a human approves it with an attested justification; only then does an official PDF exist and become downloadable, and every download re-verifies its hash. The dashboard has a new VAPT reports page. Verified with 501 backend tests, 40 frontend tests and a passing production build. Back up the database, install `requirements.txt`, then run `alembic upgrade head` from `backend`.

## Milestone 5: remediation, retesting and closure (Module H)

Migration `0012_remediation_retesting` adds remediation tracking for confirmed findings (`open`, `in_progress`, `fix_submitted`, `retest_requested`, `verified_fixed`, `reopened`, `risk_accepted`) with client notes, target dates and an append-only actor/UTC history, scoped retest requests, and an immutable assessment closure record, all protected by SQLite triggers. A retest is an ordinary assessment request made through the existing scanner path, so the live written authorisation, exact domain and methods are revalidated at request, claim and execution, with no local fallback. When the retest's observation is ingested, the finding becomes `verified_fixed` if the weakness is gone, or is reopened automatically with the fresh evidence if it still reproduces. Analysts can also reopen a finding manually and formally accept a risk with an attested justification. `POST /api/v1/assessments/{id}/close` succeeds only when every confirmed finding is verified fixed or risk accepted. The dashboard has a new Remediation page. Verified with 540 backend tests, 49 frontend tests and a passing production build. Back up the database, run `alembic upgrade head` from `backend`, and restart the assessment worker.

## Milestone 6: production hardening and end-to-end integration

Migration `0013_production_hardening` closes the authentication risks: every login success, failure, inactive-account attempt, throttled attempt and logout is written to an append-only `auth_events` table (no passwords, tokens or raw emails); repeated failures lock a login with HTTP 429 and `Retry-After`; `POST /api/v1/auth/logout` revokes the token's `jti` on the server; tokens are bound to the account's current role; and new passwords must meet a policy. Every API response carries `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` and related headers (`Strict-Transport-Security` only over TLS), and `CORS_ORIGINS` is validated at start-up.

Three roles now exist: `analyst`, `lead_analyst` (also approves reports, accepts risk, closes and reopens closures) and `admin` (everything; the bootstrap account). `SEPARATION_OF_DUTIES_ENABLED=true` adds dual sign-off: the analyst who assessed a finding cannot approve it, the report creator cannot approve the report, and whoever handled remediation cannot close the assessment. It is off by default so one admin can run the whole workflow. Once an assessment is closed, its findings and remediation are locked until a lead analyst or admin formally reopens the closure with an audited reason. Evidence purging now overwrites the file before unlinking it while keeping the document's SHA-256 as immutable audit proof, and `python -m app.cli.evidence_retention` reports expired documents without deleting anything.

`backend/tests/test_e2e_lifecycle.py` drives the whole workflow from client registration to closure and checks the audit trail at every stage. Verified with 580 backend tests, 53 frontend tests and a passing production build. The per-risk status and test references are in [docs/AUDIT_MATRIX.md](docs/AUDIT_MATRIX.md).

## Setup, run, test and deploy

All commands are PowerShell, run from the repository root unless stated. Never paste secrets, `.env` contents or private keys into chat, commits or logs.

### 1. Local Windows setup

```powershell
cd backend
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }   # never overwrite an existing .env
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into JWT_SECRET_KEY in backend\.env yourself
cd ..\frontend
npm install
```

### 2. Back up and migrate the database

```powershell
cd backend
.\.venv\Scripts\python.exe -m app.cli.backup_database      # verified copy of the SQLite file, outside the repository
.\.venv\Scripts\python.exe -m alembic upgrade head          # head is 0017_website_removal
```

To restore a backup: stop the API and all workers, then copy the backup file over `backend\snwebshield_dev.db` and check out the code that matches it (for `0016` and `0017`, the commit before Phase 1).

Back up before every migration. Migrations are additive and downgrades are refused; to go back, restore the backup together with the matching code. The API refuses to start if a required table is missing.

### 3. Create accounts

Customers sign up in the browser (`http://127.0.0.1:5173`, "Create an account") and confirm their email. The admin account is created locally:

```powershell
cd backend
.\.venv\Scripts\python.exe -m app.cli.create_admin                    # admin (manages users and plans)
```

Account emails (confirmation and password reset) go through SMTP when `SMTP_HOST` and `SMTP_SENDER` are set. Otherwise, for development only, each email is saved as a `.eml` file in `MAIL_OUTBOX_DIR` (default `%USERPROFILE%\SNWebShield-Private\outbox`, outside the repository); open it to click the link. To switch to real email, set in `backend\.env`: `SMTP_HOST`, `SMTP_PORT` (465 for SSL or 587 for STARTTLS), `SMTP_SECURITY` (`ssl` or `starttls`), `SMTP_SENDER` (the From address), `SMTP_USERNAME` and `SMTP_PASSWORD` (if your provider needs them), and `FRONTEND_BASE_URL` (the address users open, used in the email links). Restart the API afterwards.

Passwords are typed at a hidden prompt: 12 to 128 characters, at least three of lowercase, uppercase, digits and symbols, not common and not containing the email name.

### 4. Run the processes (separate terminals)

```powershell
# API (from backend)
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
# Monitoring: scheduler, worker and notification dispatcher (from backend)
.\.venv\Scripts\python.exe -m app.cli.operations scheduler
.\.venv\Scripts\python.exe -m app.cli.operations worker
.\.venv\Scripts\python.exe -m app.cli.operations notifications
# Scan worker: runs self-service scans (at most SCAN_MAX_CONCURRENT at once). Run one scan-worker process. (from backend)
.\.venv\Scripts\python.exe -m app.cli.operations scan-worker
# Legacy assessment worker: only cancels leftover queued legacy jobs (optional) (from backend)
.\.venv\Scripts\python.exe -m app.cli.operations assessment-worker
# Frontend (from frontend)
npm run dev        # http://127.0.0.1:5173
```

`scripts\start-workers.ps1` starts any local role that is not already running. The Assessments page shows the worker state and the start command when it is not running.

Restart the API and the assessment worker after changing `.env` or upgrading. Keep everything on the Windows machine; do not deploy the stack to Azure.

### 5. Environment variables (names only; put real values in the private `backend/.env`)

| Name | Purpose |
|---|---|
| `DATABASE_URL` | SQLite file by default (`sqlite:///./snwebshield_dev.db`) |
| `JWT_SECRET_KEY` | Required, random, at least 32 bytes. Also `JWT_ACCESS_TOKEN_MINUTES` (20), `JWT_ISSUER`, `JWT_AUDIENCE` |
| `CORS_ORIGINS` | Comma-separated frontend origins (`http://localhost:5173,...`); `*` is rejected |
| `EVIDENCE_ROOT`, `EVIDENCE_MAX_BYTES`, `EVIDENCE_RETENTION_DAYS` | Private evidence storage outside the repository, upload limit, retention |
| `LOGIN_MAX_FAILURES` (5), `LOGIN_WINDOW_MINUTES` (15) | Login throttling |
| `HSTS_MAX_AGE_SECONDS` | `Strict-Transport-Security` lifetime when served over HTTPS |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY` (`ssl`/`starttls`), `SMTP_SENDER`, `SMTP_USERNAME`, `SMTP_PASSWORD` | Account emails (confirmation, password reset) and monitoring notifications |
| `MAIL_OUTBOX_DIR` | Development only: where account emails are saved when SMTP is not configured (must be outside the repository) |
| `FRONTEND_BASE_URL` (`http://localhost:5173`) | Address used in email links |
| `EMAIL_VERIFICATION_HOURS` (24), `PASSWORD_RESET_MINUTES` (60) | Lifetime of emailed links |
| `SIGNUP_MAX_PER_IP` (5), `ACCOUNT_EMAIL_MAX_PER_IP` (10), `SIGNUP_WINDOW_MINUTES` (60) | Sign-up and account-email rate limits |
| `OWNERSHIP_CACHE_HOURS` (24), `OWNERSHIP_HTTP_TIMEOUT_SECONDS` (8) | How long a verification is trusted before a scan re-checks it; file/meta fetch timeout |
| `SCAN_MAX_CONCURRENT` (3), `SCAN_TIME_LIMIT_SECONDS` (900), `SERVER_PUBLIC_IPS` | Scans running at once on the server; total time per scan (past it the result is "incomplete"); this server's public IPs, never scanned |
| `NOTIFICATION_CHANNEL`, `NOTIFICATION_RECIPIENT` | Legacy monitoring notifications (dashboard by default) |
| `ASSESSMENT_LOCAL_HTTP_ENABLED` (false) | Fixed local single-HEAD profile |
| `ASSESSMENT_REMOTE_DOCKER_ENABLED`, `ASSESSMENT_REMOTE_IMAGE_ID`, `ASSESSMENT_REMOTE_REQUIRE_ISOLATION_ATTESTATION` | Remote Docker header analysis on the Azure VM; image ID is the immutable `sha256:` ID of the scanner image |
| `ASSESSMENT_NMAP_ENABLED`, `ASSESSMENT_NMAP_IMAGE_ID` | Restricted Nmap profile |
| `VITE_API_BASE_URL` (frontend) | API base URL including `/api/v1` |

### 6. Run the tests (one at a time, never together)

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest tests/test_e2e_lifecycle.py tests/test_production_hardening.py
.\.venv\Scripts\python.exe -m pytest          # full regression, about 15 minutes
cd ..\frontend
npm test                                      # unit tests (Node test runner)
npm run build                                 # production build
npm run test:e2e                              # optional Chromium journeys (Playwright)
```

Run `pytest`, `npm test` and `npm run build` strictly one after another; running them together can exhaust memory on this machine.

The legacy analyst-pipeline suites are listed in `collect_ignore` in `backend/tests/conftest.py`: they exercise the removed written-permission system and stay in the repository until Phases 2–4 replace that code. Phase 1 tests: `test_accounts.py`, `test_websites.py`, `test_website_removal.py`, `test_ownership.py`, `test_scans.py`, `test_legacy_read_only.py`, `test_auth.py`, `test_migrations.py`, and `frontend/tests/account.test.js`.

### 7. Deploy or update the isolated scanner container on the Azure VM

The scanner image is built on the existing VM `azureuser@57.159.27.58` only over SSH/SCP. Never expose Docker's TCP port 2375, never create paid Azure resources or registries, and never delete or prune existing containers, images or volumes. Only the scanner build files travel; no `.env`, database, evidence or keys. The container runs with `--network none`, a non-root user, a read-only root filesystem and strict CPU, memory, PID and time limits, enforced by `scanner/remote_runner.py`.

```powershell
# Windows: sync only the scanner build directory and the single analyser source the Dockerfile copies.
ssh azureuser@57.159.27.58 "mkdir -p ~/snwebshield-scanner/backend/app/services"
scp -r scanner azureuser@57.159.27.58:snwebshield-scanner/
scp backend/app/services/header_analyzer.py azureuser@57.159.27.58:snwebshield-scanner/backend/app/services/
```

```bash
# On the VM (ssh azureuser@57.159.27.58). Use a reviewed Python base image digest; there is no floating default.
cd ~/snwebshield-scanner
docker build --pull=false -f scanner/Dockerfile \
  --build-arg PYTHON_BASE=python:3.12-slim@sha256:REPLACE_WITH_REVIEWED_DIGEST \
  -t snwebshield-header-analysis:v1 .
docker image inspect --format '{{.Id}}' snwebshield-header-analysis:v1      # note the new sha256 image ID
# Install the runner and record the image ID (only if the image or runner changed):
sudo install -o root -g root -m 755 scanner/remote_runner.py /usr/local/libexec/snwebshield-header-runner
printf '%s\n' 'sha256:REPLACE_WITH_NEW_IMAGE_ID' | sudo tee /etc/snwebshield/header-image-id >/dev/null
/usr/local/libexec/snwebshield-header-runner --check
/usr/bin/python3 -I scanner/verify_host.py
```

Then on Windows, set `ASSESSMENT_REMOTE_IMAGE_ID` to the new ID in the private `backend\.env`, restart the API and assessment worker, and verify with `.\.venv\Scripts\python.exe -m app.cli.scanner_check` from `backend` (expect `passed: true`, `target_requests: 0`, `isolation_attested: true`, confirmed cleanup). If only `remote_runner.py` changed, skip the build and run just the `scp`, `install` and `--check` steps; the image ID does not change. When `isolation_attested` is true, set `ASSESSMENT_REMOTE_REQUIRE_ISOLATION_ATTESTATION=true`. Details and troubleshooting: [docs/REMOTE_DOCKER_SCANNER.md](docs/REMOTE_DOCKER_SCANNER.md).

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

## Running an assessment

Open Assessments, choose a website and a profile. The page checks permission without any network request, shows which authorisation will be used or the exact reason it is blocked, and enables **Run assessment** only when permission is valid. The worker re-checks permission immediately before execution. Observations are unconfirmed until an analyst validates them in Vulnerability Management.

## Scanner VM housekeeping

After updating `scanner/remote_runner.py` and `scanner/nmap/runner.py`, install them on the VM as described above and run `--check` once. Then the Assessments page button "Check VM for leftover containers" lists SNWebShield-labelled containers older than two minutes. It is read-only; remove anything it flags manually and only after you approve (`/usr/local/libexec/snwebshield-nmap-runner --cleanup <token>` removes just a matching labelled container). The Nmap runner now inspects its guard and scanner containers before starting them; results from older runners show "not attested".

## After a worker crash or restart

Start the assessment worker again. It fails any run whose lease expired (once, never repeated), ingests results that were stored but not yet turned into observations, and records a `worker_startup_recovery` audit event. A request that cannot progress is labelled on the Assessments page, and it can be cancelled at any time without a worker.

## Testing

See [docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md) for the step-by-step test process: automated suites, a manual walk through Monitors, Detects, Validates and Protects, negative and security tests, the Azure VM checks, port watch, crash recovery and a results sheet.

## The four pillars as one cycle

Open **Website lifecycle** for a per-website summary of Monitors, Detects, Validates and Protects and the single next step. The cycle is: monitoring watches uptime, DNS, TLS and response time; **port watch** (Monitoring page, off until you enable it with a written-permission attestation) re-checks TCP 80 and 443 on a schedule and alerts when a port changes state; authorised assessments detect issues, now including HTTPS use, certificate expiry and cookie flags; analysts validate observations; fixes are retested, and with `SEPARATION_OF_DUTIES_ENABLED=true` a second person must confirm a verified fix before the assessment can be closed.

After pulling this version: back up the database, run `alembic upgrade head` from `backend` (migrations 0014 and 0015; nothing is enabled by upgrading), and restart the API and workers. Port watch needs the scheduler, the assessment worker and the notification dispatcher running, plus the Nmap profile enabled and the VM runners redeployed.
