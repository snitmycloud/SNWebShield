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

## Local authorisation evidence milestone

Private document upload, authenticated retrieval, human reviews, retention/holds and the approval evidence gate are implemented for local testing. Follow [the evidence guide](docs/AUTHORIZATION_EVIDENCE.md) for migration `0003_evidence`, configuration, API details, backup limitations and Windows validation. See the monitoring guide for current validation limits; no GitHub push is required.

## Website monitoring milestone

The first operational handler uses a shared job engine with atomic claims, leases, attempts, fenced results and execution events. Separate reviewed monitoring consent and explicit activation are required. The dashboard provides HTTP/DNS/TLS metrics, response-time history, incidents and notification delivery history. Migration `0004_monitoring` preserves existing data.

Follow [monitoring setup, APIs and validation](docs/MONITORING.md) for the five local processes, Windows commands and remaining acceptance checks. Browser execution was blocked by the implementation environment, so Windows browser acceptance remains required. Scanners are not implemented and cannot inherit monitoring permission.
