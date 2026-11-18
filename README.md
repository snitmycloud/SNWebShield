# SNWebShield

**Website Security Assessment & Vulnerability Management Platform**

Tagline: **Identify. Analyse. Secure.**

SNWebShield is planned as an internal platform for a website cybersecurity services team. It will manage client engagements, authorised website assets, assessment scope, manual testing records, validated findings, evidence, PDF reports, remediation and retesting.

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

## Initial technology direction

- Frontend: React + Vite
- Backend: Python + FastAPI
- Database: PostgreSQL
- Later background jobs: Celery + Redis
- Evidence: private, encrypted object storage
- Reports: HTML templates rendered to PDF
- Development: Git + GitHub

These are proposed choices, not installed dependencies or a production-ready deployment.

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

**Milestone 0: Project foundation created.** This repository contains initial planning and security-governance documents. Application code, authentication, database migrations and scanner integrations have not yet been implemented.
