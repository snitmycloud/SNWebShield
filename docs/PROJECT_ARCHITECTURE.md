# SNWebShield — Project Architecture

**Version:** Draft v0.1

## 1. Architecture principles

1. Separate the business management application from the security testing environment.
2. Require approved, versioned scope before any testing activity.
3. Use human-led assessment and validation in the first release.
4. Treat scanner output as untrusted leads, not confirmed vulnerabilities.
5. Enforce tenant isolation on the server and database layers.
6. Store evidence privately and provide controlled access.
7. Make assessment activity auditable.

## 2. Logical components

```text
Client / Internal Staff
        |
        v
React Web Application
        |
        v
FastAPI Application
  |       |        |         |
  |       |        |         +--> Audit Log Service
  |       |        +------------> Report Service
  |       +---------------------> Assessment & Findings Services
  +-----------------------------> Client / Asset / Scope Services
        |
        +------> PostgreSQL
        |
        +------> Private Evidence Storage
        |
        +------> PDF Rendering Service

Separate Assessment Workstation / Isolated Worker
        |
        +--> Approved manual tools and, in a later phase, controlled integrations
        |
        +--> Analyst-reviewed results imported into SNWebShield
```

The assessment environment must not have unrestricted access to the management database. Future scan workers should run in an isolated network/security boundary with explicit egress controls and strict target allowlists.

## 3. Suggested backend modules

- `authentication`: identities, sessions, MFA integration and password policy
- `tenants`: client organisations and tenant context
- `users`: roles, invitations and memberships
- `assets`: websites, domains, APIs and asset ownership
- `engagements`: contracts, authorisation and rules of engagement
- `assessments`: assessment records, assignments, schedule and status
- `methodology`: test case library and versioning
- `executions`: test-case results and analyst notes
- `findings`: vulnerability records, severity, validation and lifecycle
- `evidence`: private evidence metadata and access control
- `reports`: report data snapshots, rendering, versioning and publication
- `remediation`: client fix notes and target dates
- `retests`: retest evidence and outcomes
- `audit`: append-only business/security event records

## 4. Suggested data model

Primary entities and relationships:

- `Client` 1-to-many `ClientUser`
- `Client` 1-to-many `WebsiteAsset`
- `Client` 1-to-many `Engagement`
- `Engagement` 1-to-many `EngagementAsset`
- `Engagement` 1-to-many `Assessment`
- `Assessment` 1-to-many `TestExecution`
- `Assessment` 1-to-many `Finding`
- `Finding` 1-to-many `Evidence`
- `Finding` 1-to-many `RemediationUpdate`
- `Finding` 1-to-many `Retest`
- `Assessment` 1-to-many `ReportVersion`
- All tenant-owned records carry a `client_id` or are reachable only through a server-validated tenant relationship.

Use UUID primary keys. Add created/updated timestamps, actor IDs and lifecycle status fields where appropriate. Use database migrations for all schema changes.

## 5. API route groups (proposed)

```text
/api/v1/auth/*
/api/v1/clients/*
/api/v1/client-users/*
/api/v1/assets/*
/api/v1/engagements/*
/api/v1/assessments/*
/api/v1/methodology/*
/api/v1/test-executions/*
/api/v1/findings/*
/api/v1/evidence/*
/api/v1/reports/*
/api/v1/remediation/*
/api/v1/retests/*
/api/v1/audit-events/*
```

Every route must authenticate the caller, check role permissions and enforce tenant scope. Do not trust a `client_id` supplied by the browser without checking the user's membership and permissions.

## 6. Report generation design

1. Reviewer approves the assessment findings and scope record.
2. Report service creates an immutable data snapshot for a report version.
3. HTML templates render executive and technical report views.
4. PDF renderer creates the document.
5. PDF is stored in private object storage.
6. Publication event is logged.
7. Client download is provided through a short-lived authorised link or authenticated download endpoint.

The report snapshot should preserve the exact finding and methodology versions used at publication time.

## 7. Future scanner integration design

Scanner integration is not part of the first manual release. When added:

- Only a manager-approved assessment can request a scan.
- Targets must be matched against exact approved domains/IPs and exclusions.
- Block localhost, private, link-local, multicast and cloud metadata destinations unless a separately reviewed internal scope explicitly requires them.
- Re-check DNS resolution at execution time and defend against DNS rebinding.
- Restrict redirects and outbound network destinations.
- Enforce rate, concurrency, time and response-size limits.
- Run tools in disposable, least-privilege containers or isolated workers.
- Do not expose a generic shell or arbitrary command execution endpoint.
- Save raw output as untrusted evidence; require analyst validation before creating a confirmed finding.
- Log the tool/version, configuration, operator, scope, start/end time and result digest.

## 8. Deployment direction

Development can use Docker Compose for the web app and PostgreSQL. Production should use separate services, managed secrets, encrypted backups, private evidence storage, monitoring, patching and a documented recovery process. Do not deploy the assessment worker on the same unrestricted network as the client portal.
