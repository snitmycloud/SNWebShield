# SNWebShield — Project Requirements

**Document status:** Draft v0.1  
**Product:** SNWebShield  
**Product type:** Website security assessment and vulnerability management platform

## 1. Purpose

SNWebShield will help a website cybersecurity services team manage authorised website security assessments from client onboarding through reporting, remediation and retesting. The first release will support manual analyst-led assessments. Scanner integration will be added only after the manual workflow, scope controls and report quality have been tested.

## 2. Users and roles

| Role | Main permissions |
|---|---|
| Platform Administrator | Manage platform settings, users, tenants and audit records |
| Security Manager | Create engagements, approve scope, assign analysts and oversee reports |
| Security Analyst | Work on assigned assessments, record tests, findings and evidence |
| Reviewer | Validate findings, severity, evidence and report quality |
| Client Administrator | View only their organisation's assets, assessments, findings and reports |
| Client Developer | View findings assigned for remediation and update remediation notes |

Access must be deny-by-default. A user must not gain access to a client merely by guessing an identifier or changing a URL.

## 3. Supported asset types

The platform should be technology-neutral and support, where included in the signed scope:

- WordPress and other CMS websites
- PHP and Laravel applications
- React, Angular and other JavaScript frontends
- Node.js applications
- Python and Django applications
- E-commerce applications
- Custom web applications
- Web APIs and GraphQL endpoints

The chosen test cases must depend on the real application features and technology. A checklist item may be marked not applicable or not tested, with a reason.

## 4. Functional requirements

### FR-01: Client management
- Create and update client organisation records.
- Store business contacts and authorised engagement contacts.
- Maintain engagement history.
- Separate each client's records from every other client.

### FR-02: Website asset management
- Register base URLs, domains, approved subdomains, IPs and API endpoints when applicable.
- Record technology notes, environment (production/staging) and asset owner.
- Track whether each asset is in scope, excluded or awaiting approval.
- Never infer permission from public accessibility or DNS ownership alone.

### FR-03: Authorisation and engagement scope
- Store an authorisation record, its signer, approval date, validity period and evidence/document reference.
- Record exact in-scope assets, excluded assets, testing window, approved source IPs, rate limits, allowed test categories and prohibited activities.
- Require an approved engagement and a valid scope before any assessment task can be scheduled.
- Keep scope changes versioned and require re-approval.

### FR-04: Assessment management
- Create an assessment linked to one client and one approved engagement scope.
- Assign analysts and reviewers.
- Store assessment dates, methodology version, environment, limitations and test coverage.
- Support statuses: Draft, Awaiting Authorisation, Approved, Scheduled, In Progress, Paused, Under Review, Report Published, Remediation, Retesting, Closed and Cancelled.

### FR-05: Test execution records
- Maintain a versioned library of test cases.
- Record test status: Pass, Finding, Not Applicable, Not Tested or Blocked.
- Record analyst, date, notes, evidence reference and reason for exclusions or blocked tests.
- Preserve the difference between a scanner alert, an analyst hypothesis and a validated finding.

### FR-06: Vulnerability/finding management
- Store title, unique finding ID, description, affected asset/endpoint, category, evidence, impact, likelihood/context, severity, CVSS version/vector/score where applicable, recommendation and references.
- Support states: Draft, Needs Validation, Confirmed, False Positive, Accepted Risk, Open, In Progress, Fixed Pending Retest, Resolved and Reopened.
- Require reviewer approval before a finding appears as confirmed in a final report.
- Record the rationale for severity and any client-approved risk acceptance.

### FR-07: Evidence management
- Store evidence in private storage, not a public web directory.
- Record who uploaded or captured evidence and when.
- Support screenshots and redacted text excerpts.
- Avoid collecting real customer data; redact secrets, credentials, tokens and personal data.
- Enforce retention and secure deletion policies.

### FR-08: Reporting
- Generate an executive summary PDF and a technical VAPT PDF.
- Include client, assets, scope, dates, methodology, coverage, limitations, findings, severity, evidence, impact, recommendations and retest outcomes.
- Version reports and record reviewer approval and publication time.
- Mark reports as confidential and provide controlled downloads.
- Never state that a website is fully secure based solely on a limited assessment or automated scan.

### FR-09: Client portal
- Show only the signed-in client's own assets and engagement records.
- Show assessment status, validated finding summary, remediation status and reports.
- Allow client responses and remediation notes, subject to role permissions.
- Prevent access to internal analyst notes unless explicitly designated client-visible.

### FR-10: Remediation and retesting
- Record remediation owner, target date, response and status.
- Create a retest linked to the original finding and assessment.
- Record retest method, evidence and result.
- Do not automatically mark a finding resolved because a client says it is fixed; require retest or documented risk acceptance.

### FR-11: Audit logging
- Record sign-ins, access-control failures, scope approvals/changes, assessment actions, evidence access, report downloads, finding changes and administrative actions.
- Protect logs from ordinary user modification.

## 5. Non-functional requirements

- Tenant isolation must be enforced server-side and tested.
- All traffic must use HTTPS in deployed environments.
- Sensitive data must be encrypted at rest using the selected storage/database controls.
- Secrets must be supplied through environment/secret management, never committed to Git.
- Apply least privilege to application and worker processes.
- Validate all inputs server-side.
- Apply rate limits and session protections.
- Maintain backups and test restoration.
- Provide traceable report and methodology versions.
- Design for accessibility and usable desktop/mobile layouts.
- Define data retention and deletion periods contractually.

## 6. MVP acceptance criteria

The MVP is acceptable when:

1. An administrator can create a client and invite role-based users.
2. A manager can create a website asset and an engagement scope.
3. The assessment cannot move to Approved without required written authorisation and scope fields.
4. An analyst can record test cases and evidence without executing automated scans from the portal.
5. A reviewer can validate findings and approve a report.
6. The system can generate both PDF report types from approved data.
7. A client can view only its own assessment and download its published reports.
8. A remediation item and retest result can be recorded.
9. Automated tests demonstrate tenant isolation and permission enforcement.
10. Important actions appear in audit logs.

## 7. Out of scope for MVP

- Autonomous exploitation or attack chaining
- Denial-of-service and load testing
- Unrestricted URL-to-scan functionality
- Network penetration testing beyond explicitly scoped web-facing assets
- Mobile application testing
- Cloud configuration audits
- SOC/MDR monitoring
- Compliance certification or guarantees of security

## 8. Open decisions

- Final company legal name and registered business details
- Brand logo, colours and typography
- First supported report language(s)
- Hosting provider and deployment region
- Evidence retention period and client deletion process
- Whether client authentication will use local accounts or an external identity provider
- Contract and privacy review by qualified Indian legal/compliance advisers
