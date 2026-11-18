# SNWebShield — Client and Assessment Workflow

## 1. Lead and engagement

1. Record the incoming lead.
2. Conduct an initial consultation and identify the business objective.
3. Confirm the client has authority to approve testing for each proposed asset.
4. Agree on service scope, fees, dates and deliverables.
5. Execute NDA/MSA/SOW and any required data-processing terms.

## 2. Authorisation and rules of engagement

Before assessment approval, record:

- Client legal name and authorised approving contact
- Exact domains, URLs, IP addresses, APIs and environments in scope
- Excluded domains, third-party services and infrastructure
- Evidence of written permission and its validity period
- Testing window and approved source IPs
- Rate limits and safe test constraints
- Permitted test categories and prohibited techniques
- Test accounts and role descriptions
- Emergency contact and stop-testing procedure
- Data handling, retention and deletion instructions

A change to scope requires documented approval before the changed asset or activity is tested.

## 3. Assessment preparation

- Assign a qualified analyst and independent reviewer where practicable.
- Confirm test accounts and backups/rollback arrangements with the client.
- Select the applicable methodology and technology-specific test cases.
- Confirm the test environment and communication schedule.
- Record exclusions and limitations before testing begins.

## 4. Manual assessment stages

1. Asset and technology confirmation within scope.
2. Passive discovery and configuration review.
3. Controlled review of HTTP, TLS, cookies, headers and exposed information.
4. Authentication and session management testing.
5. Authorisation and access-control testing with approved test accounts.
6. Input validation and injection testing using non-destructive test data.
7. File upload and application workflow review.
8. API security checks where included in scope.
9. Technology-specific checks for CMS/framework/e-commerce features.
10. Findings validation and evidence redaction.

Avoid destructive actions, denial-of-service, persistence, data extraction, real customer-data access and third-party system testing. If an unexpected sensitive exposure or service instability occurs, stop the relevant test, preserve minimal necessary evidence and notify the agreed contact.

## 5. Finding lifecycle

`Draft -> Needs Validation -> Confirmed -> Open -> In Progress -> Fixed Pending Retest -> Resolved`

Alternative outcomes: `False Positive`, `Accepted Risk`, `Reopened`.

A finding should include: ID, title, affected asset/endpoint, category, description, preconditions, safe evidence, impact, severity rationale, CVSS version/vector/score where appropriate, remediation, references, owner and status.

## 6. Review and reporting

- Reviewer checks scope, evidence, reproducibility, risk rating and remediation quality.
- Separate confirmed findings from observations and scanner leads.
- Prepare executive and technical reports from reviewed records.
- Include test coverage, exclusions, limitations and assessment dates.
- Obtain approval before publishing to the client portal.

## 7. Remediation and retesting

- Client records remediation owner and status.
- Retest only the affected item(s) within the agreed scope and dates.
- Record whether the issue is fixed, partially fixed, not fixed or unable to verify.
- Publish a retest addendum or revised report.
- Close only after retest or documented acceptance of residual risk.
