# SNWebShield - Website VAPT Assessment Checklist

**Document ID:** SNWS-ASM-CHK-001  
**Version:** 1.0  
**Status:** Initial working draft  
**Assessment approach:** Manual-first, tool-assisted  
**Applies to:** Websites and web applications, including WordPress, PHP, Laravel, React, Angular, Node.js, Python/Django, e-commerce and custom applications.

> **Authorisation rule:** Do not test a website, API, subdomain, IP address, hosting account or third-party integration until it is explicitly listed in a written authorisation and approved Rules of Engagement (RoE). A public URL or a client's request by itself is not sufficient proof that every related asset is in scope.

---

## 1. How to use this checklist

1. Create a separate copy of this checklist for each assessment.
2. Complete the pre-assessment gates before any active testing.
3. Mark each applicable test as **Pass**, **Fail**, **Not Applicable**, **Not Tested**, or **Blocked**.
4. Record evidence references and notes. Do not place passwords, session tokens, personal data or live secrets in the checklist.
5. Validate scanner alerts manually before recording them as confirmed vulnerabilities.
6. Record limitations and excluded test areas in the final report.
7. Obtain reviewer approval before publishing a report to the client.

### 1.1 Test result definitions

| Result | Meaning |
|---|---|
| Pass | The control was checked within the agreed scope and no issue was identified. |
| Fail | A weakness was identified and sufficient evidence was collected safely. |
| Not Applicable (N/A) | The feature or control does not exist or does not apply to this application. Explain why. |
| Not Tested (N/T) | The test was not performed. Explain why. |
| Blocked | The test could not be completed due to access, environment, safety or scope constraints. |

**Important:** A Pass does not guarantee that the application is secure. It only records the result of the specified test within the assessment scope and time window.

---

## 2. Assessment details

| Field | Value |
|---|---|
| Client / organisation |  |
| Engagement ID |  |
| Assessment ID |  |
| Primary website URL |  |
| Approved domains / subdomains |  |
| Approved IP addresses / ranges |  |
| Approved API base URLs |  |
| Application name |  |
| Environment (production / staging / development) |  |
| Application type / business purpose |  |
| Technology / CMS / framework |  |
| Hosting / CDN / WAF (client-provided details) |  |
| Client technical contact |  |
| Emergency contact |  |
| Lead analyst |  |
| Reviewer |  |
| Testing start and end time (with timezone) |  |
| Source IP address(es) used by the assessment team |  |
| Written authorisation reference |  |
| Rules of Engagement reference |  |
| Assessment limitations |  |

---

## 3. Mandatory pre-assessment gates

No active security testing may begin until all required gates are complete.

| ID | Gate / check | Required evidence | Result | Notes / evidence ref |
|---|---|---|---|---|
| PRE-01 | Client identity and authority to approve testing are verified. | Client contact and authority record |  |  |
| PRE-02 | Signed written authorisation is received. | Signed authorisation document |  |  |
| PRE-03 | Statement of Work and assessment scope are approved. | Approved SOW / scope |  |  |
| PRE-04 | Rules of Engagement are approved by both parties. | Signed RoE |  |  |
| PRE-05 | Domains, subdomains, URLs, APIs and IPs are explicitly listed. | Approved asset inventory |  |  |
| PRE-06 | Third-party services are identified and excluded unless their owner has separately authorised testing. | Third-party dependency list |  |  |
| PRE-07 | Test window, timezone, rate limits and source IPs are agreed. | Approved test schedule |  |  |
| PRE-08 | Permitted and prohibited test types are documented. | RoE |  |  |
| PRE-09 | Emergency stop contact and escalation process are confirmed. | Contact and escalation record |  |  |
| PRE-10 | Test accounts and roles are provided through an approved secure channel, where required. | Account/role matrix (no passwords in report) |  |  |
| PRE-11 | Client confirms backups / rollback arrangements for the environment, where applicable. | Client confirmation |  |  |
| PRE-12 | Data handling, evidence storage, retention and deletion terms are agreed. | Data handling agreement |  |  |
| PRE-13 | Assessment environment and source IP are identified. | Analyst setup record |  |  |
| PRE-14 | A safe testing plan is reviewed by the lead analyst. | Approved test plan |  |  |

### 3.1 Default prohibited activities unless separately assessed and expressly authorised

- Denial-of-service, stress or load testing.
- Destructive testing, deletion or modification of client data.
- Unrestricted exploitation, persistence, lateral movement or malware deployment.
- Bulk extraction or downloading of customer records.
- Brute-force or credential-stuffing campaigns.
- Testing payment providers, identity providers, CDNs, hosting providers or other third parties without their authorisation.
- Testing outside the approved domains, IPs, APIs, environment or time window.

If a test risks service disruption or exposure of real data, stop and contact the client. Use controlled test accounts and synthetic data wherever possible.

---

## 4. Scope validation and asset inventory

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| SCOPE-01 | Confirm the primary URL resolves to the client-approved asset. |  |  |
| SCOPE-02 | Confirm each proposed hostname is listed in the approved scope. |  |  |
| SCOPE-03 | Confirm redirects remain within approved scope. |  |  |
| SCOPE-04 | Identify CDN, WAF, reverse proxy and hosting dependencies from client-provided information and passive observation. |  |  |
| SCOPE-05 | Identify login areas, admin portals and user-facing application areas included in scope. |  |  |
| SCOPE-06 | Identify API endpoints and versions that are explicitly included. |  |  |
| SCOPE-07 | Identify user roles and approved test accounts. |  |  |
| SCOPE-08 | Record exclusions, inaccessible features and known testing constraints. |  |  |

---

## 5. Information gathering and technology review

Use passive or low-impact methods first. Confirm scope before any active discovery.

| ID | Check | Suggested method / tool | Result | Evidence ref / notes |
|---|---|---|---|---|
| INFO-01 | Record DNS records relevant to the approved domain. | `dig`, client DNS records |  |  |
| INFO-02 | Identify technologies and CMS where reliably observable. | WhatWeb, Wappalyzer, manual review |  |  |
| INFO-03 | Identify server/platform indicators without attempting to exploit them. | HTTP response review |  |  |
| INFO-04 | Identify publicly referenced application routes and functionality. | Browser, sitemap, client documentation |  |  |
| INFO-05 | Identify robots.txt, sitemap.xml and public metadata exposure. | Browser / HTTP client |  |  |
| INFO-06 | Identify public source maps or build artefacts that may expose sensitive implementation details. | Browser and source review |  |  |
| INFO-07 | Identify externally loaded scripts and important third-party dependencies. | Browser developer tools |  |  |
| INFO-08 | Record application version information only when exposed. | Passive review |  |  |
| INFO-09 | Confirm discovered assets remain within the written scope. | Scope register |  |  |

---

## 6. Transport security and website configuration

| ID | Check | Suggested method / tool | Result | Evidence ref / notes |
|---|---|---|---|---|
| CFG-01 | HTTP requests redirect to HTTPS where required. | Browser / `curl` |  |  |
| CFG-02 | TLS certificate is valid, trusted and matches the hostname. | Browser / `testssl.sh` |  |  |
| CFG-03 | Deprecated or weak TLS protocol / cipher configuration is not enabled. | `testssl.sh` |  |  |
| CFG-04 | HSTS is configured appropriately for the deployment. | Response header review |  |  |
| CFG-05 | Content-Security-Policy is present and appropriate to the application. | Response header review |  |  |
| CFG-06 | X-Content-Type-Options is configured appropriately. | Response header review |  |  |
| CFG-07 | Referrer-Policy is configured appropriately. | Response header review |  |  |
| CFG-08 | Permissions-Policy is configured appropriately where relevant. | Response header review |  |  |
| CFG-09 | Clickjacking protections are appropriate (CSP frame-ancestors and/or compatible controls). | Response header review |  |  |
| CFG-10 | CORS allows only required trusted origins and methods. | Response review; approved test origin |  |  |
| CFG-11 | Cookies use Secure, HttpOnly and suitable SameSite attributes where applicable. | Browser developer tools / proxy |  |  |
| CFG-12 | Directory listing is not unintentionally enabled. | Browse known in-scope paths only |  |  |
| CFG-13 | Default pages, sample applications and unnecessary services are not exposed. | Low-impact review |  |  |
| CFG-14 | Debug mode, stack traces and verbose errors are not exposed to unauthenticated users. | Controlled invalid requests |  |  |
| CFG-15 | Sensitive files, backups, environment files or repository metadata are not publicly accessible. | Check only approved, known paths |  |  |
| CFG-16 | Cache controls do not allow sensitive authenticated pages to be served to another user. | Controlled test accounts |  |  |
| CFG-17 | Security-relevant DNS records and email-domain controls are reviewed where included in scope. | DNS review |  |  |

---

## 7. Authentication and account security

Perform with client-provided test accounts. Do not attempt password spraying, credential stuffing or testing against real user accounts.

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| AUTH-01 | Login functionality uses HTTPS and does not expose credentials in URLs. |  |  |
| AUTH-02 | Authentication errors do not unnecessarily reveal whether an account exists. |  |  |
| AUTH-03 | Password policy and secure password storage controls are appropriate (review configuration / design where access is provided). |  |  |
| AUTH-04 | MFA is supported or enforced for sensitive roles where required by the client's security policy. |  |  |
| AUTH-05 | Password reset uses a secure, time-limited and single-use process. |  |  |
| AUTH-06 | Password reset does not disclose or expose reset tokens. |  |  |
| AUTH-07 | Account registration and verification flows prevent unauthorised account activation. |  |  |
| AUTH-08 | Login and recovery endpoints have proportionate anti-automation controls. |  |  |
| AUTH-09 | Logout invalidates the relevant session. |  |  |
| AUTH-10 | Sensitive account changes require appropriate re-authentication or verification. |  |  |
| AUTH-11 | Session invalidation occurs after password change or account compromise response, where expected. |  |  |
| AUTH-12 | Test accounts are limited to the roles and permissions agreed for the assessment. |  |  |

---

## 8. Session management

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| SESS-01 | Session identifiers are not exposed in URLs, referrers or client-visible logs. |  |  |
| SESS-02 | Session cookies use appropriate Secure, HttpOnly and SameSite attributes. |  |  |
| SESS-03 | Session identifiers are rotated after authentication and privilege changes where appropriate. |  |  |
| SESS-04 | Idle and absolute session timeouts align with the application's risk. |  |  |
| SESS-05 | Logout and server-side session invalidation behave as expected. |  |  |
| SESS-06 | Concurrent session behaviour matches the client's security requirements. |  |  |
| SESS-07 | Sensitive pages are not accessible from a stale session after logout. |  |  |
| SESS-08 | CSRF protections are applied to state-changing actions where relevant. |  |  |

---

## 9. Authorisation and access control

Use at least two approved test roles where possible. Use only records created for testing. Do not access unrelated customer information.

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| AC-01 | Unauthenticated users cannot access authenticated-only functions. |  |  |
| AC-02 | Lower-privileged roles cannot access administrator functions. |  |  |
| AC-03 | Users cannot access another test user's records by changing an object identifier. |  |  |
| AC-04 | Server-side authorisation is enforced for every sensitive API or action. |  |  |
| AC-05 | Hidden UI controls are not treated as the only access-control mechanism. |  |  |
| AC-06 | Direct requests to restricted routes are denied appropriately. |  |  |
| AC-07 | Role changes and privilege changes take effect correctly. |  |  |
| AC-08 | Tenant or organisation boundaries are enforced where the application is multi-tenant. |  |  |
| AC-09 | Administrative actions are restricted and logged. |  |  |
| AC-10 | File and report downloads enforce the same access controls as the related records. |  |  |

---

## 10. Input validation and injection risks

Use safe, non-destructive test values in an agreed test environment. Do not run destructive queries, modify production records or access data beyond a controlled test record.

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| INP-01 | Server-side validation is applied to user-controlled input. |  |  |
| INP-02 | Database queries use parameterisation or safe query construction. |  |  |
| INP-03 | Output is contextually encoded to prevent cross-site scripting. |  |  |
| INP-04 | HTML or rich-text features sanitise permitted content safely. |  |  |
| INP-05 | OS command execution is not constructed unsafely from user input. |  |  |
| INP-06 | Template engines do not evaluate untrusted input as executable template content. |  |  |
| INP-07 | LDAP, XML, NoSQL and other specialised interpreters are protected where used. |  |  |
| INP-08 | Error responses do not expose SQL statements, secrets or internal paths. |  |  |
| INP-09 | Input length, type and format constraints are enforced server-side. |  |  |
| INP-10 | Redirect destinations are validated to prevent unsafe open redirects. |  |  |

---

## 11. File upload and download controls

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| FILE-01 | Upload functionality allowlists required file types. |  |  |
| FILE-02 | File type is validated using more than the supplied filename or browser MIME type. |  |  |
| FILE-03 | Upload size and count limits are enforced. |  |  |
| FILE-04 | Uploaded files are stored outside executable web paths or handled safely. |  |  |
| FILE-05 | Uploaded files are not executed or interpreted by the server unexpectedly. |  |  |
| FILE-06 | File access requires appropriate authorisation. |  |  |
| FILE-07 | Download responses use safe content disposition and content type settings. |  |  |
| FILE-08 | Filenames and paths are normalised to prevent traversal or overwrite risks. |  |  |
| FILE-09 | Malware scanning or content inspection is used where required by the business risk. |  |  |
| FILE-10 | Temporary files and abandoned uploads have suitable lifecycle controls. |  |  |

---

## 12. Cross-site request and browser-side security

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| BROWSER-01 | State-changing requests have appropriate CSRF protections. |  |  |
| BROWSER-02 | Sensitive actions do not rely on GET requests where state changes are involved. |  |  |
| BROWSER-03 | CSP and other browser security headers are reviewed for unsafe allowances. |  |  |
| BROWSER-04 | Sensitive values, API secrets and private keys are not embedded in client-side code. |  |  |
| BROWSER-05 | Source maps and frontend build artefacts do not expose secrets or sensitive implementation data. |  |  |
| BROWSER-06 | DOM operations safely handle untrusted input. |  |  |
| BROWSER-07 | Third-party scripts and dependencies are identified and have a business justification. |  |  |
| BROWSER-08 | Sensitive information is not unnecessarily stored in browser local storage or session storage. |  |  |

---

## 13. API security (if APIs are in scope)

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| API-01 | API inventory and versions are documented and within approved scope. |  |  |
| API-02 | Authentication is required for protected endpoints. |  |  |
| API-03 | Object-level authorisation is enforced for every user-controlled object reference. |  |  |
| API-04 | Function-level authorisation is enforced for privileged operations. |  |  |
| API-05 | APIs expose only the data required by the caller. |  |  |
| API-06 | Server-side input validation and schema enforcement are present. |  |  |
| API-07 | Rate limits and resource controls are appropriate to endpoint sensitivity. |  |  |
| API-08 | CORS policy is restrictive and appropriate. |  |  |
| API-09 | Tokens and API keys are not exposed in URLs, client bundles or logs. |  |  |
| API-10 | Token expiry, rotation and revocation are handled appropriately. |  |  |
| API-11 | Error messages do not disclose internal implementation details. |  |  |
| API-12 | GraphQL introspection, query depth and resolver authorisation are reviewed where GraphQL is used. |  |  |
| API-13 | Deprecated API versions are identified and appropriately restricted or retired. |  |  |

---

## 14. Business logic and e-commerce checks

Only use approved test accounts, test products, test orders and non-production payment methods. Do not complete real payments or alter real customer orders during testing.

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| BIZ-01 | Critical workflows enforce expected step order and server-side validation. |  |  |
| BIZ-02 | Users cannot bypass required approval or verification steps. |  |  |
| BIZ-03 | Price, quantity, discount and totals are recalculated and validated server-side. |  |  |
| BIZ-04 | Coupon, promotion and gift-card rules cannot be abused beyond intended limits. |  |  |
| BIZ-05 | Order and invoice access is restricted to authorised users. |  |  |
| BIZ-06 | Refund, cancellation and payment-state transitions are authorised and logged. |  |  |
| BIZ-07 | Duplicate or replayed requests are handled safely for sensitive transactions. |  |  |
| BIZ-08 | Account, address and payment-related changes require appropriate verification. |  |  |
| BIZ-09 | Inventory and booking limits are enforced server-side. |  |  |
| BIZ-10 | Payment card data is handled by approved payment providers and is not unnecessarily stored by the application. |  |  |

---

## 15. Server-side request and path handling

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| SSRF-01 | Features that fetch remote URLs validate destinations against an approved allowlist. |  |  |
| SSRF-02 | Server-side fetch functions cannot reach loopback, private, link-local or cloud metadata destinations. |  |  |
| SSRF-03 | Redirects from server-side fetches are validated at every step. |  |  |
| PATH-01 | File path inputs are constrained to intended directories. |  |  |
| PATH-02 | Canonicalisation and access checks prevent traversal outside approved directories. |  |  |
| PATH-03 | Archive extraction and import functions prevent unsafe paths and overwrite behaviour. |  |  |

---

## 16. Error handling, logging and monitoring

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| LOG-01 | Authentication and access-control events are logged appropriately. |  |  |
| LOG-02 | Logs do not contain passwords, session tokens, API secrets or unnecessary personal data. |  |  |
| LOG-03 | Security-relevant events can be correlated to a timestamp and account or request identifier. |  |  |
| LOG-04 | Error pages avoid stack traces, source paths and internal configuration details. |  |  |
| LOG-05 | Logs are protected from unauthorised access and tampering. |  |  |
| LOG-06 | Alerting and incident escalation processes are documented where included in scope. |  |  |
| LOG-07 | Application and infrastructure time settings are consistent enough for incident analysis. |  |  |

---

## 17. Technology-specific modules

Only complete the modules that apply to the assessed application and are included in scope.

### 17.1 WordPress

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| WP-01 | WordPress core version is supported and updated. |  |  |
| WP-02 | Themes and plugins are maintained and sourced from trusted publishers. |  |  |
| WP-03 | Unused themes and plugins are removed or disabled. |  |  |
| WP-04 | Administrator accounts use named accounts and least privilege. |  |  |
| WP-05 | Administrative access has appropriate MFA and access restrictions. |  |  |
| WP-06 | File editing from the dashboard is disabled where not needed. |  |  |
| WP-07 | Directory listing, debug output and unnecessary version disclosure are reviewed. |  |  |
| WP-08 | Backup files and configuration files are not publicly downloadable. |  |  |
| WP-09 | Database and file permissions follow least privilege. |  |  |
| WP-10 | XML-RPC, REST API and login protections are configured according to business requirements. |  |  |

### 17.2 Laravel / PHP

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| PHP-01 | Debug mode is disabled in production. |  |  |
| PHP-02 | Environment files and secrets are outside the public web root and not publicly accessible. |  |  |
| PHP-03 | Framework and Composer dependencies are maintained. |  |  |
| PHP-04 | CSRF middleware and route-level authorisation are enabled where required. |  |  |
| PHP-05 | Mass assignment and model binding are restricted appropriately. |  |  |
| PHP-06 | File upload, storage and download controls are applied. |  |  |
| PHP-07 | Database access uses safe parameterised operations. |  |  |

### 17.3 React / Angular / Node.js

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| JS-01 | No private server-side secrets are embedded in frontend bundles. |  |  |
| JS-02 | Frontend route guards are backed by server-side authorisation. |  |  |
| JS-03 | DOM rendering safely handles untrusted data. |  |  |
| JS-04 | Package dependencies and lockfiles are maintained and reviewed. |  |  |
| JS-05 | Server-side request validation and output handling are implemented. |  |  |
| JS-06 | Security headers and session controls are configured at the serving layer. |  |  |

### 17.4 Python / Django

| ID | Check | Result | Evidence ref / notes |
|---|---|---|---|
| DJ-01 | Debug mode is disabled in production. |  |  |
| DJ-02 | Allowed hosts and trusted origins are restricted appropriately. |  |  |
| DJ-03 | CSRF middleware and secure cookie settings are configured. |  |  |
| DJ-04 | ORM use and raw query handling are reviewed for injection risks. |  |  |
| DJ-05 | Object and function permissions are enforced server-side. |  |  |
| DJ-06 | Dependencies and framework versions are maintained. |  |  |

---

## 18. Automated tool-assisted checks

Automated tools support the analyst; they do not replace manual testing or validation. Run only against approved assets and within the agreed limits.

| Tool | Intended use | Analyst validation required? | Result / reference |
|---|---|---|---|
| Nmap | Approved web-facing service discovery | Yes |  |
| WhatWeb / Wappalyzer | Technology identification | Yes |  |
| OWASP ZAP | DAST crawling and passive / approved active checks | Yes |  |
| Burp Suite | Proxy inspection and manual testing | Yes |  |
| Nuclei | Approved template-based checks with conservative rate limits | Yes |  |
| WPScan | WordPress assessment within scope | Yes |  |
| testssl.sh | TLS configuration review | Yes |  |
| Semgrep | Source-code checks when code is supplied and authorised | Yes |  |

For every tool run, record the tool name, version, operator, date/time, target asset, configuration/profile, rate limits, output reference and any exclusions. Do not attach raw scanner output as the final report without review.

---

## 19. Finding validation and risk assessment

For every suspected issue, complete the following before calling it a confirmed finding:

| ID | Validation question | Yes / No / N/A | Notes |
|---|---|---|---|
| VAL-01 | Is the affected asset explicitly in scope? |  |  |
| VAL-02 | Is the behaviour reproducible using an approved test account or controlled test data? |  |  |
| VAL-03 | Has the analyst ruled out a scanner false positive or expected application behaviour? |  |  |
| VAL-04 | Is there enough evidence to explain the issue without collecting unrelated sensitive data? |  |  |
| VAL-05 | Is the likely impact understood and documented? |  |  |
| VAL-06 | Is the remediation specific and technically actionable? |  |  |
| VAL-07 | Has the severity been reviewed against technical and business context? |  |  |
| VAL-08 | Has a second reviewer checked high and critical findings? |  |  |

### 19.1 Severity recording

Record a CVSS version, score and vector when a CVSS assessment is appropriate. Also record business impact and remediation priority separately. Do not assign severity based only on a scanner label.

| Severity | CVSS v4.0 qualitative range | Typical handling |
|---|---:|---|
| Critical | 9.0-10.0 | Escalate promptly; agree urgent mitigation with client. |
| High | 7.0-8.9 | Prioritised remediation. |
| Medium | 4.0-6.9 | Planned remediation based on exposure and business impact. |
| Low | 0.1-3.9 | Address through normal security improvement work. |
| None | 0.0 | Do not treat as a vulnerability solely on the score. |

The score is not a substitute for business context. Record the CVSS vector and rationale, and use the client's risk acceptance process for exceptions.

---

## 20. Evidence handling requirements

- Assign every evidence item a unique reference, such as `EV-001`.
- Capture only the minimum evidence required to substantiate the finding.
- Redact names, email addresses, phone numbers, tokens, cookies, passwords, personal data and customer records.
- Do not save secrets or credentials in GitHub, issue trackers or report screenshots.
- Store evidence in approved restricted storage, not in a public repository.
- Record who collected evidence and when.
- Apply the engagement's retention and secure deletion policy.
- Use test accounts and synthetic data wherever possible.

### Evidence register

| Evidence ID | Finding ID | Description | File reference / secure location | Collected by | Date/time | Redacted? |
|---|---|---|---|---|---|---|
| EV-001 |  |  |  |  |  |  |

---

## 21. Assessment completion and quality assurance

| ID | Completion check | Result | Evidence ref / notes |
|---|---|---|---|
| QA-01 | All in-scope assets have a recorded assessment result or limitation. |  |  |
| QA-02 | All failed tests have a finding record or documented reason for not reporting. |  |  |
| QA-03 | Scanner results have been reviewed and false positives removed or labelled unconfirmed. |  |  |
| QA-04 | Critical and high findings have independent review. |  |  |
| QA-05 | Report scope matches the signed authorisation and actual testing. |  |  |
| QA-06 | Report records testing dates, versions, methods, limitations and exclusions. |  |  |
| QA-07 | Sensitive evidence has been redacted and stored securely. |  |  |
| QA-08 | Urgent findings have been communicated through the agreed channel. |  |  |
| QA-09 | Temporary test accounts, files and configuration changes have been removed or handed back as agreed. |  |  |
| QA-10 | Reviewer approval is recorded before report publication. |  |  |
| QA-11 | Client has received the report through an approved secure delivery channel. |  |  |
| QA-12 | Evidence retention and deletion dates are recorded. |  |  |

---

## 22. Remediation and retesting checklist

| ID | Retest check | Result | Evidence ref / notes |
|---|---|---|---|
| RET-01 | Original finding ID and remediation change are identified. |  |  |
| RET-02 | Retest is authorised and remains within the approved scope. |  |  |
| RET-03 | The original test is repeated safely using the agreed method. |  |  |
| RET-04 | The original weakness is no longer reproducible. |  |  |
| RET-05 | The fix has not introduced an obvious related regression within the retest scope. |  |  |
| RET-06 | Finding status is updated to Fixed, Partially Fixed, Open, Risk Accepted or Unable to Retest. |  |  |
| RET-07 | Retest evidence and date are recorded. |  |  |
| RET-08 | A retest summary or revised report is delivered securely. |  |  |

---

## 23. Final assessment summary

| Metric | Count / value |
|---|---|
| Total approved assets |  |
| Total assets tested |  |
| Tests marked Pass |  |
| Tests marked Fail |  |
| Tests marked N/A |  |
| Tests not tested / blocked |  |
| Confirmed Critical findings |  |
| Confirmed High findings |  |
| Confirmed Medium findings |  |
| Confirmed Low findings |  |
| Informational observations |  |
| Major limitations / exclusions |  |

### Analyst sign-off

- Lead analyst:  
- Date:  
- Reviewer:  
- Review date:  
- Assessment manager approval:  
- Report version:  

---

## 24. Reference standards and guidance

Use the versioned or stable sources agreed by the assessment team. Standards evolve; check the official project pages when creating or updating an assessment methodology.

- [OWASP Web Security Testing Guide (WSTG)](https://wstg.owasp.org/) - use the current stable guide for test procedures; the OWASP project currently identifies v4.2 as the stable release while v5.0 work continues.
- [OWASP Application Security Verification Standard (ASVS)](https://asvs.owasp.org/) - use ASVS 5.0.0 as a requirements and verification reference where appropriate.
- [OWASP Top 10](https://owasp.org/Top10/) - use the current released edition for risk awareness and report mapping.
- [FIRST CVSS v4.0](https://www.first.org/cvss/v4.0/) - use for technical severity scoring where suitable.

This checklist is an internal starting point. It is not a certification, a guarantee of security, or a substitute for a scope-specific test plan, qualified analyst judgement, contractual requirements or applicable legal obligations.
