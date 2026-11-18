# SNWebShield — Security and Safety Guardrails

These guardrails are mandatory design requirements, not optional enhancements.

## Assessment authorisation

- No assessment may begin without written, current authorisation from an appropriately authorised client representative.
- A public URL, public DNS record, hosting login or domain registration does not independently establish permission to penetration-test an asset.
- Every asset and test activity must be within the approved engagement scope.
- Scope changes require documented approval.

## Safe testing

- Default to non-destructive testing and low request rates.
- Do not conduct denial-of-service, stress testing, destructive actions, persistence, lateral movement, credential theft, data exfiltration or tests against third-party payment/identity services as part of the standard service.
- Use client-provided test accounts and synthetic data.
- Stop testing if service instability, unexpected access to sensitive data or an out-of-scope system is encountered.
- Notify the client through the agreed emergency contact process.

## Application protections

- Deny by default and enforce server-side role and tenant checks.
- Require MFA for privileged accounts where available.
- Protect sessions, CSRF-sensitive actions and administrative endpoints.
- Rate-limit authentication and sensitive actions.
- Keep secrets out of source code and logs.
- Use HTTPS and secure cookie settings in deployed environments.

## Scanner protections (future phase)

- No user-supplied arbitrary URL may trigger a scan.
- Resolve and validate targets against approved scope before execution.
- Block loopback, private, link-local, multicast and metadata-service destinations by default.
- Revalidate redirects and DNS answers to reduce SSRF and DNS-rebinding risk.
- Use strict allowlists, egress filtering, low rate limits and execution timeouts.
- Run scanners in isolated, least-privilege workers with no access to application secrets or database networks.
- Do not implement arbitrary shell command execution through an API.
- Treat tool output as untrusted and require analyst verification.

## Evidence and privacy

- Collect the minimum evidence necessary to substantiate findings.
- Redact passwords, API keys, session tokens, personal information and customer content.
- Store evidence in private encrypted storage with access logging.
- Define and contractually communicate retention, deletion and incident-notification processes.
- Restrict report downloads to authorised client users.

## Quality and claims

- Distinguish confirmed vulnerabilities, potential issues, observations and false positives.
- Record methodology, tool versions, coverage, limitations and exclusions.
- Do not promise that a website is completely secure.
- Do not claim certification, accreditation or regulatory empanelment unless formally granted by the relevant authority.
