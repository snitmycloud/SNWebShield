# SNWebShield security and safety guardrails

Mandatory design rules. The engineering version is in `CLAUDE.md`.

## Who may be scanned

- A website is scanned (or probed by uptime checks) only after its owner has verified ownership with a DNS TXT record, a file or a meta tag. Verification is re-checked before every scan (24-hour cache) and right before execution; scans pause when it is lost.
- An administrator can verify a website by hand for 24 hours, but only with the owner's name, how they consented (email, written letter, in person) and a real reason (20+ characters); all of it is audit-logged.
- Test targets are a fixed list in code (`scanme.nmap.org`), usable only by admin accounts, with a daily limit.

## Safe scanning

- Non-destructive checks only; low request rates; per-scan time limits. No exploitation, denial of service, brute forcing or fuzzing. Nuclei templates that could do these are rejected by the template validator.
- Never contact private, loopback, link-local, multicast, cloud-metadata or this server's own addresses. DNS is resolved once per scan and the address pinned; redirects to another host are not followed.
- No arbitrary URL from a user starts a scan; no shell commands from an API; fixed argument lists for the one external binary.
- Everything from a target (headers, pages, banners, scanner output) is untrusted data, shown as escaped text.
- A check that fails or times out is "could not check", never "safe".

## Application protections

- Deny by default; server-side ownership and role checks on every route; other users get 404, not 403, for resources they cannot see.
- Argon2 passwords, a password policy, login and sign-up rate limits, server-side logout, signed short-lived tokens, strict security headers and CORS.
- Secrets stay out of source code, logs and chat; `.env` is private.
- A complete audit log for authentication, ownership checks, scans, admin actions and remediation (accepted risks, re-checks).

## Claims

- Reports list what automated checks found. They never say a website is "secure" or "clean", and a good score is not a proof.
