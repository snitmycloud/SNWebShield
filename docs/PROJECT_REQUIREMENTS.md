# SNWebShield requirements

The full product spec is [SNWEBSHIELD_SPEC.md](SNWEBSHIELD_SPEC.md); the rules for working on it are in `CLAUDE.md`. This page is the short version.

## The product

A website owner signs up, adds a website, proves they own it (about a minute) and SNWebShield then **monitors, detects, identifies and reports** automatically.

## Must always hold

1. **Ownership verification is the only approval step.** Nothing is scanned (or probed by the monitor) unless the account that owns the website has verified it; ownership is re-checked before every scan.
2. **Safe targets only.** Never contact private, loopback, link-local, multicast, cloud-metadata or this server's own addresses; resolve DNS once per scan and pin the address; no unsafe redirects.
3. **Fail safe.** A check that fails or times out is "could not check" or "incomplete", never "safe" or "clean".
4. **Plain language** on every page; technical details in an expandable section.
5. **Nothing to install on the server** beyond Python packages already in the project, plus the one pinned Nuclei binary (see `CLAUDE.md`).
6. **No secrets in logs, chat or the repository.**
7. **Complete audit logs** for authentication, ownership checks, scans, admin actions and remediation actions.

## What users get

| | Free | Pro | Business |
|---|---|---|---|
| Websites | 5 | 25 | 100 |
| Automatic scan | weekly | daily | daily |
| Scan now | 1 per website per day | 5 per day | 20 per day |
| Re-scan of one finding | 20 per day | 50 | 200 |
| Alerts | email | email | email (Slack webhook in Phase 7) |
| PDF report | yes (browser print) | yes | yes |

Numbers live in `backend/app/plans.json`. Payments and plan upgrades are Phase 7.

## Phases

1. Accounts, plans, websites, ownership verification, first scan. 2. DETECT. 3A/3B. IDENTIFY (and Nuclei). 4. REPORT (findings lifecycle). 5. MONITOR (schedules, uptime, alerts, auto-start). 6. Design polish. 7. Payments. Status and proof for each phase: [AUDIT_MATRIX.md](AUDIT_MATRIX.md).

## Out of scope

Exploitation, intrusive or denial-of-service testing, scanning websites the user does not own, certification claims ("we do not say a website is secure; we list what automated checks found").
