# SNWebShield architecture

SNWebShield is a self-service website security scanner. It runs entirely on one Windows computer (Linux later): a FastAPI backend, a React frontend and a SQLite database (PostgreSQL is supported by the same code). Nothing is deployed to Azure.

## Processes

| Process | What it does | Started by |
|---|---|---|
| **API** (`uvicorn app.main:app`, port 8000) | Accounts, websites, ownership verification, scans, findings, alerts, admin | supervisor |
| **Web app** (port 5173) | The React app (`frontend/dist` in production, Vite in development) | supervisor |
| **Scan worker** (`app.cli.operations scan-worker`) | Claims queued scans and runs them; also re-checks of single findings | supervisor |
| **Monitor** (`app.cli.operations monitor`) | Scheduled scans, uptime checks, certificate checks, alert sweeps, accepted-risk expiry | supervisor |
| **Supervisor** (`app.cli.supervisor`) | Starts the four above at boot, restarts any that stops (back-off 1 to 60 s), writes a heartbeat the Admin page shows | Task Scheduler (Windows) or systemd (Linux) |

Roles talk only through the database (scans table, heartbeats, audit events). The API never runs a scan; it only queues one.

## A scan, step by step

1. **Queue.** `scans.request_scan` (verified website, one active scan per website, plan and test-target limits). Ownership verification queues the first scan automatically; the monitor queues scheduled ones.
2. **Claim.** The worker takes the oldest queued scan, re-checks the owner, the verification and the resolved IP (`ownership.ensure_verified`, `ip_policy`), and **pins one public IP** for the whole scan.
3. **Detect** (`detect_runner`): port scan, service and version probes, technologies, DNS and email settings, exposed files, subdomains. A **scan guard** polls the database and stops the scan if the website is removed, verification is lost or the time limit passes.
4. **Identify** (`engines`): configuration checks, vulnerabilities (NVD and OSV, cached), end-of-life data, and the optional Nuclei engine, in parallel. Results merge into one finding list (`finding.py`, stable fingerprint per finding).
5. **Finish.** Findings are stored, finding states updated (new / fixed / reopened), the score recorded for the trend, alerts raised (new port, new Critical/High), audit entries written.

A check that fails or times out is reported as "could not check", never as safe.

## Safety layers

- **Ownership** (DNS TXT, file or meta tag) is the only approval step. It is re-checked before every scan (24-hour cache) and again right before execution.
- **SSRF guard** (`services/ip_policy.py`): every address must be public; private, loopback, link-local, multicast, cloud-metadata and this server's own addresses are refused. DNS is resolved once per scan and pinned (no DNS rebinding); redirects are never followed to another host.
- **Nuclei** (optional): one pinned, checksum-verified binary, vendored and validated templates only, all traffic through a local egress proxy that allows only the verified host and pinned IP, killed by the scan guard, disabled unless its self-test passes.
- **Untrusted data:** everything from a target (headers, pages, banners, scanner output) is treated as text and shown escaped.
- **Audit log:** authentication, ownership checks, scans, accepted risks, alerts, admin actions (`auth_events`, `execution_events`).

## Data

- `scans`, `scan_ports`, `scan_technologies`, `scan_observations`, `scan_findings` - what each scan found.
- `finding_states`, `finding_rechecks` - the life of a finding: open, fixed (and how), accepted risk with expiry.
- `uptime_checks`, `uptime_states`, `score_history`, `alerts`, `alert_preferences` - monitoring.
- `admins` (accounts, role `user` or staff), `websites`, `account_tokens`, `revoked_tokens`.
- `retired_tables` lists the tables of the removed analyst pipeline and written-permission system: kept with their data, no code uses them.

Plans and limits live in `backend/app/plans.json`; settings in `backend/app/core/config.py` (environment variables, `backend/.env`).

## Code map

`backend/app/api/routes` (auth, websites, alerts, admin_users, health) · `backend/app/services` (scans, detect_*, engine_*, finding_states, comparison, recheck, scheduling, uptime, alerts, ownership, ip_policy, ...) · `backend/app/models` · `backend/migrations/versions` (additive, downgrades refused) · `frontend/src` (Console.jsx and its panels, `lib/` pure helpers with unit tests).
