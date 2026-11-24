# Local Python HTTP assessments

This increment targets the user's clean Windows stage-one commit 23c196e (feature/assessment-authorization), migration 0005_assessment_intents. It is separate from the experimental Azure/container deployment. No Docker CLI, images, containers, cloud accounts, new service or paid infrastructure is needed. No external scanner binaries are integrated.

## Reuse and architecture

The existing assessment request manager, shared jobs/attempts/results/events, execution-slot lease, administrator authentication, accepted evidence revision and exact domain/method/date permission checks are retained. An explicitly requested fixed profile `local-http-headers-v1` runs through the independent `assessment-worker` CLI role. One outstanding request per website, one assessment execution slot globally, a 60-second HTTP request cooldown and one attempt/no automatic security retries apply. Scheduling monitoring or approving permission never creates an assessment.

`LocalPythonAdapter` implements the execution interface in a fixed code-owned registry. It launches only two known Python files by absolute path with `-I -S -B` and argument arrays; URLs and observations are JSON stdin, never shell commands. The trusted broker validates all DNS answers, pins one numeric socket address, checks the connected peer and preserves hostname verification/SNI and Host. It permits standard ports 80/443 only, one connection and one HEAD. Redirects, response bodies, credentials and GET fallback are excluded. Header parsing is capped at 32 KiB, selected input values at 2 KiB each. A response-header SHA256 is recorded, while raw selected values are discarded before persistence. HTTPS uses default CA verification.

The separate analyzer accepts only eight selected header names and produces policy-presence/recognized-value observations for CSP, HSTS, framing, nosniff, referrer, permissions policy and server disclosure. Findings are never confirmed automatically. Missing headers may be legitimate; report severity is a suggestion requiring analyst validation. CSP directives, feature policy allowlists and server versions are not fully validated. CSP nonces/cookies/server strings are not retained. Reports link the current written-permission document IDs/hashes/sizes, permission digest, request/admin/profile and response hash/transport facts.

## Execution limits and trust boundary

Every Python child is killable with bounded framed output, sanitized environment and monotonic parent deadlines (broker 13 seconds, analyzer 5 seconds), live permission polling and cleanup. Broker has an independent 12-second watchdog. POSIX children use RLIMIT_AS=256 MiB, RLIMIT_CPU=3 CPU seconds and 64 open files. Windows children are assigned to a Job Object before any payload is sent: 256 MiB process memory, one process, 25% CPU hard cap and kill-on-job-close. Unsupported Windows assignment fails closed, with no unbounded fallback. Platform CPU policies differ; the worker parent itself is not memory-capped. Permission is checked before DNS, after DNS, before connection, immediately before HEAD, during waits and before transactional result acceptance. An already-sent request cannot be undone by cancellation.

**This is trusted-code separation, not an OS network sandbox.** The analyzer source has no network operations and receives only selected header data, but Python itself could perform network access if untrusted code were introduced. Do not load plugins, arbitrary scripts, user commands, Nmap, Nuclei or ZAP into this adapter. Future stronger isolation requires a separately reviewed adapter. No loopback/private-address escape setting exists in production; fixtures replace DNS/transport only in test code.

## Additive database and APIs

Migration `0006_local_http` adds nullable `assessment_requests.execution_snapshot` and private `assessment_reports` JSON/hash/size/provenance rows. Existing preflights keep NULL snapshots and remain usable. No previous table/account/evidence is replaced. The existing queue tables store attempts and execution events. Downgrading destructively is deliberately refused.

- GET /api/v1/assessments/profiles: fixed profile catalogue and availability.
- POST /api/v1/assessments: existing fields plus `network_permission_confirmed`; HTTP requires True plus explicit request and currently valid reviewed permission.
- GET list/detail/events/attempts and POST cancel remain unchanged.
- GET /api/v1/assessments/{id}/report/download: authenticated, hash-checked, no-store JSON download; audited.

Reports are private DB data. No public static evidence/report paths exist. Automatic report retention/deletion, multi-tenant permissions, PostgreSQL deployment, arbitrary scan profiles and a human findings-disposition system are not part of this increment. Existing authorisation evidence retention continues unchanged.

## Windows setup and acceptance

Do not apply a Docker-stage patch or use this migration on an Azure database already at a competing 0006 revision. First verify clean Windows Git state at 23c196e and actual Alembic revision. Preserve existing .env, users, database and evidence with private backups. Apply on a new feature branch and run git apply --check first. The source archive uses CRLF; a whitespace-tolerant check is supplied in START_HERE_WINDOWS.md. Do not force patches or remove uncommitted work.

From backend, run .\.venv\Scripts\python.exe -m alembic upgrade head, then current (expect 0006_local_http). Do not copy Windows virtual environments between systems. No new Python requirements were added.

Keep ASSESSMENT_LOCAL_HTTP_ENABLED=false for initial regression; tests configure an isolated database. Only after tests pass and genuine current written permission exists for a controlled owned/staging site, add ASSESSMENT_LOCAL_HTTP_ENABLED=true to the existing private .env and restart API/worker. Do not share .env or JWTs. Register the exact site, upload/inspect its real permission document, record an accepted evidence review and approve the required automated_non_intrusive_scanning method and validity window. A synthetic preflight fixture grants no actual website permission.

In Assessments select the local HTTP profile, valid authorisation, note and BOTH explicit-request/network-permission checkboxes. Queue once, then from a second backend terminal run .\.venv\Scripts\python.exe -m app.cli.operations assessment-worker --once. Refresh/open details: expect header assessment completed, 1/1 attempt, analyst observations, zero confirmed findings, private JSON download and audit history. Verify a single HEAD/no redirect/no body in your consented staging server access log. A server that refuses HEAD produces observations about that response only, with no GET fallback. Check queued cancellation and revocation before worker start, then expiry/evidence-change failures. Do not induce failures on third-party services.

Tests cover real local HTTP parsing, private destinations, DNS mixed-answer rejection, real isolated Python analysis, deadline cleanup, report privacy/hash integrity, authorization fencing and migration preservation. Browser fixtures use a synthetic broker and a REAL Python analyzer, shared job engine and temporary DB. They never contact registered domains.

Windows Job Object enforcement and browser acceptance require actual Windows testing. Real public HTTPS/TLS-chain and owned-target access-log acceptance remain pending until explicitly performed. A successful build is not proof of these workflows.

## Prepared validation results

219 backend tests passed with one existing Starlette deprecation warning. 12 frontend helper tests passed and Vite production build passed. Thirteen browser journeys are defined; the new journey was attempted but this environment denied Chromium socket creation before launch, so no browser pass is claimed. Linux real Python IPC/limits and local HTTP fixture checks passed; Windows Job Object behaviour and a genuinely authorised public HTTPS workflow remain unverified. No paid resource, real third-party target or external scanner tool was used.
