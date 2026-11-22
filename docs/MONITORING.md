# Website monitoring — local operational engine

Monitoring is the first handler on the shared durable job engine. Existing client, website, authentication, authorisation and evidence components are reused. No scanner handler or scanner execution endpoint exists. Registering a website, uploading evidence and approving testing permission do not enable monitoring.

## Consent and operation

Use a document that explicitly permits recurring HTTP GET, DNS resolution and TLS certificate checks for the registered website. Upload, open and accept it through the existing human evidence review workflow. On **Monitoring**, select that website and document, enter the agreement reference and expiry, choose an interval/timeout and attest that you reviewed this specific monitoring permission. The API requires the current accepted evidence review by the configuring administrator. A file alone or a VAPT approval is insufficient.

Saving configuration creates a historical consent record and leaves monitoring disabled. Click **enable** separately. The scheduler queues the first check. **check now** queues work; it never performs HTTP in the API process. It requires monitoring to be enabled, no active job for that website, and a 60-second cooldown after the previous enqueue. **disable** cancels pending/running jobs; **revoke consent** also invalidates the current consent. **Stop all monitoring** disables every configured website.

A consent is tied to the website, its exact registered URL snapshot, a private document, reviewer, timestamps and expiry. A changed URL, expired/revoked consent or withdrawn/purged evidence blocks execution. Consent cannot extend beyond document retention. A complete new configuration is required to replace consent. Disabling and enabling retain prior history. Existing website/client models have no active/deleted lifecycle fields; this implementation does not invent such checks.

Consent has its own dates and scope. It is independent of the assessment permission window: revoking a VAPT approval alone does not revoke a separate monitoring agreement. Withdraw that monitoring consent or its document to stop monitoring. Never attest to a synthetic test document as permission to monitor a real third-party site.

## Shared execution architecture

The shared engine owns job creation, idempotency, atomic claims, attempts, leases, execution events, final results and scheduling dispatch. Handlers register eligibility, due scheduling and transactional result processing. The CLI scheduler dispatches registered handlers; the initial worker executes only the monitoring pool. A future scanner must register a separate policy/handler and bounded execution adapter on this engine. It must not start a second job database or scheduler, or inherit monitoring consent.

| Tables | Purpose |
| --- | --- |
| `jobs`, `job_attempts`, `job_results` | Durable work, attempts and one final result per job |
| `execution_slots`, `worker_heartbeats`, `execution_events` | Pool lease, liveness and execution/audit history |
| `monitoring_consents`, `monitoring_configs` | Reviewed agreement history and current configuration/revision |
| `monitoring_incidents`, `notification_deliveries` | Failure/recovery transitions and durable notification outbox |

All new tables are added by `0004_monitoring`; existing IDs, records, evidence and tables are preserved. Schema downgrades deliberately refuse to drop operational history. Stop every process and restore a verified matching backup/code pair if rollback is necessary.

The initial policy is deliberately small: one running check across the monitoring pool, a 60-second execution lease, at least five seconds between attempts/checks, and a minimum 60 seconds between enqueues for one website. Intervals are 60, 300, 900 or 3600 seconds; probe timeout is 2–20 seconds. Scheduler batches are capped at 100 due websites. At most one active job per website is created by the revision/next-due conditional update. There is no unbounded per-interval backlog for a busy website. Missed intervals coalesce rather than replay.

A down probe gets one retry after five seconds. Only its final outcome affects incident counters. Successful completion, result persistence, incident changes, notifications and execution events commit together. Claim tokens and configuration revisions fence late workers. Execution lease expiry marks the job failed and is not counted as website downtime; subsequent scheduling creates a fresh check. Unknown/probe-process failures also do not create downtime incidents. Every job and attempt remains inspectable. Tokens are not returned in history APIs.

The worker uses a spawned child process compatible with Windows. It verifies permission/document integrity before launching. The child requests fresh permission before DNS resolution, each connection attempt and each GET; the parent also checks during execution and terminates cancelled work. A request already sent cannot be undone. Parent deadline and child watchdog bound blocked DNS/slow-header execution; process startup/termination adds a few seconds to the configured probe timeout. The worker kills and joins overdue children. Run one scheduler initially. Claims/slots and concurrent scheduler calls have SQLite regression coverage; this is not a claim of production HA or exactly-once network requests.

## Destination and protocol controls

- Only HTTP on port 80 and HTTPS on port 443, without URL credentials or control characters.
- Fresh DNS validation on every hop; reject any non-public, loopback, private, link-local, metadata, multicast, unspecified or mapped/translation address. IPv6 is conservatively restricted to ordinary global unicast (`2000::/3`) with special-purpose/translation/documentation ranges excluded; IPv4 protocol-assignment/relay ranges are also excluded across supported Python versions. Mixed public/private answers are rejected as a set. At most 32 DNS records are accepted; at most four addresses are attempted per hop.
- Connect directly to the validated numeric socket address. Check the connected peer. No second hostname lookup is used for the connection. The original hostname remains the HTTP Host and TLS SNI/verification name.
- Follow at most three redirects within the same scheme, hostname and standard port. HTTPS downgrade, other origins and unsafe new DNS answers are blocked. No environment proxy, cookie jar, credentials or arbitrary request headers are used.
- TLS uses Python's default verified trust context and hostname checks. Certificate expiry is recorded on a successful TLS handshake. Invalid chains/hostnames are down; valid certificates with 30 days or less remaining are degraded. HTTP sites have no TLS measurement. An invalid certificate does not yield a trusted expiry date.
- Read HTTP response headers only; never fetch/store response bodies, pages, cookies or redirect URLs. Python's HTTP parser bounds header lines/count; the subprocess deadline additionally bounds slow responses. Results store numeric status, timing, validated addresses and coarse error codes.

Application controls supplement deployment egress controls. Private/internal targets, custom ports, custom CAs, authenticated checks, cross-origin redirects, ICMP and vulnerability scans are unsupported. There is no production flag to bypass the private-address rule.

## Status and incidents

HTTP 200–399 is up (redirects are followed); 400–499 is degraded; 500+ and DNS/connection/TLS failures are down. Policy violations are blocked and disable the configuration without creating a downtime incident. Infrastructure/process failures are unknown. Missing or old results display **stale** for enabled websites after twice the interval plus 30 seconds; disabled and blocked are shown separately. Historical samples remain visible with their timestamps, even when disabled.

Both down and degraded finalized checks count toward the configured incident threshold (1–5). Consecutive up checks close an open incident after the recovery threshold (1–5). Thus an incident may represent certificate/HTTP degradation, not only a total outage. Unknown samples do not count as successes or failures. The chart shows end-to-end header-check duration including DNS, TLS and redirects; it is not page-load timing or a statistical uptime SLA.

The dashboard shows process heartbeats, current settings/consent expiry, last HTTP/DNS/TLS metrics, response-time samples and paginated results, jobs, attempts, incidents, events, notification deliveries and consents. No historical result is relabelled to imply a fresh measurement. All monitoring APIs require the existing active administrator role. Tenant/client access remains outside this local milestone.

## APIs

All paths use `/api/v1` and bearer authentication.

| Method and path | Behaviour |
| --- | --- |
| GET `/monitoring/overview` | Website status/metrics/configuration/consent and process heartbeats |
| GET `/websites/{id}/monitoring` | Current configuration and consent |
| POST `/websites/{id}/monitoring/configure` | Validated permission/settings; saves disabled |
| POST `/websites/{id}/monitoring/enable` | Explicit activation |
| POST `/websites/{id}/monitoring/disable` | Disable and cancel pending execution |
| POST `/websites/{id}/monitoring/check-now` | Queue a bounded manual check; 429 for active job/cooldown |
| POST `/websites/{id}/monitoring/revoke-consent` | Revoke consent, disable and cancel |
| GET `/websites/{id}/monitoring/{collection}` | `results`, `jobs`, `attempts`, `incidents`, `events`, `notifications`, `consents`; limit 1–100, offset >=0 |
| POST `/monitoring/stop` | Stop all configured monitoring |

Configuration JSON fields: `evidence_id`, `consent_reference` (10–150 characters), `monitoring_permission_reviewed: true`, timezone-aware future `expires_at`, `interval_seconds`, `timeout_seconds`, `failure_threshold`, `recovery_threshold`. Unknown fields are rejected.

## Notifications

The default `NOTIFICATION_CHANNEL=dashboard` records durable in-app delivery; no external email is sent. A separate notification dispatcher marks it delivered. Delivery history remains visible in the dashboard even if the dispatcher is stopped.

Optional SMTP is an operator configuration in the **existing** private `backend/.env`:

```dotenv
NOTIFICATION_CHANNEL=smtp
NOTIFICATION_RECIPIENT=ops@example.com
SMTP_HOST=your-smtp-host
SMTP_PORT=465
SMTP_SENDER=monitor@example.com
SMTP_USERNAME=your-smtp-user
SMTP_PASSWORD=your-local-secret
```

SMTP uses implicit TLS with certificate verification and a 10-second socket timeout. Only website ID, event and a stable delivery reference are included, not documents, credentials, URLs or response contents. Claims have leases, failed sends back off (60 then 120 seconds), and three attempts lead to a visible failed delivery. An expired final delivery lease is also failed. SMTP may deliver twice after a crash between remote acceptance and local commit; stable Message-ID assists deduplication but cannot guarantee it. Real provider credentials/delivery have not been tested here. SMTP hostname resolution depends on the host resolver, so production should use a supervised dispatcher and reliable local DNS. Recipient settings are operator-wide, not per-client routing.

## Windows setup and testing

First stop existing API/worker processes. Preserve `.env`, your administrator, database and private evidence directory. Back up both database and evidence; `backup_database` covers only SQLite, not document files.

```powershell
Set-Location C:\SNWebShield-Local\backend
.\.venv\Scripts\python.exe -m app.cli.backup_database
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m alembic current
.\.venv\Scripts\python.exe -m pytest -q
```

Expected migration: `0004_monitoring (head)`. Tests use disposable databases/documents and controlled transports, including a real local HTTP fixture. The loopback exception exists only in that test's patched resolver, never in production. A spawned real worker test demonstrates loopback is blocked; a hanging-child test checks forced termination. No automated test contacts a third-party monitoring target.

Run five separate PowerShell terminals, using the backend directory for API and operation commands:

```powershell
# Terminal 1, backend
Set-Location C:\SNWebShield-Local\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
# Terminal 2, backend
Set-Location C:\SNWebShield-Local\backend
.\.venv\Scripts\python.exe -m app.cli.operations scheduler
# Terminal 3, backend
Set-Location C:\SNWebShield-Local\backend
.\.venv\Scripts\python.exe -m app.cli.operations worker
# Terminal 4, backend
Set-Location C:\SNWebShield-Local\backend
.\.venv\Scripts\python.exe -m app.cli.operations notifications
# Terminal 5
Set-Location C:\SNWebShield-Local\frontend
npm run dev
```

Use Ctrl+C to stop a process. Each operational role also supports `--once` for diagnosis. Keep scheduler and worker running independently of FastAPI reload. All must use the same backend working directory, `.env`, database and evidence root. Heartbeats should become recent within a few seconds; a stopped process becomes stale after 90 seconds. No service installation or automatic startup is included.

Run frontend checks separately:

```powershell
Set-Location C:\SNWebShield-Local\frontend
npm test
npm run build
npx playwright install chromium
npm run test:e2e
```

Eight browser journeys are defined. The new journey configures consent, confirms disabled-by-default, enables the real job engine with a test-only synthetic probe outcome, inspects metrics/history, disables and revokes consent. Existing evidence/login/expiry journeys remain. The browser fixture is isolated in `backend/tests/e2e_server.py`, uses a disposable database, and never executes a real probe. Browser execution in the implementation environment was blocked before any journey ran by Chromium's local socket restriction. Windows browser acceptance is therefore required before marking this milestone complete.

For a manual real check, use only an owned site with genuine written monitoring permission. Follow the consent workflow above, enable and wait for a result (allow queue time). Check HTTP/DNS/timing/TLS expiry, then disable and confirm no new check starts. Test failure/recovery using an owned staging endpoint you control and a consented stable URL; do not simulate outages against third-party services. The local fixture suite covers HTTP 200/404/503, same-origin redirects, deadlines, DNS policy, TLS outcomes, retry/incident transitions, cancelled results and notification delivery failure without production traffic.

## Remaining validation and limits

Implementation validation: 142 backend tests passed (one existing Starlette/httpx deprecation warning), 10 frontend helper tests passed, the production frontend build passed, and eight browser journeys were discovered. Chromium failed at launch before those journeys could run. Local backend behaviour, queue policy and frontend compilation/helper tests are verified; Windows browser acceptance, a Windows real-worker smoke test, real public HTTPS/TLS-chain integration and actual SMTP provider delivery remain to be verified. PostgreSQL, production HA/load, tenant isolation, evidence encryption, scanner isolation, operating-system egress controls and service supervision are not covered. Historical rows are retained without automatic pruning; define retention/backups before sustained use. The initial one-worker pool may accumulate latency for many websites; stale labels expose this rather than inventing successful checks. Review these limits before production deployment or building a scanner on this engine.
