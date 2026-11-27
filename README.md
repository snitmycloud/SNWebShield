# SNWebShield

**Self-service website security scanner â€” MONITORS. DETECTS. VALIDATES. PROTECTS.**

SNWebShield is a self-service website security scanner for website owners. A user signs up, adds their websites, proves they own each one (DNS TXT record, uploaded file or homepage meta tag), and SNWebShield scans it automatically. The product spec and build phases are in [docs/SNWEBSHIELD_SPEC.md](docs/SNWEBSHIELD_SPEC.md).

> Safety principle: domain ownership verification is the only approval step, and nothing is scanned without it. Ownership is re-checked before every scan, only the single public IP resolved at the start of a scan is contacted, private and cloud-internal addresses are refused, and a check that cannot finish is reported as "incomplete", never as "safe".

### Phase 1 (self-service accounts and ownership): what changed

- **Accounts:** sign up with email and password, confirm the email, sign in and out, forgot/reset password, change password. Passwords use Argon2 and the existing policy; sign-up, login and reset emails are rate-limited. Roles are `user` (customer) and `admin`; the older staff roles `lead_analyst` and `analyst` remain for the read-only legacy pages. Customers see only their own websites and scans and are refused by every staff route.
- **Plans:** limits live in one file, [backend/app/plans.json](backend/app/plans.json) (Free = 5 websites, Pro = 25, Business = 100), re-read when it changes. New accounts are Free; an admin changes plans on the Admin page. Adding a website past the limit shows a friendly message with an **Upgrade** button.
- **Websites and verification:** the domain is cleaned up (scheme, path, port, case) and IP addresses, `localhost` and internal names are refused. Each website gets its own random code. "Verify now" checks at once and shows what was found against what was expected; if the file/meta method fails because the site has no valid HTTPS, it points to the DNS TXT method. Verifying `example.com` covers its subdomains; verifying `www.example.com` covers only that host.
- **Remove website:** the owner can remove a website from its page or the list. They must type the domain to confirm. Removal deletes the website's verification code, deletes its queued scans, ends a running scan, and frees a plan slot. The website row, finished scan records, execution events and the audit log are kept, and `website_removed` (user, domain, time, what was cancelled) is written to the audit log (migration `0017_website_removal`). The same domain can be added again later with a new code.
- **Approved test targets (for Phase 2 testing):** a fixed list in code (`APPROVED_TEST_TARGETS` in `backend/app/core/config.py`) containing only `scanme.nmap.org`, which the Nmap project publicly allows scanning for tests. Only `admin` accounts can add it (everyone else gets "reserved"); it needs no DNS proof, is labelled **Test target** in the app, is limited to **2 scans per day** (UTC, shared by all admins, not resettable by removing and re-adding), and every scan is audited with `test_target: true`. It cannot be read or changed from the app, the API or `.env`, and it never covers subdomains.
- **Scan now (Phase 2):** the owner of a verified website can start a scan from its page. Limits come from `plans.json` (Free 1 per website per day, Pro 5, Business 20 per account, UTC days); the scans left are shown next to the button and reaching the limit shows a friendly message with an Upgrade button, never an error page. A test target keeps its stricter 2-per-day limit shared by all admins. Pressing it while a scan is running returns that scan and uses nothing up. The automatic first scan is not counted.
- **Automatic first scan:** as soon as verification succeeds, the first scan is queued and run by the new `scan-worker`. In Phase 1 a scan re-checks ownership, resolves and pins one public IP, records the audit entry and ends as **incomplete**; the port, version and technology checks arrive in Phase 2.
- **Removed:** written authorisations, evidence uploads, approval states, attestation checkboxes, the assessment profile picker and dual sign-off. Their tables and data are kept and listed in `retired_tables` (migration `0016_self_service`). The earlier analyst pipeline (assessments, Docker/Nmap profiles, workbench, VAPT reports, remediation, port watch, monitoring set-up) is **read-only**: staff can still read past data, only "stop" actions work, and it will be deleted after Phases 2â€“4 replace it.

## What it does

1. **MONITORS** - uptime every 5 minutes, certificate expiry, scheduled scans, score trend and email alerts.
2. **DETECTS** - open ports, services and versions, technologies, DNS and email settings, exposed files, subdomains.
3. **IDENTIFIES** - vulnerabilities (NVD, OSV, end-of-life data and pinned Nuclei templates) and configuration problems.
4. **REPORTS** - what you have, what you should have, how risky it is and how to fix it; re-scan to confirm a fix; accepted risks; comparison between scans.

## Repository map

```text
backend/   FastAPI app (app/api, app/services, app/models), migrations, tests, scan data (app/data)
frontend/  React app (src), unit tests (tests)
scripts/   start-demo, install-autostart, fresh-clone-check, Nuclei firewall helpers
deploy/    systemd unit for Linux (written, not yet tested on Linux)
docs/      product spec, audit matrix, demo script, proof (screenshots and run output)
```

Product spec and build phases: [docs/SNWEBSHIELD_SPEC.md](docs/SNWEBSHIELD_SPEC.md). Evidence per phase: [docs/AUDIT_MATRIX.md](docs/AUDIT_MATRIX.md).

## Phase 2: DETECT (what a scan finds)

A scan now runs six steps against the **one IP pinned at the start of the scan**, in Python only (no Nmap, Docker or VM), inside the existing `scan-worker`:

1. **Ports:** an asyncio TCP connect scan of the fixed top-1,000 Nmap ports (`backend/app/data/top_ports.py`, generated once from Nmap's `nmap-services`; the app never downloads it) plus the risky-service ports that Nmap's default list omits: **6379 Redis and 27017 MongoDB** (the spec's risky database ports) and, added on review, **11211 Memcached, 2375/2376 Docker API, 5984 CouchDB, 5601 Kibana, 2379 etcd, 10250 kubelet, 15672 RabbitMQ management and 9300 Elasticsearch transport** (all commonly exposed by mistake), 1,011 ports in all. The other risky services in the spec (Telnet, FTP, MySQL, PostgreSQL, SQL Server, Elasticsearch 9200, RDP, SMB) are already in Nmap's list. Pro and above can request a full 1â€“65535 scan through the API (`POST /websites/{id}/scan` with `{"scan_type": "full"}`); there is no UI for it yet and Free is refused.
2. **Versions:** per open port (3 s limit each): the banner (SSH, FTP, SMTP, POP3, IMAP, MySQL, others), `HEAD /` and `GET /` for web servers, and a TLS handshake that records the TLS version, cipher and the certificate's subject, issuer and expiry. Harmless probes only; no logins, no attack payloads; cookie values are never kept.
3. **Technologies:** fingerprints from headers, cookies, meta tags, script and CSS paths and a few known files, defined in the editable `backend/app/data/fingerprints.json` (the 21 starter technologies from the spec).
4. **Exposed files:** a fixed list of paths, each confirmed by its content (not a 200 status), with a soft-404 baseline. File contents are never stored.
5. **Email and DNS:** SPF, DMARC, DKIM (common selectors), CAA and MX via this machine's resolver (never a third-party DNS-over-HTTPS service).
6. **Subdomains:** listed from certificate-transparency logs (crt.sh gets only the domain name; 6 s timeout, "could not check" if slow). Only listed, never scanned.

Limits are in settings (`SCAN_CONNECT_CONCURRENCY` 100, `SCAN_PORT_TIMEOUT_SECONDS` 1.5, `SCAN_PORTS_PER_SECOND` 300, `SCAN_PROBE_TIMEOUT_SECONDS` 3, `SCAN_BANNER_MAX_BYTES` 1024, `CRTSH_TIMEOUT_SECONDS` 6, `SCAN_GUARD_POLL_SECONDS` 1, `SCAN_TIME_LIMIT_SECONDS` 900 = 15 minutes for a standard scan, and `SCAN_FULL_TIME_LIMIT_SECONDS` 3600 = 60 minutes for a full 1-65535 scan). A step that fails or times out is **"could not check"**, never "clean": a scan is "completed" only if every step finished, and otherwise "incomplete" with the reasons.

**Long checks stop cleanly.** A guard re-reads the database about every second and before each step and batch. If the website is removed, ownership verification is lost (or a test target's owner stops being an active admin), the owner is disabled, the scan is taken over, or the time limit passes, the running step is cancelled (closing its connections), nothing further is contacted, partial results are kept, and the scan ends **incomplete** with the reason. Removal ends the scan record immediately and the worker stops within about a second.

**Port timing: Windows development host vs Linux production.** The default port timeout stays **1.5 s**. A Windows machine takes about 2 s to report a refused connection, longer than that timeout, so when scanning from the Windows development host closed ports are counted as "not answering" instead of "closed" (in the real scan: 999 not answering, 0 closed) and a standard scan takes 15-30 s. Open ports are unaffected. The production server will run on **Linux, where a refused connection comes back immediately**, so closed ports are classified exactly and scans are much faster. To get exact closed-port counts on Windows anyway, set `SCAN_PORT_TIMEOUT_SECONDS=2.5` (slower scans).

Results are stored in `scan_ports`, `scan_technologies` and `scan_observations` (migration `0018_detect_results`) and shown on the website page; `GET /websites/{id}/scans/{scan_id}` returns them.

## Phase 3A: IDENTIFY (findings)

After the six DETECT steps, a scan runs three more steps, each an **engine** with one common interface (`backend/app/services/engines.py`) and one common finding format (`finding.py`: kind, check, title, location, severity, confidence, what you have / should have, why, how to fix, CVE, CVSS, affected range, first fixed version, evidence, caveat, sources). A later engine (Nuclei, Phase 3B) plugs in by registering itself; the runner, database, API and screen need no change.

1. **Security settings** (`engine_config.py`, check ids such as `tls:*`, `header:*`, `cookie:*`, `cors:*`, `http:*`, `port:*`, `exposed:*`): certificate expired / expiring in 7 or 30 days / wrong name / self-made / not trusted; TLS 1.0 and 1.1 still accepted (one handshake each, to the pinned IP only); weak ciphers; no HTTPS; no http-to-https redirect; mixed content; missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; cookie flags (Secure, HttpOnly, SameSite; names and flags only, **never values**); CORS (one GET with a foreign `Origin`); version disclosure; risky open ports; exposed files. Severities come from one reviewed table (`app/data/severity_rules.py`).
2. **Known vulnerabilities** (`engine_vulns.py`): server and CMS versions are matched in **NVD** by CPE name (editable map `app/data/cpe_map.json`, old and new vendor names both queried), JavaScript libraries in **OSV**. Only a software name and version is ever sent to either service (see `docs/THIRD_PARTY.md`). Severity comes from the CVSS score (>= 9 Critical, >= 7 High, >= 4 Medium, below that Low).
3. **End of life** (`engine_eol.py`): from committed data (`app/data/eol.json`, generated from endoflife.date by `tools/update_eol.py`; no network at scan time) plus hand-written release hints (`eol_hints.json`). Two tiers worded differently: **High, "No longer receives security updates"** (all support, including paid, has ended) and **Medium, "Only paid extended support remains"**. Both are confirmed and count in the score. A package from a Linux distribution is judged by its **distribution release**, not the upstream branch, and a version that several releases ship is called end of life only if **every** one of them has ended. OpenSSH gets no version cut-off, only its distribution's end of life plus its CVEs. If the data is older than 90 days the finding says so.

**False positives.** A vulnerability is **confirmed** (counts in the score, shown under Findings) only if our own version comparison confirms that the version is inside the database's affected range, the software is **not** an Ubuntu/Debian/Red Hat package (those vendors fix problems without changing the version number), it is not behind a proxy or CDN, and the CVE is not disputed or dependent on another component. Otherwise it is **possible**: shown under **Needs checking** with a plain explanation and the command to check it (`apt changelog openssh-server | grep CVE-`, `ubuntu-security-status`, `rpm -q --changelog ...`), and **never counted**. A CVE without a score is Medium and possible; rejected CVEs are skipped; at most 50 CVEs per item are shown. A version that is not disclosed gives an Info finding that says we cannot check it.

**When a database is slow or down.** Answers are cached for 24 hours in `vuln_cache` (shared by all scans; one request per product version at a time). Each look-up has a 10 s timeout, two retries (honouring `Retry-After`), an 8 MB limit, no redirects, a rate limit (5 requests per 30 s without a key), a circuit breaker (3 failures: pause 60 s) and a 120 s budget per scan. A failed look-up makes the step **"could not check"** and the scan **incomplete**; it is never shown as "no vulnerabilities". Old cached data may add findings (flagged with its date) but never supports "none found". Entries unused for 30 days are removed.

**What the screen says.** Findings are grouped Critical, High, Medium, Low (red, orange, yellow, blue; the word is always shown), then **Needs checking**, then "Good to know" (Info). An empty list reads **"No findings from these checks"**, never "safe" or "clean", and a check that did not finish is listed under **"Could not check"** with the reason.

**Limits worth knowing.** The weak-cipher test needs a weak cipher that this computer's OpenSSL can offer; on this Windows machine it cannot, so that single test is listed as "not available" in the step details (never counted as a pass) and will work on a Linux host whose OpenSSL has them. Joomla and Drupal versions are not matched yet. Distribution hints cover common Ubuntu, Debian and CentOS releases only. Nuclei is not part of 3A.

Stored in `scan_findings` and `vuln_cache` (migration `0019_findings`); returned as `findings` by `GET /websites/{id}/scans/{scan_id}`.

## Phase 3B: Nuclei (extra template checks, off by default)

Nuclei is one more engine (`engine_nuclei.py`, step `nuclei`) behind the same interface as the built-in checks. It is an **optional** step: if it is off or cannot run, the scan and its core results are unaffected (a failure adds a note; it never makes a scan "incomplete"). The only exception to "scans run in Python" is this ONE pinned, checksum-verified binary (see `CLAUDE.md`).

**Safety layers (all must hold, checked on every scan):**
1. **Pinned binary.** `app/data/engines.lock.json` pins Nuclei v3.11.1 and its SHA-256 hashes; `tools/install_nuclei.py` refuses any download that differs and extracts only the one expected file; the engine re-hashes the installed binary before every run.
2. **Pinned templates.** 3,948 reviewed templates (nuclei-templates v10.5.2) are vendored with their licence and a `MANIFEST.json`; a changed, added or missing file keeps the engine off. Nothing is downloaded at scan time.
3. **Validator** (`nuclei_templates.py`, `tools/validate_templates.py`). A template is vendored only if it is plain `http`, GET/HEAD only, targets only `{{BaseURL}}`/`{{RootURL}}`, has matchers, no raw requests, payloads, fuzzing, bodies, OAST/interactsh, exec/file/sleep helpers, at most 8 requests and same-host redirects, and none of the tags intrusive, dos, fuzz, bruteforce, rce, sqli, xss, lfi, ssrf, xxe, ssti, oast, dast, fuzzing, default-login. CVE templates may only use word/status/regex/size matchers. Of 8,960 templates in the five categories 3,948 pass.
4. **Egress proxy** (`egress_proxy.py`). Nuclei's only way out: `CONNECT` to the verified host on 443 and plain HTTP to it on 80 only, always to the scan's one pinned IP (never resolved again); every other host, port, IP-literal or method is refused. Every allowed and refused attempt is logged to `NUCLEI_LOG_DIR/<scan id>.jsonl` (no paths, headers or bodies) and summarised in the scan result.
5. **Process limits.** Fixed argument list, no shell, minimal environment (no secrets or proxy variables), private throw-away working folder, `-ni -fhr -duc`, rate and concurrency limits, output cap, time limit, and the whole process tree is killed when the scan guard stops the scan.
6. **Self-test** (`python -m app.services.nuclei_selftest`). The REAL binary must reach an allowed canary through the proxy and be unable to reach a second one (the proxy refuses an IP-literal host and a wrong port); a cancelled run must leave no process behind; and the operating-system firewall rule that blocks the binary's own direct network access must exist. Windows: `scripts\nuclei-firewall-dev.ps1` (run by the administrator; undo with `scripts\nuclei-firewall-dev-undo.ps1`). Linux: an nftables/iptables rule carrying the comment `snwebshield-nuclei-egress` (not yet verified, see AUDIT_MATRIX). Remove the rule and the self-test fails and the engine stays off.

**Quick and Deep (feat/nuclei-speed).** A normal scan runs the **Quick** set: every exposures and misconfiguration template, the sensitive panels, and CVE templates matching software the scan detected (1,426 templates + up to 300 CVEs, 100 s limit, about 1,800 requests on scanme in 99 s). The **Deep** set (all 3,948, 600 s limit) is reserved for scheduled deep scans in Phase 5 and is not reachable from the app yet. Nuclei is started with a loopback-only resolver file and `-sr`: its own DNS look-ups were blocked by the firewall rule and cost about 5 s each (measured: 2 requests/s; with the fix 22 requests/s, see `docs/proof/nuclei-speed/`). Nuclei runs in parallel with the vulnerability and end-of-life steps (limit 180 s) and is on by default in development; it still only runs while its self-test passes. **Before every release run `powershell -ExecutionPolicy Bypass -File scripts\fresh-clone-check.ps1`**: it clones the repository into a temporary folder, installs it from scratch, checks the Nuclei manifest and that `.gitignore` hides nothing needed, and runs the backend and frontend tests and the build.

**How results appear.** Findings merge into the one list: the same issue found by a built-in check and a template (`app/data/nuclei/equivalents.json`) or the same CVE found by NVD and a template appears once with both sources. **Technologies** found by templates never create findings: they are added to the Technologies list (name, version if known, source "nuclei") merged with the built-in detection. **Login and admin pages** are grouped into ONE Info finding per website ("Login or admin pages found: 4", list inside); a sensitive panel (database admin tools, Jenkins and other CI, Grafana/Kibana/Elasticsearch, Docker/Kubernetes dashboards, router/firewall and hosting/server admin) becomes its own Medium finding, decided by the editable `app/data/nuclei/sensitive_panels.json` (the same list also makes the built-in login-page check report `/phpmyadmin/` and Adminer as Medium; the network-device group covers real router and firewall admin pages only, not meeting or collaboration apps). CVE templates are always "possible" (needs checking); severity is capped at High.

## Phase 4: findings lifecycle (accepted risk, re-scan to confirm a fix, comparison)

Every finding has a life across scans of the same website (`finding_states`, migration `0020_finding_states`; identity = the finding's fingerprint, so it is the same finding in every scan).

- **Open / Fixed / Accepted.** A finding is **Fixed** only when a later full scan or a re-check finished the check that produces it and did not find it; the screen says how it was confirmed ("by a re-check" or "by a full scan"). If that check could not finish, the finding stays open ("could not be confirmed"); a failed or timed-out check is never "fixed". If a later scan finds a fixed finding again it is **reopened**.
- **Re-scan to confirm fix** (button on a finding; owner only). Runs only the check behind that one finding, against the website's one pinned IP, through the normal scan worker (ownership re-checked first, stop guard, 120 s limit). It never replaces the website's latest scan. Allowance per day is separate from manual scans: `rechecks_per_day` in `backend/app/plans.json` (Free 20, Pro 50, Business 200), and a test target has its own 20 a day. Findings that cannot be checked alone (the grouped "login pages" line, "more known issues" lines) say so.
- **Accept risk** (owner only; analysts and other users cannot). Needs a typed reason (10 to 300 characters) and a period of 30, 90 (default), 180 or 365 days. The finding stays listed (section "Accepted risks") but is not counted in the score. Seven days before the end it shows **Review soon**. When the period ends it goes back to **Open** by itself (checked by the worker every few seconds and whenever the website is read), counts in the score again, and the expiry is written to the audit log. The owner can accept again with a new reason or stop accepting at any time.
- **Changes since last scan.** "2 new, 3 fixed, 14 unchanged" at the top of the Vulnerabilities and Report tabs, with lists. The baseline is the website's previous full scan (completed or incomplete). A finding that is gone is called Fixed only if its step finished OK in the newer scan; otherwise it is counted as "could not be confirmed".
- **Audit log events:** `recheck_requested`, `finding_fixed`, `finding_reopened`, `risk_accepted`, `risk_unaccepted`, `risk_acceptance_expired`.
- **API:** `POST /websites/{id}/findings/{fingerprint}/accept` (`{reason, days}`), `POST .../unaccept` to stop accepting, `POST .../recheck`, `GET /websites/{id}/scans/{scan_id}/comparison`. A finding in a scan detail carries `state`, `recheckable` and `scored`.
- **Proof:** `docs/proof/phase4/real-scanme-flow.json` (real scanme.nmap.org: accept raised the score 73 to 83, stopping brought it back to 73, a re-check reported "still there", comparison of two real scans). Test fixtures prove "fixed" and "reopened" (`backend/tests/test_findings_lifecycle.py`).

## Phase 5: MONITOR (scheduled scans, uptime, alerts, auto-start)

Migration `0021_monitor`; the new background role is `monitor` (`python -m app.cli.operations monitor`), next to the scan worker.

- **Scheduled scans** (`services/scheduling.py`): weekly on Free, daily on Pro and Business (`scan_interval_hours` in `backend/app/plans.json`). Each website has its own fixed slot inside the period (from its id), so scans do not all start together; at most 5 are queued per round (`SCHEDULED_SCANS_PER_TICK`). Only verified websites of active accounts; the first scan is still started by ownership verification; the scan worker re-checks owner, verification and resolved IP right before running. Scheduled scans of the test target count against its 10 a day. One website failing never stops the others.
- **Uptime** (`services/uptime.py`): every 5 minutes (`UPTIME_INTERVAL_SECONDS`), every 30 minutes for the test target (`TEST_TARGET_UPTIME_INTERVAL_SECONDS`): one request to `/` over HTTPS (HTTP if HTTPS does not answer) to the one public address of the website, same SSRF rules as scans. 5xx, no answer or time-out is a failure; 2 failures in a row means down (alert), the first good check means back up. An address that is not allowed is "could not check", never "down". Status code, response time and the certificate's end date are kept 30 days; nothing else from the answer. **Uptime checks never count against scan limits.**
- **Certificate expiry** is read from the same connection once a day, so the 14-day alert works between weekly scans.
- **Score trend** (`score_history`): the score after each finished full scan; the Monitor tab draws it (older scans are filled in when first read).
- **Email alerts** (`services/alerts.py`): new open port, new Critical/High finding (compared with the previous scan; the first scan raises nothing), certificate ending within 14 days, website down and back up, ownership no longer proved, accepted risk ending within 7 days. Plain language, the website name in the subject, one "What to do:" line, a link, and "Turn off this kind of alert" (opens Settings with that type highlighted). The same alert is sent at most once per 24 hours. Each type can be switched on or off in Settings (and "Send me a test alert"). Until SMTP is configured, emails are written to the outbox folder (`MAIL_OUTBOX_DIR`). Slack/webhook alerts are Phase 7 (Business plan).
- **Development safety:** set `MONITOR_DOMAIN_ALLOWLIST=scanme.nmap.org` in `backend/.env` and the monitor schedules scans and runs uptime checks ONLY for those domains (empty = every verified website, which is what production uses).
- **Auto-start and restart** (`python -m app.cli.supervisor`): starts the API (8000), the web app (5173, from `frontend\dist`), the scan worker and the monitor, and restarts any that stops after 1, 2, 4 ... 60 seconds; its heartbeat (with each role's process id and restart count) feeds **Admin > Workers**. Windows: run `scripts\install-autostart.ps1` once as administrator (Task Scheduler task "SNWebShield-Supervisor": runs at boot whether or not you are logged in, under your account, restarted by Task Scheduler if it stops; no new package); undo with `scripts\uninstall-autostart.ps1`. Linux: `deploy/systemd/snwebshield.service` (written, not yet tested on Linux). `start-demo.ps1` still starts everything by hand; do not use both at once.
- **Settings added:** `UPTIME_INTERVAL_SECONDS`, `TEST_TARGET_UPTIME_INTERVAL_SECONDS`, `UPTIME_TIMEOUT_SECONDS`, `UPTIME_FAILURES_BEFORE_ALERT`, `UPTIME_KEEP_DAYS`, `SCHEDULED_SCANS_PER_TICK`, `CERTIFICATE_ALERT_DAYS`, `ALERT_REPEAT_HOURS`, `PUBLIC_APP_URL`, `MONITOR_DOMAIN_ALLOWLIST`.
- **Proof:** `docs/proof/phase5/` (screenshots, supervisor crash test, a sample alert email).

### Manual verification is strict (2026-11-27)

An administrator can still verify a website by hand for 24 hours, but only with all three of: **Owner name or company**, **How consent was given** (email, written letter or in person) and a **reason of at least 20 characters** that says what the owner agreed to. "admin only", "test", "demo" and similar filler are refused (server and form use the same rules: `ownership.manual_details_problem`, `lib/account.js`). The details are stored with the verification, written to the `manual_verification` audit event and shown in the website's **Audit history** panel (`GET /api/v1/websites/{id}/audit`; the owner sees "an administrator", staff see who). Older entries without these details are shown as "not recorded". Three websites verified earlier with the reason "admin only" were reset to unverified (audit event `verification_reset`).

## Phase 6: design (themes, branding, dashboard, reports, small screens)

- **Navigation:** Dashboard, Websites, Reports, Settings (and Admin for admins). Each website keeps its four tabs: Monitor, Detect, Vulnerabilities, Report.
- **Dashboard:** four pillar cards across ALL your websites: **MONITOR** (sites up and down, certificates ending within 14 days), **DETECT** (open ports and technologies found), **VULNERABILITIES** (open Critical, High, Medium and Low counts; accepted and fixed findings are not counted) and **REPORT** (latest reports). Each card links to the right website and tab. A website with no scan yet says "not scanned yet", never "safe".
- **Reports page:** the latest report of every website with **View** and **Download PDF** (the browser's print dialog, Save as PDF; the button follows the plan setting `pdf_report`; the PDF is always light, whatever theme is on screen).
- **Themes:** light and dark (switch in the top bar and on the sign-in page; first choice follows the system, then it is remembered). Colours are tokens in `frontend/src/styles/tokens.css` (generated by `frontend/tools/make_tokens.py`): one teal accent, plus the fixed severity colours (Critical red, High orange, Medium yellow, Low blue, Info grey, Fixed green). A test checks 4.5:1 contrast for every text and background pair in both themes.
- **Type and layout:** 14 px body text, nothing meant to be read below 13 px (uppercase labels 12 px; a test enforces it), consistent spacing, system font (no font download from a third party).
- **Small screens:** works at 360 px: the sidebar becomes a menu, tables become cards, no sideways scrolling. Keyboard focus is always visible, there is a skip link, and animations respect "reduce motion".
- **Branding:** the SNwebshield name and a simple shield logo (SVG) in the header, sign-in and sign-up pages, favicon, every email (HTML and plain text, same accent colour) and the printed report.
- **Empty states and loading:** every empty screen says what to do next; loading shows skeletons.
- **Also:** emails are now multipart (plain text and branded HTML); the sign-in headline no longer claims to tell you "how safe" a website is.
- Proof: `docs/proof/phase6/` (every main page in light and dark at desktop and 360 px, the print view and a PDF).

## Setup, run, test and deploy

All commands are PowerShell, run from the repository root unless stated. Never paste secrets, `.env` contents or private keys into chat, commits or logs.

### 1. Local Windows setup

```powershell
cd backend
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }   # never overwrite an existing .env
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into JWT_SECRET_KEY in backend\.env yourself
cd ..\frontend
npm install
```

### 2. Back up and migrate the database

```powershell
cd backend
.\.venv\Scripts\python.exe -m app.cli.backup_database      # verified copy of the SQLite file, outside the repository
.\.venv\Scripts\python.exe -m alembic upgrade head          # head is 0022_legacy_retired
```

To restore a backup: stop the API and all workers, then copy the backup file over `backend\snwebshield_dev.db` and check out the code that matches it (for `0016` to `0018`, the commit before Phase 1).

Back up before every migration. Migrations are additive and downgrades are refused; to go back, restore the backup together with the matching code. The API refuses to start if a required table is missing.

### 3. Create accounts

Customers sign up in the browser (`http://127.0.0.1:5173/app/`, "Create an account"; the public landing page is at `/`) and confirm their email. The admin account is created locally:

```powershell
cd backend
.\.venv\Scripts\python.exe -m app.cli.create_admin                    # admin (manages users and plans)
```

Account emails (confirmation and password reset) go through SMTP when `SMTP_HOST` and `SMTP_SENDER` are set. Otherwise, for development only, each email is saved as a `.eml` file in `MAIL_OUTBOX_DIR` (default `%USERPROFILE%\SNWebShield-Private\outbox`, outside the repository); open it to click the link. To switch to real email, set in `backend\.env`: `SMTP_HOST`, `SMTP_PORT` (465 for SSL or 587 for STARTTLS), `SMTP_SECURITY` (`ssl` or `starttls`), `SMTP_SENDER` (the From address), `SMTP_USERNAME` and `SMTP_PASSWORD` (if your provider needs them), and `FRONTEND_BASE_URL` (the address users open, used in the email links). Restart the API afterwards.

Passwords are typed at a hidden prompt: 12 to 128 characters, at least three of lowercase, uppercase, digits and symbols, not common and not containing the email name.

### 4. Run the processes

**Everything at once, and after every reboot:** run `scripts\install-autostart.ps1` once as administrator (Phase 5). The supervisor then starts the API (8000), the web app (5173, from `frontend\dist`), the scan worker and the monitor at boot and restarts any that stops.

**By hand for a demo:** `powershell -ExecutionPolicy Bypass -File scripts\start-demo.ps1` (API, scan worker, monitor and the dev web app; skips what is already running). Or in separate terminals from `backend`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
.\.venv\Scripts\python.exe -m app.cli.operations scan-worker     # runs scans and re-checks (one process)
.\.venv\Scripts\python.exe -m app.cli.operations monitor         # scheduled scans, uptime, certificates, alerts
# frontend (from frontend):  npm run dev   # http://127.0.0.1:5173
```

Restart the API and the workers after changing `.env` or upgrading. Keep everything on the Windows machine; do not deploy the stack to Azure. The Admin page shows the state of every role.

**DNS look-ups and the second resolvers.** SPF, DMARC, DKIM, CAA and MX look-ups retry before a scan says "could not check": attempt 1 uses this machine's resolver, attempt 2 uses the second resolvers `1.1.1.1` and `9.9.9.9` (setting `SCAN_DNS_FALLBACK_RESOLVERS`, plain DNS, never DNS-over-HTTPS; approved by the owner because the domain names being scanned are public), attempt 3 uses this machine's resolver again (`SCAN_DNS_ATTEMPTS` 3, `SCAN_DNS_TIMEOUT_SECONDS` 2.5). Leave `SCAN_DNS_FALLBACK_RESOLVERS` empty to use only this machine's resolvers.

### 5. Environment variables (names only; put real values in the private `backend/.env`)

| Name | Purpose |
|---|---|
| `DATABASE_URL` | SQLite file by default (`sqlite:///./snwebshield_dev.db`) |
| `JWT_SECRET_KEY` | Required, random, at least 32 bytes. Also `JWT_ACCESS_TOKEN_MINUTES` (20), `JWT_ISSUER`, `JWT_AUDIENCE` |
| `CORS_ORIGINS` | Comma-separated frontend origins (`http://localhost:5173,...`); `*` is rejected |
| `LOGIN_MAX_FAILURES` (5), `LOGIN_WINDOW_MINUTES` (15) | Login throttling |
| `HSTS_MAX_AGE_SECONDS` | `Strict-Transport-Security` lifetime when served over HTTPS |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY` (`ssl`/`starttls`), `SMTP_SENDER`, `SMTP_USERNAME`, `SMTP_PASSWORD` | Account emails (confirmation, password reset) and monitoring notifications |
| `MAIL_OUTBOX_DIR` | Development only: where account emails are saved when SMTP is not configured (must be outside the repository) |
| `FRONTEND_BASE_URL` (`http://localhost:5173`) | Address used in email links (they open `/app/...`) |
| `SITE_DOMAIN` (`snwebshield.com`, placeholder) | The public domain, used by the landing page build (canonical, Open Graph, sitemap, robots). Also read by `npm run build` from `backend/.env` |
| `GST_MODE` (`none`; `exclusive` or `inclusive`) and `GST_PERCENT` (18) | How the landing page pricing shows GST |
| `EMAIL_VERIFICATION_HOURS` (24), `PASSWORD_RESET_MINUTES` (60) | Lifetime of emailed links |
| `SIGNUP_MAX_PER_IP` (5), `ACCOUNT_EMAIL_MAX_PER_IP` (10), `SIGNUP_WINDOW_MINUTES` (60) | Sign-up and account-email rate limits |
| `OWNERSHIP_CACHE_HOURS` (24), `OWNERSHIP_HTTP_TIMEOUT_SECONDS` (8) | How long a verification is trusted before a scan re-checks it; file/meta fetch timeout |
| `SCAN_CONNECT_CONCURRENCY` (100), `SCAN_PORT_TIMEOUT_SECONDS` (1.5), `SCAN_PORTS_PER_SECOND` (300), `SCAN_PROBE_TIMEOUT_SECONDS` (3), `SCAN_PROBE_CONCURRENCY` (8), `SCAN_BANNER_MAX_BYTES` (1024), `SCAN_HTTP_BODY_MAX_BYTES` (262144), `SCAN_HTTP_REQUEST_TIMEOUT_SECONDS` (3), `SCAN_DNS_TIMEOUT_SECONDS` (3), `CRTSH_TIMEOUT_SECONDS` (6), `SCAN_GUARD_POLL_SECONDS` (1) | Detection limits (Phase 2) |
| `SCAN_MAX_CONCURRENT` (3), `SCAN_TIME_LIMIT_SECONDS` (900), `SCAN_FULL_TIME_LIMIT_SECONDS` (3600), `SERVER_PUBLIC_IPS` | Scans running at once on the server; total time per scan, 15 minutes standard and 60 minutes full (past it the result is "incomplete"); this server's public IPs, never scanned |
| `NVD_API_KEY` (optional), `VULN_CACHE_HOURS` (24), `VULN_HTTP_TIMEOUT_SECONDS` (10), `VULN_MAX_RESPONSE_BYTES` (8 MB), `SCAN_IDENTIFY_BUDGET_SECONDS` (120), `SCAN_TLS_PROBE_TIMEOUT_SECONDS` (2) | Phase 3A vulnerability look-ups. Works **without** a key (5 NVD requests per 30 s); with a free key 50. Put the key only in `backend/.env`; it is read as a secret, sent only in the `apiKey` header to NVD and never logged. No code change is needed to add it |
| `SCAN_DNS_TIMEOUT_SECONDS` (2.5), `SCAN_DNS_ATTEMPTS` (3), `SCAN_DNS_FALLBACK_RESOLVERS` (`1.1.1.1,9.9.9.9`; empty = this machine's resolvers only) | DNS look-ups for SPF/DMARC/DKIM/CAA/MX: per-attempt timeout, attempts (system resolver, second resolvers, system resolver) before "could not check" |
| `NUCLEI_ENABLED` (true in development; it only runs while its self-test passes, and is skipped if the binary is not installed), `NUCLEI_DIR`, `NUCLEI_LOG_DIR`, `NUCLEI_RUN_SECONDS` (180, quick), `NUCLEI_DEEP_RUN_SECONDS` (600), `NUCLEI_MAX_QUICK_CVES` (300), `NUCLEI_RATE_LIMIT` (25), `NUCLEI_CONCURRENCY` (10), `NUCLEI_MAX_OUTPUT_BYTES`, `NUCLEI_SELFTEST_VALID_MINUTES` (60) | Phase 3B Nuclei engine. Off by default, and even when on it only runs while its self-test passes |
| `VITE_API_BASE_URL` (frontend) | API base URL including `/api/v1` |

### 6. Run the tests (one at a time, never together)

```powershell
powershell -File scripts\test-quick.ps1      # backend quick level + frontend tests, about 1 minute
powershell -File scripts\test-full.ps1       # all backend tests (parallel with pytest-xdist) + frontend tests + build, about 1 minute
```

By hand: `cd backend; .\.venv\Scripts\python.exe -m pytest` (add `-m "not slow"` for quick, `-n 6` for parallel after `pip install -r requirements-dev.txt`), then `cd frontend; npm test; npm run build`. Before merging a phase run `powershell -ExecutionPolicy Bypass -File scripts\fresh-clone-check.ps1` (clone, install from scratch, all tests and the build). Details: [docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md).

## Removed: the earlier analyst pipeline

On 2026-11-27 the earlier analyst-led pipeline (clients, authorisation evidence, assessments, observation review, vulnerability management, the analyst workbench, VAPT reports, remediation sign-off, port watch, the old monitoring jobs and the Docker/VM Nmap runner) was removed from the code. Phases 2 to 5 replaced it. Everything is recoverable from the git tag `before-legacy-removal`. The database tables are kept with all their data (listed in `retired_tables`, migration `0022_legacy_retired`) and all audit data (`execution_events`, `auth_events`, `authorization_audit_events`) is unchanged.

## Public landing page (feat/landing)

- `/` is a static, fast page (no framework, CSS inlined, about 25 KB): the four pillars, how it works, pricing, FAQ (including "we only scan websites you own"), sign-up and log-in buttons, a footer with company details, and Terms of Service (`/terms/`), Privacy Policy (`/privacy/`) and Acceptable Use (`/acceptable-use/`). Every legal page starts and ends with **DRAFT – needs legal review** and shows `[PLACEHOLDER: ...]` for details still missing. Also `robots.txt` (the app and API are not indexed), `sitemap.xml`, Open Graph and Twitter tags, JSON-LD and `og-image.png`.
- The app moved to `/app/` (hash routes are unchanged: `/app/#/websites/ID`). Sign-up button: `/app/#/signup`. Email links (verification, reset, alerts) use `/app/`.
- Pricing is read from `backend/app/plans.json` at build time (`price.monthly`/`price.yearly` in rupees; "2 months free" is worked out from them). Change a price, run `npm run build`. `GST_MODE` is `none` (default), `exclusive` ("+ 18% GST") or `inclusive`.
- One place for the domain: `SITE_DOMAIN` (default placeholder `snwebshield.com`) in the environment or `backend/.env`. Company name, address and contact email are in `frontend/site/site.config.json`.
- Pages are generated by `frontend/vite.config.js` from `frontend/site/` (`pages.js`, `legal.js`, `site.css`); tests are in `frontend/tests/site.test.js`. Proof screenshots: `docs/proof/landing/`.
- **Price safety:** the built page carries its prices in a `snwebshield-prices` tag. `services/site_check.py` compares it with `plans.json` when the API starts (a mismatch is logged as `LANDING PAGE PRICE CHECK ...` with both values), `GET /api/v1/admin/site-check` feeds a warning on **Admin** (a missing or unreadable page is also a warning, never "fine"), and the supervisor (`SiteWatch`, every 30 s, in a background thread) rebuilds the site by itself when `plans.json` changes (a failed rebuild is retried after 10 minutes or when `plans.json` changes again; audit events `site_rebuilt` / `site_rebuild_failed`). **Checkout and billing always use `plans.json`, never the page.**

