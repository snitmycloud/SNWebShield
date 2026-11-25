# SNWebShield testing guide

**MONITORS. DETECTS. VALIDATES. PROTECTS.**

This guide tells you how to test SNWebShield end to end on your Windows machine: first the automated tests, then a manual walk through every pillar with the result to expect at each step, then the negative and security tests, the Azure VM checks, crash recovery, and a sheet to record your results.

It matches the code at commit `4ab1a30` (migrations up to `0015_port_watch`). If the screen differs slightly from a label quoted here, the behaviour described is what matters.

---

## 0. Ground rules (read first)

1. **Only test websites you are authorised to test.** SNWebShield will refuse anything else, and you should too. For the manual tests you need a real public website that you own or have written permission to assess. You cannot test against `localhost`, a private address or an IP literal: those are blocked on purpose, and checking that they are blocked is one of the tests.
2. **Never scan a third party's website** to "see what happens". The only exception built in is the VM self-test (section 8), which scans the scanner VM's own ports 80 and 443.
3. **Never paste or share** `backend/.env`, JWT secrets, passwords, tokens or SSH keys, not even into a test record.
4. **Back up the database before migrating** (section 2.3), and keep the backup.
5. **Run heavy tests one at a time.** `pytest`, `npm test`, `npm run build` and `npm run test:e2e` must not run together on this machine.
6. **Do not push to GitHub** as part of testing. Nothing in this guide needs it.
7. **Port watch and the Azure scanner profiles send real network traffic** to the authorised target or the VM. Everything else in sections 4 to 6 works without the VM.

### What you need

| Need | For | Notes |
|---|---|---|
| Windows machine with this repo, Python venv and Node | Everything | `backend\.venv`, `frontend\node_modules` already exist |
| A website you are authorised to test, with a real HTTPS URL | Manual tests | Use its exact hostname (for example `www.example.com`), no IP, no port |
| A signed permission document (PDF or image) for that website | Authorisation and monitoring | A real or clearly labelled test document; the file is stored privately |
| Three accounts: `admin`, `lead_analyst`, `analyst` | Role and sign-off tests | Created in section 2.4 |
| Azure VM access (`azureuser@57.159.27.58`) | Sections 7 and 8 only | Optional; skip these if you only test locally |

### Worked example target: `www.snitsolutions.in`

Use this as the test website throughout the guide. The steps below are what the app will require for it. SNWebShield never assumes ownership: it only acts on the written permission you upload.

| Item | Value to use |
|---|---|
| Website name | SN IT Solutions |
| Website URL | `https://www.snitsolutions.in/` |
| Authorised domain (exact) | `www.snitsolutions.in` |
| Not covered unless you add it | `snitsolutions.in` (without `www`), any subdomain, and any `*.` wildcard: scope is by **exact hostname**, so the apex domain needs its own entry and its own wording in the letter |
| Permitted methods | *Automated non-intrusive scanning* (sections 5.2 to 5.6). Add *TCP port discovery* **only** for sections 8.2 and 8.3 |
| Monitoring | Separate consent, covered in section 5.1; the same letter may include it if it says so explicitly |

**Before you start:**

1. **Confirm that this site is yours to test**, or get the owner's written permission. The site's company is the one signing the letter, so the signatory must have authority over the website.
2. **Write the permission letter** (template in Appendix A) and save it as a PDF. Upload that PDF as the evidence in section 4.2.
3. **Know where the site is hosted.** If `www.snitsolutions.in` sits on shared hosting or behind a CDN, its public IP address is shared with other customers who have **not** given permission. In that case do **not** run the Nmap profile or port watch (sections 8.2 and 8.3) against it, and do not put that IP in the authorised domains. The HTTP header, certificate, cookie, DNS and monitoring tests (sections 4 to 6) send one ordinary request to the website and are fine. Only run port checks if the IP address belongs to you or the hosting provider has explicitly permitted it in writing.
4. For the Azure VM and Nmap checks in section 8.1, the VM scans **only itself**, so that does not touch this website.

---

## 1. Automated tests (about 25 minutes in total)

Do these first. If they fail, fix that before testing by hand.

Run **one at a time**, in this order.

### 1.1 Backend (about 20 minutes)

```powershell
cd C:\SNWebShield-Local\backend
.\.venv\Scripts\python.exe -m pytest -q
```

**Expect:** `789 passed` (the number grows as tests are added; there must be **0 failed**). One harmless warning about `httpx` is normal.

Useful single suites while developing:

| Area | Command |
|---|---|
| Whole lifecycle with dual sign-off | `pytest tests/test_e2e_lifecycle.py` |
| Port watch | `pytest tests/test_port_watch.py` |
| Permission / one-step flow | `pytest tests/test_one_step_flow.py tests/test_assessments.py` |
| Worker recovery | `pytest tests/test_job_recovery.py tests/test_worker_status.py` |
| Nmap container checks and orphan report | `pytest tests/test_nmap_inspection.py` |
| Database behaviour before migration | `pytest tests/test_unmigrated.py` |

### 1.2 Frontend unit tests (seconds)

```powershell
cd C:\SNWebShield-Local\frontend
npm test
```

**Expect:** `pass 70`, `fail 0`.

### 1.3 Production build (seconds)

```powershell
npm run build
```

**Expect:** `✓ built in …` and no errors.

### 1.4 Browser tests (about 1 minute)

```powershell
npm run test:e2e
```

**Expect:** `22 passed`. These start their own isolated servers on ports 15173 and 18000 with synthetic data, so they never touch your real database or any real website.

> **What these prove and do not prove.** They prove the logic, the permission checks and the screens against synthetic scanner output. They do not prove a real scan against a real website or the real Azure VM. That is what sections 4 to 8 are for.

---

## 2. Prepare the real environment

### 2.1 Check the configuration (names only, never values)

Open `backend\.env` privately and confirm these exist. Do not share the file.

| Setting | For the tests |
|---|---|
| `JWT_SECRET_KEY` | Must be set (32 or more random bytes) |
| `SEPARATION_OF_DUTIES_ENABLED` | `false` for the first pass; set `true` for section 5.6 |
| `ASSESSMENT_LOCAL_HTTP_ENABLED` | `true` to run the local HTTP profile (section 5.3) |
| `ASSESSMENT_REMOTE_DOCKER_ENABLED`, `ASSESSMENT_REMOTE_IMAGE_ID` | Only for the Azure header profile (section 7) |
| `ASSESSMENT_NMAP_ENABLED`, `ASSESSMENT_NMAP_IMAGE_ID` | Only for Nmap and port watch (sections 7 and 8). Keep `false` until section 7 passes |

After changing `.env`, restart the API and the assessment worker.

### 2.2 Stop anything stale

Close old terminals running the API, frontend or workers so you start from a known state.

### 2.3 Back up and migrate (do this once per new version)

```powershell
cd C:\SNWebShield-Local\backend
.\.venv\Scripts\python.exe -m app.cli.backup_database
.\.venv\Scripts\python.exe -m alembic upgrade head
```

**Expect:** the backup command reports a verified copy; the upgrade ends without an error. The database is now at `0015_port_watch`. Upgrading adds tables only; it enables nothing and scans nothing.

**Check:** `.\.venv\Scripts\python.exe -m alembic current` prints `0015_port_watch (head)`.

### 2.4 Create the three accounts

Run the command three times, choosing a strong password each time at the hidden prompt (12 to 128 characters, three of lowercase / uppercase / digits / symbols):

```powershell
.\.venv\Scripts\python.exe -m app.cli.create_admin                       # admin
.\.venv\Scripts\python.exe -m app.cli.create_admin --role lead_analyst
.\.venv\Scripts\python.exe -m app.cli.create_admin --role analyst
```

Use three different email addresses and write down which is which (not the passwords).

### 2.5 Start everything (separate terminals)

```powershell
# Terminal 1: API
cd C:\SNWebShield-Local\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Terminal 2: frontend
cd C:\SNWebShield-Local\frontend
npm run dev

# Terminal 3: the background roles (scheduler, monitoring worker, notifications, assessment worker)
cd C:\SNWebShield-Local
.\scripts\start-workers.ps1
```

`start-workers.ps1` opens one window per role and skips any that is already running.

### 2.6 Smoke check

| # | Step | Expect |
|---|---|---|
| S1 | Open `http://127.0.0.1:8000/api/v1/health` | A small JSON success reply |
| S2 | Open `http://127.0.0.1:5173` | The sign-in page |
| S3 | Sign in as the **admin** | The overview page; the top bar shows **API connected** |
| S4 | Open **Assessments** | The line "Assessment worker: Running" with a recent heartbeat. If it says *Not started* or *Stale*, the page shows the exact start command; start the worker and refresh |

If S1 to S4 pass, the stack is healthy.

---

## 3. Sign-in, accounts and roles

| # | Step | Expect |
|---|---|---|
| A1 | Sign in with a wrong password once | A generic "invalid" message; no hint which part was wrong |
| A2 | Sign in correctly | You reach the overview |
| A3 | Wait until the token expires or sign out and use the browser back button | You are returned to sign-in; the app does not show data |
| A4 | Sign out, then open `http://127.0.0.1:8000/api/v1/clients` in the browser | `401` (not signed in) |
| A5 | Login throttling: with a **made-up email**, fail to sign in 5 times | The 6th attempt is refused for about 15 minutes. Do not do this with your real admin email |
| A6 | Sign in as **analyst** and open Remediation, then try to close an assessment | Closing is refused (senior role needed), reading and everyday work still work |

---

## 4. Register the client, website and written authorisation

This is the foundation: nothing can be scanned without it.

### 4.1 Client and website

1. **Clients**, then **Register a client**: enter the organisation and a contact.
2. **Websites**, then **Register a website**: choose the client, enter the website's name and its HTTPS URL.

**Expect:** both appear in their lists. The website shows an authorisation status of *not requested*.

### 4.2 Authorisation request

1. Open **Authorizations** and create a request for the website. Fill in:
   - an authorisation reference (your own),
   - the person who authorised it,
   - **authorised domains**: the website's exact hostname (add the IPv4 address too **only** if you plan to test Nmap or port watch, and only if the permission document covers it),
   - **permitted methods**: tick *automated non-intrusive scanning*, and *TCP port discovery* only if the document permits it,
   - the valid-from and valid-until dates (UTC).
2. Open the request and, in the evidence panel, **upload the permission document**.
3. Record the **human evidence review**: *Accept evidence* after you have actually looked at the document.
4. Approve the authorisation.

**Expect at each step:**

| # | Check | Expect |
|---|---|---|
| B1 | Try to approve **before** uploading any document | Refused: approval needs an accepted evidence review |
| B2 | After upload and acceptance, approve | Status becomes *approved* and *active*; an audit entry records who approved and when |
| B3 | The website's authorisation status | Changes to *active* |
| B4 | Open the audit trail of the authorisation | Shows uploaded, opened, review accepted, approved, each with your account |

### 4.3 Negative authorisation tests

Do these on a **spare** authorisation (create a second one), not your working one.

| # | Action | Expect |
|---|---|---|
| N1 | Create an authorisation whose valid-until date is in the past, try to approve | Refused or shown as expired; it can only be rejected |
| N2 | Approve one, then **revoke** it with a reason | Status *revoked*; the website no longer shows it as active |
| N3 | An authorisation with a future start date | Shown as *scheduled*, not active yet |
| N4 | Reject an authorisation | Status *rejected* with the reason in the audit trail |

---

## 5. The four pillars, step by step

Before starting, tick the website you will use and keep it selected throughout.

### 5.1 MONITORS: uptime, DNS, TLS, response time

Monitoring needs its **own** consent: the permission document must explicitly allow recurring HTTP, DNS and TLS checks.

**Prerequisite: the "Reviewed permission document" list must not be empty.** That list shows only permission documents that are (a) uploaded to an authorisation of the website you chose under *Manage website*, and (b) in the *available* state. If it shows only "Choose available evidence", do this first:

1. Make sure the right website is selected under **Manage website**.
2. Open **Authorizations**. If the website has no authorisation request yet, create one (section 4.2): documents are stored against an authorisation, so there is nowhere to upload one otherwise.
3. Open that authorisation and **upload the permission PDF** in the evidence panel.
4. Record the **human evidence review** (*Accept evidence*) **using the same account you will use to save the monitoring form**. Monitoring refuses a document that a different account reviewed ("First inspect and accept this document through the evidence review workflow").
5. Go back to **Monitoring** and choose the website again (or reload the page). The list is loaded when the website is selected and is not refreshed by itself.

The document may be the same PDF as for the assessment authorisation, but its wording must explicitly permit recurring monitoring; "existing testing approval alone is insufficient".

1. Open **Monitoring**, choose the website under **Manage website**.
2. Fill **Monitoring permission and configuration**: choose the uploaded document, enter a monitoring agreement reference (10 or more characters), set the consent expiry, interval (start with 1 or 5 minutes), timeout and thresholds, tick the attestation, **Save monitoring configuration**.
3. **Expect:** "Configuration saved disabled". Monitoring does **not** start by itself.
4. Press **enable**, then **check-now**.

| # | Check | Expect |
|---|---|---|
| M1 | After the first check | A row in the table with status, HTTP status (for example 200), duration in ms, DNS "Resolved", TLS expiry date |
| M2 | Monitoring history, type *results* | A response-time chart appears after several checks |
| M3 | Background processes strip | `scheduler`, `monitoring-worker`, `notification-dispatcher` show a recent heartbeat. If one says *Not running / stale*, start it with `start-workers.ps1` |
| M4 | **disable**, then **revoke consent** | Monitoring stops; enabling again is refused with a clear message until a new consent is saved |
| M5 | Monitoring a site whose URL is `http://127.0.0.1` or a private address | Blocked (the destination is not public) |

**Incident test (optional, needs a spare site you control):** point monitoring at a URL that you can briefly make unavailable. After the configured number of failures an incident opens and a notification appears; when the site returns, the incident closes.

### 5.2 DETECTS: permission preflight (no network)

1. Open **Assessments**.
2. **1. Website**: choose your website. The page immediately shows **Permission: valid** with the authorisation reference and its expiry, or **Permission: blocked** with the exact reason.
3. **2. Assessment profile**: *Non-intrusive assessment permission preflight*.
4. **3. Run assessment**.

| # | Check | Expect |
|---|---|---|
| D1 | Permission line | "valid", names the authorisation the system picked; you do not choose it |
| D2 | After pressing Run | A request appears: *queued*, then within seconds *Preflight completed*. No scan, no network request, no findings |
| D3 | Request details | Outcome "permission preflight passed"; execution attempts: 1 |
| D4 | Press Run again straight away while one is queued | Blocked: "An assessment for this website is already queued or running" |

### 5.3 DETECTS: local HTTP header assessment (one real request)

Needs `ASSESSMENT_LOCAL_HTTP_ENABLED=true` and a restart. This sends **one HEAD request** from your PC to the authorised website.

1. **Assessments**, choose the website, profile *Local HTTP header observations*.
2. Tick the written-permission attestation, then **Run assessment**.

| # | Check | Expect |
|---|---|---|
| D5 | Worker status | Running; the request goes queued, running, **Header assessment completed** |
| D6 | Details | Shows HTTP status, TLS version, response time. No Azure fields (it ran locally) |
| D7 | Header observations | One line per check, each marked *observed* or *review needed* with a suggested severity. The original eight are CSP, HSTS, X-Frame-Options, CSP frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and Server disclosure |
| D8 | New checks | **HTTPS in use** always appears. **Certificate expiry** appears for HTTPS sites. **Cookie flags** appears only if the site set cookies. None of them stores cookie names or values |
| D9 | **Download private assessment report** | A JSON file; it contains no raw header values, no cookie names or values |
| D10 | Nothing is called "confirmed" | Every observation says human validation is required |

### 5.4 DETECTS: cancel and failure behaviour

| # | Action | Expect |
|---|---|---|
| C1 | Queue an assessment, enter a cancellation reason (10+ characters), **Cancel assessment request** | Status *cancelled*; no scan runs; reason in the audit trail |
| C2 | Stop the assessment worker (close its window), queue a request | It stays *queued*; the page says to start the worker and shows the command. After two minutes it also says "waiting for the worker" |
| C3 | Start the worker again | The queued request runs and completes |

### 5.5 VALIDATES: turning observations into confirmed findings

Observations that were *review needed* are now **unconfirmed vulnerabilities**. A human decides what is real.

1. Open **Vulnerabilities**. **Expect:** each failed check is listed as *unconfirmed*, with confidence and the scanner's suggested severity. Nothing is confirmed automatically.
2. Open one (**Open vulnerability**): see the evidence, history and reproduction steps.
3. Open **Analyst workbench** and **Review finding**:
   - **Risk assessment**: set likelihood, business impact, risk rating, business context and a remediation recommendation, **Save assessment**.
   - **Sign-off**: choose the decision (confirm, or reject as false positive / not applicable), write the justification, tick the attestation, **Record sign-off**.

| # | Check | Expect |
|---|---|---|
| V1 | Confirm a finding | State becomes *confirmed*; the audit trail shows your name, time and justification |
| V2 | Reject another as a false positive | State becomes *false positive*; it can be suppressed until a date; it will not appear in reports |
| V3 | Try to confirm without saving a risk assessment first | Refused |
| V4 | Run a second assessment | The same findings are **updated**, not duplicated (detection count rises) |
| V5 | **Assessments**, the observation review panel | You can record a disposition per observation, and export a reviewed report once all are reviewed |

### 5.6 PROTECTS: report, fix, retest, sign-off, closure

For this section set `SEPARATION_OF_DUTIES_ENABLED=true`, restart the API, and use **two** people: an analyst for everyday work and a lead analyst (or admin) for approvals.

1. **Report.** As the analyst, **VAPT reports**, *Generate a draft report* for the assessment. **Expect:** a draft PDF with only the confirmed findings. As the same analyst, try to approve it: **refused**. As the lead analyst, **Approve and publish official report** with a justification: the **official PDF** becomes downloadable. Before approval there is no official PDF.
2. **Fix.** As the analyst, **Remediation**, *Manage remediation* on a confirmed finding: set the status to *in progress*, then *fix submitted* (after the website owner has really fixed it).
3. **Retest.** *Request a scoped retest*: choose the authorisation, write a note, tick both confirmations. **Expect:** another assessment is queued and the worker revalidates permission before it runs. When it finishes: if the weakness is gone the finding becomes **verified fixed**; if it is still there it is **reopened** automatically with fresh evidence.
4. **Second-person sign-off.** As the lead analyst, open the same finding: the **Sign off the verified fix** form appears. As the analyst who requested the retest, the same action is **refused**. The lead confirms (or rejects, which reopens the finding).
5. **Closure.** As the analyst, try to close the assessment: refused (senior role). As the lead: closing is **blocked** while any verified fix awaits sign-off, then succeeds once signed off and nothing is unresolved.
6. **Lock.** After closure try to change a finding, request a retest or save an assessment: all **refused** (locked). The lead can **Reopen closure** with a reason; that is audited.

| # | Check | Expect |
|---|---|---|
| P1 | Official PDF before approval | Not available |
| P2 | Creator approves own report (dual sign-off on) | Refused |
| P3 | Retest on a revoked authorisation | Refused with the exact reason |
| P4 | Requester signs off own retest | Refused |
| P5 | Close with an unresolved or unsigned finding | Blocked, with the reason listed |
| P6 | Edit after closure | Refused until the closure is formally reopened |

### 5.7 The lifecycle page ties it together

Open **Website lifecycle**, choose the website.

| # | Check | Expect |
|---|---|---|
| L1 | Four cards | MONITORS, DETECTS, VALIDATES, PROTECTS, each with counts that match what you see on the other pages |
| L2 | Next step | A single recommended action with a button that opens the right page. Typical order: set up monitoring, run the first assessment, review findings, sign off fixes, request retests, generate the report |
| L3 | Change something (for example confirm all findings) and press Refresh | The counts and the next step change accordingly |
| L4 | The page itself | Runs no scan and writes nothing |

---

## 6. Negative and security tests (the system must say no)

Each of these must be **refused with a clear reason**, and must leave no scan, no job and no side effect. The reasons are quoted from the screen.

### 6.1 Permission

| # | Setup | Expect on the Assessments page |
|---|---|---|
| X1 | Revoke the authorisation | "This website has no approved authorisation." The **Run assessment** button is disabled and the reason is shown |
| X2 | Authorisation expired (valid-until in the past) | "The authorisation is expired or not yet valid (UTC dates)." |
| X3 | Authorisation not yet valid | The same message |
| X4 | Authorised domain edited so it does not match the site's hostname | "The website's exact domain is not in the authorised scope." Wildcards such as `*.example.com` do **not** count |
| X5 | Permitted methods lack what the profile needs | "The authorisation does not permit the methods this profile needs." |
| X6 | Evidence changed after approval (new revision not accepted) | "The written evidence has not been accepted for the current authorisation revision." |
| X7 | Try to register a website with URL `http://127.0.0.1` or an IP address, and if registration accepts it, authorise it and try to assess | Either registration refuses it, or the assessment says "The website URL is not a supported public hostname for assessment." |
| X8 | Queue an assessment, then **revoke the authorisation before the worker runs it** | The job ends *cancelled*; the audit trail shows "permission denied" and **no network request** was made (this is the time-of-use re-check) |

### 6.2 Access control

| # | Action | Expect |
|---|---|---|
| R1 | With no login, call any `/api/v1/...` data route | `401` |
| R2 | Analyst opens a lead-only action (approve a report, close an assessment, enable port watch, VM housekeeping) | `403` |
| R3 | Deactivate an account, then use its old session | Refused |
| R4 | Check the page and the audit trail for secrets | No password, token or `.env` value appears anywhere |

### 6.3 Content safety

| # | Action | Expect |
|---|---|---|
| H1 | Put `<script>alert(1)</script>` in a note, finding comment or client name | It is stored and displayed as plain text; nothing executes |
| H2 | Look at any observation or evidence view | Remote text is clearly labelled untrusted and shown as text |

---

## 7. Azure VM checks (optional; real network use)

Only after the earlier sections pass. This changes files on the VM, so do it deliberately. Never expose Docker port 2375, never create paid resources and never delete existing containers, images or volumes.

1. Deploy the updated runners (see the "Scanner VM housekeeping" section of the README and `docs/NMAP_SCANNER.md`): copy the scanner directory with `scp`, back up the two installed runners on the VM, install `remote_runner.py` as `snwebshield-header-runner` and `scanner/nmap/runner.py` as `snwebshield-nmap-runner`.
2. On the VM, expect each of these to print JSON and not an error:

   ```bash
   /usr/local/libexec/snwebshield-header-runner --check
   /usr/local/libexec/snwebshield-nmap-runner --check
   /usr/local/libexec/snwebshield-header-runner --orphans
   /usr/local/libexec/snwebshield-nmap-runner --orphans
   ```

   `--orphans` should list no containers (`"orphans":[]`).
3. From Windows, with `ASSESSMENT_REMOTE_DOCKER_ENABLED=true` and the image ID set, restart the API and worker, then:

   ```powershell
   cd C:\SNWebShield-Local\backend
   .\.venv\Scripts\python.exe -m app.cli.scanner_check
   ```

   **Expect:** `passed: true`, `target_requests: 0`, `isolation_attested: true`, cleanup confirmed.
4. Run the **Azure header analysis** profile on your website from the Assessments page. **Expect:** completed, with the execution box showing container time, CPU, memory, cleanup *confirmed*, and "Container isolation: verified by the runner before start".
5. Press **Check VM for leftover containers**. **Expect:** "No leftover containers." for each scanner. It is read-only and removes nothing.

If a check fails closed (for example "container isolation mismatch"), that is the system protecting you. Stop and diagnose; do not weaken the check.

---

## 8. Nmap and port watch (real scans: be deliberate)

### 8.1 Nmap self-test on the VM's own ports

Set `ASSESSMENT_NMAP_ENABLED=true` and the image ID, restart the API and worker, then:

```powershell
.\.venv\Scripts\python.exe -m app.cli.nmap_check
```

**Expect:** `passed: true`, the two ports' states, `isolation_attested: true`, cleanup confirmed. This scans only the VM itself. **Do not enable port watch until this passes.**

### 8.2 Nmap on your website (restricted to TCP 80 and 443)

Needs: an authorisation that permits TCP port discovery **and** lists the website's public IPv4 address in its authorised domains, accepted by an analyst.

1. **Assessments**, profile *Nmap · restricted TCP ports 80 and 443*. If you are not permitted the page says exactly why.
2. Tick the attestation, **Run assessment**.
3. **Expect:** completed; TCP port observations for 80 and 443 (open, closed or filtered); the execution box; no vulnerability is created from port state alone.

### 8.3 Port watch (recurring checks)

Needs the **scheduler**, **assessment worker** and **notification dispatcher** running.

| # | Step | Expect |
|---|---|---|
| W1 | **Monitoring**, the *Port watch* panel at the bottom, choose the website | If Nmap is not permitted it shows the exact reason and the button stays disabled |
| W2 | Tick the attestation, choose an interval (start with *Every hour*), **Enable port watch** | "Port watch enabled." State *Active*. **Nothing** has been scanned yet; the first run comes at the next scheduler tick |
| W3 | Wait for the first run to finish | Last result "baseline"; "Last known state" shows ports 80 and 443. **No alert** is raised for the baseline |
| W4 | Next run with no change | Last result "unchanged" |
| W5 | (Only if the website owner really changes a port) next run | A **Port changes** entry such as "TCP 443: closed to open"; a notification; the lifecycle page's next step becomes "Port state changed" |
| W6 | Revoke the authorisation | At the next slot the watch becomes **Blocked** with the exact reason, **no scan runs**, and one audit event is written. Restore the authorisation and it resumes by itself |
| W7 | **Disable port watch** with a reason | State off; no more checks. Re-enabling starts a fresh baseline |

Check the VM afterwards with **Check VM for leftover containers**: there should be none.

---

## 9. Crash and restart recovery

These prove the system is safe if something dies.

| # | Action | Expect |
|---|---|---|
| K1 | While an assessment is *running*, close the assessment worker window | The run stays *running* until its lease expires (about two minutes). The page says the worker stopped. You can cancel it at any time |
| K2 | Start the worker again | The dead run is marked **failed** (never repeated automatically); the website can be assessed again |
| K3 | Start the worker with a completed but un-ingested report (only reproducible by stopping the worker exactly between result and ingestion) | On start the worker ingests it; observations appear unconfirmed. This is covered by an automated test; do not try to time it by hand |
| K4 | Stop the **scheduler** while port watch is enabled | Checks pause; they resume when the scheduler returns. No duplicate scans |
| K5 | Hang test: leave the worker alone for a few minutes | The status stays *Running*. If the worker ever hangs, the heartbeat stops and the page shows *Stale* |

---

## 10. Before a migration has been applied (for information)

If you run the new code against a database that is not yet migrated: the existing pages, monitoring and the scheduler keep working; the **Port watch** endpoints answer with a clear instruction to run `alembic upgrade head`. This is covered by `tests/test_unmigrated.py`.

---

## 11. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| "API offline" in the top bar | API not running or wrong port | Start Terminal 1; check `http://127.0.0.1:8000/api/v1/health` |
| Assessment worker "Not started" or "Stale" | Worker process not running | Run `scripts\start-workers.ps1` or the command shown on the page |
| A request stays *queued* | Worker down, or another run holds the pool | Start the worker; wait for the current run |
| "Permission: blocked" | See the reason on the page | Fix the authorisation (dates, domain, methods, evidence) |
| Run button disabled for a network profile | Attestation unticked | Tick the written-permission checkbox |
| Port watch panel says 503 / needs migration | Migration 0015 not applied | Back up, then `alembic upgrade head` |
| Monitoring will not enable | Consent expired or revoked, or evidence missing | Save a new monitoring configuration with valid evidence |
| Monitoring form: the "Reviewed permission document" list is empty | No document uploaded for an authorisation of the selected website, or the wrong website is selected, or the page has not reloaded since the upload | Follow the prerequisite at the start of section 5.1 |
| Monitoring says "First inspect and accept this document" | The document was accepted by a different account, or the evidence changed after it was accepted | Accept it again using the account that is saving the form |
| Azure profile fails closed | Runner or image mismatch, or isolation check failed | Run the VM `--check` commands; compare image IDs; do not disable checks |
| Nmap says the IP is not in scope | Public IPv4 not listed in the authorised domains | Add the IP to the authorisation (with written permission) and have it re-reviewed |
| `pytest` and `npm` crash together | Memory | Run them strictly one after another |
| Pages error right after pulling new code | Database behind the code | Back up, migrate, restart the API and workers |

---

## 12. Test record

Copy this table, mark each line **Pass**, **Fail** or **Skipped**, and add the date and tester. A Fail needs the exact message you saw (no secrets).

| Area | Tests | Result | Notes |
|---|---|---|---|
| Automated | 1.1 backend, 1.2 frontend, 1.3 build, 1.4 browser | | |
| Environment | S1 to S4 | | |
| Accounts | A1 to A6 | | |
| Authorisation | B1 to B4, N1 to N4 | | |
| Monitors | M1 to M5 | | |
| Detects | D1 to D10, C1 to C3 | | |
| Validates | V1 to V5 | | |
| Protects | P1 to P6 | | |
| Lifecycle | L1 to L4 | | |
| Permission refusals | X1 to X8 | | |
| Access and content | R1 to R4, H1 to H2 | | |
| Azure VM | Section 7 | | |
| Nmap and port watch | Section 8 | | |
| Recovery | K1 to K5 | | |

**Release rule of thumb:** do not rely on port watch or the Azure scanner until sections 7 and 8.1 pass on the real VM; everything else can be relied on once sections 1 to 6 pass.

---

## 13. Known limits

- The browser tests do not cover the second-person sign-off form, and monitoring cannot be configured without real consent evidence, so those parts need the manual steps above.
- Port-state changes raise an alert but have no acknowledge button; analysts review them through the assessment's port observations.
- Passive checks are limited to what one HEAD request and the TLS handshake reveal. They are not a full vulnerability scan, and every result needs human validation.
- No test here establishes that the platform has been independently penetration tested; it has not.

---

## Appendix A: permission letter template

Save as a PDF on company letterhead, sign it, and upload it as the evidence for the authorisation (section 4.2). Adjust the wording and dates; keep every item, because the reviewer must be able to verify the scope against it.

> **Authorisation for security monitoring and assessment**
>
> **Date:** (today's date)
> **Organisation (website owner):** SN IT Solutions (full legal name and address)
> **Signatory:** (full name, job title; must have authority over the website)
>
> I confirm that SN IT Solutions owns and controls the website below and authorises the security checks listed for the period stated.
>
> **Website and exact scope:** `www.snitsolutions.in` only. This authorisation does not cover any other host name, sub-domain or third-party service.
>
> **Permitted checks:**
> 1. Recurring availability, DNS and TLS certificate monitoring over HTTP and HTTPS (ports 80 and 443).
> 2. Automated non-intrusive security assessment: one HTTP HEAD request per assessment, response header analysis, TLS certificate and cookie attribute observations.
> 3. *(Only if you intend to test it, and only if the IP address is yours)* TCP port state checks of ports 80 and 443 on the server IP address `x.x.x.x`.
>
> **Not permitted:** exploitation, brute force, denial of service, authenticated testing, content crawling, or any check not listed above.
>
> **Valid from:** (date and time, UTC) **Valid until:** (date and time, UTC)
>
> **Contact for incidents during testing:** (name, email, phone)
>
> **Signature:** __________________ **Name and title:** __________________

**Reminder:** the permitted-methods and dates you enter in the app must match this letter, and the evidence reviewer must accept it before the authorisation can be approved.
