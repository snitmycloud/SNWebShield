# SNwebshield — Product Spec and Build Instructions

Read this whole file before starting. Then do ONLY the phase I name in my message. Do not start the next phase until I say so.

---

## 0. What SNwebshield is

SNwebshield is a self-service website security scanner for website owners, like Detectify or Intruder.

A user signs up, adds their websites, proves they own them, and SNwebshield automatically:

1. **MONITORS** — keeps watching each website and alerts on changes
2. **DETECTS** — finds open ports, services, versions and technologies
3. **IDENTIFIES** — finds vulnerabilities in what was detected
4. **REPORTS** — shows what was found, what version they have, what version they should have, how risky it is and how to fix it

**User flow:** Sign up → Add website → Verify ownership (about 1 minute) → Scan runs automatically → Dashboard + report

---

## 1. Rules for every task (always follow)

1. **Domain ownership verification is the ONLY approval step.** Remove and do not add: permission letters, attestations, evidence uploads, analyst approval, dual sign-off, profile pickers, extra checkboxes or confirmation dialogs.
2. **Every feature must solve a real problem for a website owner.** If you think something extra is needed, ask me first. Do not build it.
3. **Nothing to install on the server:** no Nmap, no Docker, no VM. Use Python's standard library (`asyncio`, `socket`, `ssl`, `http.client`, `dns` lookups via `socket`) and packages already in the project. If a new package is truly needed, ask me first.
4. **Plain language on every page.** Write "Your database port is open to the internet", not "TCP/3306 open".
5. **Fail safe:** if a check fails or times out, show "could not check" or "incomplete", never "safe" or "clean".
6. **Change only what the current phase needs.** Reuse existing working code where it fits.
7. **Every phase ends with proof** (see section 9). Do not claim something works without it.

---

## 2. Plans

| | Free | Pro | Business |
|---|---|---|---|
| Websites | **5** | 25 | 100 |
| Automatic scan | Weekly | Daily | Daily + on demand |
| Manual "Scan now" | 1 per website per day | 5 per day | 20 per day |
| Ports | Top 1,000 | Top 1,000 + full scan | Top 1,000 + full scan |
| Report | Online report | Online + PDF | Online + PDF + white-label |
| Alerts | Email | Email | Email + webhook (Slack) |
| Scan history | 30 days | 1 year | 2 years |

- Store plan limits in ONE config table or file so I can change numbers without code changes.
- Pro and Business prices are set later (Phase 7). Until then, every new account is Free, and an admin can change a user's plan manually.
- When a limit is reached, show a friendly message with an "Upgrade" button. Never show an error page.

---

## 3. Accounts

- Sign up with email + password and email verification. Log in, log out, forgot password, change password.
- Passwords hashed with a strong algorithm (bcrypt or argon2, whichever the project already uses). Rate-limit login and sign-up.
- Roles: **user** (normal customer) and **admin** (me). Admins see all users, can change plans and can disable accounts.
- Each user sees ONLY their own websites, scans and reports. Test this.

---

## 4. Add website + ownership verification

**Add website:** the user enters a domain (e.g. `www.snitsolutions.in`). Normalize it: strip `http://`, paths and trailing slashes, and lowercase it. Reject IP addresses, `localhost` and internal names.

**Verify (the user picks one method):**
- **DNS TXT:** add `snwebshield-verify=<token>` to the domain's DNS
- **File:** upload `https://<domain>/.well-known/snwebshield-<token>.txt` containing the token
- **Meta tag:** add `<meta name="snwebshield-verify" content="<token>">` to the homepage

- The token is random and unique per website per user.
- Clicking "Verify" checks immediately. On failure, show exactly what was found and what was expected.
- Re-check ownership before every scan (cache the result for 24 hours). If verification is lost, pause scans and tell the user how to fix it.
- Verifying `example.com` also covers its subdomains. Verifying `www.example.com` covers only that host.
- **As soon as verification succeeds, start the first scan automatically.**

**Remove the old permission system:** authorisations, written-permission attestations, evidence, approval states, dual sign-off and related pickers. Keep the database tables with a migration that marks them unused. Do not delete data.

---

## 5. Scan engine (Python only, runs in the existing worker)

### 5.1 Safety (fail closed)
- Scan only verified websites belonging to the user who owns the scan.
- Resolve the domain's IP once per scan, scan only that IP, and store it.
- Refuse private, loopback, link-local, multicast and cloud-metadata addresses (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, ::1, fc00::/7, fe80::/10), and the server's own IPs.
- At most 1 scan per website at a time and at most 3 scans on the server at once (both in settings).
- Every scan has a total time limit. Past it, the result is "incomplete".
- Audit log entry per scan: user, website, IP, scan type, start, end, result.

### 5.2 DETECT — ports and versions
- TCP connect scan with asyncio: top 1,000 ports (a fixed list in the code, the same list Nmap uses). On paid plans, an optional full scan of ports 1–65535.
- Limits: 100 connections at once, 1.5-second timeout per port, 300 ports per second, all in settings.
- Port states: open, closed, filtered.
- **Version detection on open ports** (3-second limit each, harmless probes only, never log in or send attack payloads):
  - Read the banner on connect (SSH, FTP, SMTP, POP3, IMAP, others)
  - HTTP(S): `HEAD /` and `GET /`, reading `Server`, `X-Powered-By` and other identifying headers
  - TLS: handshake on every open port, recording the TLS version, cipher, certificate subject, issuer and expiry
  - MySQL: version from the greeting packet
- Store per port: number, service, product, version (or "not disclosed"), banner (plain text, cut to 1 KB).

### 5.3 DETECT — technologies
- Fingerprint the website from headers, cookies, HTML `<meta name="generator">`, script and CSS paths, and known files.
- Keep the fingerprints in a JSON rule file (name, category, pattern, version regex) so I can add more. Start with: nginx, Apache, IIS, LiteSpeed, Cloudflare, PHP, ASP.NET, Node/Express, WordPress (+ version), Joomla, Drupal, Shopify, Wix, jQuery, Bootstrap, React, Angular, Vue, Lodash, Moment.js, Google Analytics.

### 5.4 DETECT — other
- **Subdomains:** from public certificate transparency logs (crt.sh). Only list them. Scan a subdomain only if it is covered by verification and the user adds it.
- **DNS/email security:** SPF, DMARC and DKIM (common selectors), CAA and MX present.
- **Exposed files:** check a fixed list (`/.git/HEAD`, `/.env`, `/backup.zip`, `/wp-config.php.bak`, `/phpinfo.php`, `/server-status`, `/.DS_Store`, admin login pages, directory listing). Confirm each by content signature, not just a 200 status, to avoid false alarms on "soft 404" pages.

### 5.5 IDENTIFY — vulnerabilities
- **Known vulnerabilities by version:**
  - Server software (nginx, Apache, OpenSSH, PHP, MySQL and others): look up CVEs from the NVD API by product and version. Cache the results in the database for 24 hours.
  - JavaScript libraries: look up with the OSV API (npm ecosystem).
  - WordPress core: check against known vulnerable versions.
  - Store per finding: CVE ID, CVSS score, severity, the affected version range and the first fixed version.
- **Configuration checks:**
  - Security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
  - TLS: old protocols (TLS 1.0/1.1), weak ciphers, a certificate expired or expiring within 30 days, hostname mismatch, self-signed
  - HTTP that doesn't redirect to HTTPS, mixed content
  - Cookies without Secure/HttpOnly/SameSite
  - CORS that allows any origin with credentials
  - Version shown in banners ("information disclosure")
- **Risky exposed services:** Telnet, FTP, database ports (3306, 5432, 1433, 27017, 6379, 9200), RDP, SMB, admin panels.
- **Only safe, read-only checks.** No SQL injection, XSS or other attack testing in this version.

**Severity:** Critical, High, Medium, Low, Info. Use the CVSS score where there is one, otherwise a rule table in code.

---

## 6. REPORT

For every finding, show:

| Field | Example |
|---|---|
| Title (plain language) | Outdated web server with known vulnerabilities |
| Where | `www.snitsolutions.in:443` |
| You have | nginx 1.18.0 |
| You should have | nginx 1.26.x or later |
| Risk | High (CVE-2021-23017, CVSS 7.7) |
| Why it matters | One or two plain sentences |
| How to fix | Clear steps and config snippets where useful |
| Status | Open / Fixed / Accepted risk |

- **Website report page:** security score, grade, summary counts by severity, then findings grouped by the four pillars, plus a "Technologies and versions" table (what they have vs latest or recommended).
- **"Re-scan to confirm fix":** re-runs only the checks for that finding. If it's resolved, mark it Fixed with the date.
- **Accepted risk:** the user can mark a finding as accepted with a reason. It's then excluded from the score but still listed.
- **PDF:** a print-ready HTML report page with print CSS, saved through the browser's "Save as PDF" (no new packages). Pro and above only.
- **Scan comparison:** show what is new, fixed or unchanged since the last scan.

---

## 7. MONITOR — dashboard and alerts

- **Dashboard (home after login):** one card per website with the score (0–100), grade (A–F), counts by severity, certificate expiry, last scan time, verification status and a "Scan now" button.
- **Score:** start at 100. Subtract per open finding: Critical 25, High 10, Medium 4, Low 1 (minimum 0). Grades: A 90+, B 75+, C 60+, D 40+, F below 40. Put the weights in settings.
- **Score trend** chart per website.
- **Uptime check:** every 5 minutes, HTTP status and response time. Alert if the site is down for 2 checks in a row.
- **Scheduled scans** by plan (weekly or daily), handled by the scheduler. A failing job type must not stop the others.
- **Alerts** (email, plus a webhook on Business): new open port, new Critical/High finding, certificate expiring within 14 days, site down/up, verification lost. Do not repeat the same alert more than once per 24 hours.
- **Workers and the scheduler must start automatically** and restart on crash (as a service / process manager). The admin page shows worker health.

---

## 8. Look and feel

- Modern, clean dark theme with a light theme option. One accent colour plus severity colours: Critical red, High orange, Medium yellow, Low blue, Info grey, Fixed green.
- **Navigation:** Dashboard · Websites · Monitor · Detect · Vulnerabilities · Reports · Settings (and Admin for admins).
- Every website page has four tabs: **Monitor · Detect · Vulnerabilities · Report**.
- No empty screens. Every empty state says what to do next (e.g. "Add your first website").
- Show live scan progress ("Scanning ports… 412 / 1000").
- Mobile-friendly and fast. Loading skeletons, not spinners everywhere.
- Plain-language text everywhere. Technical details go in an expandable "Technical details" section.

---

## 9. Phases and proof

Do one phase at a time. Each phase ends with:
1. Automated tests for the new logic, including refusal and safety cases
2. **A real run against `www.snitsolutions.in`** with screenshots or output of the result on the website
3. A list of anything not done or not verified
4. A commit to a branch with a clear message. Do not merge to `main` until I approve.

| Phase | Work | Done when |
|---|---|---|
| 1 | Accounts, plans config (Free = 5 websites), add website, ownership verification, remove the old permission system, auto first scan trigger | I can sign up, add snitsolutions.in, verify it, and a scan starts. A 6th website on Free shows the upgrade message. |
| 2 | DETECT: ports, versions, technologies, DNS/email, exposed files, subdomain list | The real scan shows open ports with versions and the technology list |
| 3 | IDENTIFY: CVE matching, configuration checks, severity | Real findings with CVE IDs and severities appear |
| 4 | REPORT: report page, fix re-scan, accepted risk, PDF, scan comparison | I can open the report, see "you have / you should have", and re-scan a fix |
| 5 | MONITOR: dashboard, score, trend, uptime, schedules, alerts, auto-start workers | After a server reboot everything runs, and I get a test alert email |
| 6 | Design polish across all pages | Every page follows section 8 |
| 7 | Payments (Razorpay for India; Stripe later) and plan upgrades | A test payment upgrades the plan and its limits apply |
