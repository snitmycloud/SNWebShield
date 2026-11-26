# SNWebShield technical audit matrix

| | |
|---|---|
| Audit date | 2026-11-24 |
| Branch | `feat/snwebshield-hardening` (created from `feature/local-http-assessments` @ `23c196e`) |
| Commits | `3ee099e` is the pre-existing uncommitted Module Dâ€“H work, committed unchanged as a baseline. The Milestone 1 hardening commit follows it. |
| Baseline before changes | 299 backend tests, 14 frontend unit tests, production build: all passing |
| After Milestone 1 | **393 backend tests, 17 frontend unit tests, 18 Chromium journeys, production build: all passing** |
| After Milestone 2 (Module E) | **430 backend tests, 22 frontend unit tests, production build: all passing** |
| After Milestone 3 (Module F) | **470 backend tests, 31 frontend unit tests, production build: all passing** |
| After Milestone 4 (Module G) | **501 backend tests, 40 frontend unit tests, production build: all passing** |
| After Milestone 5 (Module H) | **540 backend tests, 49 frontend unit tests, production build: all passing** |
| After Milestone 6 (production hardening) | **580 backend tests (incl. 39 in `test_production_hardening.py` and 1 end-to-end lifecycle test), 53 frontend unit tests, production build: all passing** |
| Database | Alembic head is `0013_production_hardening` after Milestone 6 (`0012_remediation_retesting` after Milestone 5). Pre-0013 backup: `backups/db-*-pre-0013/` (gitignored, integrity-checked). `0013` was applied to a **copy** of the development database and verified (data, triggers and `integrity_check` intact); the development database file itself is migrated by the operator with `python -m alembic upgrade head` (see Milestone 6 manual steps). |

## Self-service Phase 1 (branch `feat/phase1-self-service`, 2026-11-25)

Product direction changed to the self-service scanner in [SNWEBSHIELD_SPEC.md](SNWEBSHIELD_SPEC.md). Everything below this section describes the earlier analyst workflow, which is now **read-only** (staff can read; only stop actions work) and will be deleted after Phases 2â€“4 replace it.

| Spec item (Phase 1) | Status | Tests / proof |
|---|---|---|
| Sign up, email verification, log in/out, forgot/reset/change password; Argon2; rate-limited sign-up, login and account emails | âœ… | `test_accounts.py`, `test_auth.py`, `test_auth_claims.py`; real run screenshots 01â€“04 |
| Roles `user` / `admin`; admin lists users, changes plans, disables accounts (audited); customers refused by every staff route | âœ… | `test_accounts.py::test_admin_*`, `test_only_the_admin_role_manages_users`, `test_auth.py::test_customer_is_refused_by_every_staff_route` |
| Each user sees only their own websites and scans | âœ… | `test_websites.py::test_each_user_sees_only_their_own_websites`, `test_another_users_verified_parent_covers_nothing` |
| Plans in one file (`backend/app/plans.json`), Free = 5; friendly limit message with Upgrade button | âœ… | `test_websites.py::test_free_plan_allows_five_websites_*`, `test_plan_limits_are_read_from_the_config_file`; screenshot 07 |
| Add website: normalise, refuse IPs, `localhost`, internal names | âœ… | `test_websites.py::test_domain_normalisation`, `test_ip_addresses_localhost_and_internal_names_are_refused` |
| Verify by DNS TXT / file / meta; found vs expected; no-HTTPS â†’ use DNS; parent covers subdomains, `www.` covers only itself | âœ… | `test_ownership.py`, `test_websites.py`; screenshots 05â€“06b (real DNS and redirect results from snitsolutions.in) |
| Hardened ownership fetch: one vetted IP, pinned connection, certificate checked, same-host HTTPS redirects only, 256 KB cap | âœ… | `test_ownership.py::test_fetch_*` |
| Re-check ownership before each scan (24 h cache); lost â†’ scans paused; uncertain â†’ scan refused without declaring loss | âœ… | `test_ownership.py::test_*recheck*`, `test_scans.py::test_lost_verification_refuses_and_pauses` |
| Automatic first scan on successful verification | âœ… | `test_websites.py::test_successful_verification_starts_the_first_scan_automatically`; real run pending the owner's DNS record |
| Scan safety: resolve once, refuse private/loopback/link-local/multicast/CGNAT/metadata/own IPs, 1 per website (unique index), 3 per server, time limit â†’ incomplete, worker crash â†’ incomplete, audit per scan | âœ… | `test_scans.py` |
| Old permission system removed (authorisations, evidence, approvals, attestations, pickers, dual sign-off); tables kept and listed in `retired_tables` | âœ… | `test_auth.py::test_the_written_permission_api_is_gone`, `test_legacy_read_only.py`, `test_migrations.py::test_self_service_migration_*` |
| Remove website: typed-domain confirmation, owner only, verification deleted, queued scans deleted / running scan stopped, past scans + audit kept, `website_removed` audited, plan slot freed, domain can be re-added, nothing scans a removed site | âœ… | `test_website_removal.py` (20 tests), `test_migrations.py::test_website_removal_migration_*`; real run screenshots 11â€“14 |
| Approved test targets (branch `feat/phase2-test-targets`): fixed list `scanme.nmap.org`; admin accounts only; labelled "Test target"; 2 scans/day (shared, not resettable); every scan audited; list not changeable from app, API or `.env` | âœ… | `test_test_targets.py` (30 tests: users/analysts/leads refused, forged rows refused, demoted or disabled admin refused, no subdomain coverage, quota incl. remove/re-add and day rollover, audit flags, no route/env/assignment can change the list); 277 backend + 76 frontend tests |
| Scan checks (ports, versions, technologies) | âŒ Phase 2 | Phase 1 scans end "incomplete" by design |

**Migration `0017_website_removal`** (added `websites.removed_at`; the unique "owner + domain" rule now covers only websites that are not removed). Applied to the development database on 2026-11-25 after a verified backup (`%USERPROFILE%\SNWebShield-Backups\snwebshield-before-auth-correctness-20261125T125230773926Z.db`); counts unchanged, integrity OK.

**Migration `0016_self_service`.** Applied to the development database on 2026-11-25 after a verified backup (`%USERPROFILE%\SNWebShield-Backups\snwebshield-before-auth-correctness-20261125T123720495115Z.db`). All row counts unchanged; integrity check OK; `auth_events` append-only triggers re-created. Of the 4 legacy websites, 2 were given to the first admin account; the other 2 share a domain with those and stay staff-only legacy rows.

**Test results (2026-11-25, Windows, run sequentially).** Backend: **247 passed** (legacy analyst-pipeline suites are excluded via `collect_ignore` in `backend/tests/conftest.py` until that code is deleted). Frontend: **75 unit tests passed**; production build OK.

**Live checks (2026-11-25).** All five background roles (scheduler, monitoring worker, notifications, assessment worker, scan worker) and the API were restarted on the final code and their heartbeats are current. The development database has no port-watch rows, no queued legacy jobs, and no legacy request newer than 10:35 UTC (before Phase 1); the code paths that created them (`port_watch.schedule`, `AssessmentHandler.eligible`) are retired and tested.

**Pending item accepted by the owner (2026-11-25): the first real scan on `snitsolutions.in` is pending DNS access.** The owner confirms they own the domain, but the person with the DNS/hosting login is unavailable, and the verification TXT record was never visible on any resolver or on the authoritative nameservers (`ns1/ns2.md-in-40.webhostbox.net`). Until then `www.snitsolutions.in` stays **unverified** in the admin account (website #2), has **zero scans**, and must not be scanned or marked verified. To finish later: in that account add the bare `snitsolutions.in` (`www` is a CNAME, so a TXT record cannot live on it), add its TXT record, click Verify, and `www` is covered automatically; then capture the first-scan screenshots (numbered 15+). Phase 1 was accepted with this one item pending.

**Not done in Phase 1:** a running scan removed mid-way stops at its next step, so Phase 2's long checks must also re-check `removed_at` between steps; manual "Scan now" and scheduled scans (Phases 4â€“5); dark theme and the four website tabs (Phase 6); payments (Phase 7).

---

## Self-service Phase 2: DETECT (branch `feat/phase2-detect`, 2026-11-25)

| Spec item (Phase 2) | Status | Tests / proof |
|---|---|---|
| Fixed top-1000 Nmap port list (generated once from `nmap-services`, never downloaded at runtime), plus the risky ports Nmap's list omits: 6379 Redis and 27017 MongoDB (spec) and, added on review, 11211 Memcached, 2375/2376 Docker API, 5984 CouchDB, 5601 Kibana, 2379 etcd, 10250 kubelet, 15672 RabbitMQ management and 9300 Elasticsearch transport: 1,011 ports | âœ… | `test_detect_ports.py::test_the_fixed_port_lists`; generator `backend/tools/make_top_ports.py` |
| asyncio TCP connect scan: open / closed / filtered, 100 concurrent, 1.5 s per port, 300 ports/s, all in settings; unusual network errors are "could not check", never "no open ports" | âœ… | `test_detect_ports.py` (states, concurrency cap, rate, timeout, errors, cancel closes connections) |
| Version detection per open port (3 s each, harmless probes): banners, HEAD + GET, TLS handshake with version/cipher/certificate subject, issuer, expiry, MySQL greeting; "not disclosed"; cookie values never stored; 1 KB banners cleaned | âœ… | `test_detect_versions.py` (32, with real loopback SSH/MySQL/HTTP/TLS servers), `test_x509_lite.py` |
| Technology fingerprints from an editable JSON file; the 21 starter technologies with versions | âœ… | `test_detect_tech.py` (every starter technology, bad rules skipped, hostile pages) |
| DNS/email: SPF, DMARC, DKIM (common selectors), CAA, MX; lookup failure is "could not check", not "missing" | âœ… | `test_detect_dns_subdomains.py` |
| Subdomain list from crt.sh (list only, short timeout, hostile names rejected) | âœ… | `test_detect_dns_subdomains.py` |
| Exposed files: fixed list confirmed by content signature, soft-404 baseline, contents never stored | âœ… | `test_detect_exposed.py` |
| A step that fails or times out is "could not check"; a scan is "completed" only if every step finished, otherwise "incomplete" with reasons; nothing is ever shown as safe or clean | âœ… | `test_detect_pipeline.py`, `frontend/tests/detect.test.js` |
| **Long checks stop cleanly if the website is removed or verification is lost** (also: owner disabled, taken over, time limit, unreadable database fails closed) | âœ… | `test_scan_stops_cleanly.py` (12): removal and lost verification **during the port step and during the HTTP step**, each ending incomplete in < 4 s, all connections closed, nothing opened afterwards, partial results kept |
| "Scan now" with plans.json limits (Free 1/website/day, Pro 5, Business 20), scans left shown, friendly limit message, stricter shared test-target limit | âœ… | `test_scan_now.py` (17) |
| Full 1-65535 scan code path, Pro and above only, API only (no UI); Free refused; re-checked at run time; not allowed on test targets | âœ… | `test_scan_now.py::test_free_is_refused_a_full_scan_*`, `test_a_full_scan_is_refused_again_at_run_time_*` |
| Live progress ("Scanning portsâ€¦ 412 / 1002") and results panel in plain language | âœ… | real run screenshots 21â€“23 |

**Migration `0018_detect_results`** (adds `scan_ports`, `scan_technologies`, `scan_observations`; additive). Applied to the development database after a verified backup (`%USERPROFILE%\SNWebShield-Backups\snwebshield-before-auth-correctness-20261125T183035529464Z.db`); counts unchanged, integrity OK.

**Test results (2026-11-25/26, Windows, run alone).** Backend **422 passed** (about 16 minutes; no test reaches the internet: scan sockets are limited to loopback, real DNS and crt.sh are blocked). Frontend **86 unit tests passed**; production build OK.

**Real run (approved test target `scanme.nmap.org`, synthetic admin `phase2-admin@example.com`, screenshots and report in `docs/proof/phase2/`).** Scan 1 (the automatic first scan) finished in 31 s, status *completed*, ip 45.33.32.156: open 22 OpenSSH 6.6.1p1, 80 Apache 2.4.7, 9929 nping-echo (not identified); technologies Apache 2.4.7 and Google Analytics; DNS: SPF, DMARC, DKIM, CAA, MX not found; exposed: directory listing at `/images/`; no subdomains listed; every step `ok`; audited with `test_target: true`. Scan 2 (*Scan now*) was stopped by **removing the website at "Scanning portsâ€¦ 303 / 1002"**: it ended *incomplete* (`website_removed`, step `ports`) at the moment of removal, the worker's `scan_worker_stopped` event followed 0.04 s later, and the ports found before the stop (22, 80) were kept. Both of the test target's 2 daily scans (UTC) are now used.

**Phase 2 review follow-ups (2026-11-25/26).**
1. *Port 31337:* it is in Nmap's top 1000 (rank 931) and in the standard scan, and the real scan did attempt all of the ports it planned. Tests with a fake network now prove it is reported whenever it is open (`test_detect_ports.py::test_a_port_open_like_scanmes_31337_*`, and `test_detect_pipeline.py::test_the_standard_scan_reports_ports_open_like_scanmes_including_31337`, which runs the whole standard scan with the real port list). So the scanner logic is not the cause; the port either was not open or its answer did not reach this host (31337 is a classic "backdoor" port that routers, ISPs and security software often block; this machine's firewall rules could not be read without elevation). **Closed 2026-11-26: two real scans showed only 22, 80 and 9929; accepted as blocked on the path from this machine.**
2. *"Not checked yet" screenshot while a scan runs:* **done 2026-11-26: screenshot `docs/proof/phase3a/41-day2-scan2-running-not-checked-yet.png`.**
3. *Extra risky ports:* the risky ports from the spec that Nmap's top 1000 misses are **6379 Redis and 27017 MongoDB** (already approved); added on review: **11211 Memcached and 2375 Docker API**, then (owner decision, second review) **2376 Docker TLS, 5984 CouchDB, 5601 Kibana, 2379 etcd, 10250 kubelet, 15672 RabbitMQ management and 9300 Elasticsearch transport**, each with plain wording in the results panel. 9200 Elasticsearch and Telnet, FTP, MySQL, PostgreSQL, SQL Server, RDP and SMB are already in Nmap's list. The standard scan is now **1,011 ports**. Still not added (also missing from Nmap's list): 27018 MongoDB shard, 2181 ZooKeeper.
4. *Closed-port timing:* 1.5 s stays the default; the README states that the Windows dev host reports refusals late and the Linux production server will not.
5. *Full-scan time limit:* `SCAN_FULL_TIME_LIMIT_SECONDS` = 3600 (60 minutes); a standard scan keeps 900 (15 minutes). Used for the scan's lease and deadline; tested (`test_scan_stops_cleanly.py`: defaults, lease, and a standard scan stopping at its limit while a full scan runs on to its own).
6. *Test accounts:* `phase1-owner@example.com` (id 5) was cleaned on 2026-11-25 (log: `docs/proof/phase2/test-data-cleanup-log.md`). `phase2-admin@example.com` (id 6) was kept until the day-2 scanme scans were saved, and was **cleaned the same way on 2026-11-26** with `backend/tools/delete_test_account.py`. The account rows are kept as anonymized, disabled tombstones because `auth_events` is append-only. The owner's accounts 1-4 and website #2 were not touched.

**Not done / not verified, and known limitations**
- **First real scan of `snitsolutions.in` is still pending DNS access** (it stays unverified and unscanned).
- **Windows closed-port quirk (development host only):** this host takes about 2 s to report a refused connection, longer than the 1.5 s timeout (kept as the default), so closed ports are counted as "not answering" (999 "not answering", 0 "closed" in the real scan) and a standard scan takes about 15-30 s. Open ports are unaffected. The production server runs Linux, where refusals return immediately (stated in the README). `SCAN_PORT_TIMEOUT_SECONDS=2.5` classifies them exactly on Windows but slows scans.
- **A full 1-65535 scan was never run against a real target**, and on this host it would probably exceed the 15-minute time limit and end "incomplete" (about 64 ports/s). Only the plan gate and the port list are tested.
- scanme.nmap.org normally also has port 31337 open; the real scan did not report it. Not investigated (the port is in the list); the single scan available for the stop proof was spent as designed.
- The cutoff of Nmap's top 1000 is a frequency tie (the 1000th and 1001st ports share a frequency), so one port at the boundary may differ from Nmap's own choice.
- Only open ports are stored; closed and not-answering ports are counted in the scan result.
- After a removal the scan's per-step summary is not written (the removal writes the record immediately); the open ports found so far are kept in `scan_ports`. Stop time is bounded by the 1 s guard poll plus clean-up; the measured real stop was 0.04 s, and the tests show worst cases under 4 s.
- A crt.sh request in flight when a scan stops finishes in the background (6 s limit); it contacts crt.sh only, never the target.
- Rule patterns in `fingerprints.json` run on size-limited text with no regex timeout, so a pathological pattern added by an operator could be slow.
- DKIM only checks 15 common selectors; subdomains for a non-`www` host come from that exact host's certificates.
- IPv6-only websites and scans from a non-Windows host are untested.
- After the last live scan I fixed the results panel so a step that has not run reads "Not checked yet" instead of "nothing found" (unit-tested); it was **not re-screenshotted against a live scan** because the test target's daily limit was spent.

---

## Self-service Phase 3A: IDENTIFY (branch `feat/phase3a-identify`, 2026-11-26)

| Spec item (Phase 3A, as approved) | Status | Tests / proof |
|---|---|---|
| One finding format and one engine interface (Nuclei plugs in later with no change to runner, DB, API or UI); engines never raise, time out or hang the scan: a crash, timeout or bad result is "could not check" | ✅ | `test_findings_core.py` (12) |
| De-duplication across engines (same location + CVE or check id), sources unioned, stronger confidence and CVSS severity kept | ✅ | `test_findings_core.py` |
| Built-in checks: certificate expired / 7 d / 30 d / wrong name / self-signed / untrusted, TLS 1.0 and 1.1, weak ciphers, no HTTPS, no redirect, mixed content, six security headers, cookie flags (names only), CORS, version disclosure, risky ports, exposed files | ✅ (weak-cipher test cannot run on this Windows OpenSSL: reported as "not available", never a pass) | `test_engine_config.py` (37, incl. real local TLS servers) |
| Severity table (approved) in one file | ✅ | `app/data/severity_rules.py`; `test_engine_config.py` |
| NVD (servers, CMS) and OSV (npm libraries), name+version only, fixed hosts, public-address policy + pinned HTTPS, no redirects, 10 s timeout, 2 retries with Retry-After, 8 MB cap, rate limit, circuit breaker, 120 s scan budget; `NVD_API_KEY` optional, header only, never logged | ✅ | `test_vuln_sources.py` (22, fake database on loopback) |
| 24 h shared cache; stale data only adds findings (flagged with its date), never supports "none"; single flight; prune after 30 days; no scan or user data in it | ✅ | `test_vuln_cache.py` (9) |
| False-positive control: confirmed only if our comparator verifies the range, not a distro package (Ubuntu / Debian / Red Hat), not behind a proxy or CDN, not disputed, not AND-configuration; otherwise "possible" + how to check, never scored; rejected CVEs skipped; unscored = Medium + possible; max 50 per item; JS libraries and WordPress are never treated as distro packages | ✅ | `test_vuln_matching.py` (44) |
| Hidden version: Info finding "cannot check", never "safe" | ✅ | `test_vuln_matching.py`, `test_identify_pipeline.py` |
| End of life: High "No longer receives security updates" / Medium "Only paid extended support remains"; distro release judged, not the upstream branch; ambiguity rule (every candidate release must have ended); OpenSSH has no version cut-off; one finding per OS release or branch; stale-data (> 90 days) warning; data from endoflife.date, no network at scan time | ✅ | `test_eol.py` (26) |
| Whole scan: findings saved incrementally, groups and scoring in the API, cookie values never stored, owner-only access, only a name+version ever sent to NVD/OSV | ✅ | `test_identify_pipeline.py` (7) |
| **Stop cleanly while waiting on a slow NVD/OSV**: removal ends the scan incomplete within seconds, the wait is cancelled, findings found before the stop are kept | ✅ | `test_identify_pipeline.py::test_the_scan_stops_cleanly_while_waiting_for_a_slow_database` |
| Database failure fails safe: step "could not check", scan "incomplete", message "does not mean your website is safe" | ✅ | `test_identify_pipeline.py` |
| Migration `0019_findings` (`scan_findings`, `vuln_cache`), additive, existing rows unchanged | ✅ | `test_migrations.py` (new test) |
| Frontend: findings panel (severity order and colours, Needs checking, Good to know, Could not check, "No findings from these checks") | ✅ | `frontend/tests/findings.test.js` (8); screenshots pending the real scan |
| `docs/THIRD_PARTY.md` (NVD, OSV, endoflife.date MIT, crt.sh, Nmap services NPSL) | ✅ | `docs/THIRD_PARTY.md` |

**Verified against the real services (name + version only, no scan).** Every CPE name and OSV package in `cpe_map.json` was queried once: NVD answered 200 for OpenSSH 6.6.1p1 (54 CVEs), Apache 2.4.7 (138), nginx 1.18.0 (f5: 6; the old `nginx:nginx` name: 0), PHP 7.4.3, MySQL (both vendor names), MariaDB, ProFTPD, vsftpd (`vsftpd_project`: 3; `beasts`: 0), Exim, Postfix, Dovecot, lighttpd, WordPress, Tomcat, IIS and Sendmail; an unknown version returns 200 with 0 results (not an error). OSV answered for jQuery, lodash, moment, AngularJS, Bootstrap, Vue, React and @angular/core.

**Real run on the approved test target (2026-11-26 06:31 UTC, admin `phase2-admin@example.com`, 3A code, migration 0019 applied after a verified backup, screenshots and report in `docs/proof/phase3a/`).** Scan 1 (first scan) and scan 2 (*Scan now*), both IP 45.33.32.156, 39 s and 32 s: ports 22 OpenSSH 6.6.1p1, 80 Apache 2.4.7, 9929 (not identified); steps ports, versions, technologies, exposed, dns, configuration, vulnerabilities and lifecycle all `ok`; **subdomains `could_not_check` (crt.sh did not answer), so both scans ended *incomplete* (before subdomains became an optional step, see above) with the message "We could not finish these checks: subdomain list... It does not mean your website is safe."** Findings (identical in both): **2 High confirmed** (Ubuntu 14.04 no longer receives security updates; no HTTPS), **1 Medium** (directory listing at `/images/`), **3 Low** (CSP, X-Frame-Options, X-Content-Type-Options missing), Info items, and **100 "Needs checking" CVEs** (50 each for OpenSSH 6.6.1p1 and Apache 2.4.7, all `possible` because both banners say Ubuntu; **0 confirmed CVEs**), with the Ubuntu back-port explanation and the `apt changelog` command on each. NVD answered for both products (no API key, 2 look-ups, no failures). Both of today's test-target scans are used.
- **Port 31337 was not reported again** (3 open ports, 1,008 not answering, 0 errors). The scanner reports it whenever it is open (tests), so it was most likely closed or blocked on the path from this host; not something this scanner can distinguish.
- **"Not checked yet" while running: confirmed live** (`41-day2-scan2-running-not-checked-yet.png`: the Findings panel and every section read "Not checked yet" at "Scanning ports... 3 / 1011").
- **Two defects found by this real run and fixed afterwards** (the scans above predate the fixes; the daily limit is spent, so they are covered by tests, not re-scanned): (1) 100 cards made the page very long, so the screen now shows the 10 highest-scored "Needs checking" items and puts the rest behind "Show the other N"; (2) the cut-off at 50 per product was recorded on an arbitrary CVE, it is now its own Info line ("88 more known issues for Apache HTTP Server 2.4.7 are not listed", `test_vuln_matching.py`).
- `phase2-admin@example.com` (id 6) was cleaned the tombstone way after the proof was saved (`docs/proof/phase2/test-data-cleanup-log.md`, including 220 findings rows; `delete_test_account.py` now also removes `scan_findings`). Accounts 1-4 and website #2 (`www.snitsolutions.in`: unverified, 0 scans) were not touched. After the migration the app was checked: API and frontend up, login worked, the Phase 2 scans were intact (3 and 2 open ports kept).

**Core and optional steps (owner decision 2026-11-26).** A scan is "completed" only if every **core** step finished; any core failure or stop makes it "incomplete". An **optional** step depends on an outside service that is not part of the security results: if it cannot check, the scan still ends "completed", the step is still recorded as `could_not_check` (`result.optional_unavailable`), and the message adds: "Subdomain list unavailable right now (outside service didn't answer). This does not affect your security results." Stops (removal, lost verification, time limit) always end "incomplete".

| Step | Kind |
|---|---|
| Open ports, service versions, technologies, exposed files, email and DNS records | **core** |
| Security settings (TLS, headers, cookies, CORS, ports, exposed files), known vulnerabilities (NVD/OSV), end of life | **core** |
| Subdomain list (crt.sh) | **optional** |

Tests: `test_detect_pipeline.py` (optional step down: completed with the note; core step down: incomplete; both down: incomplete without the subdomain wording; vulnerability database down: incomplete; no problem: no note; exact core/optional lists), `frontend/tests/detect.test.js`.

**Item closed: port 31337.** Accepted as blocked or closed on the path from this machine (two real scans reported only 22, 80 and 9929; tests prove the scanner reports 31337 whenever it is open). No further action.

**Test results (2026-11-26, Windows, run one after another).** Backend **667 passed** in one full run (17 min 49 s, after the optional-step change and all fixes). Frontend **94 unit tests passed**; production build OK.

**Not done / not verified, and known limitations (Phase 3A)**
- **Weak-cipher check: to be verified on the Linux server.** On this Windows machine its OpenSSL has no weak cipher to offer, so the test is reported as "not available" (never a pass); its "accepted" path is only tested with a stubbed handshake.
- Nuclei and its safety layers are Phase 3B and start only after 3A is approved.
- The weak-cipher check cannot run on this Windows machine (its OpenSSL has no weak cipher to offer); it is listed as "not available" in the step details, and works where OpenSSL has them (expected on the Linux server). Its "accepted" path is tested with a stubbed handshake, not a real weak server.
- Joomla and Drupal versions are not matched yet; distribution release hints cover common Ubuntu, Debian and CentOS releases only (unknown versions give no end-of-life finding).
- The CPE-name approach can miss a CVE that NVD has not yet attached to a product name, and an NVD or OSV outage ends the scan "incomplete". Windows production is not planned.
- The proxy/CDN and "AND configuration" tests cover our rules; they are not validated against a large sample of real sites.

---

## Self-service Phase 3B: Nuclei (branch `feat/phase3b-nuclei`, 2026-11-26/27) - IN PROGRESS

| Spec item (Phase 3B, as approved) | Status | Tests / proof |
|---|---|---|
| Plug-in engine, off by default, optional step (a failure never makes a scan incomplete) | ✅ | `test_nuclei_runner_engine.py` |
| Pinned binary: version + SHA-256 in `engines.lock.json`, verified install, re-hash before every run, only the expected file extracted | ✅ | `test_nuclei_selftest_install.py`, `test_nuclei_runner_engine.py` |
| Vendored, hash-pinned template set (3,948 of 8,960; nuclei-templates v10.5.2, commit `5442582a`); an added, changed or missing file keeps the engine off; all 3,948 re-validated by a test | ✅ | `test_nuclei_mapping.py`, `test_nuclei_runner_engine.py` |
| Validator with the owner-approved rules (incl. xss, lfi, ssrf, xxe, ssti, oast + dast, fuzzing, default-login) and a strict YAML reader that fails closed (cross-checked: identical to PyYAML on 8,923 of 8,959 files, 36 refused, 0 different) | ✅ | `test_nuclei_validator.py` (106) |
| Egress proxy: CONNECT only to the verified host on 443, HTTP only on 80, pinned IP only, no name resolution, every allowed/refused connection logged, limits | ✅ | `test_egress_proxy.py` (39) |
| Runner: no shell, minimal environment, private working folder, kill of the whole process tree on stop / timeout / output cap | ✅ | `test_nuclei_runner_engine.py` |
| Technologies from templates go to the Technologies list (never findings), merged with built-in detection | ✅ | `test_nuclei_mapping.py`, `test_identify_pipeline.py` |
| Login/admin pages: ONE Info finding per website with the list inside; Medium only for sensitive panels (editable `sensitive_panels.json`) | ✅ | `test_nuclei_mapping.py`, `frontend/tests/findings.test.js` |
| Built-in login-page check: `/phpmyadmin/`, `/adminer.php` and `/adminer/` are their own Medium finding ("Database admin tool login page is reachable from the internet"), decided by the same editable `sensitive_panels.json`; other login pages stay Info | ✅ | `test_engine_config.py`, `test_detect_exposed.py`, `test_identify_pipeline.py` |
| Sensitive list trimmed to real network-device admin pages (pfSense, OPNsense, FortiGate, SonicWall, Sophos, MikroTik, Cisco ASA, ...); meeting, collaboration, email and voice apps (Cisco Webex, Unified CM, Finesse, FortiMail, ...) stay Info. Of the 1,545 vendored panel templates: 146 sensitive (router/firewall group 100 -> 70), 1,399 ordinary | ✅ | `test_nuclei_mapping.py` |
| Duplicates between built-in checks, NVD and Nuclei appear once with both sources | ✅ | `test_nuclei_runner_engine.py`, `test_identify_pipeline.py` |
| Self-test with the REAL binary: proxy containment and kill-on-stop | ✅ passed (2026-11-26, loopback canaries) | `python -m app.services.nuclei_selftest` |
| Self-test with the firewall rule present: **all 5 checks pass** with the REAL binary (binary hash and version, 3,948 templates re-validated, firewall rule active, proxy containment, kill on stop) | ✅ 2026-11-26 after the administrator created the rule | `docs/proof/phase3b/selftest-pass-with-firewall-rule.json` |
| Self-test with the rule REMOVED fails on the firewall check and the engine stays off (with NUCLEI_ENABLED on: `could_not_check`, `selftest_failed`, 0 findings, no run against the scan target, twice in a row) | ✅ 2026-11-26 after the administrator ran the undo script | `docs/proof/phase3b/selftest-fail-without-firewall-rule.json`, `test_nuclei_selftest_install.py` |
| Real scanme scan with built-in + Nuclei findings merged, and its proxy log | ⏳ after 05:30 on 2026-11-27 (daily limit) | |
| Full backend run, frontend tests and build for 3B | ⏳ at the end of 3B | |

**Known limits so far**
- The validator is strict, so some useful templates are not included, for example `phpmyadmin-panel` (payload list of paths) and `adminer-panel` (more than 8 requests). By owner decision the validator is NOT relaxed; the built-in login-page check covers phpMyAdmin and Adminer instead (Medium).
- Only the verified host on ports 80 and 443 is scanned by Nuclei (the proxy allows nothing else).
- Technology versions found by Nuclei are shown in the Technologies list but are not fed back into the NVD/OSV matching of the same scan.
- Linux: the firewall check looks for the `snwebshield-nuclei-egress` rule comment; this is written but **not verified** on a Linux host.

---

## Demo build (2026-11-26): manual verification, robustness, report (minimal Phase 4)

| Item | Status | Tests / proof |
|---|---|---|
| Test-target limit 10 scans per UTC day (constant in `config.py`, still not changeable from the app) | ✅ | `test_test_targets.py`, `test_scan_now.py` |
| Real scanme scan with Nuclei on: the proxy log shows ONLY scanme's pinned IP (160 allowed, 0 refused). Nuclei reached its 90 s cap with no findings and the scan took 4 min 38 s, so **Nuclei is OFF for the demo** (optional; default off). Self-test now runs once at worker start and a scan never waits for it | ✅ / ⚠️ | `docs/proof/phase3b/real-scan-proxy-log.jsonl` |
| Admin-only "Verify manually": typed reason (10-300 characters), 24 hours, label "Manually verified by admin", audit event `manual_verification` (admin, reason, time, owner), a scan in progress stops when it runs out; normal users, analysts and disabled admins get 403; a site verified by DNS/file/meta is never downgraded | ✅ | `test_manual_verification.py` (32) |
| Verification screen: numbered plain steps, copy buttons (code, file name, folder, address, TXT value, meta tag), "Check again"; file/meta checks follow an `example.com` <-> `www.example.com` redirect, check both and explain (loops, wrong host and non-www redirects are never followed) | ✅ | `test_manual_verification.py`, screenshots 04-06 |
| CDN/WAF detection (Cloudflare, Akamai, Fastly, CloudFront, Azure Front Door, Sucuri, Imperva, Vercel, Netlify, GitHub Pages, ...): "This site is behind <CDN>. Port results show the CDN, not your server."; versions seen through a CDN are only "possible" | ✅ | `test_robustness_report.py` |
| Blocking sites (403/429/challenge pages), hanging sites, HTTPS-only, HTTP-only, www/bare redirects, no open ports: plain-language notes, never a crash or a pass; IPv6-only is refused with "not supported yet" and nothing is contacted | ✅ | `test_robustness_report.py` |
| Scan time for a normal site: real scanme scan **43 seconds** (Nuclei off); vulnerability budget 90 s; partial results appear after every item and progress names the software being checked | ✅ | screenshots 10-11 |
| Score and grade (spec section 7: 100 minus 25/10/4/1 per confirmed Critical/High/Medium/Low, A 90+, B 75+, C 60+, D 40+, F; weights in settings; needs-checking and Info never count; incomplete scans marked) | ✅ | `test_robustness_report.py`, `frontend/tests/report.test.js` |
| Report page per website: score, grade, counts, Confirmed / Needs checking with Where, You have, You should have, Risk, Why it matters, How to fix; print stylesheet and "Download PDF" (the browser's Save as PDF); score on the dashboard card; four tabs Monitor, Detect, Vulnerabilities, Report | ✅ | screenshots 12-17, `report-scanme.pdf` |
| No browser console errors, warnings or failed requests during the walkthrough; a page that fails to draw shows a plain message (error boundary) | ✅ | `docs/proof/demo/console-problems.txt` ("none") |
| `docs/DEMO_SCRIPT.md`, `scripts/start-demo.ps1`, `scripts/stop-demo.ps1` | ✅ | |

**Not done / not verified**
- Skipped by instruction: re-scan to confirm a fix, accepted risk, scan comparison, alerts, schedules, payments, uptime checks, score trend.
- The manual-verification button was exercised by tests and the form was screenshotted, but **not submitted live** (that would start a scan of a site we are not allowed to scan); it is to be shown on the GitHub Pages test site once its domain is known.
- The PDF button uses the browser's print dialog and is available to every plan (the spec says Pro and above; not gated yet).
- Real-world CDN behaviour was tested with header fixtures, not against live Cloudflare/Akamai sites.
- Vulnerability look-ups without an NVD key are slow when several products are found (5 requests per 30 s); results appear as they arrive.
- Nuclei: see Phase 3B; it is off for the demo.

---

## Nuclei speed (branch `feat/nuclei-speed`, 2026-11-27)

| Item | Status | Tests / proof |
|---|---|---|
| Why only 160 requests in 4 min 38 s: **measured, not guessed.** The egress proxy handles 50 parallel connections in 0.05 s (not the cause); a slow response is not the cause (`-timeout 2` changed nothing); throughput was exactly concurrency / 5 s. Cause: Nuclei's own DNS look-ups are blocked by the firewall rule (the second safety layer) and each waited about 5 s. Fix: a loopback-only resolver file plus `-sr` (system resolver fallback): 2.0 -> **21.9 requests per second** (11 times). Per-request timeout 10 -> 5 s, retries 0 | ✅ | `docs/proof/nuclei-speed/measurements.md`, `test_nuclei_quick.py` |
| **Quick** set for normal scans: all exposures (466) and misconfiguration (814) templates, the 146 sensitive panels, and CVE templates whose tags/product match software we detected (highest severity first, capped at 300) = 1,426 + CVEs; run limit 100 s | ✅ | `test_nuclei_quick.py` |
| **Deep** set: all 3,948 templates, 600 s limit; selected only when the scan type is `deep` (scheduled deep scans, Phase 5, Pro and above). Not reachable from the app yet | ✅ (code and tests) | `test_nuclei_quick.py` |
| Real scanme scan with Quick: Nuclei step **99.4 s**, 1,435 templates, **1,778 requests**, whole scan 146 s; proxy log: 1,778 allowed to `scanme.nmap.org:80` at **45.33.32.156 only**, 2 refused (ports 9001 and 4040); Nuclei contributed "HTTP Missing Security Headers" (Info) | ✅ | `docs/proof/nuclei-speed/` |
| **Repository bug found and fixed:** 4 vendored templates under `http/exposures/backups/` were silently excluded by `.gitignore` (`backups/`), so `main` at `5936e74` was missing them (a fresh clone would have kept the engine off, fail-closed). They were re-fetched from the pinned tag, accepted only because their SHA-256 equals the manifest, the folder is now un-ignored, and a test checks every manifest template is tracked and not ignored | ✅ | `test_nuclei_quick.py::test_every_vendored_template_is_tracked_by_git_not_ignored` |
| Plan setting `pdf_report` in `plans.json` (true for every plan for now; the Download PDF button follows it; limits to be decided in Phase 7) | ✅ | `test_pdf_plan_setting.py`, `frontend/tests/report.test.js` |
| **Parallel Nuclei:** an engine marked `parallel` starts first and runs alongside the vulnerability (NVD/OSV) and end-of-life steps; its results are merged when it finishes; a stop cancels it and keeps what the others found; Quick limit raised to **180 s** | ✅ | `test_parallel_engines.py` (7) |
| **DNS reliability:** SPF/DMARC/DKIM/CAA/MX look-ups make up to 3 attempts of 2.5 s (this machine's resolver, then a SECOND resolver set `1.1.1.1,9.9.9.9` (plain DNS, setting `SCAN_DNS_FALLBACK_RESOLVERS`, empty = off), then this machine's again); a clean "no such record" is never retried; DKIM stops after 3 failures in a row and then says "could not check", never "missing". Only after that does the step, and the scan, become incomplete | ✅ | `test_detect_dns_subdomains.py` (+13) |
| One retry for single-request web probes (CORS, TLS protocol, weak cipher, certificate trust) before "could not check" | ✅ | `test_engine_config.py` |
| **Fresh-clone check** `scripts\fresh-clone-check.ps1`: no uncommitted changes, nothing needed hidden by `.gitignore`, fresh `git clone`, new venv + `pip install`, Nuclei manifest check (all templates present, hashes equal, both platforms pinned, all tracked), backend tests, `npm ci`, `npm test`, `npm run build`; exit code 0 only if all pass. Run it before every release (`-Fast -SkipFrontend` takes about 12 minutes) | ✅ | script; first quick run caught a stale test |
| **Nuclei ON by default in development** (`NUCLEI_ENABLED=true`; the test suite forces `false`). It still runs only while its self-test passes; a missing binary means a quiet "skipped" (no note); a self-test still starting at worker start-up means skipped for that scan | ✅ | `test_nuclei_runner_engine.py` |
| Real scanme scan with the final settings: **completed in 150 s (2 min 30 s)**; Nuclei 105 s, 1,778 requests, proxy log shows only 45.33.32.156 | ✅ | `docs/proof/nuclei-speed/parallel-scan-*` |
| Two shutdown bugs found by timing the self-test (132 s, now 16 s): `EgressProxy.stop()` and the canary server waited for a hung connection before cancelling it | ✅ | `test_egress_proxy.py`, `test_nuclei_selftest_install.py` |
| The self-test no longer re-parses all 3,948 templates (the manifest hash check proves none changed; a test re-validates them all) | ✅ | |

**Not done / not verified:** the Quick run finishes just inside its 100 s limit on scanme (about 18 requests per second); a slower site is cut off at 100 s and reported as "did not finish" (optional step, other results unaffected). On Linux the resolver fallback goes through the system resolver of the Nuclei user, which the Linux firewall rule may also block (unverified). The Quick set does not include ordinary login-page templates or technology detection (the built-in checks cover those); both are in Deep.

---

**Status legend.** âœ… Fully implemented and tested Â· ðŸŸ¡ Partially implemented Â· ðŸ§ª Implemented but not tested Â· âŒ Missing Â· ðŸ”§ Broken or requiring improvement

Test paths are relative to `backend/tests/`. Milestone 6 tests are in `test_production_hardening.py` (`H::` below) and `test_e2e_lifecycle.py` (`E2E::`). Module E and F test names below are real function names in `test_vulnerabilities.py` and `test_workbench.py`. Browser journeys are in `frontend/tests/e2e/authorization.spec.js`. All API routes are under `/api/v1`.

---

## Final module status (after Milestone 6)

| Module | Final status | Primary test references (all passing) |
|---|---|---|
| A. Application foundation | âœ… Complete. Auth audit, throttling, server-side logout, role-bound JWTs, password policy, security headers and strict CORS closed in M6 | `test_auth.py`, `test_auth_claims.py`, `test_api.py`, `test_migrations.py`, `test_production_hardening.py` (R1â€“R3, headers, CORS, roles) |
| B. Authorisation and evidence | âœ… Complete. Retention checks, overwrite-then-unlink purge and immutable evidence hashes added in M6 (limits stated in the B table) | `test_evidence.py`, `test_authorization_correctness.py`, `test_production_hardening.py` (retention and purge) |
| C. Website monitoring | âœ… Complete | `test_monitoring.py`, `test_monitor_probe.py`, `test_monitor_http_fixture.py`, `test_e2e_lifecycle.py` (monitoring step) |
| D. Scanner worker | âœ… Complete in code. The installed VM runner still needs its manual redeploy (R4) and real-target acceptance is a user step (R12) | `test_assessments.py`, `test_scanner_hardening.py`, `test_local_assessment.py`, `test_remote_assessment.py`, `test_nmap.py`, `test_e2e_lifecycle.py` |
| E. Vulnerability management | âœ… Complete | `test_vulnerabilities.py`, `test_e2e_lifecycle.py` |
| F. Analyst workbench | âœ… Complete. Roles and optional dual sign-off added in M6 | `test_workbench.py`, `test_production_hardening.py` (dual sign-off) |
| G. VAPT reporting | âœ… Complete. Report approval now needs a senior role and, with dual sign-off, a second person | `test_reports.py`, `test_production_hardening.py`, `test_e2e_lifecycle.py` |
| H. Remediation, retesting and closure | âœ… Complete. Closed-assessment lock and formal reopening added in M6 | `test_remediation.py`, `test_production_hardening.py` (lock, reopen, generations), `test_e2e_lifecycle.py` |

Risks R1â€“R15 are listed with their final status and test reference in the [risk register](#risk-register-final-status-after-milestone-6) below. Open items are R4 and R5 and R12 (manual user steps), R6 and R8 (not built), R11 and R13 (accepted); R15 is partly mitigated.

---

## A. Application foundation

| Sub-feature | Status | Evidence |
|---|---|---|
| React dashboard | âœ… | `frontend/src/App.jsx`, page components; 18 Playwright journeys; `npm run build` passes |
| FastAPI backend | âœ… | `backend/app/main.py`, `GET /health` (`test_api.py::test_health_endpoint`) |
| Admin authentication | âœ… | `POST /auth/login`, `GET /auth/me` (`api/routes/auth.py`); bcrypt plus constant-time unknown-user check; `test_auth.py` |
| JWT | âœ… | `core/security.py`: `iss`, `aud`, `nbf`, `exp` and `jti` required; 20-minute default; HS256 with a â‰¥32-byte secret that is checked at use. **M6:** the `role` claim must be a known role **and equal the account's current role** (a token minted before a promotion or demotion is refused); a revoked `jti` is refused. `test_auth_claims.py`; `H::test_revoked_entries_expire_and_a_stale_role_claim_is_rejected`, `H::test_forged_unknown_role_and_wrong_signature_tokens_are_rejected` |
| Logout / session expiry | âœ… | Client-side idle timer and expiry (`api.test.js`, e2e "idle token expiry"). **M6 (R3):** `POST /auth/logout` writes the token's `jti` to `revoked_tokens`; it is refused everywhere afterwards while other sessions of the same account stay valid, and entries are pruned once past expiry. The UI calls it through `api.signOut()`. `H::test_logout_revokes_only_the_presented_token_and_is_audited`; frontend `signOut clears the browser session firstâ€¦`, `signOut still signs the person out when the server cannot be reached` |
| Authentication audit logging | âœ… | **M6 (R1):** append-only `auth_events` (`login_success`, `login_failure`, `login_inactive`, `login_throttled`, `logout`) with UTC time, account id, TCP peer address and a SHA-256 of the email; never a password, token or raw email. ORM guards plus SQLite triggers. `H::test_login_outcomes_are_audited_without_passwords_tokens_or_raw_emails`, `H::test_auth_events_are_append_only_in_orm_and_database` |
| Login brute-force protection | âœ… | **M6 (R2):** durable, restart-safe throttling from recent `login_failure` events: 5 failures per email and address, 20 per email from anywhere, 20 per address (15-minute sliding window, configurable). A locked login returns 429 with `Retry-After`, even for the correct password, and computes no hash. A successful login resets the email's count. `H::test_repeated_failures_lock_the_login_even_for_the_correct_password`, `H::test_lock_lifts_after_the_window_and_other_accounts_are_unaffected`, `H::test_a_successful_login_resets_the_failure_count`, `H::test_credential_stuffing_from_one_address_is_throttled` |
| Password policy and hashing | âœ… | Argon2id with the library's current parameters; hashes with outdated parameters are upgraded transparently on login. `app.cli.create_admin` enforces 12â€“128 characters, three character classes, no common or repetitive passwords and no email name. `H::test_password_policy`, `H::test_password_hash_uses_argon2id_and_old_hashes_are_upgraded_on_login` |
| HTTP security headers | âœ… | **M6:** pure-ASGI `SecurityHeadersMiddleware` adds `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'â€¦`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Resource-Policy` and `Cache-Control: no-store` on every API response (success, error and CORS preflight); `Strict-Transport-Security` only when the request truly arrived over TLS (a forwarded-proto header is never trusted). Route-set headers such as the evidence-download CSP are not overwritten; the Swagger pages `/docs` and `/redoc` get no CSP so they keep working. `H::test_security_headers_on_success_error_and_preflight_responses`, `H::test_hsts_only_over_https_and_never_from_a_forwarded_header`, `H::test_evidence_downloads_keep_their_stricter_route_headers` |
| Strict CORS | âœ… | **M6:** `CORS_ORIGINS` is validated at start-up (http(s) origins only; no `*`, paths or schemes such as `javascript:`), methods are `GET`, `POST`, `OPTIONS` and headers are an allow-list. `H::test_cors_only_trusts_configured_origins_and_rejects_unsafe_configuration` |
| Client and website management | ðŸŸ¡ | Create, list and get only: `POST/GET /clients`, `POST/GET /websites` (`test_api.py`). No update, archive or delete, and no UI form to create authorisations. |
| DB models / migrations | âœ… | `app/models/*`, Alembic `0001`â€“`0013`; `test_migrations.py` (fresh, legacy adoption, partial-schema refusal, data preservation) |
| API protection | âœ… | Router-level `Depends(get_current_admin)` (and the role allow-lists below); unauthenticated tests in `test_auth.py`, `test_assessments.py::test_authentication_and_pagination`, `test_findings.py`, `test_evidence.py` |

## B. Authorisation and evidence management

| Sub-feature | Status | Evidence |
|---|---|---|
| Written permission and exact domain scope | âœ… | `models/authorization.py` (`authorized_domains`, `permitted_methods`); `schemas/authorization.py` (normalisation, duplicates, registered host required); `test_api.py` |
| UTC validity and approval states | âœ… | `timestamps_verified`, effective states; `test_authorization_correctness.py` (offsets, boundaries, legacy block, concurrent decisions) |
| Private document upload and validation | âœ… | `POST /authorizations/{id}/evidence`; PDF/PNG/JPEG signature check, active-content PDF rejection, size limit; `test_evidence.py` |
| SHA-256 hashes and authenticated downloads | âœ… | `GET /evidence/{key}/{operation}`; tamper detection blocks approval (`test_hash_tampering_blocks_approval`) |
| Human evidence review | âœ… | `POST /authorizations/{id}/evidence/reviews`; reviewer-bound and revision-bound (`test_review_is_bound_to_reviewerâ€¦`, `test_changed_revisionâ€¦`) |
| Approval, rejection, revocation and audit history | âœ… | `POST /authorizations/{id}/approve|reject|revoke`, `GET â€¦/events`; `AuthorizationAuditEvent`; revocation cancels queued and running assessments (`assessments.cancel_for_authorization`) |
| Retention and secure deletion | âœ… (with stated limits) | `retain_until`, legal hold, `POST /evidence/{key}/purge` with retry (`test_retention_hold_and_purgeâ€¦`, `test_purge_failureâ€¦`). **M6 (R9):** retention is re-checked against UTC now on every purge (retention running, legal hold, approved authorisation and un-withdrawn documents each block it); the stored file is **overwritten with random bytes, flushed to disk, then unlinked** (`secure_erase`, regular files only, symlinks refused); the row, SHA-256, `purged_at` and `purge_method` are kept as the immutable audit proof, and the purge event records the retained hash. SQLite triggers and ORM guards make a document's identity and hash immutable, forbid deleting it, make `purged` final and make `evidence_events` append-only. `python -m app.cli.evidence_retention` reports expired documents and what blocks each (it deletes nothing; a human purges with a reason). `H::test_purge_overwrites_the_file_then_unlinks_and_keeps_the_audit_hash`, `H::test_purge_is_refused_during_retention_legal_hold_or_active_approval`, `H::test_retention_report_lists_expired_documents_with_blockers_and_deletes_nothing`, `H::test_secure_erase_handles_missing_and_special_files`, `H::test_evidence_identity_hash_and_history_are_immutable_in_orm_and_database`. **Limit:** overwrite-in-place is best effort on SSDs and journaling or copy-on-write filesystems, so keep the evidence volume encrypted (BitLocker); the purge is still operator-initiated, not scheduled. |

## C. Website monitoring

| Sub-feature | Status | Evidence |
|---|---|---|
| Explicit monitoring consent | âœ… | `MonitoringConsent`, `POST /websites/{id}/monitoring/configure`, `revoke-consent`; `test_monitoring.py::test_explicit_enableâ€¦`, e2e "monitoring requires separate consent" |
| HTTP/HTTPS availability, response time, DNS, TLS expiry | âœ… | `services/monitor_probe.py`; `test_monitor_probe.py` (pinned IP and SNI, TLS failure, near-expiry degraded, DNS failure) |
| Scheduling and background execution | âœ… | `job_engine.py`, `cli/operations.py` (`scheduler`, `worker`); `test_due_enqueue_competitionâ€¦`, `test_worker_hard_deadlineâ€¦` |
| History, incidents, alerts and recovery | âœ… | `MonitoringIncident`, `NotificationDelivery` (dashboard or SMTP); `test_retry_incident_recoveryâ€¦`, `test_smtp_*` |

## D. Security scanner worker (Milestone 1 scope)

| Sub-feature | Status | Evidence |
|---|---|---|
| Assessment job creation and lifecycle | âœ… | `POST/GET /assessments`, `GET /assessments/{id}`, `/{collection}`; `AssessmentRequest`, `Job`, `JobAttempt`, `JobResult`; `test_assessments.py` (idempotency, one active job per site, concurrent claims) |
| Authorisation and exact-scope revalidation | âœ… | `assessments.permission()` runs at request, at claim (`still_permitted`), continuously during execution, and again under lock in `finish()`. **M1 tests:** `test_scanner_hardening.py::test_remote_job_revalidated_before_any_ssh` (revoked, expired, not-yet-valid, scope, method, evidence, requester), `::test_revocation_during_remote_runâ€¦` |
| Trusted network broker | âœ… | `services/assessment_broker.py`: one HEAD, one connection, no retry, no body, header allowlist, Windows Job Object limits. **M1:** TLS â‰¥ 1.2, TLS version telemetry |
| DNS/IP validation, SSRF and rebinding protection | âœ… | `monitor_probe.resolve` rejects any non-global or special answer, including mixed answers; the connection is pinned to the resolved IP and the peer is checked. **M1 tests:** 21 prohibited ranges (incl. `169.254.169.254`, CGNAT, NAT64, ULA, `::ffff:127.0.0.1`), unsafe URLs rejected before DNS, single resolution with a rebinding second answer never used, revocation after DNS prevents connect |
| Safe redirect handling | âœ… | **M1:** `classify_redirect` gives a fixed category, never follows, never stores `Location`. Real-socket tests show one request only and no target text persisted. |
| HTTP HEAD assessment | âœ… | `test_local_assessment.py::test_real_head_never_follows_redirect_or_saves_headers` |
| Python security-header analysis | âœ… | `services/header_analyzer.py` (pure, bounded input); `test_analyzer_rejects_unselected_or_unbounded_data`; remote output must equal the local recomputation |
| SSH Docker on `azureuser@57.159.27.58` | âœ… | **M1:** `services/ssh_transport.py` (pinned binary, hardened options, fixed runners). Live `app.cli.scanner_check` passed on 2026-11-24 (cleanup confirmed, 0 target requests). |
| Container isolation (`--network none`, non-root, read-only, CPU/RAM/PID/timeout) | âœ… / ðŸ”§ | `scanner/remote_runner.py::create_args`; previously live-verified by `scanner/verify_host.py`. **M1:** `--ipc=none` and per-run `verify_isolation` (refuses to start on any mismatch); 16 weakening cases tested. ðŸ”§ The **installed** VM runner predates this and reports `isolation_attested: false` until redeployed (manual step below). |
| Resource and duration telemetry | âœ… | `validate_execution` whitelists duration, CPU and peak RSS; `remote_docker_execution_finished` event; shown on the dashboard |
| Cancellation | âœ… | `POST /assessments/{id}/cancel`; permission polled every 100 ms; SSH process killed; targeted cleanup. **M1:** real-process cancellation and deadline tests |
| Structured JSON results and audit logs | âœ… | `AssessmentReport` (SHA-256, 32 KiB cap), `ExecutionEvent` |
| No host fallback | âœ… | **M1:** `test_worker_fails_closed_when_ssh_or_docker_unavailable` (client missing, unreachable, Docker down, wrong runner) asserts no HEAD and no local adapter |
| Lease vs execution budget | âœ… | **M1:** per-handler lease (assessment 120 s â‰¥ worst-case 55 s + 30 s margin); `test_assessment_lease_exceeds_every_bounded_remote_budget` |
| Restricted Nmap (TCP 80/443) | âœ… | `nmap_*` services, `scanner/nmap/*`; `test_nmap.py`. Now shares the hardened SSH transport. |

## E. Vulnerability management (Milestone 2: complete)

Service functions are in `backend/app/services/vulnerabilities.py`, routes in `backend/app/api/routes/vulnerabilities.py`, models in `backend/app/models/vulnerability.py`.

| Sub-feature | Status | Evidence |
|---|---|---|
| Normalised finding records | âœ… | `Vulnerability` with unique `fingerprint` per website, check and target (`fingerprint()`, `_record()`, migration `0009_vulnerabilities`); `GET /vulnerabilities`, `GET /vulnerabilities/{id}` (`listing()`, `detail()`). Tests: `test_completed_assessment_ingests_unconfirmed_normalised_records`, `test_secure_response_creates_no_records`, `test_listing_filters_counts_and_ordering` |
| Safe ingestion of untrusted scanner output | âœ… | `parse_observation()` (fixed vocabulary, strict booleans), `ingest_report()` (report SHA-256 re-check via `report_intact()`, 64-observation cap), `ingest_one()`, `ingest_pending()`. Tests: `test_untrusted_or_non_applicable_observations_are_not_ingested`, `test_hostile_report_cannot_confirm_or_inject_checks`, `test_oversized_observation_list_rejected`, `test_tampered_report_is_rejected_audited_and_left_pending`, `test_backfill_is_idempotent`, `test_ingestion_failure_never_loses_scanner_result`, `test_port_inventory_reports_are_marked_but_not_ingested` |
| Severity and confidence | âœ… | `scanner_severity`, `analyst_severity`, `score()` (explainable `confidence_factors`). Tests: `test_confidence_scoring_is_deterministic_and_bounded`, `test_later_pass_is_recorded_lowers_confidence_and_never_auto_closes` |
| Evidence and reproduction steps | âœ… | `VulnerabilityOccurrence` with `evidence` and `evidence_sha256` (`evidence()`); `reproduction()` and `safe_url()`; `occurrences()`. Tests: `test_reproduction_command_is_shell_inert`, `test_completed_assessment_ingests_unconfirmed_normalised_records` |
| Duplicate detection | âœ… | Fingerprint dedup across assessments and profiles with `detection_count`, `not_detected_count`, first/last seen. Test: `test_deduplicates_across_assessments_and_profiles` |
| False-positive management | âœ… | `decide()` creates `VulnerabilitySuppression` (future, at most 365 days); redetection reopens after expiry. Tests: `test_false_positive_suppression_carries_forward_then_expires`, `test_suppression_expiry_must_be_future_and_bounded`, `test_dismissal_needs_timezone_aware_expiry`, `test_reopen_revokes_suppression` |
| Human validation and analyst comments | âœ… | `decide()` (`TRANSITIONS`, `expected_revision`, intact-source check), `comment()`, `events()`; `POST /vulnerabilities/{id}/validation`, `/comments`. Tests: `test_confirmation_requires_attested_analyst_decision`, `test_confirmation_requires_intact_source_evidence`, `test_comments_and_history_are_append_only`. **Milestone 3 tightened this:** confirmation now also needs a saved risk assessment (see F). |
| Authentication and unknown records | âœ… | Router-level `get_current_admin`. Test: `test_authentication_and_unknown_records` |
| Frontend | âœ… | `VulnerabilitiesPage.jsx`, `lib/vulnerabilities.js`; `tests/vulnerabilities.test.js` |

## F. Security analyst workbench (Milestone 3: complete)

Service functions are in `backend/app/services/vulnerabilities.py` (extended, not rebuilt), routes in `backend/app/api/routes/workbench.py` (`/api/v1/workbench`), the role gate in `backend/app/core/rbac.py`, migration `0010_analyst_workbench`, UI in `frontend/src/WorkbenchPage.jsx` and `frontend/src/lib/workbench.js`.

| Sub-feature | Status | Evidence |
|---|---|---|
| Manual finding validation and review queue | âœ… | `GET /workbench/queue` (`queue()`): stages `needs_assessment`, `ready_for_signoff`, `report_eligible`, `dismissed`, `all`, with severity, website and search filters and per-stage counts. Test: `test_review_queue_stages_filters_and_counts` |
| Risk and business-impact assessment | âœ… | `POST /workbench/{id}/assessment` (`save_assessment()`): likelihood x business impact matrix (`calculate_rating()`), analyst override only with a recorded reason, business context, append-only versions bound to the vulnerability revision. Tests: `test_risk_matrix_is_deterministic`, `test_assessment_records_business_impact_and_remediation`, `test_override_needs_reason_and_reason_needs_override`, `test_invalid_assessments_rejected_without_writes`, `test_assessment_rejects_stale_revision_and_decided_records` |
| Tailored remediation recommendations | âœ… | `remediation` (min 20 characters) and `remediation_priority` are mandatory in every assessment version. Test: `test_assessment_records_business_impact_and_remediation` |
| Mandatory analyst sign-off gate | âœ… | `POST /workbench/{id}/signoff` (`signoff()` â†’ `decide()`): approve requires a current assessment, reproduction steps, justification and attestation; the confirmed severity is the assessed rating; reject dismisses with a bounded suppression; reopen voids the sign-off and stales the assessment. The legacy `/vulnerabilities/{id}/validation` route is gated by the same check in `decide()`. Tests: `test_approval_is_impossible_without_a_current_assessment`, `test_legacy_validation_cannot_bypass_the_assessed_rating`, `test_attested_approval_confirms_and_makes_report_eligible`, `test_rejection_dismisses_with_suppression_and_is_never_report_eligible`, `test_reopening_revokes_eligibility_and_stales_the_assessment`, `test_concurrent_signoffs_only_one_wins` |
| VAPT report eligibility | âœ… | `report_eligible()` is true only while the record is confirmed **and** its latest sign-off is an approval bound to the current revision with a risk assessment. Tests: `test_eligibility_requires_the_signoff_to_match_the_current_revision`, queue stage `report_eligible`. The report itself is Milestone 4. |
| Immutable analyst decision history | âœ… | `VulnerabilitySignoff` ledger (analyst id, UTC time, prior and new state, justification, revision, assessment id) plus `VulnerabilityEvent`; `GET /workbench/{id}/audit` and `/signoffs` resolve analyst names. Append-only in the ORM (`before_update`/`before_delete`) **and** by SQLite triggers on `vulnerability_events`, `vulnerability_risk_assessments`, `vulnerability_signoffs`. Tests: `test_audit_trail_records_analyst_identity_time_states_and_justification`, `test_orm_blocks_rewriting_assessments_signoffs_and_events`, `test_database_triggers_block_raw_sql_rewrites`, `test_migration_installs_tables_and_immutability_triggers_preserving_data` |
| RBAC and session protection | âœ… | Every route depends on `require_analyst` (allow-list `ANALYST_ROLES`) on top of `get_current_admin` (signed token, `iss`/`aud`/`exp`/`jti`, active account). Tests: `test_every_workbench_route_rejects_unauthenticated_callers`, `test_workbench_rejects_tokens_for_other_roles_and_deactivated_analysts`, `test_role_allow_list_gates_every_workbench_route_and_writes_nothing`, `test_unknown_records_and_malformed_ids`. **M6:** three roles: `analyst` (assess, sign off, prepare reports, remediate, retest), `lead_analyst` (plus report approval, risk acceptance, closure and closure reopening) and `admin` (all, the bootstrap account); optional dual sign-off (below). `H::test_role_matrix_on_routes_that_need_a_senior_role`, `H::test_dual_signoff_blocks_self_approval_of_findings_reports_and_closure` |
| Safe handling of untrusted evidence | âœ… | API returns evidence as JSON only (`test_untrusted_text_is_stored_and_returned_as_inert_data`). The UI shows it as escaped text in `<pre>` through `safeText()` (control and bidi characters replaced, 20,000-character cap) with no `dangerouslySetInnerHTML`. Frontend tests: `untrusted evidence renders as escaped text, never as markup`, `safeText strips control and bidi charactersâ€¦` |
| Frontend workbench | âœ… | `WorkbenchPage.jsx`: queue, evidence viewer, assessment form, sign-off form, audit trail. `tests/workbench.test.js` (9 tests: matrix, override rule, transitions, attestation, escaping, API paths) |

**Known limits.** Second-analyst approval is available but **off by default** (`SEPARATION_OF_DUTIES_ENABLED=false`) so a single bootstrap admin can operate the system; turn it on once two people hold roles (R14). Assessments cannot be edited, only superseded by a new version. The CVSS vector is not captured.

**Test evidence (2026-11-24):** 470 backend tests (`python -m pytest`), 31 frontend unit tests (`npm test`) and `npm run build` all passed.

## G. VAPT reporting (Milestone 4: complete)

Service functions are in `backend/app/services/reports.py`, routes in `backend/app/api/routes/reports.py` (`/api/v1/reports`), models in `backend/app/models/report.py`, migration `0011_vapt_reports`, role gates in `backend/app/core/rbac.py` (`require_report_role`, `require_report_approver`), UI in `frontend/src/ReportsPage.jsx` and `frontend/src/lib/reports.js`. PDFs are rendered with `reportlab` (pure Python, built-in Helvetica/Courier fonts, no GTK/Pango).

| Sub-feature | Status | Evidence |
|---|---|---|
| Report entity, versions and lifecycle | âœ… | `VaptReport` (`draft`, `pending_approval`, `approved`, `rejected`, `superseded`), per-assessment `revision`, frozen snapshot with `content_sha256` (`content_digest()`); `generate()` supersedes older open drafts, `decide()` supersedes an older approved report. `pending_approval` is reserved for Milestone 6 second-analyst review; today a draft is decided directly. Tests: `test_new_revision_supersedes_older_drafts_and_a_new_approval_supersedes_the_old_one`, `test_listing_filters_and_pagination` |
| Strict eligibility enforcement | âœ… | `gather()` includes a finding only if `vulnerabilities.report_eligible()` holds **and** its evidence hash re-verifies; everything else is counted by reason (`unassessed`, `unconfirmed`, `dismissed`, `stale_or_missing_signoff`, `evidence_integrity_failed`). A report with no eligible finding is refused (409). Tests: `test_only_report_eligible_findings_are_included_and_the_rest_counted`, `test_report_needs_an_eligible_finding_and_a_known_completed_assessment`, `test_tampered_evidence_is_excluded_from_the_report` |
| Executive summary | âœ… | `summarise()` builds a deterministic summary from validated counts (no free text from targets). Covered by `test_approval_publishes_an_official_pdf_with_matching_sha256` |
| Scope and methodology | âœ… | `_scope()` (client, website, exact target, authorised domains, methods, UTC window) and `_methodology()` (profile, request/redirect/body budgets, TLS version, isolation attestation and cleanup, source report SHA-256). The PDF states honestly when isolation is not attested or not applicable. Same test as above (section headings asserted in the PDF text) |
| Technical findings, severity and remediation | âœ… | Assessed rating, likelihood, impact, escaped evidence, evidence SHA-256, reproduction steps, analyst sign-off per finding, remediation grouped by priority. `render_pdf()`; `test_approval_publishes_an_official_pdf_with_matching_sha256` |
| PDF generation | âœ… | `render_pdf()`; `%PDF-` bytes, SHA-256 stored in `vapt_report_artifacts` and on the report; verified again on every download. Tests: `test_approval_publishes_an_official_pdf_with_matching_sha256`, `test_downloads_verify_the_stored_pdf_hash` |
| Untrusted data escaping | âœ… | `strip_controls()` at snapshot time (control, format and bidi characters removed, bounded), `pdf_text()` at render time (markup escaped, transcoded to Latin-1), `evidence_lines()` (evidence flattened to bounded JSON-escaped lines in a monospace style). No links or scripts are ever emitted. Tests: `test_hostile_evidence_and_names_render_as_inert_text`, `test_pdf_text_escapes_markup_and_removes_control_characters`, `test_strip_controls_bounds_length_and_flattens_single_line_fields` |
| Mandatory human approval gate | âœ… | `POST /reports/{id}/approve` and `/reject` need `human_validation_confirmed: true` and a justification (20-4000 characters). Approval re-verifies the snapshot hash and that every included finding is still eligible at the same revision and sign-off (`_still_eligible()`), then renders the official PDF. `GET /reports/{id}/pdf` returns 409 unless the report is approved; `GET /reports/{id}/preview` is a watermarked draft. Tests: `test_official_download_is_impossible_before_human_approval`, `test_rejection_is_final_and_never_releases_a_pdf`, `test_decision_requires_attested_justification`, `test_approval_is_refused_when_a_finding_changed_after_generation`, `test_approval_is_refused_when_the_snapshot_was_tampered_with` |
| Immutable approval and audit records | âœ… | `VaptReportApproval` (one decision per report, bound to the content and PDF hashes), `VaptReportEvent` (generated, previews, official downloads, approvals, rejections, supersessions; `GET /reports/{id}/events`). ORM guards plus SQLite triggers: frozen snapshot columns, no deletes, final statuses, write-once official hash, append-only artifacts, approvals and events. Tests: `test_audit_trail_records_generation_decisions_and_downloads`, `test_orm_and_database_block_rewriting_snapshots_history_and_final_states`, `test_migration_installs_report_tables_and_triggers_preserving_data` |
| Authentication and RBAC | âœ… | Router-level `require_report_role`; approve and reject also need `require_report_approver` (separate allow-lists, so Milestone 6 can split them). Tests: `test_every_report_route_rejects_unauthenticated_callers`, `test_forged_role_tokens_and_deactivated_admins_are_rejected`, `test_role_allow_lists_gate_reporting_and_approval_separately`, `test_unknown_reports_and_malformed_ids` |
| Frontend | âœ… | `ReportsPage.jsx`: eligible vs excluded counts before generating, report list, detail (summary, scope, findings, evidence as escaped text), approve/reject with attestation, draft preview and approval-gated official download, audit trail. `tests/reports.test.js` (9 tests: API paths and tokens, PDF routes, server refusal, download gating, decision gating, generation gating, assessment filter, labels and file names, escaped rendering) |

**Known limits.** With `SEPARATION_OF_DUTIES_ENABLED=false` (the default) one person can generate and approve the same report; when it is true, the generator cannot approve (`H::test_dual_signoff_blocks_self_approval_of_findings_reports_and_closure`, `E2E::test_full_lifecycleâ€¦`). Reports cover one assessment each, and there is no client-facing portal. PDFs use the built-in Latin-1 fonts, so characters outside Latin-1 in client or target text print as `?`. The PDF is stored in the database, not on the evidence volume.

## H. Remediation, retesting and closure (Milestone 5: complete)

Service functions are in `backend/app/services/remediation.py`, routes in `backend/app/api/routes/remediation.py` (`/api/v1/remediation`) plus `GET /assessments/{id}/closure` and `POST /assessments/{id}/close` in `api/routes/assessments.py`, models in `backend/app/models/remediation.py`, migration `0012_remediation_retesting`, role gates in `core/rbac.py` (`require_remediation_role`, `ensure_risk_acceptor`, `require_closure_role`), UI in `frontend/src/RemediationPage.jsx` and `frontend/src/lib/remediation.js`. The older observation-level fields (`remediation_status`, `FindingDueDate`, `retest_assessment_id`, `test_findings.py`) belong to Module D reviews and are unchanged; Module H tracks the confirmed `Vulnerability` entities from Modules E and F.

| Sub-feature | Status | Evidence |
|---|---|---|
| Remediation lifecycle per confirmed finding | âœ… | `VulnerabilityRemediation` (`open` is implicit until the first update), statuses `open`, `in_progress`, `fix_submitted`, `retest_requested`, `verified_fixed`, `reopened`, `risk_accepted`; `update_status()` with `MANUAL_TRANSITIONS` and optimistic `expected_version`. `retest_requested` and `verified_fixed` can only be reached through a retest. Tests: `test_confirmed_findings_start_open_and_status_changes_record_client_updates`, `test_illegal_transitions_stale_versions_and_unconfirmed_findings_are_refused`, `test_invalid_updates_are_rejected_without_writes` |
| Client notes, target dates and actor/UTC history | âœ… | Notes and target date (within 730 days) are stored on the record and in the append-only `RemediationEvent` ledger with actor, UTC time and from/to status (`add_event()`); `GET /remediation/{id}` returns the history. Tests: `test_confirmed_findings_start_open_and_status_changes_record_client_updates`, `test_hostile_notes_are_stored_as_inert_bounded_text` |
| Formal risk acceptance | âœ… | `risk_accepted` needs a 20-character justification, an explicit attestation and the separate `RISK_ACCEPTANCE_ROLES` allow-list; only a reopen leaves it. Tests: `test_risk_acceptance_needs_attestation_and_a_real_justification`, `test_role_allow_lists_gate_remediation_risk_acceptance_and_closure_separately` |
| Authorisation-gated retest requests | âœ… | `request_retest()` needs `fix_submitted`, an explicit request and network confirmation, and then calls the existing `assessments.create_request()`, so the live written authorisation, exact domain, methods, evidence, DNS pinning and the worker's execution-time revalidation apply unchanged; any denial is audited by that path and nothing is recorded. No local fallback, one retest at a time, at most 10 per finding. Tests: `test_retest_needs_a_submitted_fix_and_explicit_confirmation`, `test_retest_requests_revalidate_authorisation_scope_and_methods` (revoked, expired, out of scope, method not permitted, unknown authorisation), `test_retest_is_refused_when_the_website_target_no_longer_matches_the_finding`, `test_revocation_after_a_retest_request_fails_the_retest_closed`, `test_one_retest_at_a_time_and_a_retest_cannot_be_reopened_mid_flight` |
| Fix verification and automatic reopening | âœ… | `reconcile()` resolves a retest from its job and the scanner's stored, hash-checked occurrence: not detected â†’ `verified_fixed`, detected â†’ automatic `reopened` with the fresh occurrence and evidence hash linked, no applicable or tampered observation â†’ `inconclusive` (back to `fix_submitted`), failed or cancelled job â†’ `failed`. Only conclusive outcomes increment `retest_attempts`. It runs from the worker hook (`vulnerabilities.ingest_after_assessment` â†’ `on_assessment_ingested()`) and lazily on reads. Tests: `test_a_retest_that_no_longer_detects_the_weakness_verifies_the_fix`, `test_a_retest_that_still_reproduces_reopens_with_fresh_evidence_and_counts_the_attempt`, `test_retest_waits_for_ingestion_then_resolves_through_the_worker_hook`, `test_a_retest_without_an_applicable_observation_is_inconclusive`, `test_retest_evidence_that_fails_its_hash_check_is_inconclusive_not_verified` |
| Manual analyst reopening | âœ… | `reopen()` from `verified_fixed`, `risk_accepted` or `fix_submitted` with a 20-character reason; refused while a retest is pending. Tests: `test_analysts_can_reopen_verified_accepted_and_submitted_findings_with_a_reason`, `test_open_findings_cannot_be_reopened` |
| Final assessment closure | âœ… | `closure_state()` / `close_assessment()`: every confirmed finding detected in the assessment must be `verified_fixed` or `risk_accepted` (blocked by `open`, `in_progress`, `fix_submitted`, `retest_requested`, `reopened`); attested justification; immutable `AssessmentClosure` with a status snapshot and SHA-256; cannot close twice. Detected findings an analyst has not yet reviewed do not block closure but are reported as `unreviewed_count`. Tests: `test_closure_is_blocked_while_confirmed_findings_are_unresolved`, `test_assessment_closes_once_every_confirmed_finding_is_verified_or_formally_accepted`, `test_closure_of_unknown_assessments_and_assessments_without_confirmed_findings` |
| Immutable audit records | âœ… | ORM guards plus SQLite triggers: append-only remediation events and closures, retest request columns frozen after the request, a finished retest's result is final, no deletes. Tests: `test_orm_and_database_block_rewriting_history_closures_and_finished_retests`, `test_migration_installs_remediation_tables_and_triggers_preserving_data` |
| Authentication, RBAC and sanitisation | âœ… | Router-level `require_remediation_role`; closure also needs `require_closure_role`; strict pydantic bodies (`extra="forbid"`), `strip_controls()` on every note. Tests: `test_every_remediation_and_closure_route_rejects_unauthenticated_callers`, `test_forged_role_tokens_and_deactivated_admins_are_rejected_without_writes`, `test_role_allow_lists_gate_remediation_risk_acceptance_and_closure_separately`, `test_unknown_findings_and_malformed_ids_and_filters`, `test_listing_filters_counts_search_and_pagination` |
| Closed-assessment lock (M6) | âœ… | While an assessment has an **active closure** (one with no reopening record), every finding detected in it is frozen: remediation updates, manual reopen, retest requests, sign-off decisions (approve, reject, reopen, legacy validation) and new risk assessments return 409; reading and append-only comments still work. `POST /assessments/{id}/reopen-closure` (lead analyst or admin, attested, â‰¥20-character reason) appends an immutable `assessment_closure_reopenings` record and lifts the lock; the closure row itself is never edited. A later closure is stored as `generation` 2, 3â€¦ (unique per assessment, so concurrent closers collide). `services/closure_lock.py`. `H::test_confirmed_findings_and_remediation_are_immutable_after_closure`, `H::test_closure_reopening_is_role_gated_attested_audited_and_unlocks_edits`, `H::test_an_assessment_can_be_closed_again_as_a_new_generation`, `H::test_closures_and_reopenings_cannot_be_rewritten`, `H::test_unreviewed_findings_detected_in_the_closed_assessment_are_locked_too`, `E2E::test_full_lifecycleâ€¦` (step 12) |
| Frontend | âœ… | `RemediationPage.jsx`: status filters and counts, remediation updates, retest request with authorisation choice, retest history and outcomes, manual reopen, closure panel with blocking reasons and (M6) a closure-reopening form. `tests/remediation.test.js` (10 tests: API paths and tokens, server refusals, allowed transitions, risk acceptance, retest gating, outcome labels, reopen, closure gating, blocking statuses, closure reopening) |

**Known limits.** `verified_fixed` is recorded by the scanner comparison without a second analyst sign-off; the independent check is at closure (R15). Client fix updates are entered by analysts; there is no client-facing portal or notification. The existing 60-second cooldown and one-pending-assessment-per-website rule also apply to retests. Closing an assessment now locks its findings until the closure is formally reopened (Milestone 6). A retest whose scanner report fails ingestion stays `retest_requested` until ingestion succeeds. Only header profiles can be retested (the Nmap profile creates no vulnerabilities).

---

## Risk register (final status after Milestone 6)

| ID | Risk | Severity | Final status and test reference |
|---|---|---|---|
| R1 | Authentication events not audit-logged | High | **Closed (M6).** Append-only `auth_events`, no secrets stored. `H::test_login_outcomes_are_audited_without_passwords_tokens_or_raw_emails`, `H::test_auth_events_are_append_only_in_orm_and_database`, `E2E` step 13 |
| R2 | No login rate limiting or lockout | Medium | **Closed (M6).** Per email+address, per email and per address thresholds over a sliding window. `H::test_repeated_failures_lock_the_login_even_for_the_correct_password`, `H::test_lock_lifts_after_the_window_and_other_accounts_are_unaffected`, `H::test_credential_stuffing_from_one_address_is_throttled`. Residual: an attacker can lock a victim's email for up to 15 minutes from many addresses (the email-wide threshold is 4x); the lock is time-boxed and audited |
| R3 | Logout is client-side only | Medium | **Closed (M6).** `jti` denylist plus role-bound tokens. `H::test_logout_revokes_only_the_presented_token_and_is_audited`, `H::test_revoked_entries_expire_and_a_stale_role_claim_is_rejected`. Residual: a token is valid until logout or expiry (20 minutes); there is no "revoke all sessions" action |
| R4 | Installed VM header runner predates per-run isolation inspection | Medium | **Mitigated in code; manual VM step pending (user).** Redeploy the runner, then set `ASSESSMENT_REMOTE_REQUIRE_ISOLATION_ATTESTATION=true` (Milestone 1 manual steps; `test_scanner_hardening.py`). Not verifiable from this repository |
| R5 | The SSH identity can use Docker on the VM (root-equivalent) | Medium | **Open (accepted, user step).** Key is restricted with `restrict`; adding a `command=` forced-command wrapper in `authorized_keys` is recommended |
| R6 | A VM or runner crash can leave an orphaned analysis container | Lowâ€“Med | **Mitigated in code; needs runner redeploy (R4).** `GET /assessments/orphan-containers` (admin or lead analyst, audited, explicit button only) asks each runner for a label-scoped, read-only inventory and flags containers older than 120 s. Nothing is ever removed or pruned automatically; removal stays a manual, approved step. Tests: `test_nmap_inspection.py` |
| R7 | The HEAD broker runs on the Windows host, not in a container | Low | **Accepted by design.** Python `-I -S`, Windows Job Object limits, header-only parsing; `test_scanner_hardening.py`, `test_local_assessment.py` |
| R8 | The Nmap guard container runs as root with `NET_ADMIN` on a bridge network and is not covered by per-run inspection | Medium | **Mitigated in code; needs runner redeploy (R4).** The Nmap runner now inspects the guard and the scanner after create and before start, checking 17 properties each (no privileged mode, guard has exactly NET_ADMIN, scanner has no added capability and shares only the guard netns, read-only rootfs, resource limits, no mounts/devices/ports/host namespaces, labels, image). A mismatch fails closed and the container is never started. Runs report `isolation_verified`; older runners show as "not attested". The guard still needs root and NET_ADMIN by design |
| R9 | Evidence retention not enforced; deletion not a secure wipe | Medium | **Mitigated (M6).** Hardened expiry checks, overwrite-then-unlink purge, immutable audit hash, report-only retention CLI. Remaining: purging is operator-initiated, and overwrite is best effort on SSD/copy-on-write media (use BitLocker). `H::test_purge_*`, `H::test_retention_report_*`, `H::test_secure_erase_*`, `H::test_evidence_identity_hash_and_history_are_immutable_in_orm_and_database` |
| R10 | PDF reports without a publication approval gate | Medium (product) | **Closed (M4).** `test_reports.py` (human approval gate, hash-verified downloads) |
| R11 | Starlette/httpx test-client deprecation warning | Low | **Open (accepted).** One warning in the test run; upgrade in a maintenance pass |
| R12 | Real-target acceptance with genuine written authorisation not performed for the hardened build | Medium | **Open (user step).** See the manual steps below; cannot be done without a real authorised site |
| R13 | Single global assessment slot and 60-second cooldown limit throughput | Low | **Accepted for local use** |
| R14 | One person can both assess and approve (findings and reports) | Medium | **Mitigated (M6).** Roles `analyst` / `lead_analyst` / `admin` and configurable dual sign-off (`SEPARATION_OF_DUTIES_ENABLED`): the risk-assessment author cannot approve the finding and the report creator cannot approve the report. Default is **off** to keep single-admin bootstrap usable, so enable it once two people hold roles. `H::test_role_matrix_on_routes_that_need_a_senior_role`, `H::test_dual_signoff_blocks_self_approval_of_findings_reports_and_closure`, `H::test_separation_rule_is_a_runtime_switch_read_at_call_time`, `H::test_single_admin_bootstrap_still_runs_the_whole_workflow_by_default`, `E2E` |
| R15 | `verified_fixed` and closure need no second person | Lowâ€“Med | **Partly mitigated (M6).** With dual sign-off on, whoever updated remediation, accepted a risk or requested a retest for the assessment's findings cannot close it, and a closed assessment is locked until formally reopened with an audit record (`H::test_dual_signoff_â€¦`, `H::test_confirmed_findings_and_remediation_are_immutable_after_closure`). Not built: a second-analyst sign-off on `verified_fixed` itself (scanner comparison remains the verifier) and a dashboard indicator for a retest stuck on failed ingestion |

---

## Milestone 1: harden and complete the scanner worker (Module D)

**Status: complete, verified and committed on `feat/snwebshield-hardening`.**

### Changes

| Area | Change | Files |
|---|---|---|
| SSH transport | Single fixed builder. Pinned `ssh.exe` path. Options override `ssh_config`: no agent/X11/port forwarding, no proxies, no passwords or keyboard-interactive, no local command, no multiplexing, strict host keys. Only allow-listed runners and operations; execution IDs must be 32 lowercase hex characters. | `backend/app/services/ssh_transport.py` (new), `remote_assessment_runtime.py`, `nmap_runtime.py` |
| Fail closed | Missing client, unreachable VM, transport deadline or Docker/runner failure each become a `RemoteFailure` with a specific audited code. No HEAD after a failed preflight, and no local fallback. | same |
| Lease | `job_engine.lease_seconds(kind)`; assessments use 120 s, monitoring keeps 60 s. Stage budgets are named constants with `WORST_CASE_SECONDS`. | `job_engine.py`, `assessments.py` |
| Broker | Requires TLS â‰¥ 1.2 and records `tls_version`. Redirects are classified, not followed, and `Location` is never persisted. | `assessment_broker.py` |
| Runner | `--ipc=none`. `verify_isolation()` inspects the created container and refuses to start it on any mismatch (16 properties), then reports `isolation_verified`. | `scanner/remote_runner.py` |
| Untrusted output | Attestation must be exactly `True` (a test caught `1 == True` passing a membership check). Unknown runner fields are dropped. | `remote_assessment_runtime.py` |
| Config | `ASSESSMENT_REMOTE_REQUIRE_ISOLATION_ATTESTATION` (default `false`) | `config.py`, `.env.example` |
| Dashboard | Shows isolation attestation, TLS version and redirect category, built only from fixed vocabulary | `frontend/src/lib/scanner.js` (new), `AssessmentsPage.jsx` |

### Test results (2026-11-24, Windows)

| Suite | Result |
|---|---|
| Backend `pytest` (full regression) | **393 passed**, 1 deprecation warning. 94 more than the baseline, all in the new `test_scanner_hardening.py`. Two existing tests were updated for the new lease and inspection step. |
| Frontend unit (`npm test`) | **17 passed** (3 new in `tests/scanner.test.js`) |
| Playwright Chromium | **18 passed** (Azure journey now asserts isolation and TLS display) |
| `npm run build` | Passed |
| Live `python -m app.cli.scanner_check` | Passed through the hardened SSH transport: preflight, synthetic container, cleanup confirmed, `target_requests: 0`, `isolation_attested: false` (old runner installed) |
| `ssh -G` with hardened options | Accepted by Windows OpenSSH 9.5p2; `IdentityFile` from the user config preserved |

New security tests cover: valid, expired, not-yet-valid, revoked, out-of-scope, method-denied, evidence-changed and inactive-requester authorisations at execution time; revocation mid-run; SSRF (21 address classes) and unsafe URLs; DNS pinning against rebinding; redirect classification over real sockets; real-process cancellation and deadline kill; Docker isolation flags and 16 weakened-inspection cases; a container never started on mismatch; SSH client missing, VM unreachable (real subprocess), Docker unavailable and wrong runner; untrusted runner fields dropped; malformed attestation rejected.

### Manual Azure SSH and host steps

No VM changes were made by this milestone. These steps are for the operator:

1. **Redeploy the header runner** (needs `sudo`; no image rebuild, and the image ID is unchanged). Follow "Redeploying the Milestone 1 runner" in [REMOTE_DOCKER_SCANNER.md](REMOTE_DOCKER_SCANNER.md). Copy only `scanner/remote_runner.py` and `scanner/verify_host.py`, diff against the installed copy, `install` as root 755, then run `--check` and `verify_host.py`.
2. Run `.\.venv\Scripts\python.exe -m app.cli.scanner_check` on Windows and expect `"isolation_attested": true`.
3. Set `ASSESSMENT_REMOTE_REQUIRE_ISOLATION_ATTESTATION=true` in the private `backend/.env`, then restart the API and `assessment-worker`.
4. **Recommended (R5):** in the VM's `~azureuser/.ssh/authorized_keys`, add a `command="/usr/local/libexec/snwebshield-ssh-dispatch"` forced command that runs only the two runner paths with `--check`, `--cleanup <hex32>` or stdin-only `run`. Keep `restrict`.
5. Keep the VM host key pinned in `known_hosts`. Do not set `StrictHostKeyChecking=no`. After a deallocate/start cycle, verify the public IP has not changed before running jobs.
6. **Real-target acceptance (R12):** with genuine written permission for a site you control, queue one `remote-docker-headers-v1` assessment. Confirm exactly one HEAD in the server access log and check the report shows TLS, redirect, isolation and cleanup.

---

## Milestone 3: human security analyst workbench (Module F)

**Status: complete, verified and committed on `feat/snwebshield-hardening`.**

| Area | Change | Files |
|---|---|---|
| Migration | `0010_analyst_workbench`: `vulnerability_risk_assessments`, `vulnerability_signoffs`, and SQLite `BEFORE UPDATE/DELETE` triggers that make events, assessments and sign-offs immutable at database level. Additive; downgrade is refused to preserve history. | `backend/migrations/versions/0010_analyst_workbench.py` |
| Models | `VulnerabilityRiskAssessment`, `VulnerabilitySignoff`; ORM append-only guards; triggers also attached through `after_create` so fresh databases match migrated ones | `backend/app/models/vulnerability.py` |
| Service | Extended `vulnerabilities.py`: matrix, assessments, queue, sign-off, eligibility, audit. `decide()` now refuses confirmation without a current assessment and writes a sign-off row in the same transaction. | `backend/app/services/vulnerabilities.py` |
| API / RBAC | `/api/v1/workbench/*` behind `require_analyst` | `api/routes/workbench.py`, `core/rbac.py`, `main.py` (startup check for the new table) |
| Frontend | Analyst workbench page and pure helpers; new API client calls | `WorkbenchPage.jsx`, `lib/workbench.js`, `lib/api.js`, `App.jsx` |
| Behaviour change | Confirming a vulnerability from the Vulnerabilities page now fails with a clear 409 until a risk assessment is saved in the workbench. Existing confirmed records keep their state but have no sign-off row, so they are **not** report eligible until re-approved through the workbench. | |

### Manual configuration

1. Back up, then migrate the development database: `cd backend; .\.venv\Scripts\python.exe -m alembic upgrade head` (a pre-0010 copy is in `backups/`). Restart the API; startup refuses to run without the new tables.
2. Any vulnerability confirmed before this milestone must be re-assessed and re-approved in the workbench to become report eligible.
3. No Azure, VM, Docker or `.env` changes are needed. The Milestone 1 manual VM steps are still pending.

---

## Milestone 4: VAPT reporting (Module G)

**Status: complete, verified and committed on `feat/snwebshield-hardening`.**

| Area | Change | Files |
|---|---|---|
| Migration | `0011_vapt_reports`: `vapt_reports`, `vapt_report_artifacts`, `vapt_report_approvals`, `vapt_report_events` plus SQLite triggers (frozen snapshot, no delete, final statuses, write-once official hash, append-only history). Additive; downgrade is refused to preserve approval history. | `backend/migrations/versions/0011_vapt_reports.py` |
| Models | `VaptReport`, `VaptReportArtifact`, `VaptReportApproval`, `VaptReportEvent` with ORM guards; triggers also attached through `after_create` so fresh databases match migrated ones | `backend/app/models/report.py` |
| Service | Eligibility gathering, deterministic snapshot and summary, escaped PDF rendering, approval workflow, verified downloads | `backend/app/services/reports.py` |
| API / RBAC | `/api/v1/reports/*` behind `require_report_role`; approve/reject behind `require_report_approver`; startup refuses to run without the new tables | `api/routes/reports.py`, `core/rbac.py`, `main.py` |
| Dependency | `reportlab>=4.2,<5` (pure Python, installs cleanly on Windows) | `backend/requirements.txt` |
| Frontend | VAPT reports page and pure helpers; new API client calls; navigation entry | `ReportsPage.jsx`, `lib/reports.js`, `lib/api.js`, `App.jsx` |
| Test fixes | Three existing assertions that pinned the Alembic head now expect `0011_vapt_reports` | `test_migrations.py`, `test_workbench.py` |

### Test results (2026-11-24, Windows)

| Suite | Result |
|---|---|
| `python -m pytest tests/test_reports.py` | **31 passed** |
| Backend `pytest` (full regression, run on an otherwise idle machine) | **501 passed**, 1 deprecation warning (470 before, plus 31 new) |
| Frontend unit (`npm test`) | **40 passed** (31 before, plus 9 in `tests/reports.test.js`) |
| `npm run build` | Passed |
| Playwright journeys | Not re-run in this milestone (no existing journey touches reports) |

Security tests cover: exclusion of unassessed, unconfirmed, dismissed, stale-revision and evidence-tampered findings; no official PDF or download before human approval; approval refused when a finding changed or the snapshot was tampered with; rejection is final; attestation and justification required; hostile markup, control and bidi characters rendered as inert text with no PDF actions; unauthenticated, forged-role, deactivated-admin and role-allow-list rejection; ORM and raw-SQL immutability.

### Manual configuration

1. Back up, then migrate the development database: `cd backend; .\.venv\Scripts\python.exe -m alembic upgrade head` (a pre-0011 copy is in `backups/`). Restart the API; startup refuses to run without the new tables.
2. Install the new dependency in the backend virtual environment: `.\.venv\Scripts\python.exe -m pip install -r requirements.txt` (adds `reportlab`; `Pillow` was already required).
3. Findings confirmed before Milestone 3 are still not report eligible until re-approved in the workbench.
4. No Azure, VM, Docker or `.env` changes are needed. The Milestone 1 manual VM steps are still pending.
5. Run the frontend build and tests while no other heavy process is running; on this machine a concurrent `pytest` and `vite build` exhausted memory.

---

## Milestone 5: remediation, retesting and closure (Module H)

**Status: complete, verified and committed on `feat/snwebshield-hardening`.**

| Area | Change | Files |
|---|---|---|
| Migration | `0012_remediation_retesting`: `vulnerability_remediations`, `remediation_events`, `retest_requests`, `assessment_closures` plus SQLite triggers (append-only events and closures, frozen retest request columns, final retest results, no deletes). Additive; downgrade is refused to preserve history. | `backend/migrations/versions/0012_remediation_retesting.py` |
| Models | `VulnerabilityRemediation`, `RemediationEvent`, `RetestRequest`, `AssessmentClosure` with ORM guards; triggers also attached through `after_create` | `backend/app/models/remediation.py` |
| Service | Status workflow, retest request through the existing assessment path, reconciliation, closure | `backend/app/services/remediation.py` |
| Worker hook | After a scanner report is ingested, linked retests are reconciled (failures never affect the recorded scanner result) | `backend/app/services/vulnerabilities.py` (`ingest_after_assessment`) |
| API / RBAC | `/api/v1/remediation/*`, `GET /assessments/{id}/closure`, `POST /assessments/{id}/close`; separate remediation, risk acceptance and closure allow-lists; startup refuses to run without the new tables | `api/routes/remediation.py`, `api/routes/assessments.py`, `core/rbac.py`, `main.py` |
| Frontend | Remediation and retesting page, pure helpers, API client calls, navigation entry | `RemediationPage.jsx`, `lib/remediation.js`, `lib/api.js`, `App.jsx` |
| Test fixes | Three existing assertions that pinned the Alembic head now expect `0012_remediation_retesting` | `test_migrations.py`, `test_workbench.py`, `test_reports.py` |

### Test results (2026-11-24, Windows, run sequentially)

| Suite | Result |
|---|---|
| `python -m pytest tests/test_remediation.py` | **39 passed** |
| Backend `pytest` (full regression) | **540 passed**, 1 deprecation warning (501 before, plus 39 new) |
| Frontend unit (`npm test`) | **49 passed** (40 before, plus 9 in `tests/remediation.test.js`) |
| `npm run build` | Passed |
| Playwright journeys | Not re-run (no existing journey touches remediation) |

Security tests cover: retests rejected for revoked, expired, out-of-scope, method-denied and unknown authorisations with no assessment or retest recorded; revocation after a request cancels the job, makes no target request and fails the retest closed; fix verification versus automatic reopen with fresh linked evidence; tampered or missing retest evidence never verifies a fix; closure blocked by every unresolved status and succeeding only when all confirmed findings are verified or formally accepted; unauthenticated, forged-role, deactivated-admin and role-allow-list rejection; ORM and raw-SQL immutability.

### Manual configuration

1. Back up, then migrate the development database: `cd backend; .\.venv\Scripts\python.exe -m alembic upgrade head` (a pre-0012 copy is in `backups/`). Restart the API; startup refuses to run without the new tables.
2. Restart the `assessment-worker` so it loads the retest reconciliation hook.
3. No new dependencies, `.env` settings, Azure, VM or Docker changes. The Milestone 1 manual VM steps are still pending.
4. A retest uses the existing assessment profile settings (for example `ASSESSMENT_LOCAL_HTTP_ENABLED` or the remote Docker settings) and the existing 60-second cooldown. It needs a currently valid approved authorisation for the exact domain.
5. Run `pytest`, `npm test` and `npm run build` one after another, never together.

---

## Milestone 6: production security hardening and end-to-end integration

**Status: complete, verified and committed on `feat/snwebshield-hardening`.**

| Area | Change | Files |
|---|---|---|
| Migration | `0013_production_hardening`: `auth_events`, `revoked_tokens`, `assessment_closure_reopenings`; `admins.role` CHECK widened to `admin`/`lead_analyst`/`analyst`; `assessment_closures.generation` replaces the one-per-assessment unique key (SQLite table rebuild; closure triggers re-created); `authorization_evidence.purged_at`/`purge_method`; triggers freezing evidence identity/hash and making auth, closure-reopening and evidence events append-only. Existing rows preserved; downgrade refused. | `backend/migrations/versions/0013_production_hardening.py`, `models/security.py` |
| Authentication | Login audit and throttling, `POST /auth/logout`, role-bound tokens, password policy, hash upgrade on login | `api/routes/auth.py`, `core/security.py`, `services/auth_audit.py`, `cli/create_admin.py` (`--role`) |
| HTTP | Security-header middleware, strict CORS validation, start-up check for the new tables | `core/headers.py`, `core/config.py`, `main.py` |
| RBAC | Three roles, per-capability allow-lists, `enforce_distinct()` dual sign-off, `reopen-closure` route. **Bug found by the e2e test and fixed:** the scanner permission check hard-coded `role == "admin"`, so analysts could not request assessments or retests; it now uses `ANALYST_ROLES` | `core/rbac.py`, `services/assessments.py`, `services/vulnerabilities.py`, `services/reports.py`, `services/remediation.py` |
| Closure lock | Active-closure lookup and 409 on every state-changing path for locked findings; reopening and re-closure | `services/closure_lock.py`, `services/remediation.py` |
| Evidence | Overwrite-then-unlink purge, hardened purge checks, retention report and CLI | `services/evidence.py`, `api/routes/evidence.py`, `cli/evidence_retention.py` |
| Frontend | `api.signOut()` (server-side revoke), 429 retry hint, closure-reopening helper, API call and form | `lib/api.js`, `lib/remediation.js`, `RemediationPage.jsx`, `App.jsx` |
| Test fixes | Alembic-head pins now expect `0013_production_hardening`; the row-preservation test compares the pre-existing columns because later migrations append nullable columns | `test_migrations.py`, `test_workbench.py`, `test_reports.py`, `test_remediation.py` |

### Test results (2026-11-24, Windows, run sequentially)

| Suite | Result |
|---|---|
| `python -m pytest tests/test_e2e_lifecycle.py` | **1 passed** |
| `python -m pytest tests/test_production_hardening.py` | **39 passed** (32 test functions; `test_password_policy` is parametrised over 8 cases) |
| Backend `pytest` (full regression) | **580 passed**, 1 deprecation warning (540 before, plus 40 new: 39 hardening plus 1 end-to-end) |
| Frontend unit (`npm test`) | **53 passed** (49 before, plus 3 in `api.test.js` and 1 in `remediation.test.js`) |
| `npm run build` | Passed |
| Playwright journeys | Not re-run (no journey touches the changed screens) |
| Migration | `0013` applied to a copy of the development database: version, data, triggers and `PRAGMA integrity_check` verified; `H::test_migration_0013_â€¦` covers a 0012 â†’ head upgrade with data |

The end-to-end test (`E2E::test_full_lifecycle_from_registration_to_closure_with_audit_trail`) runs with dual sign-off enabled and three accounts. It covers client and website registration; an authorisation that cannot be approved without a document, then upload, human review and approval; a monitoring check; proof that nothing scans on its own; refusal of requests for a method-denied, revoked, out-of-scope or unconfirmed-network authorisation (no assessment or job created); an explicit request, scanner execution and ingestion of 8 normalised findings; an analyst assessment whose own sign-off is refused and a lead's accepted; a PDF generated by the analyst, refused for the analyst and approved by the lead with an official download only afterwards; remediation, a scoped retest that verifies the fix; closure refused for the analyst and for nobody who handled remediation; six refused post-closure mutations with unchanged state; and audit rows for authentication, authorisation, evidence, monitoring, assessment, sign-off, report, remediation and closure. All scanner output is synthetic: no network, DNS, SSH or Docker.

### Manual configuration

1. Back up, then migrate the development database: `cd backend; python -m app.cli.backup_database` then `.\.venv\Scripts\python.exe -m alembic upgrade head` (a pre-0013 copy is in `backups/`). Restart the API; start-up refuses to run without the new tables. Restart the `assessment-worker` too (it loads the role check).
2. Existing accounts keep the `admin` role and keep working. To add people: `python -m app.cli.create_admin --role analyst` (or `lead_analyst`). Existing sessions remain valid until they expire.
3. When at least two people hold roles, set `SEPARATION_OF_DUTIES_ENABLED=true` in the private `backend/.env` and restart. Optional tuning: `LOGIN_MAX_FAILURES`, `LOGIN_WINDOW_MINUTES`, `HSTS_MAX_AGE_SECONDS`. Serve the API over HTTPS (reverse proxy or `uvicorn --ssl-*`) if it is ever reachable beyond localhost; HSTS is only sent on TLS requests.
4. Run `python -m app.cli.evidence_retention` periodically; purge listed documents with `POST /evidence/{key}/purge` after review. Keep the evidence volume encrypted.
5. The Milestone 1 manual VM steps are still pending (R4/R5). No Azure, VM, Docker or scanner-image changes were made in this milestone, so no scanner redeploy is required by it.
6. Run `pytest`, `npm test` and `npm run build` one after another, never together.

---

## Remaining roadmap

Milestone 6 closes the planned series. Each milestone followed the CLAUDE.md workflow: back up the database, add migrations, unit/API/security tests, frontend tests and a build, update this file and the README, and commit locally.

| Milestone | Scope | Depends on |
|---|---|---|
| M1 â€” Scanner worker hardening (D) | Done | |
| M2 â€” Vulnerability management (E) | Done | M1 |
| M3 â€” Analyst workbench (F) | Done | M2 |
| M4 â€” VAPT reporting (G) | Done | M3 |
| M5 â€” Remediation, retesting and closure (H) | Done | M4 |
| M6 â€” Production hardening | Done: R1, R2, R3, R14, closed-assessment lock, evidence retention hardening, end-to-end test. Later milestone: R8 and R6 (see the Nmap inspection section). Not done: second-analyst sign-off on `verified_fixed`, stuck-ingestion indicator, client/website edit and archive | M3 |

---

## Assessment module stabilisation (branch `feature/assessment-module-stabilise`)

### Worker "Not running / stale" (diagnosed 2026-11-24)
Root cause was **process startup, not a code defect**: no `assessment-worker` process was running (last heartbeat 2026-11-24 07:25 UTC) because the worker is a separate process that nothing starts. Heartbeat timestamps and UTC serialisation were correct. Two real defects were fixed alongside:
- The browser compared its own clock with the heartbeat; the server now computes `state` (`running` / `stale` / `not_started`), `age_seconds` and the start command (`GET /assessments/worker-status`, stale after 45 s).
- Heartbeats only ran between ticks, so a long scan could make a healthy worker look dead; the worker now heartbeats every 10 s from a dedicated thread.
The page now names the state and shows the exact start command. `scripts/start-workers.ps1` starts any missing local role.

### Implementation matrix (from inspection; not every row re-verified end to end this session)
| Area | Status |
|---|---|
| Permission preflight (network-free), explicit request, live revalidation, idempotency, one active assessment | Implemented, covered by `test_assessments.py` (49 pass) |
| HTTP HEAD profile, remote Docker header profile, Nmap 80/443 profile | Implemented in M1; VM runner redeploy and isolation attestation still pending the user |
| Job states, lease expiry, cancel, late-result rejection | Implemented and tested |
| Worker health | Fixed here |
| Observations, analyst validation, vulnerability ingestion, PDF reports | Implemented in M2-M4 |
| One-step request flow and simplified UI | Done and verified (below) |
| Not yet done | VM runner redeploy and live verification of the new checks (user) |

### One-step request flow (verified 2026-11-24)
Select website, pick a profile, and the page shows permission status and enables **Run assessment**. `GET /assessments/readiness?website_id=` is network-free and writes nothing; it reuses `permission()` and selects an authorisation only if it is approved, inside its UTC window, covers the exact domain, permits the profile's methods and has currently accepted evidence. Otherwise the button is disabled and the exact reason is shown. The browser never chooses an authorisation. `create_request()` and the `assessment-worker` re-check permission again before any network call (TOCTOU preserved). The separate authorisation picker, note requirement and "explicitly request" checkbox were removed; clicking Run is the explicit request, and network profiles keep one written-permission attestation.

| Suite | Result |
|---|---|
| Backend `pytest tests` (full) | 600 passed, 0 failed (16m41s) |
| New `test_one_step_flow.py` | 18 passed: read-only readiness, expired/not-yet-valid/revoked/pending/rejected/unverified, out-of-scope and wildcard domain, missing methods, stale evidence, disabled profile, unknown website, auth required, one-step request then active-assessment block, worker cancels after revocation with no network call, observations ingested as unconfirmed then confirmed only by an analyst |
| New `test_worker_status.py` | 2 passed |
| Frontend `npm test` | 59 passed, 0 failed (incl. 6 new `runGate` tests) |
| Frontend `npm run build` | Succeeded |
| Playwright browser tests | 18 passed, 0 failed (assessment specs rewritten for the new form) |

Not exercised: a real Azure VM scan or real target traffic (all adapters were simulated), and a live worker against the dev database.


---

## Nmap runner inspection and orphan report (branch `feature/nmap-inspection-orphan-report`, verified 2026-11-24)

**R8.** `scanner/nmap/runner.py` gained `isolation_failures()` / `verify_isolation()`. It reads `docker inspect` for the guard and the scanner right after create and before start, so what Docker actually created is checked, not what was requested. `execution.isolation_verified` is reported only when both pass; the backend records `isolation_attested` (same contract as the header profile, optional unless `ASSESSMENT_REMOTE_REQUIRE_ISOLATION_ATTESTATION=true`) and the page shows it for Nmap results.

**R6.** Both runners accept a new read-only `--orphans` operation (label-filtered `container ls` plus `inspect`, capped at 50, no remove/stop/prune). The backend's fixed SSH allow-list gained only that operation. The Assessments page has a "Check VM for leftover containers" button; nothing runs on page load, disabled scanners are not contacted, and each report is audited (`orphan_report_generated`).

| Suite | Result |
|---|---|
| Backend `pytest tests` (full) | 656 passed, 0 failed (16m34s) |
| New `test_nmap_inspection.py` | 56 passed: compliant containers, 34 single-property weakenings each caught and named, malformed inspect output fails closed, noncompliant guard/scanner never started and cleaned up, attestation contract, read-only runner listing, bounded output, SSH allow-list, age classification, disabled/unreachable/old runner, hostile output sanitised, 401/403/200 role matrix |
| Frontend `npm test` | 61 passed, 0 failed |
| Frontend `npm run build` | Succeeded |
| Playwright browser tests | 19 passed, 0 failed (new housekeeping spec) |

**Not verified (important).** Everything here ran against synthetic Docker output and fake SSH. The checks have **not** been run against the real VM's Docker, so exact `inspect` field values (for example how Docker renders `NetworkMode` for a shared namespace, or whether the guard's tmpfs appears under `Mounts`) are unconfirmed. The checks fail closed, so a mismatch would stop Nmap scans rather than weaken isolation. Deploying is a manual step: install both updated runners and run `--check` and `--orphans` on the VM (see README), keep `ASSESSMENT_NMAP_ENABLED=false` until a real run is confirmed.


---

## Stuck-job recovery review (branch `feature/stuck-job-recovery`, verified 2026-11-24)

Reviewed `job_engine.claim/finish`, the assessment worker loop, ingestion and the retest hook for what happens when a worker dies, hangs or restarts.

| # | Finding | Result |
|---|---|---|
| 1 | Dead run: expired leases are failed by the next `claim()` of that job type, once, with no retry (`max_attempts=1`); slot is released by its own expiry | **Sound.** Now covered by tests (single `lease_expired` event, attempt outcome, no result invented, never re-executed, website usable again) |
| 2 | Lease not yet expired when a worker restarts | **Sound.** Left alone, since the old worker may still be alive; its token check rejects late results |
| 3 | The threaded heartbeat added in the first milestone **masked a hung worker** (the thread kept beating while the loop was stuck) | **Bug, fixed.** The beat now requires recent main-loop progress, limited to lease + 15 s (135 s); legitimate scans (worst case 55 s) never look hung |
| 4 | A crash after a result commits but before ingestion left a completed report with no observations, retried only by a manual API call | **Gap, fixed.** `recover_on_start()` ingests such reports when the worker starts. Ingestion is idempotent and creates unconfirmed observations only. A tampered or invalid report is rejected and audited, not looped |
| 5 | A stuck job looked like a normal "running" or "queued" job, and blocks new requests for that website | **Gap, fixed.** The API returns `recovery` (`lease_expired`, or `waiting_for_worker` after 2 minutes) and the page shows the explanation. Cancel already works on both states without a worker (tested) |
| 6 | Retests on a failed or cancelled assessment | **Sound (code review).** `reconcile` is idempotent and runs on reads, marking the retest failed; not changed |
| 7 | Orphan containers after a killed worker | Covered by the runner's own SIGHUP cleanup, the guard's 35 s alarm and the orphan report; not changed |

| Suite | Result |
|---|---|
| Backend `pytest tests` (full) | 669 passed, 0 failed (17m29s) |
| New `test_job_recovery.py` | 13 passed |
| Frontend `npm test` / build | 61 passed / succeeded |
| Playwright | 19 passed |

**Limits.** A crash is simulated as database state (claim without finish, then clock advanced and a fresh worker tick), which is faithful for the job engine but is not a real killed process. The new page note is covered by the API tests and the build only; there is no browser test for it. A poisoned report is re-rejected, with one audit event, on each worker start. SQLite single-writer locking under a very busy worker was not load-tested.


---

## Lifecycle completion: passive checks, sign-off, lifecycle view, port watch (branch `feature/lifecycle-completion`)

Goal: the four pillars work as one cycle per website. **Monitors** (uptime, DNS, TLS, response time and now TCP 80/443 state), **Detects** (authorised assessments), **Validates** (human review), **Protects** (reports, fixes, retests).

### 1. Port watch (open-port monitoring, Option A)
Recurring TCP 80/443 checks of one approved public IPv4, run on the isolated VM. It is **off until a person enables it**; registration, approval and migration never start anything.
- **Explicit act.** `POST /port-watch/{id}/enable` (admin or lead analyst) needs the written-permission attestation, an interval of 1 hour to 7 days, and a live check that a real Nmap assessment would be allowed now (approved, in date, exact domain, `tcp_port_discovery`, approved IPv4, accepted evidence). Audited.
- **Same gates as any scan.** The scheduler queues an ordinary Nmap assessment through `create_request`, so permission is re-checked at request, again at claim, and again immediately before execution by the worker, which uses the existing VM isolation. A failed check blocks the watch with an exact reason and one audit event; it never scans anyway and resumes by itself once permission is valid again.
- **Change detection.** Each completed run is compared with the last known state; a change is stored append-only, audited and queued as a notification. The first run after enabling only records a baseline. A failed run never alerts and never replaces the last good state. A change is an observation for an analyst, not a vulnerability.
- **Crash safety.** The request key is stable per slot (no double scans), and `reconcile_pending` settles a run whose comparison was lost when the worker died.
- **Needs running:** the scheduler role, the assessment worker, the notification dispatcher, migration 0015, and `ASSESSMENT_NMAP_ENABLED=true` with the pinned image.

### 2. Passive checks (Detects)
Three backend-only checks derived from the single HEAD and TLS handshake already made: HTTPS in use, certificate expiry within 30 days (medium within 7), and cookie Secure/HttpOnly/SameSite flags (counts only; cookie names and values are never stored). Only applicable results enter a report, so analysts are not asked to review something that cannot apply. `header_analyzer.analyze()` was deliberately **not** changed: the VM image runs the same function and the backend requires byte-identical output, so changing it would have broken the remote profile until the image was rebuilt and re-pinned. No VM change is needed.

### 3. Second-person sign-off on verified fixes
Migration 0014 adds the append-only `fix_verification_signoffs`. A second analyst confirms or rejects (rejection reopens the finding) the scanner's `verified_fixed` result; whoever requested the retest or handled the remediation cannot. Required for closure only when `SEPARATION_OF_DUTIES_ENABLED=true`; optional otherwise. This closes the item the earlier audit listed as not done (R15).

### 4. Website lifecycle view
`GET /websites/{id}/lifecycle` and the "Website lifecycle" page: one read-only summary per website of Monitors, Detects, Validates and Protects, with a single rule-based next step (priority order is unit-tested). It runs no scan and writes nothing.

### Also fixed
The scheduler ran each job type in sequence, so an error in one (for example a table that has not been migrated yet) could stop monitoring scheduling. A failing type is now isolated and reported with a generic line.

| Suite | Result |
|---|---|
| Backend `pytest tests` (full, final code) | 789 passed, 0 failed (20m33s) |
| New backend files | `test_passive_checks` 30, `test_fix_signoff` 13, `test_lifecycle` 34, `test_port_watch` 36, `test_scheduler_isolation` 3, `test_unmigrated` 4 |
| Frontend `npm test` | 70 passed |
| Frontend `npm run build` | Succeeded |
| Playwright browser tests | 22 passed |

**Not verified.** Everything ran against synthetic VM, DNS and scanner output: no real port scan, no real VM, no live scheduler process. A real run needs your steps below. The browser tests do not cover the sign-off form or the lifecycle "next step" for every state (the rules are unit-tested instead). Monitoring itself still cannot be configured without consent evidence, so the lifecycle integration tests pin a healthy monitor. A change in port state is reported once; there is no acknowledge button (analysts review it through the assessment's port observations).

**To use it (your steps).** Back up the database (`python -m app.cli.backup_database` from `backend`), run `.\.venv\Scripts\python.exe -m alembic upgrade head` from `backend` (adds 0014 and 0015; nothing is enabled), restart the API, then run the scheduler, assessment worker and notification dispatcher (`scripts\start-workers.ps1`). Until the migration is applied, the new Port watch endpoints answer 503 with that instruction, while the lifecycle view, remediation pages, scheduler and monitoring keep working without the new data (`test_unmigrated.py`). The VM runners from the previous milestone still need your redeploy and a real Nmap check before turning port watch on.
