# SNWebShield technical audit matrix

| | |
|---|---|
| Audit date | 2026-11-24 |
| Branch | `feat/snwebshield-hardening` (created from `feature/local-http-assessments` @ `23c196e`) |
| Commits | `3ee099e` is the pre-existing uncommitted Module D–H work, committed unchanged as a baseline. The Milestone 1 hardening commit follows it. |
| Baseline before changes | 299 backend tests, 14 frontend unit tests, production build: all passing |
| After Milestone 1 | **393 backend tests, 17 frontend unit tests, 18 Chromium journeys, production build: all passing** |
| Database | `backend/snwebshield_dev.db` at Alembic head `0008_findings_dashboard`; backed up to `backups/db-20261124T080620Z/` (gitignored, integrity-checked). No migration added. |

**Status legend.** ✅ Fully implemented and tested · 🟡 Partially implemented · 🧪 Implemented but not tested · ❌ Missing · 🔧 Broken or requiring improvement

Test paths are relative to `backend/tests/`. Browser journeys are in `frontend/tests/e2e/authorization.spec.js`. All API routes are under `/api/v1`.

---

## A. Application foundation

| Sub-feature | Status | Evidence |
|---|---|---|
| React dashboard | ✅ | `frontend/src/App.jsx`, page components; 18 Playwright journeys; `npm run build` passes |
| FastAPI backend | ✅ | `backend/app/main.py`, `GET /health` (`test_api.py::test_health_endpoint`) |
| Admin authentication | ✅ | `POST /auth/login`, `GET /auth/me` (`api/routes/auth.py`); bcrypt plus constant-time unknown-user check; `test_auth.py` |
| JWT | ✅ | `core/security.py`: `iss`, `aud`, `nbf`, `exp` and `jti` required; 20-minute default; `test_auth_claims.py` (invalid claims, deactivated admin invalidates token) |
| Logout / session expiry | 🟡 | Client-side idle timer and expiry (`frontend/src/lib/api.js`; `api.test.js`, e2e "idle token expiry"). **No server-side revocation:** a token stays valid until `exp` after logout. |
| Authentication audit logging | ❌ | Login success and failure are not recorded (`auth.py` only sets `last_login_at`). This breaks a CLAUDE.md invariant. See risk R1. |
| Login brute-force protection | ❌ | No rate limiting or lockout (R2) |
| Client and website management | 🟡 | Create, list and get only: `POST/GET /clients`, `POST/GET /websites` (`test_api.py`). No update, archive or delete, and no UI form to create authorisations. |
| DB models / migrations | ✅ | `app/models/*`, Alembic `0001`–`0008`; `test_migrations.py` (fresh, legacy adoption, partial-schema refusal, data preservation) |
| API protection | ✅ | Router-level `Depends(get_current_admin)`; unauthenticated tests in `test_auth.py`, `test_assessments.py::test_authentication_and_pagination`, `test_findings.py`, `test_evidence.py` |

## B. Authorisation and evidence management

| Sub-feature | Status | Evidence |
|---|---|---|
| Written permission and exact domain scope | ✅ | `models/authorization.py` (`authorized_domains`, `permitted_methods`); `schemas/authorization.py` (normalisation, duplicates, registered host required); `test_api.py` |
| UTC validity and approval states | ✅ | `timestamps_verified`, effective states; `test_authorization_correctness.py` (offsets, boundaries, legacy block, concurrent decisions) |
| Private document upload and validation | ✅ | `POST /authorizations/{id}/evidence`; PDF/PNG/JPEG signature check, active-content PDF rejection, size limit; `test_evidence.py` |
| SHA-256 hashes and authenticated downloads | ✅ | `GET /evidence/{key}/{operation}`; tamper detection blocks approval (`test_hash_tampering_blocks_approval`) |
| Human evidence review | ✅ | `POST /authorizations/{id}/evidence/reviews`; reviewer-bound and revision-bound (`test_review_is_bound_to_reviewer…`, `test_changed_revision…`) |
| Approval, rejection, revocation and audit history | ✅ | `POST /authorizations/{id}/approve|reject|revoke`, `GET …/events`; `AuthorizationAuditEvent`; revocation cancels queued and running assessments (`assessments.cancel_for_authorization`) |
| Retention and secure deletion | 🟡 | `retain_until`, legal hold, `POST /evidence/{key}/purge` with retry (`test_retention_hold_and_purge…`, `test_purge_failure…`). **Purge is manual**, with no scheduled sweep. Deletion is a filesystem unlink, not a secure wipe (R10). |

## C. Website monitoring

| Sub-feature | Status | Evidence |
|---|---|---|
| Explicit monitoring consent | ✅ | `MonitoringConsent`, `POST /websites/{id}/monitoring/configure`, `revoke-consent`; `test_monitoring.py::test_explicit_enable…`, e2e "monitoring requires separate consent" |
| HTTP/HTTPS availability, response time, DNS, TLS expiry | ✅ | `services/monitor_probe.py`; `test_monitor_probe.py` (pinned IP and SNI, TLS failure, near-expiry degraded, DNS failure) |
| Scheduling and background execution | ✅ | `job_engine.py`, `cli/operations.py` (`scheduler`, `worker`); `test_due_enqueue_competition…`, `test_worker_hard_deadline…` |
| History, incidents, alerts and recovery | ✅ | `MonitoringIncident`, `NotificationDelivery` (dashboard or SMTP); `test_retry_incident_recovery…`, `test_smtp_*` |

## D. Security scanner worker (Milestone 1 scope)

| Sub-feature | Status | Evidence |
|---|---|---|
| Assessment job creation and lifecycle | ✅ | `POST/GET /assessments`, `GET /assessments/{id}`, `/{collection}`; `AssessmentRequest`, `Job`, `JobAttempt`, `JobResult`; `test_assessments.py` (idempotency, one active job per site, concurrent claims) |
| Authorisation and exact-scope revalidation | ✅ | `assessments.permission()` runs at request, at claim (`still_permitted`), continuously during execution, and again under lock in `finish()`. **M1 tests:** `test_scanner_hardening.py::test_remote_job_revalidated_before_any_ssh` (revoked, expired, not-yet-valid, scope, method, evidence, requester), `::test_revocation_during_remote_run…` |
| Trusted network broker | ✅ | `services/assessment_broker.py`: one HEAD, one connection, no retry, no body, header allowlist, Windows Job Object limits. **M1:** TLS ≥ 1.2, TLS version telemetry |
| DNS/IP validation, SSRF and rebinding protection | ✅ | `monitor_probe.resolve` rejects any non-global or special answer, including mixed answers; the connection is pinned to the resolved IP and the peer is checked. **M1 tests:** 21 prohibited ranges (incl. `169.254.169.254`, CGNAT, NAT64, ULA, `::ffff:127.0.0.1`), unsafe URLs rejected before DNS, single resolution with a rebinding second answer never used, revocation after DNS prevents connect |
| Safe redirect handling | ✅ | **M1:** `classify_redirect` gives a fixed category, never follows, never stores `Location`. Real-socket tests show one request only and no target text persisted. |
| HTTP HEAD assessment | ✅ | `test_local_assessment.py::test_real_head_never_follows_redirect_or_saves_headers` |
| Python security-header analysis | ✅ | `services/header_analyzer.py` (pure, bounded input); `test_analyzer_rejects_unselected_or_unbounded_data`; remote output must equal the local recomputation |
| SSH Docker on `azureuser@57.159.27.58` | ✅ | **M1:** `services/ssh_transport.py` (pinned binary, hardened options, fixed runners). Live `app.cli.scanner_check` passed on 2026-11-24 (cleanup confirmed, 0 target requests). |
| Container isolation (`--network none`, non-root, read-only, CPU/RAM/PID/timeout) | ✅ / 🔧 | `scanner/remote_runner.py::create_args`; previously live-verified by `scanner/verify_host.py`. **M1:** `--ipc=none` and per-run `verify_isolation` (refuses to start on any mismatch); 16 weakening cases tested. 🔧 The **installed** VM runner predates this and reports `isolation_attested: false` until redeployed (manual step below). |
| Resource and duration telemetry | ✅ | `validate_execution` whitelists duration, CPU and peak RSS; `remote_docker_execution_finished` event; shown on the dashboard |
| Cancellation | ✅ | `POST /assessments/{id}/cancel`; permission polled every 100 ms; SSH process killed; targeted cleanup. **M1:** real-process cancellation and deadline tests |
| Structured JSON results and audit logs | ✅ | `AssessmentReport` (SHA-256, 32 KiB cap), `ExecutionEvent` |
| No host fallback | ✅ | **M1:** `test_worker_fails_closed_when_ssh_or_docker_unavailable` (client missing, unreachable, Docker down, wrong runner) asserts no HEAD and no local adapter |
| Lease vs execution budget | ✅ | **M1:** per-handler lease (assessment 120 s ≥ worst-case 55 s + 30 s margin); `test_assessment_lease_exceeds_every_bounded_remote_budget` |
| Restricted Nmap (TCP 80/443) | ✅ | `nmap_*` services, `scanner/nmap/*`; `test_nmap.py`. Now shares the hardened SSH transport. |

## E. Vulnerability management

| Sub-feature | Status | Evidence |
|---|---|---|
| Normalised finding records | 🟡 | Findings are derived from the latest confirmed `ObservationReview` per `(report, check)` (`services/findings.py`, `GET /findings`). There is no dedicated normalised Finding entity across assessments. |
| Severity and confidence | 🟡 | Analyst severity exists; scanner `severity_suggestion` exists. No confidence field. |
| Evidence and reproduction steps | 🟡 | `supporting_evidence` text and `evidence_ref`. No structured reproduction steps. |
| Duplicate detection | ❌ | Repeated assessments are deliberately kept separate. No cross-assessment fingerprinting. |
| False-positive management | 🟡 | `dismissed` and `not_applicable` dispositions with history. No suppression rules carried to later assessments. |
| Human validation and analyst comments | ✅ | `POST /assessments/{id}/reviews/{check}` requires `human_validation_confirmed`; `test_observation_reviews.py` |

## F. Security analyst workbench

| Sub-feature | Status | Evidence |
|---|---|---|
| Manual finding validation | ✅ | `AssessmentReviews.jsx`; e2e "analyst reviews track remediation…" |
| Risk and business-impact assessment | ❌ | Only severity. No likelihood, impact, CVSS or business context fields. |
| Remediation recommendations | ✅ | `recommendation` required for confirmed issues (schema validator) |
| Analyst approval and audit history | ✅ | Append-only revisions with `expected_revision` concurrency (`test_concurrent_reviews…`). No second-analyst approval. |

## G. VAPT reporting

| Sub-feature | Status | Evidence |
|---|---|---|
| Executive summary | ❌ | — |
| Scope and methodology | 🟡 | Reviewed JSON export includes authorisation, evidence hashes, profile and limitations. No narrative methodology. |
| Technical findings and evidence | 🟡 | `POST /assessments/{id}/reviewed-reports` produces an immutable, hash-checked JSON snapshot (`test_reviewed_export…`) |
| Severity and remediation guidance | 🟡 | Present in the JSON export only |
| PDF report generation | ❌ | — |
| Human approval before publication | ❌ | Exports are private snapshots. There is no publish state or approval gate. |

## H. Remediation and retesting

| Sub-feature | Status | Evidence |
|---|---|---|
| Remediation tracking | ✅ | `remediation_status`, owner, due dates with history (`FindingDueDate`, `test_findings.py`) |
| Client updates | ❌ | No client-facing view or notifications |
| Retest requests | 🟡 | Resolution needs a later completed same-target assessment (`retest_assessment_id`, `test_resolution_requires_later_same_target_retest`). No retest-request workflow. |
| Verification of fixes | 🟡 | Analyst links the retest. No automatic comparison of the check result. |
| Reopening unresolved issues | ✅ | `test_resolved_not_overdue_and_reopened_uses_same_deadline` |
| Final assessment closure | ❌ | No engagement or closure entity |

---

## Risk register

| ID | Risk | Severity | Status and mitigation |
|---|---|---|---|
| R1 | Authentication events (login success/failure, inactive-account attempts) are not audit-logged, against a CLAUDE.md invariant | **High** | Open. Milestone 2. Add an append-only auth event table without storing passwords or tokens. |
| R2 | No login rate limiting or lockout | Medium | Open. Milestone 2. |
| R3 | Logout is client-side; a stolen token stays valid up to 20 minutes | Medium | Open. Milestone 2: `jti` denylist on logout. |
| R4 | The installed VM header runner predates per-run isolation inspection | Medium | Mitigated in code. Redeploy manually, then set `ASSESSMENT_REMOTE_REQUIRE_ISOLATION_ATTESTATION=true`. |
| R5 | The SSH identity can use Docker on the VM, which is root-equivalent. A compromised Windows account means a compromised VM. | Medium | Key restricted with `restrict`. **Recommended:** add a `command="…"` forced-command wrapper in `authorized_keys` that allows only the two runner paths. |
| R6 | A VM or runner crash can leave an orphaned analysis container (cleanup unconfirmed) | Low–Med | Audited as unconfirmed. Roadmap: label-scoped orphan report (`com.snwebshield.runner`), never a broad prune. |
| R7 | The HEAD broker runs on the Windows host, not in a container | Low | By design: CLAUDE.md requires `--network none` for analysis, so the target request must be made elsewhere. Mitigated with Python `-I -S`, a Job Object (256 MiB, CPU cap), header-only parsing and a 32 KiB limit. |
| R8 | The Nmap guard container runs as root with `NET_ADMIN` on a bridge network (needed for its egress firewall) and is not covered by per-run inspection | Medium | Open. Milestone 2: extend inspection to `scanner/nmap/runner.py`. |
| R9 | Evidence retention is not enforced automatically; deletion is not a secure wipe | Medium | Open. Add a scheduled retention report. Recommend BitLocker on the evidence volume. |
| R10 | Findings are not normalised or deduplicated; no PDF or executive reports; no publication approval | Medium (product) | Roadmap: Milestones 3–5 |
| R11 | Starlette/httpx test-client deprecation warning | Low | Upgrade dependency in a maintenance pass |
| R12 | Real-target acceptance with genuine written authorisation not yet performed for the hardened build | Medium | User step (below) |
| R13 | Single global assessment slot and 60-second cooldown limit throughput | Low | Accepted for local use |

---

## Milestone 1: harden and complete the scanner worker (Module D)

**Status: complete, verified and committed on `feat/snwebshield-hardening`.**

### Changes

| Area | Change | Files |
|---|---|---|
| SSH transport | Single fixed builder. Pinned `ssh.exe` path. Options override `ssh_config`: no agent/X11/port forwarding, no proxies, no passwords or keyboard-interactive, no local command, no multiplexing, strict host keys. Only allow-listed runners and operations; execution IDs must be 32 lowercase hex characters. | `backend/app/services/ssh_transport.py` (new), `remote_assessment_runtime.py`, `nmap_runtime.py` |
| Fail closed | Missing client, unreachable VM, transport deadline or Docker/runner failure each become a `RemoteFailure` with a specific audited code. No HEAD after a failed preflight, and no local fallback. | same |
| Lease | `job_engine.lease_seconds(kind)`; assessments use 120 s, monitoring keeps 60 s. Stage budgets are named constants with `WORST_CASE_SECONDS`. | `job_engine.py`, `assessments.py` |
| Broker | Requires TLS ≥ 1.2 and records `tls_version`. Redirects are classified, not followed, and `Location` is never persisted. | `assessment_broker.py` |
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

## Remaining roadmap

Each milestone follows the CLAUDE.md workflow: back up the database, add migrations, unit/API/security tests, frontend tests and a build, update this file and the README, and commit locally.

| Milestone | Scope | Depends on |
|---|---|---|
| **M2 — Foundation and scanner security gaps** | R1 auth audit log; R2 login throttling; R3 server-side logout (`jti` denylist); client/website edit and archive with audit; extend per-run isolation inspection to the Nmap runner (R8); label-scoped orphan-container report (R6); evidence retention report (R9) | M1 |
| **M3 — Vulnerability management (E)** | Normalised `Finding` entity with a stable fingerprint `(website, check, scope)`; dedup across assessments; confidence; structured reproduction steps; false-positive suppression carried forward with expiry and audit | M2 |
| **M4 — Analyst workbench (F)** | Likelihood, impact and business-context risk rating (CVSS-style optional); second-analyst approval for high and critical findings | M3 |
| **M5 — VAPT reporting (G)** | Report entity (draft → in review → approved → published); executive summary; scope and methodology from the authorisation snapshot; locally rendered PDF with a SHA-256 manifest; human approval gate before publish | M3, M4 |
| **M6 — Remediation and retesting (H)** | Retest request workflow tied to a fresh authorisation check; automatic before/after check comparison; client update log; engagement closure with a final report | M5 |
