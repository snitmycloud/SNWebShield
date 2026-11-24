# SNWebShield technical audit matrix

| | |
|---|---|
| Audit date | 2026-11-24 |
| Branch | `feat/snwebshield-hardening` (created from `feature/local-http-assessments` @ `23c196e`) |
| Commits | `3ee099e` is the pre-existing uncommitted Module D–H work, committed unchanged as a baseline. The Milestone 1 hardening commit follows it. |
| Baseline before changes | 299 backend tests, 14 frontend unit tests, production build: all passing |
| After Milestone 1 | **393 backend tests, 17 frontend unit tests, 18 Chromium journeys, production build: all passing** |
| After Milestone 2 (Module E) | **430 backend tests, 22 frontend unit tests, production build: all passing** |
| After Milestone 3 (Module F) | **470 backend tests, 31 frontend unit tests, production build: all passing** |
| After Milestone 4 (Module G) | **501 backend tests, 40 frontend unit tests, production build: all passing** |
| After Milestone 5 (Module H) | **540 backend tests, 49 frontend unit tests, production build: all passing** |
| After Milestone 6 (production hardening) | **580 backend tests (incl. 39 in `test_production_hardening.py` and 1 end-to-end lifecycle test), 53 frontend unit tests, production build: all passing** |
| Database | Alembic head is `0013_production_hardening` after Milestone 6 (`0012_remediation_retesting` after Milestone 5). Pre-0013 backup: `backups/db-*-pre-0013/` (gitignored, integrity-checked). `0013` was applied to a **copy** of the development database and verified (data, triggers and `integrity_check` intact); the development database file itself is migrated by the operator with `python -m alembic upgrade head` (see Milestone 6 manual steps). |

**Status legend.** ✅ Fully implemented and tested · 🟡 Partially implemented · 🧪 Implemented but not tested · ❌ Missing · 🔧 Broken or requiring improvement

Test paths are relative to `backend/tests/`. Milestone 6 tests are in `test_production_hardening.py` (`H::` below) and `test_e2e_lifecycle.py` (`E2E::`). Module E and F test names below are real function names in `test_vulnerabilities.py` and `test_workbench.py`. Browser journeys are in `frontend/tests/e2e/authorization.spec.js`. All API routes are under `/api/v1`.

---

## Final module status (after Milestone 6)

| Module | Final status | Primary test references (all passing) |
|---|---|---|
| A. Application foundation | ✅ Complete. Auth audit, throttling, server-side logout, role-bound JWTs, password policy, security headers and strict CORS closed in M6 | `test_auth.py`, `test_auth_claims.py`, `test_api.py`, `test_migrations.py`, `test_production_hardening.py` (R1–R3, headers, CORS, roles) |
| B. Authorisation and evidence | ✅ Complete. Retention checks, overwrite-then-unlink purge and immutable evidence hashes added in M6 (limits stated in the B table) | `test_evidence.py`, `test_authorization_correctness.py`, `test_production_hardening.py` (retention and purge) |
| C. Website monitoring | ✅ Complete | `test_monitoring.py`, `test_monitor_probe.py`, `test_monitor_http_fixture.py`, `test_e2e_lifecycle.py` (monitoring step) |
| D. Scanner worker | ✅ Complete in code. The installed VM runner still needs its manual redeploy (R4) and real-target acceptance is a user step (R12) | `test_assessments.py`, `test_scanner_hardening.py`, `test_local_assessment.py`, `test_remote_assessment.py`, `test_nmap.py`, `test_e2e_lifecycle.py` |
| E. Vulnerability management | ✅ Complete | `test_vulnerabilities.py`, `test_e2e_lifecycle.py` |
| F. Analyst workbench | ✅ Complete. Roles and optional dual sign-off added in M6 | `test_workbench.py`, `test_production_hardening.py` (dual sign-off) |
| G. VAPT reporting | ✅ Complete. Report approval now needs a senior role and, with dual sign-off, a second person | `test_reports.py`, `test_production_hardening.py`, `test_e2e_lifecycle.py` |
| H. Remediation, retesting and closure | ✅ Complete. Closed-assessment lock and formal reopening added in M6 | `test_remediation.py`, `test_production_hardening.py` (lock, reopen, generations), `test_e2e_lifecycle.py` |

Risks R1–R15 are listed with their final status and test reference in the [risk register](#risk-register-final-status-after-milestone-6) below. Open items are R4 and R5 and R12 (manual user steps), R6 and R8 (not built), R11 and R13 (accepted); R15 is partly mitigated.

---

## A. Application foundation

| Sub-feature | Status | Evidence |
|---|---|---|
| React dashboard | ✅ | `frontend/src/App.jsx`, page components; 18 Playwright journeys; `npm run build` passes |
| FastAPI backend | ✅ | `backend/app/main.py`, `GET /health` (`test_api.py::test_health_endpoint`) |
| Admin authentication | ✅ | `POST /auth/login`, `GET /auth/me` (`api/routes/auth.py`); bcrypt plus constant-time unknown-user check; `test_auth.py` |
| JWT | ✅ | `core/security.py`: `iss`, `aud`, `nbf`, `exp` and `jti` required; 20-minute default; HS256 with a ≥32-byte secret that is checked at use. **M6:** the `role` claim must be a known role **and equal the account's current role** (a token minted before a promotion or demotion is refused); a revoked `jti` is refused. `test_auth_claims.py`; `H::test_revoked_entries_expire_and_a_stale_role_claim_is_rejected`, `H::test_forged_unknown_role_and_wrong_signature_tokens_are_rejected` |
| Logout / session expiry | ✅ | Client-side idle timer and expiry (`api.test.js`, e2e "idle token expiry"). **M6 (R3):** `POST /auth/logout` writes the token's `jti` to `revoked_tokens`; it is refused everywhere afterwards while other sessions of the same account stay valid, and entries are pruned once past expiry. The UI calls it through `api.signOut()`. `H::test_logout_revokes_only_the_presented_token_and_is_audited`; frontend `signOut clears the browser session first…`, `signOut still signs the person out when the server cannot be reached` |
| Authentication audit logging | ✅ | **M6 (R1):** append-only `auth_events` (`login_success`, `login_failure`, `login_inactive`, `login_throttled`, `logout`) with UTC time, account id, TCP peer address and a SHA-256 of the email; never a password, token or raw email. ORM guards plus SQLite triggers. `H::test_login_outcomes_are_audited_without_passwords_tokens_or_raw_emails`, `H::test_auth_events_are_append_only_in_orm_and_database` |
| Login brute-force protection | ✅ | **M6 (R2):** durable, restart-safe throttling from recent `login_failure` events: 5 failures per email and address, 20 per email from anywhere, 20 per address (15-minute sliding window, configurable). A locked login returns 429 with `Retry-After`, even for the correct password, and computes no hash. A successful login resets the email's count. `H::test_repeated_failures_lock_the_login_even_for_the_correct_password`, `H::test_lock_lifts_after_the_window_and_other_accounts_are_unaffected`, `H::test_a_successful_login_resets_the_failure_count`, `H::test_credential_stuffing_from_one_address_is_throttled` |
| Password policy and hashing | ✅ | Argon2id with the library's current parameters; hashes with outdated parameters are upgraded transparently on login. `app.cli.create_admin` enforces 12–128 characters, three character classes, no common or repetitive passwords and no email name. `H::test_password_policy`, `H::test_password_hash_uses_argon2id_and_old_hashes_are_upgraded_on_login` |
| HTTP security headers | ✅ | **M6:** pure-ASGI `SecurityHeadersMiddleware` adds `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'…`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Resource-Policy` and `Cache-Control: no-store` on every API response (success, error and CORS preflight); `Strict-Transport-Security` only when the request truly arrived over TLS (a forwarded-proto header is never trusted). Route-set headers such as the evidence-download CSP are not overwritten; the Swagger pages `/docs` and `/redoc` get no CSP so they keep working. `H::test_security_headers_on_success_error_and_preflight_responses`, `H::test_hsts_only_over_https_and_never_from_a_forwarded_header`, `H::test_evidence_downloads_keep_their_stricter_route_headers` |
| Strict CORS | ✅ | **M6:** `CORS_ORIGINS` is validated at start-up (http(s) origins only; no `*`, paths or schemes such as `javascript:`), methods are `GET`, `POST`, `OPTIONS` and headers are an allow-list. `H::test_cors_only_trusts_configured_origins_and_rejects_unsafe_configuration` |
| Client and website management | 🟡 | Create, list and get only: `POST/GET /clients`, `POST/GET /websites` (`test_api.py`). No update, archive or delete, and no UI form to create authorisations. |
| DB models / migrations | ✅ | `app/models/*`, Alembic `0001`–`0013`; `test_migrations.py` (fresh, legacy adoption, partial-schema refusal, data preservation) |
| API protection | ✅ | Router-level `Depends(get_current_admin)` (and the role allow-lists below); unauthenticated tests in `test_auth.py`, `test_assessments.py::test_authentication_and_pagination`, `test_findings.py`, `test_evidence.py` |

## B. Authorisation and evidence management

| Sub-feature | Status | Evidence |
|---|---|---|
| Written permission and exact domain scope | ✅ | `models/authorization.py` (`authorized_domains`, `permitted_methods`); `schemas/authorization.py` (normalisation, duplicates, registered host required); `test_api.py` |
| UTC validity and approval states | ✅ | `timestamps_verified`, effective states; `test_authorization_correctness.py` (offsets, boundaries, legacy block, concurrent decisions) |
| Private document upload and validation | ✅ | `POST /authorizations/{id}/evidence`; PDF/PNG/JPEG signature check, active-content PDF rejection, size limit; `test_evidence.py` |
| SHA-256 hashes and authenticated downloads | ✅ | `GET /evidence/{key}/{operation}`; tamper detection blocks approval (`test_hash_tampering_blocks_approval`) |
| Human evidence review | ✅ | `POST /authorizations/{id}/evidence/reviews`; reviewer-bound and revision-bound (`test_review_is_bound_to_reviewer…`, `test_changed_revision…`) |
| Approval, rejection, revocation and audit history | ✅ | `POST /authorizations/{id}/approve|reject|revoke`, `GET …/events`; `AuthorizationAuditEvent`; revocation cancels queued and running assessments (`assessments.cancel_for_authorization`) |
| Retention and secure deletion | ✅ (with stated limits) | `retain_until`, legal hold, `POST /evidence/{key}/purge` with retry (`test_retention_hold_and_purge…`, `test_purge_failure…`). **M6 (R9):** retention is re-checked against UTC now on every purge (retention running, legal hold, approved authorisation and un-withdrawn documents each block it); the stored file is **overwritten with random bytes, flushed to disk, then unlinked** (`secure_erase`, regular files only, symlinks refused); the row, SHA-256, `purged_at` and `purge_method` are kept as the immutable audit proof, and the purge event records the retained hash. SQLite triggers and ORM guards make a document's identity and hash immutable, forbid deleting it, make `purged` final and make `evidence_events` append-only. `python -m app.cli.evidence_retention` reports expired documents and what blocks each (it deletes nothing; a human purges with a reason). `H::test_purge_overwrites_the_file_then_unlinks_and_keeps_the_audit_hash`, `H::test_purge_is_refused_during_retention_legal_hold_or_active_approval`, `H::test_retention_report_lists_expired_documents_with_blockers_and_deletes_nothing`, `H::test_secure_erase_handles_missing_and_special_files`, `H::test_evidence_identity_hash_and_history_are_immutable_in_orm_and_database`. **Limit:** overwrite-in-place is best effort on SSDs and journaling or copy-on-write filesystems, so keep the evidence volume encrypted (BitLocker); the purge is still operator-initiated, not scheduled. |

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

## E. Vulnerability management (Milestone 2: complete)

Service functions are in `backend/app/services/vulnerabilities.py`, routes in `backend/app/api/routes/vulnerabilities.py`, models in `backend/app/models/vulnerability.py`.

| Sub-feature | Status | Evidence |
|---|---|---|
| Normalised finding records | ✅ | `Vulnerability` with unique `fingerprint` per website, check and target (`fingerprint()`, `_record()`, migration `0009_vulnerabilities`); `GET /vulnerabilities`, `GET /vulnerabilities/{id}` (`listing()`, `detail()`). Tests: `test_completed_assessment_ingests_unconfirmed_normalised_records`, `test_secure_response_creates_no_records`, `test_listing_filters_counts_and_ordering` |
| Safe ingestion of untrusted scanner output | ✅ | `parse_observation()` (fixed vocabulary, strict booleans), `ingest_report()` (report SHA-256 re-check via `report_intact()`, 64-observation cap), `ingest_one()`, `ingest_pending()`. Tests: `test_untrusted_or_non_applicable_observations_are_not_ingested`, `test_hostile_report_cannot_confirm_or_inject_checks`, `test_oversized_observation_list_rejected`, `test_tampered_report_is_rejected_audited_and_left_pending`, `test_backfill_is_idempotent`, `test_ingestion_failure_never_loses_scanner_result`, `test_port_inventory_reports_are_marked_but_not_ingested` |
| Severity and confidence | ✅ | `scanner_severity`, `analyst_severity`, `score()` (explainable `confidence_factors`). Tests: `test_confidence_scoring_is_deterministic_and_bounded`, `test_later_pass_is_recorded_lowers_confidence_and_never_auto_closes` |
| Evidence and reproduction steps | ✅ | `VulnerabilityOccurrence` with `evidence` and `evidence_sha256` (`evidence()`); `reproduction()` and `safe_url()`; `occurrences()`. Tests: `test_reproduction_command_is_shell_inert`, `test_completed_assessment_ingests_unconfirmed_normalised_records` |
| Duplicate detection | ✅ | Fingerprint dedup across assessments and profiles with `detection_count`, `not_detected_count`, first/last seen. Test: `test_deduplicates_across_assessments_and_profiles` |
| False-positive management | ✅ | `decide()` creates `VulnerabilitySuppression` (future, at most 365 days); redetection reopens after expiry. Tests: `test_false_positive_suppression_carries_forward_then_expires`, `test_suppression_expiry_must_be_future_and_bounded`, `test_dismissal_needs_timezone_aware_expiry`, `test_reopen_revokes_suppression` |
| Human validation and analyst comments | ✅ | `decide()` (`TRANSITIONS`, `expected_revision`, intact-source check), `comment()`, `events()`; `POST /vulnerabilities/{id}/validation`, `/comments`. Tests: `test_confirmation_requires_attested_analyst_decision`, `test_confirmation_requires_intact_source_evidence`, `test_comments_and_history_are_append_only`. **Milestone 3 tightened this:** confirmation now also needs a saved risk assessment (see F). |
| Authentication and unknown records | ✅ | Router-level `get_current_admin`. Test: `test_authentication_and_unknown_records` |
| Frontend | ✅ | `VulnerabilitiesPage.jsx`, `lib/vulnerabilities.js`; `tests/vulnerabilities.test.js` |

## F. Security analyst workbench (Milestone 3: complete)

Service functions are in `backend/app/services/vulnerabilities.py` (extended, not rebuilt), routes in `backend/app/api/routes/workbench.py` (`/api/v1/workbench`), the role gate in `backend/app/core/rbac.py`, migration `0010_analyst_workbench`, UI in `frontend/src/WorkbenchPage.jsx` and `frontend/src/lib/workbench.js`.

| Sub-feature | Status | Evidence |
|---|---|---|
| Manual finding validation and review queue | ✅ | `GET /workbench/queue` (`queue()`): stages `needs_assessment`, `ready_for_signoff`, `report_eligible`, `dismissed`, `all`, with severity, website and search filters and per-stage counts. Test: `test_review_queue_stages_filters_and_counts` |
| Risk and business-impact assessment | ✅ | `POST /workbench/{id}/assessment` (`save_assessment()`): likelihood x business impact matrix (`calculate_rating()`), analyst override only with a recorded reason, business context, append-only versions bound to the vulnerability revision. Tests: `test_risk_matrix_is_deterministic`, `test_assessment_records_business_impact_and_remediation`, `test_override_needs_reason_and_reason_needs_override`, `test_invalid_assessments_rejected_without_writes`, `test_assessment_rejects_stale_revision_and_decided_records` |
| Tailored remediation recommendations | ✅ | `remediation` (min 20 characters) and `remediation_priority` are mandatory in every assessment version. Test: `test_assessment_records_business_impact_and_remediation` |
| Mandatory analyst sign-off gate | ✅ | `POST /workbench/{id}/signoff` (`signoff()` → `decide()`): approve requires a current assessment, reproduction steps, justification and attestation; the confirmed severity is the assessed rating; reject dismisses with a bounded suppression; reopen voids the sign-off and stales the assessment. The legacy `/vulnerabilities/{id}/validation` route is gated by the same check in `decide()`. Tests: `test_approval_is_impossible_without_a_current_assessment`, `test_legacy_validation_cannot_bypass_the_assessed_rating`, `test_attested_approval_confirms_and_makes_report_eligible`, `test_rejection_dismisses_with_suppression_and_is_never_report_eligible`, `test_reopening_revokes_eligibility_and_stales_the_assessment`, `test_concurrent_signoffs_only_one_wins` |
| VAPT report eligibility | ✅ | `report_eligible()` is true only while the record is confirmed **and** its latest sign-off is an approval bound to the current revision with a risk assessment. Tests: `test_eligibility_requires_the_signoff_to_match_the_current_revision`, queue stage `report_eligible`. The report itself is Milestone 4. |
| Immutable analyst decision history | ✅ | `VulnerabilitySignoff` ledger (analyst id, UTC time, prior and new state, justification, revision, assessment id) plus `VulnerabilityEvent`; `GET /workbench/{id}/audit` and `/signoffs` resolve analyst names. Append-only in the ORM (`before_update`/`before_delete`) **and** by SQLite triggers on `vulnerability_events`, `vulnerability_risk_assessments`, `vulnerability_signoffs`. Tests: `test_audit_trail_records_analyst_identity_time_states_and_justification`, `test_orm_blocks_rewriting_assessments_signoffs_and_events`, `test_database_triggers_block_raw_sql_rewrites`, `test_migration_installs_tables_and_immutability_triggers_preserving_data` |
| RBAC and session protection | ✅ | Every route depends on `require_analyst` (allow-list `ANALYST_ROLES`) on top of `get_current_admin` (signed token, `iss`/`aud`/`exp`/`jti`, active account). Tests: `test_every_workbench_route_rejects_unauthenticated_callers`, `test_workbench_rejects_tokens_for_other_roles_and_deactivated_analysts`, `test_role_allow_list_gates_every_workbench_route_and_writes_nothing`, `test_unknown_records_and_malformed_ids`. **M6:** three roles: `analyst` (assess, sign off, prepare reports, remediate, retest), `lead_analyst` (plus report approval, risk acceptance, closure and closure reopening) and `admin` (all, the bootstrap account); optional dual sign-off (below). `H::test_role_matrix_on_routes_that_need_a_senior_role`, `H::test_dual_signoff_blocks_self_approval_of_findings_reports_and_closure` |
| Safe handling of untrusted evidence | ✅ | API returns evidence as JSON only (`test_untrusted_text_is_stored_and_returned_as_inert_data`). The UI shows it as escaped text in `<pre>` through `safeText()` (control and bidi characters replaced, 20,000-character cap) with no `dangerouslySetInnerHTML`. Frontend tests: `untrusted evidence renders as escaped text, never as markup`, `safeText strips control and bidi characters…` |
| Frontend workbench | ✅ | `WorkbenchPage.jsx`: queue, evidence viewer, assessment form, sign-off form, audit trail. `tests/workbench.test.js` (9 tests: matrix, override rule, transitions, attestation, escaping, API paths) |

**Known limits.** Second-analyst approval is available but **off by default** (`SEPARATION_OF_DUTIES_ENABLED=false`) so a single bootstrap admin can operate the system; turn it on once two people hold roles (R14). Assessments cannot be edited, only superseded by a new version. The CVSS vector is not captured.

**Test evidence (2026-11-24):** 470 backend tests (`python -m pytest`), 31 frontend unit tests (`npm test`) and `npm run build` all passed.

## G. VAPT reporting (Milestone 4: complete)

Service functions are in `backend/app/services/reports.py`, routes in `backend/app/api/routes/reports.py` (`/api/v1/reports`), models in `backend/app/models/report.py`, migration `0011_vapt_reports`, role gates in `backend/app/core/rbac.py` (`require_report_role`, `require_report_approver`), UI in `frontend/src/ReportsPage.jsx` and `frontend/src/lib/reports.js`. PDFs are rendered with `reportlab` (pure Python, built-in Helvetica/Courier fonts, no GTK/Pango).

| Sub-feature | Status | Evidence |
|---|---|---|
| Report entity, versions and lifecycle | ✅ | `VaptReport` (`draft`, `pending_approval`, `approved`, `rejected`, `superseded`), per-assessment `revision`, frozen snapshot with `content_sha256` (`content_digest()`); `generate()` supersedes older open drafts, `decide()` supersedes an older approved report. `pending_approval` is reserved for Milestone 6 second-analyst review; today a draft is decided directly. Tests: `test_new_revision_supersedes_older_drafts_and_a_new_approval_supersedes_the_old_one`, `test_listing_filters_and_pagination` |
| Strict eligibility enforcement | ✅ | `gather()` includes a finding only if `vulnerabilities.report_eligible()` holds **and** its evidence hash re-verifies; everything else is counted by reason (`unassessed`, `unconfirmed`, `dismissed`, `stale_or_missing_signoff`, `evidence_integrity_failed`). A report with no eligible finding is refused (409). Tests: `test_only_report_eligible_findings_are_included_and_the_rest_counted`, `test_report_needs_an_eligible_finding_and_a_known_completed_assessment`, `test_tampered_evidence_is_excluded_from_the_report` |
| Executive summary | ✅ | `summarise()` builds a deterministic summary from validated counts (no free text from targets). Covered by `test_approval_publishes_an_official_pdf_with_matching_sha256` |
| Scope and methodology | ✅ | `_scope()` (client, website, exact target, authorised domains, methods, UTC window) and `_methodology()` (profile, request/redirect/body budgets, TLS version, isolation attestation and cleanup, source report SHA-256). The PDF states honestly when isolation is not attested or not applicable. Same test as above (section headings asserted in the PDF text) |
| Technical findings, severity and remediation | ✅ | Assessed rating, likelihood, impact, escaped evidence, evidence SHA-256, reproduction steps, analyst sign-off per finding, remediation grouped by priority. `render_pdf()`; `test_approval_publishes_an_official_pdf_with_matching_sha256` |
| PDF generation | ✅ | `render_pdf()`; `%PDF-` bytes, SHA-256 stored in `vapt_report_artifacts` and on the report; verified again on every download. Tests: `test_approval_publishes_an_official_pdf_with_matching_sha256`, `test_downloads_verify_the_stored_pdf_hash` |
| Untrusted data escaping | ✅ | `strip_controls()` at snapshot time (control, format and bidi characters removed, bounded), `pdf_text()` at render time (markup escaped, transcoded to Latin-1), `evidence_lines()` (evidence flattened to bounded JSON-escaped lines in a monospace style). No links or scripts are ever emitted. Tests: `test_hostile_evidence_and_names_render_as_inert_text`, `test_pdf_text_escapes_markup_and_removes_control_characters`, `test_strip_controls_bounds_length_and_flattens_single_line_fields` |
| Mandatory human approval gate | ✅ | `POST /reports/{id}/approve` and `/reject` need `human_validation_confirmed: true` and a justification (20-4000 characters). Approval re-verifies the snapshot hash and that every included finding is still eligible at the same revision and sign-off (`_still_eligible()`), then renders the official PDF. `GET /reports/{id}/pdf` returns 409 unless the report is approved; `GET /reports/{id}/preview` is a watermarked draft. Tests: `test_official_download_is_impossible_before_human_approval`, `test_rejection_is_final_and_never_releases_a_pdf`, `test_decision_requires_attested_justification`, `test_approval_is_refused_when_a_finding_changed_after_generation`, `test_approval_is_refused_when_the_snapshot_was_tampered_with` |
| Immutable approval and audit records | ✅ | `VaptReportApproval` (one decision per report, bound to the content and PDF hashes), `VaptReportEvent` (generated, previews, official downloads, approvals, rejections, supersessions; `GET /reports/{id}/events`). ORM guards plus SQLite triggers: frozen snapshot columns, no deletes, final statuses, write-once official hash, append-only artifacts, approvals and events. Tests: `test_audit_trail_records_generation_decisions_and_downloads`, `test_orm_and_database_block_rewriting_snapshots_history_and_final_states`, `test_migration_installs_report_tables_and_triggers_preserving_data` |
| Authentication and RBAC | ✅ | Router-level `require_report_role`; approve and reject also need `require_report_approver` (separate allow-lists, so Milestone 6 can split them). Tests: `test_every_report_route_rejects_unauthenticated_callers`, `test_forged_role_tokens_and_deactivated_admins_are_rejected`, `test_role_allow_lists_gate_reporting_and_approval_separately`, `test_unknown_reports_and_malformed_ids` |
| Frontend | ✅ | `ReportsPage.jsx`: eligible vs excluded counts before generating, report list, detail (summary, scope, findings, evidence as escaped text), approve/reject with attestation, draft preview and approval-gated official download, audit trail. `tests/reports.test.js` (9 tests: API paths and tokens, PDF routes, server refusal, download gating, decision gating, generation gating, assessment filter, labels and file names, escaped rendering) |

**Known limits.** With `SEPARATION_OF_DUTIES_ENABLED=false` (the default) one person can generate and approve the same report; when it is true, the generator cannot approve (`H::test_dual_signoff_blocks_self_approval_of_findings_reports_and_closure`, `E2E::test_full_lifecycle…`). Reports cover one assessment each, and there is no client-facing portal. PDFs use the built-in Latin-1 fonts, so characters outside Latin-1 in client or target text print as `?`. The PDF is stored in the database, not on the evidence volume.

## H. Remediation, retesting and closure (Milestone 5: complete)

Service functions are in `backend/app/services/remediation.py`, routes in `backend/app/api/routes/remediation.py` (`/api/v1/remediation`) plus `GET /assessments/{id}/closure` and `POST /assessments/{id}/close` in `api/routes/assessments.py`, models in `backend/app/models/remediation.py`, migration `0012_remediation_retesting`, role gates in `core/rbac.py` (`require_remediation_role`, `ensure_risk_acceptor`, `require_closure_role`), UI in `frontend/src/RemediationPage.jsx` and `frontend/src/lib/remediation.js`. The older observation-level fields (`remediation_status`, `FindingDueDate`, `retest_assessment_id`, `test_findings.py`) belong to Module D reviews and are unchanged; Module H tracks the confirmed `Vulnerability` entities from Modules E and F.

| Sub-feature | Status | Evidence |
|---|---|---|
| Remediation lifecycle per confirmed finding | ✅ | `VulnerabilityRemediation` (`open` is implicit until the first update), statuses `open`, `in_progress`, `fix_submitted`, `retest_requested`, `verified_fixed`, `reopened`, `risk_accepted`; `update_status()` with `MANUAL_TRANSITIONS` and optimistic `expected_version`. `retest_requested` and `verified_fixed` can only be reached through a retest. Tests: `test_confirmed_findings_start_open_and_status_changes_record_client_updates`, `test_illegal_transitions_stale_versions_and_unconfirmed_findings_are_refused`, `test_invalid_updates_are_rejected_without_writes` |
| Client notes, target dates and actor/UTC history | ✅ | Notes and target date (within 730 days) are stored on the record and in the append-only `RemediationEvent` ledger with actor, UTC time and from/to status (`add_event()`); `GET /remediation/{id}` returns the history. Tests: `test_confirmed_findings_start_open_and_status_changes_record_client_updates`, `test_hostile_notes_are_stored_as_inert_bounded_text` |
| Formal risk acceptance | ✅ | `risk_accepted` needs a 20-character justification, an explicit attestation and the separate `RISK_ACCEPTANCE_ROLES` allow-list; only a reopen leaves it. Tests: `test_risk_acceptance_needs_attestation_and_a_real_justification`, `test_role_allow_lists_gate_remediation_risk_acceptance_and_closure_separately` |
| Authorisation-gated retest requests | ✅ | `request_retest()` needs `fix_submitted`, an explicit request and network confirmation, and then calls the existing `assessments.create_request()`, so the live written authorisation, exact domain, methods, evidence, DNS pinning and the worker's execution-time revalidation apply unchanged; any denial is audited by that path and nothing is recorded. No local fallback, one retest at a time, at most 10 per finding. Tests: `test_retest_needs_a_submitted_fix_and_explicit_confirmation`, `test_retest_requests_revalidate_authorisation_scope_and_methods` (revoked, expired, out of scope, method not permitted, unknown authorisation), `test_retest_is_refused_when_the_website_target_no_longer_matches_the_finding`, `test_revocation_after_a_retest_request_fails_the_retest_closed`, `test_one_retest_at_a_time_and_a_retest_cannot_be_reopened_mid_flight` |
| Fix verification and automatic reopening | ✅ | `reconcile()` resolves a retest from its job and the scanner's stored, hash-checked occurrence: not detected → `verified_fixed`, detected → automatic `reopened` with the fresh occurrence and evidence hash linked, no applicable or tampered observation → `inconclusive` (back to `fix_submitted`), failed or cancelled job → `failed`. Only conclusive outcomes increment `retest_attempts`. It runs from the worker hook (`vulnerabilities.ingest_after_assessment` → `on_assessment_ingested()`) and lazily on reads. Tests: `test_a_retest_that_no_longer_detects_the_weakness_verifies_the_fix`, `test_a_retest_that_still_reproduces_reopens_with_fresh_evidence_and_counts_the_attempt`, `test_retest_waits_for_ingestion_then_resolves_through_the_worker_hook`, `test_a_retest_without_an_applicable_observation_is_inconclusive`, `test_retest_evidence_that_fails_its_hash_check_is_inconclusive_not_verified` |
| Manual analyst reopening | ✅ | `reopen()` from `verified_fixed`, `risk_accepted` or `fix_submitted` with a 20-character reason; refused while a retest is pending. Tests: `test_analysts_can_reopen_verified_accepted_and_submitted_findings_with_a_reason`, `test_open_findings_cannot_be_reopened` |
| Final assessment closure | ✅ | `closure_state()` / `close_assessment()`: every confirmed finding detected in the assessment must be `verified_fixed` or `risk_accepted` (blocked by `open`, `in_progress`, `fix_submitted`, `retest_requested`, `reopened`); attested justification; immutable `AssessmentClosure` with a status snapshot and SHA-256; cannot close twice. Detected findings an analyst has not yet reviewed do not block closure but are reported as `unreviewed_count`. Tests: `test_closure_is_blocked_while_confirmed_findings_are_unresolved`, `test_assessment_closes_once_every_confirmed_finding_is_verified_or_formally_accepted`, `test_closure_of_unknown_assessments_and_assessments_without_confirmed_findings` |
| Immutable audit records | ✅ | ORM guards plus SQLite triggers: append-only remediation events and closures, retest request columns frozen after the request, a finished retest's result is final, no deletes. Tests: `test_orm_and_database_block_rewriting_history_closures_and_finished_retests`, `test_migration_installs_remediation_tables_and_triggers_preserving_data` |
| Authentication, RBAC and sanitisation | ✅ | Router-level `require_remediation_role`; closure also needs `require_closure_role`; strict pydantic bodies (`extra="forbid"`), `strip_controls()` on every note. Tests: `test_every_remediation_and_closure_route_rejects_unauthenticated_callers`, `test_forged_role_tokens_and_deactivated_admins_are_rejected_without_writes`, `test_role_allow_lists_gate_remediation_risk_acceptance_and_closure_separately`, `test_unknown_findings_and_malformed_ids_and_filters`, `test_listing_filters_counts_search_and_pagination` |
| Closed-assessment lock (M6) | ✅ | While an assessment has an **active closure** (one with no reopening record), every finding detected in it is frozen: remediation updates, manual reopen, retest requests, sign-off decisions (approve, reject, reopen, legacy validation) and new risk assessments return 409; reading and append-only comments still work. `POST /assessments/{id}/reopen-closure` (lead analyst or admin, attested, ≥20-character reason) appends an immutable `assessment_closure_reopenings` record and lifts the lock; the closure row itself is never edited. A later closure is stored as `generation` 2, 3… (unique per assessment, so concurrent closers collide). `services/closure_lock.py`. `H::test_confirmed_findings_and_remediation_are_immutable_after_closure`, `H::test_closure_reopening_is_role_gated_attested_audited_and_unlocks_edits`, `H::test_an_assessment_can_be_closed_again_as_a_new_generation`, `H::test_closures_and_reopenings_cannot_be_rewritten`, `H::test_unreviewed_findings_detected_in_the_closed_assessment_are_locked_too`, `E2E::test_full_lifecycle…` (step 12) |
| Frontend | ✅ | `RemediationPage.jsx`: status filters and counts, remediation updates, retest request with authorisation choice, retest history and outcomes, manual reopen, closure panel with blocking reasons and (M6) a closure-reopening form. `tests/remediation.test.js` (10 tests: API paths and tokens, server refusals, allowed transitions, risk acceptance, retest gating, outcome labels, reopen, closure gating, blocking statuses, closure reopening) |

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
| R6 | A VM or runner crash can leave an orphaned analysis container | Low–Med | **Mitigated in code; needs runner redeploy (R4).** `GET /assessments/orphan-containers` (admin or lead analyst, audited, explicit button only) asks each runner for a label-scoped, read-only inventory and flags containers older than 120 s. Nothing is ever removed or pruned automatically; removal stays a manual, approved step. Tests: `test_nmap_inspection.py` |
| R7 | The HEAD broker runs on the Windows host, not in a container | Low | **Accepted by design.** Python `-I -S`, Windows Job Object limits, header-only parsing; `test_scanner_hardening.py`, `test_local_assessment.py` |
| R8 | The Nmap guard container runs as root with `NET_ADMIN` on a bridge network and is not covered by per-run inspection | Medium | **Mitigated in code; needs runner redeploy (R4).** The Nmap runner now inspects the guard and the scanner after create and before start, checking 17 properties each (no privileged mode, guard has exactly NET_ADMIN, scanner has no added capability and shares only the guard netns, read-only rootfs, resource limits, no mounts/devices/ports/host namespaces, labels, image). A mismatch fails closed and the container is never started. Runs report `isolation_verified`; older runners show as "not attested". The guard still needs root and NET_ADMIN by design |
| R9 | Evidence retention not enforced; deletion not a secure wipe | Medium | **Mitigated (M6).** Hardened expiry checks, overwrite-then-unlink purge, immutable audit hash, report-only retention CLI. Remaining: purging is operator-initiated, and overwrite is best effort on SSD/copy-on-write media (use BitLocker). `H::test_purge_*`, `H::test_retention_report_*`, `H::test_secure_erase_*`, `H::test_evidence_identity_hash_and_history_are_immutable_in_orm_and_database` |
| R10 | PDF reports without a publication approval gate | Medium (product) | **Closed (M4).** `test_reports.py` (human approval gate, hash-verified downloads) |
| R11 | Starlette/httpx test-client deprecation warning | Low | **Open (accepted).** One warning in the test run; upgrade in a maintenance pass |
| R12 | Real-target acceptance with genuine written authorisation not performed for the hardened build | Medium | **Open (user step).** See the manual steps below; cannot be done without a real authorised site |
| R13 | Single global assessment slot and 60-second cooldown limit throughput | Low | **Accepted for local use** |
| R14 | One person can both assess and approve (findings and reports) | Medium | **Mitigated (M6).** Roles `analyst` / `lead_analyst` / `admin` and configurable dual sign-off (`SEPARATION_OF_DUTIES_ENABLED`): the risk-assessment author cannot approve the finding and the report creator cannot approve the report. Default is **off** to keep single-admin bootstrap usable, so enable it once two people hold roles. `H::test_role_matrix_on_routes_that_need_a_senior_role`, `H::test_dual_signoff_blocks_self_approval_of_findings_reports_and_closure`, `H::test_separation_rule_is_a_runtime_switch_read_at_call_time`, `H::test_single_admin_bootstrap_still_runs_the_whole_workflow_by_default`, `E2E` |
| R15 | `verified_fixed` and closure need no second person | Low–Med | **Partly mitigated (M6).** With dual sign-off on, whoever updated remediation, accepted a risk or requested a retest for the assessment's findings cannot close it, and a closed assessment is locked until formally reopened with an audit record (`H::test_dual_signoff_…`, `H::test_confirmed_findings_and_remediation_are_immutable_after_closure`). Not built: a second-analyst sign-off on `verified_fixed` itself (scanner comparison remains the verifier) and a dashboard indicator for a retest stuck on failed ingestion |

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
| Migration | `0013` applied to a copy of the development database: version, data, triggers and `PRAGMA integrity_check` verified; `H::test_migration_0013_…` covers a 0012 → head upgrade with data |

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
| M1 — Scanner worker hardening (D) | Done | |
| M2 — Vulnerability management (E) | Done | M1 |
| M3 — Analyst workbench (F) | Done | M2 |
| M4 — VAPT reporting (G) | Done | M3 |
| M5 — Remediation, retesting and closure (H) | Done | M4 |
| M6 — Production hardening | Done: R1, R2, R3, R14, closed-assessment lock, evidence retention hardening, end-to-end test. Later milestone: R8 and R6 (see the Nmap inspection section). Not done: second-analyst sign-off on `verified_fixed`, stuck-ingestion indicator, client/website edit and archive | M3 |

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
| Not yet done | stuck-job recovery review after worker restart; VM runner redeploy and live verification of the new checks (user) |

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
