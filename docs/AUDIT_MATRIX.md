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
| Database | Alembic head is `0011_vapt_reports` after Milestone 4 (`0010_analyst_workbench` after Milestone 3). Pre-0011 backup: `backups/db-*-pre-0011/` (gitignored, integrity-checked). The development database file itself is migrated by the operator with `python -m alembic upgrade head` (see Milestone 4 manual steps). |

**Status legend.** ✅ Fully implemented and tested · 🟡 Partially implemented · 🧪 Implemented but not tested · ❌ Missing · 🔧 Broken or requiring improvement

Test paths are relative to `backend/tests/`. Module E and F test names below are real function names in `test_vulnerabilities.py` and `test_workbench.py`. Browser journeys are in `frontend/tests/e2e/authorization.spec.js`. All API routes are under `/api/v1`.

---

## A. Application foundation

| Sub-feature | Status | Evidence |
|---|---|---|
| React dashboard | ✅ | `frontend/src/App.jsx`, page components; 18 Playwright journeys; `npm run build` passes |
| FastAPI backend | ✅ | `backend/app/main.py`, `GET /health` (`test_api.py::test_health_endpoint`) |
| Admin authentication | ✅ | `POST /auth/login`, `GET /auth/me` (`api/routes/auth.py`); bcrypt plus constant-time unknown-user check; `test_auth.py` |
| JWT | ✅ | `core/security.py`: `iss`, `aud`, `nbf`, `exp` and `jti` required; 20-minute default; `test_auth_claims.py` (invalid claims, deactivated admin invalidates token) |
| Logout / session expiry | 🟡 | Client-side idle timer and expiry (`frontend/src/lib/api.js`; `api.test.js`, e2e "idle token expiry"). **No server-side revocation:** a token stays valid until `exp` after logout (R3, owned by Milestone 6). |
| Authentication audit logging | ❌ | Login success and failure are not recorded (`auth.py` only sets `last_login_at`). This breaks a CLAUDE.md invariant. See risk R1, owned by **Milestone 6 (Production Hardening)**. |
| Login brute-force protection | ❌ | No rate limiting or lockout (R2, owned by Milestone 6) |
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
| RBAC and session protection | ✅ | Every route depends on `require_analyst` (allow-list `ANALYST_ROLES`) on top of `get_current_admin` (signed token, `iss`/`aud`/`exp`/`jti`, active account). Tests: `test_every_workbench_route_rejects_unauthenticated_callers`, `test_workbench_rejects_tokens_for_other_roles_and_deactivated_analysts`, `test_role_allow_list_gates_every_workbench_route_and_writes_nothing`, `test_unknown_records_and_malformed_ids`. Only the `admin` role exists today; finer roles (and second-analyst approval) are tracked in Milestone 6. |
| Safe handling of untrusted evidence | ✅ | API returns evidence as JSON only (`test_untrusted_text_is_stored_and_returned_as_inert_data`). The UI shows it as escaped text in `<pre>` through `safeText()` (control and bidi characters replaced, 20,000-character cap) with no `dangerouslySetInnerHTML`. Frontend tests: `untrusted evidence renders as escaped text, never as markup`, `safeText strips control and bidi characters…` |
| Frontend workbench | ✅ | `WorkbenchPage.jsx`: queue, evidence viewer, assessment form, sign-off form, audit trail. `tests/workbench.test.js` (9 tests: matrix, override rule, transitions, attestation, escaping, API paths) |

**Known limits.** No second-analyst approval yet (one attested analyst can approve). Assessments cannot be edited, only superseded by a new version. The CVSS vector is not captured.

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

**Known limits.** One analyst can generate and approve the same report (R14, Milestone 6). Reports cover one assessment each, and there is no client-facing portal. PDFs use the built-in Latin-1 fonts, so characters outside Latin-1 in client or target text print as `?`. The PDF is stored in the database, not on the evidence volume.

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
| R1 | Authentication events (login success/failure, inactive-account attempts) are not audit-logged, against a CLAUDE.md invariant | **High** | Open. **Milestone 6 (Production Hardening).** Add an append-only auth event table without storing passwords or tokens. |
| R2 | No login rate limiting or lockout | Medium | Open. **Milestone 6 (Production Hardening).** |
| R3 | Logout is client-side; a stolen token stays valid up to 20 minutes | Medium | Open. **Milestone 6 (Production Hardening):** `jti` denylist on logout. |
| R4 | The installed VM header runner predates per-run isolation inspection | Medium | Mitigated in code. Redeploy manually, then set `ASSESSMENT_REMOTE_REQUIRE_ISOLATION_ATTESTATION=true`. |
| R5 | The SSH identity can use Docker on the VM, which is root-equivalent. A compromised Windows account means a compromised VM. | Medium | Key restricted with `restrict`. **Recommended:** add a `command="…"` forced-command wrapper in `authorized_keys` that allows only the two runner paths. |
| R6 | A VM or runner crash can leave an orphaned analysis container (cleanup unconfirmed) | Low–Med | Audited as unconfirmed. Roadmap: label-scoped orphan report (`com.snwebshield.runner`), never a broad prune. |
| R7 | The HEAD broker runs on the Windows host, not in a container | Low | By design: CLAUDE.md requires `--network none` for analysis, so the target request must be made elsewhere. Mitigated with Python `-I -S`, a Job Object (256 MiB, CPU cap), header-only parsing and a 32 KiB limit. |
| R8 | The Nmap guard container runs as root with `NET_ADMIN` on a bridge network (needed for its egress firewall) and is not covered by per-run inspection | Medium | Open. Milestone 6: extend inspection to `scanner/nmap/runner.py`. |
| R9 | Evidence retention is not enforced automatically; deletion is not a secure wipe | Medium | Open. Add a scheduled retention report. Recommend BitLocker on the evidence volume. |
| R10 | PDF or executive reports; no publication approval | Medium (product) | **Closed in Milestone 4.** Reports contain only eligible findings, an official PDF exists only after a human approval, and every download re-verifies its SHA-256. Residual risk is R14 (single analyst may generate and approve). |
| R14 | One analyst can both assess and approve (findings and reports); only the `admin` role exists | Medium | Open. Milestone 6: distinct analyst/reviewer roles, second-analyst approval for high and critical findings and for report approval (`pending_approval` is reserved for this). |
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

## Remaining roadmap

Each milestone follows the CLAUDE.md workflow: back up the database, add migrations, unit/API/security tests, frontend tests and a build, update this file and the README, and commit locally.

| Milestone | Scope | Depends on |
|---|---|---|
| M1 — Scanner worker hardening (D) | Done | |
| M2 — Vulnerability management (E) | Done | M1 |
| M3 — Analyst workbench (F) | Done | M2 |
| M4 — VAPT reporting (G) | Done | M3 |
| **M5 — Remediation and retesting (H)** | Retest request workflow tied to a fresh authorisation check; automatic before/after check comparison; client update log; engagement closure with a final report | M4 |
| **M6 — Production hardening** | **R1** auth audit log; **R2** login throttling; **R3** server-side logout (`jti` denylist); **R14** distinct analyst roles and second-analyst approval; R8 Nmap runner isolation inspection; R6 orphan-container report; R9 evidence retention report; client/website edit and archive with audit | M3 |
