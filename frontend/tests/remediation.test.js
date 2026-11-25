import { afterEach, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { api } from "../src/lib/api.js";
import { buildClosure, buildClosureReopening, buildReopen, buildRetest, buildUpdate, canClose, closureSummary, isBlocking, outcomeLabel,
  reportableAssessment, statusLabel, updateOptions } from "../src/lib/remediation.js";

const open = { vulnerability_id: "v1", status: "open", version: 0, allowed_statuses: ["fix_submitted", "in_progress", "risk_accepted"],
  can_request_retest: false, can_reopen: false };
const submitted = { ...open, status: "fix_submitted", version: 2, allowed_statuses: ["in_progress", "risk_accepted"],
  can_request_retest: true, can_reopen: true };
const retestForm = { authorization_id: "7", note: "Verify the CDN header change on the exact target.", confirmed: true };
let calls;

beforeEach(() => {
  calls = [];
  const storage = new Map([["snwebshield_access_token", "synthetic-unit-test-token"],
    ["snwebshield_access_token_expiry", String(Date.now() + 60000)]]);
  globalThis.sessionStorage = { getItem: k => storage.get(k) ?? null, setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k) };
  globalThis.window = { dispatchEvent: () => {} };
  globalThis.fetch = async (url, options) => { calls.push([url, options]); return { ok: true, status: 200, text: async () => "{}" }; };
});
afterEach(() => api.logout());

test("remediation API calls are authenticated, encode identifiers and use POST bodies", async () => {
  await api.remediationList({ status: "reopened", website_id: "", search: "csp" }, 50);
  await api.remediation("a/b");
  await api.updateRemediation("v1", { expected_version: 0, status: "in_progress", note: "x".repeat(10) });
  await api.reopenRemediation("v1", { expected_version: 3, reason: "y".repeat(20) });
  assert.equal(api.requestRetest, undefined);  // legacy retests were retired in Phase 1
  await api.assessmentClosure("as 1");
  await api.closeAssessment("as1", { human_validation_confirmed: true, justification: "z".repeat(20) });
  const paths = calls.map(([url]) => new URL(url).pathname + new URL(url).search);
  assert.deepEqual(paths, ["/api/v1/remediation?limit=50&offset=50&status=reopened&search=csp", "/api/v1/remediation/a%2Fb",
    "/api/v1/remediation/v1/update", "/api/v1/remediation/v1/reopen",
    "/api/v1/assessments/as%201/closure", "/api/v1/assessments/as1/close"]);
  assert.ok(calls.every(([, options]) => options.headers.Authorization === "Bearer synthetic-unit-test-token"));
  assert.equal(calls.filter(([, options]) => options.method === "POST").length, 3);  // update, reopen, close
  assert.equal(JSON.parse(calls[5][1].body).human_validation_confirmed, true);
});

test("server refusals such as a retired action or closure surface as errors", async () => {
  globalThis.fetch = async () => ({ ok: false, status: 410, text: async () => JSON.stringify({ detail: "This older feature is now read-only." }) });
  await assert.rejects(api.updateRemediation("v1", {}), /now read-only/);
  globalThis.fetch = async () => ({ ok: false, status: 409, text: async () => JSON.stringify({ detail: "Cannot close: 1 confirmed finding(s) are unresolved" }) });
  await assert.rejects(api.closeAssessment("a", {}), /Cannot close/);
});

test("status updates only offer the server's allowed transitions and never verify or request retests by hand", () => {
  assert.deepEqual(updateOptions(open), ["fix_submitted", "in_progress", "risk_accepted"]);
  assert.deepEqual(updateOptions({ allowed_statuses: ["verified_fixed", "retest_requested", "in_progress"] }), ["in_progress"]);
  assert.deepEqual(updateOptions({ status: "retest_requested", allowed_statuses: [] }), []);
  assert.deepEqual(updateOptions(null), []);
  const ok = buildUpdate(open, { status: "in_progress", note: "Ticket OPS-12 opened.", target_date: "2026-12-30" });
  assert.deepEqual(ok.payload, { expected_version: 0, status: "in_progress", note: "Ticket OPS-12 opened.", target_date: "2026-12-30" });
  assert.match(buildUpdate(open, { status: "verified_fixed", note: "Looks fixed to me." }).error, /not allowed/);
  assert.match(buildUpdate(open, { status: "in_progress", note: "short" }).error, /10 characters/);
  assert.match(buildUpdate(open, { status: "in_progress", note: "x".repeat(4001) }).error, /4000/);
  assert.equal(buildUpdate(open, { status: "in_progress", note: "A valid remediation note." }).payload.target_date, undefined);
});

test("risk acceptance needs a longer justification and an explicit attestation", () => {
  const note = "Business owner accepts the residual risk until the platform migration.";
  assert.match(buildUpdate(open, { status: "risk_accepted", note: "Accepted for now." }).error, /20 characters/);
  assert.match(buildUpdate(open, { status: "risk_accepted", note }).error, /formally accepts/);
  assert.deepEqual(buildUpdate(open, { status: "risk_accepted", note, attested: true }).payload,
    { expected_version: 0, status: "risk_accepted", note, human_validation_confirmed: true });
});

test("retest state handling: only a submitted fix without a pending retest can be retested", () => {
  assert.match(buildRetest(open, retestForm).error, /submitted fix/);
  assert.match(buildRetest({ ...submitted, can_request_retest: false, active_retest_id: "r1" }, retestForm).error, /already in progress|submitted fix/);
  assert.match(buildRetest(submitted, { ...retestForm, authorization_id: "" }).error, /authorisation/);
  assert.match(buildRetest(submitted, { ...retestForm, confirmed: false }).error, /Explicitly request/);
  assert.match(buildRetest(submitted, { ...retestForm, note: "short" }).error, /20 characters/);
  assert.deepEqual(buildRetest(submitted, retestForm).payload, { expected_version: 2, authorization_id: 7, note: retestForm.note,
    explicitly_requested: true, network_permission_confirmed: true });
});

test("retest outcomes are described from a fixed vocabulary, including auto-reopen", () => {
  assert.match(outcomeLabel({ status: "completed", outcome: "verified_fixed" }), /Verified fixed/);
  assert.match(outcomeLabel({ status: "completed", outcome: "still_present" }), /reopened automatically/);
  assert.match(outcomeLabel({ status: "completed", outcome: "inconclusive" }), /Inconclusive/);
  assert.match(outcomeLabel({ status: "requested" }), /Waiting/);
  assert.match(outcomeLabel({ status: "failed", failure_code: "<script>" }), /no target evidence/);
  assert.equal(outcomeLabel({ status: "completed", outcome: "<img>" }), "Unknown outcome");
  assert.equal(statusLabel("<script>"), "Unknown status");
  assert.equal(statusLabel("reopened"), "Reopened");
  assert.equal(outcomeLabel(null), "");
});

test("manual reopening needs a reopenable finding and a real reason", () => {
  assert.match(buildReopen(open, { reason: "The fix was rolled back during release." }).error, /Only verified/);
  assert.match(buildReopen(submitted, { reason: "too short" }).error, /20 characters/);
  assert.deepEqual(buildReopen(submitted, { reason: "The fix was rolled back during release." }).payload,
    { expected_version: 2, reason: "The fix was rolled back during release." });
});

test("closure gating: blocked until the server reports no unresolved confirmed findings", () => {
  const blocked = { closed: false, can_close: false, blockers: [{ vulnerability_id: "v1", status: "open" }],
    blocking_reasons: ["1 confirmed finding(s) are unresolved (1 open)."] };
  const ready = { closed: false, can_close: true, blockers: [] };
  const form = { attested: true, justification: "All confirmed findings are verified or formally accepted." };
  assert.equal(canClose(blocked), false);
  assert.equal(canClose({ ...ready, blockers: [{}] }), false);  // blockers always win, even over a stale flag
  assert.equal(canClose({ ...ready, closed: true }), false);
  assert.equal(canClose(ready), true);
  assert.equal(canClose(null), false);
  assert.match(buildClosure(blocked, form).error, /Resolve every blocking finding/);
  assert.match(buildClosure({ ...ready, closed: true, can_close: false }, form).error, /already closed/);
  assert.match(buildClosure(ready, { ...form, attested: false }).error, /reviewed the final/);
  assert.match(buildClosure(ready, { ...form, justification: "short" }).error, /20 characters/);
  assert.deepEqual(buildClosure(ready, form).payload, { human_validation_confirmed: true, justification: form.justification });
  assert.deepEqual([closureSummary(blocked), closureSummary(ready), closureSummary({ closed: true })], ["Blocked", "Ready to close", "Closed"]);
});

test("blocking statuses and reportable assessments follow the server's rules", () => {
  for (const status of ["open", "in_progress", "fix_submitted", "retest_requested", "reopened"]) assert.equal(isBlocking(status), true, status);
  for (const status of ["verified_fixed", "risk_accepted"]) assert.equal(isBlocking(status), false, status);
  assert.equal(reportableAssessment({ job: { status: "completed" } }), true);
  assert.equal(reportableAssessment({ job: { status: "running" } }), false);
  assert.equal(reportableAssessment(undefined), false);
});

test("reopening a closure needs an active closure, an attestation and a real reason", async () => {
  const closed = { closed: true, can_close: false };
  const form = { attested: true, justification: "The client supplied new information about the fix." };
  assert.match(buildClosureReopening({ closed: false }, form).error, /no active closure/);
  assert.match(buildClosureReopening(null, form).error, /no active closure/);
  assert.match(buildClosureReopening(closed, { ...form, attested: false }).error, /deliberately/);
  assert.match(buildClosureReopening(closed, { ...form, justification: "short" }).error, /20 characters/);
  assert.deepEqual(buildClosureReopening(closed, form).payload, { human_validation_confirmed: true, justification: form.justification });
  await api.reopenClosure("as 1", buildClosureReopening(closed, form).payload);
  const [url, options] = calls.at(-1);
  assert.equal(new URL(url).pathname, "/api/v1/assessments/as%201/reopen-closure");
  assert.equal(options.method, "POST");
  assert.equal(options.headers.Authorization, "Bearer synthetic-unit-test-token");
});

test("fix verification needs a pending verified fix, a decision, a real note and attestation", async () => {
  const { buildFixVerification } = await import("../src/lib/remediation.js");
  const item = { version: 4, fix_verification: { applicable: true, state: "pending", required: true } };
  const good = { decision: "confirmed", note: "I reviewed the stored retest evidence and the header is present.", attested: true };
  assert.deepEqual(buildFixVerification(item, good).payload,
    { expected_version: 4, decision: "confirmed", note: good.note, human_validation_confirmed: true });
  assert.equal(buildFixVerification(item, { ...good, decision: "rejected" }).payload.decision, "rejected");
  for (const bad of [{ ...good, decision: "maybe" }, { ...good, note: "short" }, { ...good, attested: false }, { ...good, note: "   " }]) {
    assert.ok(buildFixVerification(item, bad).error, JSON.stringify(bad));
  }
  for (const other of [null, {}, { fix_verification: { applicable: false } }, { fix_verification: { applicable: true, state: "confirmed" } }]) {
    assert.match(buildFixVerification(other, good).error, /no verified fix/);
  }
});
