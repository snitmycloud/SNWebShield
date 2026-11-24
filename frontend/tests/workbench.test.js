import { afterEach, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { api } from "../src/lib/api.js";
import { allowedSignoffs, auditLine, buildAssessment, buildSignoff, calculateRating, safeText, stageLabel }
  from "../src/lib/workbench.js";

const NOW = new Date(2026, 10, 24, 12, 0, 0);
const unconfirmed = { revision: 2, validation_state: "unconfirmed", can_assess: true, can_approve: true, allowed_decisions: ["confirmed", "false_positive", "not_applicable"] };
const confirmed = { revision: 3, validation_state: "confirmed", can_assess: false, can_approve: false, allowed_decisions: ["unconfirmed"] };
const assessForm = { likelihood: "likely", business_impact: "major", business_context: "Customer portal with regulated data.",
  remediation: "Set the header at the CDN edge and verify with a HEAD request.", remediation_priority: "immediate" };
const signForm = { attested: true, justification: "Reviewed the stored evidence for the exact target." };
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

test("risk matrix matches the server and unknown values yield no rating", () => {
  assert.equal(calculateRating("rare", "negligible"), "informational");
  assert.equal(calculateRating("unlikely", "minor"), "low");
  assert.equal(calculateRating("possible", "moderate"), "medium");
  assert.equal(calculateRating("likely", "major"), "high");
  assert.equal(calculateRating("almost_certain", "severe"), "critical");
  assert.equal(calculateRating("certain", "severe"), null);
});

test("assessment defaults to the calculated rating and requires a reason to override", () => {
  const ok = buildAssessment(unconfirmed, assessForm);
  assert.equal(ok.payload.risk_rating, "high");
  assert.equal(ok.payload.override_reason, undefined);
  assert.equal(ok.payload.expected_revision, 2);
  const needs = buildAssessment(unconfirmed, { ...assessForm, risk_rating: "critical" });
  assert.match(needs.error, /override/);
  const overridden = buildAssessment(unconfirmed, { ...assessForm, risk_rating: "critical", override_reason: "Holds regulated customer data." + " ".repeat(2) });
  assert.equal(overridden.payload.risk_rating, "critical");
  assert.match(overridden.payload.override_reason, /^Holds regulated/);
});

test("assessment validates every field and refuses decided records", () => {
  assert.match(buildAssessment(unconfirmed, { ...assessForm, likelihood: "certain" }).error, /likelihood/i);
  assert.match(buildAssessment(unconfirmed, { ...assessForm, business_impact: "huge" }).error, /impact/i);
  assert.match(buildAssessment(unconfirmed, { ...assessForm, remediation_priority: "asap" }).error, /priority/i);
  assert.match(buildAssessment(unconfirmed, { ...assessForm, business_context: "short" }).error, /business context/i);
  assert.match(buildAssessment(unconfirmed, { ...assessForm, remediation: "  fix  " }).error, /remediation/i);
  assert.match(buildAssessment(confirmed, assessForm).error, /reopen/);
});

test("sign-off state transitions: approval is locked until an assessment exists", () => {
  assert.deepEqual(allowedSignoffs(unconfirmed), ["approve", "reject"]);
  assert.deepEqual(allowedSignoffs({ ...unconfirmed, can_approve: false }), ["reject"]);
  assert.deepEqual(allowedSignoffs(confirmed), ["reopen"]);
  assert.deepEqual(allowedSignoffs({ revision: 4, validation_state: "false_positive", allowed_decisions: ["unconfirmed"] }), ["reopen"]);
  assert.deepEqual(allowedSignoffs(null), []);
  const locked = { ...unconfirmed, can_approve: false };
  assert.match(buildSignoff(locked, { ...signForm, decision: "approve", reproduction_steps: "x".repeat(25) }, NOW).error, /not available/);
  assert.match(buildSignoff(confirmed, { ...signForm, decision: "approve", reproduction_steps: "x".repeat(25) }, NOW).error, /not available/);
});

test("approval and rejection need attestation, justification and their own required fields", () => {
  const steps = "Send one HEAD request and inspect the header.";
  assert.deepEqual(buildSignoff(unconfirmed, { ...signForm, decision: "approve", reproduction_steps: steps }, NOW).payload, {
    expected_revision: 2, decision: "approve", human_validation_confirmed: true,
    justification: signForm.justification, reproduction_steps: steps });
  assert.match(buildSignoff(unconfirmed, { ...signForm, attested: false, decision: "approve", reproduction_steps: steps }, NOW).error, /personally reviewed/);
  assert.match(buildSignoff(unconfirmed, { ...signForm, attested: "yes", decision: "approve", reproduction_steps: steps }, NOW).error, /personally reviewed/);
  assert.match(buildSignoff(unconfirmed, { ...signForm, justification: " short ", decision: "approve", reproduction_steps: steps }, NOW).error, /20 characters/);
  assert.match(buildSignoff(unconfirmed, { ...signForm, decision: "approve", reproduction_steps: "curl" }, NOW).error, /reproduction/i);
  const reject = buildSignoff(unconfirmed, { ...signForm, decision: "reject", rejection_outcome: "not_applicable", suppress_until: "2026-12-24" }, NOW);
  assert.equal(reject.payload.rejection_outcome, "not_applicable");
  assert.equal(new Date(reject.payload.suppress_until).getTime(), new Date(2026, 11, 24, 23, 59, 59).getTime());
  assert.equal(reject.payload.reproduction_steps, undefined);
  assert.match(buildSignoff(unconfirmed, { ...signForm, decision: "reject", rejection_outcome: "confirmed", suppress_until: "2026-12-24" }, NOW).error, /outcome/);
  assert.match(buildSignoff(unconfirmed, { ...signForm, decision: "reject", rejection_outcome: "false_positive", suppress_until: "2026-11-01" }, NOW).error, /future/);
  assert.deepEqual(buildSignoff(confirmed, { ...signForm, decision: "reopen", reproduction_steps: steps }, NOW).payload, {
    expected_revision: 3, decision: "reopen", human_validation_confirmed: true, justification: signForm.justification });
});

const HOSTILE = { header: "<script>alert(1)</script><img src=x onerror=alert(2)>", note: "a‮evil\u0007​" };

test("untrusted evidence renders as escaped text, never as markup", () => {
  const html = renderToStaticMarkup(createElement("pre", null, safeText(HOSTILE)));
  assert.ok(!html.includes("<script>") && !html.includes("<img"));
  assert.ok(html.includes("&lt;script&gt;") && html.includes("&lt;img src=x onerror=alert(2)&gt;"));
});

test("safeText strips control and bidi characters, bounds size and survives odd input", () => {
  const cleaned = safeText(HOSTILE);
  assert.ok(!/[‮\u0007​]/.test(cleaned));
  assert.match(safeText(HOSTILE.note), /^a�evil��$/);  // raw strings: replaced
  assert.ok(cleaned.includes("a�evil\\u0007�"));  // JSON-serialised objects: control chars already escaped
  const long = safeText("x".repeat(30), 10);
  assert.match(long, /^x{10}\n… truncated \(20 more characters\)$/);
  assert.equal(safeText(undefined), "");
  const cyclic = {}; cyclic.self = cyclic;
  assert.equal(safeText(cyclic), "[unserialisable evidence]");
  assert.equal(safeText("plain\nmultiline\ttext"), "plain\nmultiline\ttext");
});

test("labels and audit lines only use known vocabulary and never produce markup", () => {
  assert.equal(stageLabel("<b>x</b>"), "Unknown stage");
  assert.equal(stageLabel("report_eligible"), "Signed off · report eligible");
  assert.equal(auditLine({ sequence: 4, occurred_at: "2026-11-24T10:00:00+00:00", action: "validation_changed",
    from_state: "unconfirmed", to_state: "confirmed", actor_id: 7, actor_name: "Asha Analyst" }),
  "#4 · 2026-11-24T10:00:00+00:00 · validation changed · unconfirmed → confirmed · Asha Analyst");
  assert.match(auditLine({ sequence: 1, action: "detected_new", to_state: "unconfirmed", actor_id: null }), /new → unconfirmed · System/);
});

test("workbench API calls are authenticated, encode identifiers and use POST bodies", async () => {
  await api.workbenchQueue({ stage: "ready_for_signoff", search: "a&b", severity: "" }, 50);
  const url = new URL(calls[0][0]);
  assert.equal(url.pathname, "/api/v1/workbench/queue");
  assert.equal(url.searchParams.get("stage"), "ready_for_signoff");
  assert.equal(url.searchParams.get("search"), "a&b");
  assert.equal(url.searchParams.has("severity"), false);
  assert.equal(calls[0][1].headers.Authorization, "Bearer synthetic-unit-test-token");
  await api.workbenchDetail("../x");
  assert.equal(new URL(calls[1][0]).pathname, "/api/v1/workbench/..%2Fx");
  await api.saveWorkbenchAssessment("id-1", { likelihood: "rare" });
  assert.equal(new URL(calls[2][0]).pathname, "/api/v1/workbench/id-1/assessment");
  assert.equal(calls[2][1].method, "POST");
  await api.signoffWorkbench("id-1", { decision: "approve" });
  assert.equal(new URL(calls[3][0]).pathname, "/api/v1/workbench/id-1/signoff");
  assert.deepEqual(JSON.parse(calls[3][1].body), { decision: "approve" });
  await api.workbenchAudit("id-1");
  assert.equal(new URL(calls[4][0]).pathname, "/api/v1/workbench/id-1/audit");
});
