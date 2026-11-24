import { afterEach, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { api } from "../src/lib/api.js";
import { buildDecision, confidenceSummary, decisionLabel, stateLabel, suppressionExpiry } from "../src/lib/vulnerabilities.js";

const NOW = new Date(2026, 10, 24, 12, 0, 0);
const unconfirmed = { revision: 3, allowed_decisions: ["confirmed", "false_positive", "not_applicable"] };
const base = { attested: true, justification: "Inspected stored evidence for the exact target." };
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

test("confirmation needs attestation, justification, severity and reproduction steps", () => {
  const form = { ...base, decision: "confirmed", severity: "high", reproduction_steps: "Send one HEAD and inspect the header." };
  assert.deepEqual(buildDecision(unconfirmed, form, NOW).payload, {
    expected_revision: 3, decision: "confirmed", human_validation_confirmed: true,
    justification: base.justification, severity: "high", reproduction_steps: form.reproduction_steps });
  assert.match(buildDecision(unconfirmed, { ...form, attested: false }, NOW).error, /personally validated/);
  assert.match(buildDecision(unconfirmed, { ...form, attested: "true" }, NOW).error, /personally validated/);
  assert.match(buildDecision(unconfirmed, { ...form, justification: "  short  " }, NOW).error, /20 characters/);
  assert.match(buildDecision(unconfirmed, { ...form, severity: "urgent" }, NOW).error, /severity/);
  assert.match(buildDecision(unconfirmed, { ...form, reproduction_steps: "curl" }, NOW).error, /reproduction/);
});

test("decisions outside the server-provided transitions are refused", () => {
  const confirmed = { revision: 4, allowed_decisions: ["unconfirmed"] };
  assert.match(buildDecision(confirmed, { ...base, decision: "false_positive", suppress_until: "2026-12-01" }, NOW).error, /not available/);
  assert.deepEqual(buildDecision(confirmed, { ...base, decision: "unconfirmed", severity: "high" }, NOW).payload, {
    expected_revision: 4, decision: "unconfirmed", human_validation_confirmed: true, justification: base.justification });
});

test("dismissals require a bounded future suppression expiry", () => {
  const ok = buildDecision(unconfirmed, { ...base, decision: "false_positive", suppress_until: "2026-12-24" }, NOW);
  assert.equal(new Date(ok.payload.suppress_until).getTime(), new Date(2026, 11, 24, 23, 59, 59).getTime());
  assert.equal(ok.payload.severity, undefined);
  assert.match(suppressionExpiry("", NOW).error, /Choose/);
  assert.match(suppressionExpiry("2026-02-30", NOW).error, /valid date/);
  assert.match(suppressionExpiry("2026-11-23", NOW).error, /future/);
  assert.match(suppressionExpiry("2027-12-01", NOW).error, /365/);
  assert.ok(suppressionExpiry("2026-11-24", NOW).value);
});

test("labels and confidence text only use known vocabulary", () => {
  assert.equal(stateLabel("<b>x</b>"), "Unknown state");
  assert.equal(decisionLabel("delete"), "Unknown decision");
  assert.equal(confidenceSummary({ confidence: "high", confidence_score: 85, confidence_factors: [
    { factor: "check_reliability", effect: 80 }, { factor: "repeated_detection", effect: 5 }, { factor: 7, effect: "x" }] }),
  "high (85/100) — check reliability +80, repeated detection +5");
});

test("vulnerability API calls are authenticated and encode identifiers", async () => {
  await api.getVulnerabilities({ state: "unconfirmed", suppressed: "", search: "a&b" }, 50);
  const url = new URL(calls[0][0]);
  assert.equal(url.pathname, "/api/v1/vulnerabilities");
  assert.equal(url.searchParams.get("search"), "a&b");
  assert.equal(url.searchParams.has("suppressed"), false);
  assert.equal(calls[0][1].headers.Authorization, "Bearer synthetic-unit-test-token");
  await api.vulnerabilityHistory("../admin", "anything-else");
  assert.equal(new URL(calls[1][0]).pathname, "/api/v1/vulnerabilities/..%2Fadmin/events");
  await api.decideVulnerability("id-1", { decision: "unconfirmed" });
  assert.equal(calls[2][1].method, "POST");
  assert.deepEqual(JSON.parse(calls[2][1].body), { decision: "unconfirmed" });
  await api.ingestVulnerabilities();
  assert.deepEqual(JSON.parse(calls[3][1].body), {});
});
