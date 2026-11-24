import { afterEach, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { api } from "../src/lib/api.js";
import { buildDecision, canDecide, canDownloadOfficial, canGenerate, eligibilitySummary, pdfFileName, reasonLabel,
  reportableAssessment, severityRows, shortHash, statusLabel } from "../src/lib/reports.js";
import { safeText } from "../src/lib/workbench.js";

const draft = { id: "0b2f6c1e-1111-4222-8333-444455556666", status: "draft", can_decide: true, can_download_official: false, official_pdf_sha256: null };
const approved = { ...draft, status: "approved", can_decide: false, can_download_official: true, official_pdf_sha256: "a".repeat(64) };
const form = { attested: true, justification: "Reviewed every finding and the evidence for this report." };
let calls;

beforeEach(() => {
  calls = [];
  const storage = new Map([["snwebshield_access_token", "synthetic-unit-test-token"],
    ["snwebshield_access_token_expiry", String(Date.now() + 60000)]]);
  globalThis.sessionStorage = { getItem: k => storage.get(k) ?? null, setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k) };
  globalThis.window = { dispatchEvent: () => {} };
  globalThis.fetch = async (url, options) => {
    calls.push([url, options]);
    return { ok: true, status: 200, text: async () => "{}", blob: async () => new Blob(["%PDF-1.4"]) };
  };
});
afterEach(() => api.logout());

test("report API calls hit the report routes with the bearer token and JSON bodies", async () => {
  await api.reportEligibility("abc 123");
  await api.generateReport("11111111-2222-4333-8444-555555555555");
  await api.reports({ status: "approved", assessment_id: "" }, 50);
  await api.report("r/1");
  await api.reportEvents("r1");
  await api.approveReport("r1", { human_validation_confirmed: true, justification: "x".repeat(20) });
  await api.rejectReport("r1", { human_validation_confirmed: true, justification: "y".repeat(20) });
  const paths = calls.map(([url]) => new URL(url).pathname + new URL(url).search);
  assert.deepEqual(paths, [
    "/api/v1/reports/eligibility?assessment_id=abc%20123", "/api/v1/reports",
    "/api/v1/reports?limit=50&offset=50&status=approved", "/api/v1/reports/r%2F1", "/api/v1/reports/r1/events?limit=100",
    "/api/v1/reports/r1/approve", "/api/v1/reports/r1/reject"]);
  assert.ok(calls.every(([, options]) => options.headers.Authorization === "Bearer synthetic-unit-test-token"));
  assert.equal(calls[1][1].method, "POST");
  assert.deepEqual(JSON.parse(calls[1][1].body), { assessment_id: "11111111-2222-4333-8444-555555555555" });
  assert.equal(JSON.parse(calls[5][1].body).human_validation_confirmed, true);
});

test("PDF downloads use separate authenticated routes for the draft preview and the official report", async () => {
  const preview = await api.downloadReportPdf("r1", false);
  const official = await api.downloadReportPdf("r1", true);
  assert.deepEqual(calls.map(([url]) => new URL(url).pathname), ["/api/v1/reports/r1/preview", "/api/v1/reports/r1/pdf"]);
  assert.ok(calls.every(([, options]) => options.headers.Authorization.startsWith("Bearer ")));
  assert.ok(preview instanceof Blob && official instanceof Blob);
});

test("server refusals such as an unapproved official download surface as errors", async () => {
  globalThis.fetch = async () => ({ ok: false, status: 409, text: async () => JSON.stringify({ detail: "Only an approved report can be downloaded as an official PDF" }) });
  await assert.rejects(api.downloadReportPdf("r1", true), /Only an approved report/);
});

test("the official download is offered only for an approved report with a recorded hash", () => {
  assert.equal(canDownloadOfficial(approved), true);
  for (const status of ["draft", "pending_approval", "rejected", "superseded"]) {
    assert.equal(canDownloadOfficial({ ...approved, status }), false, status);
  }
  assert.equal(canDownloadOfficial({ ...approved, official_pdf_sha256: null }), false);
  assert.equal(canDownloadOfficial({ ...approved, can_download_official: false }), false);
  assert.equal(canDownloadOfficial({ ...approved, can_download_official: "true" }), false);
  assert.equal(canDownloadOfficial(null), false);
});

test("approval gating: only undecided reports, with attestation and a justification, can be decided", () => {
  assert.deepEqual(buildDecision(draft, form), { payload: { human_validation_confirmed: true, justification: form.justification } });
  assert.match(buildDecision(draft, { ...form, attested: false }).error, /personally reviewed/);
  assert.match(buildDecision(draft, { ...form, justification: "too short" }).error, /20 characters/);
  assert.match(buildDecision(draft, { ...form, justification: " ".repeat(40) }).error, /20 characters/);
  assert.match(buildDecision(draft, { ...form, justification: "x".repeat(4001) }).error, /4000/);
  for (const status of ["approved", "rejected", "superseded"]) {
    assert.match(buildDecision({ ...draft, status }, form).error, /undecided/, status);
  }
  assert.equal(canDecide({ ...draft, can_decide: false }), false);
  assert.equal(canDecide({ ...draft, status: "pending_approval" }), true);
  assert.equal(buildDecision(draft, form).payload.attested, undefined);
});

test("generation is offered only when at least one finding is report eligible", () => {
  assert.equal(canGenerate({ can_generate: true, eligible_count: 2 }), true);
  assert.equal(canGenerate({ can_generate: false, eligible_count: 0 }), false);
  assert.equal(canGenerate({ can_generate: true, eligible_count: 0 }), false);
  assert.equal(canGenerate(null), false);
  assert.equal(eligibilitySummary({ eligible_count: 2, excluded_count: 6 }), "2 eligible · 6 excluded");
  assert.equal(eligibilitySummary(null), "");
});

test("only completed header assessments can be reported", () => {
  const row = { job: { status: "completed" }, mode: "remote_docker" };
  assert.equal(reportableAssessment(row), true);
  assert.equal(reportableAssessment({ ...row, mode: "local_http" }), true);
  assert.equal(reportableAssessment({ ...row, mode: "remote_nmap" }), false);
  assert.equal(reportableAssessment({ ...row, mode: "policy_only" }), false);
  assert.equal(reportableAssessment({ ...row, job: { status: "running" } }), false);
  assert.equal(reportableAssessment(undefined), false);
});

test("state rendering helpers use fixed vocabularies and safe file names", () => {
  assert.match(statusLabel("draft"), /awaiting human approval/);
  assert.match(statusLabel("approved"), /official/);
  assert.equal(statusLabel("<script>"), "Unknown status");
  assert.match(reasonLabel("unassessed"), /No risk assessment/);
  assert.equal(reasonLabel("<img>"), "Not eligible");
  assert.equal(pdfFileName(draft, true), `vapt-report-${draft.id}.pdf`);
  assert.match(pdfFileName(draft, false), /DRAFT-not-for-release\.pdf$/);
  assert.equal(pdfFileName({ id: "../../x\\y<z>" }, true), "vapt-report-.pdf");  // no path or markup characters survive
  assert.deepEqual(severityRows({ severity_counts: { critical: 1, low: 2 } }).map(r => r.count), [1, 0, 0, 2, 0]);
  assert.equal(shortHash("a".repeat(64)), `${"a".repeat(16)}…`);
  assert.equal(shortHash(null), "not recorded");
});

test("untrusted report text renders as escaped text, never as markup", () => {
  const hostile = "<img src=x onerror=alert(1)><script>steal()</script>‮\u0000";
  const markup = renderToStaticMarkup(createElement("pre", null, safeText({ note: hostile })));
  assert.ok(!markup.includes("<img") && !markup.includes("<script"), markup);
  assert.ok(markup.includes("&lt;img") && markup.includes("&lt;script&gt;"));
  assert.ok(!markup.includes("‮") && !markup.includes("\u0000"));
});
