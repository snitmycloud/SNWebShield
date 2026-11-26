import { test } from "node:test";
import assert from "node:assert/strict";
import { GRADE_TONE, TABS, certificateView, gradeView, reportFields, reportGroups, riskText, scanDuration, severityRows } from "../src/lib/report.js";
import { MANUAL_REASON_MIN, manualReasonOk, manualTimeLeft, verificationView } from "../src/lib/account.js";

const f = (over = {}) => ({ fingerprint: `x${Math.random()}`, title: "t", severity: "high", confidence: "confirmed", group: "findings", ...over });

test("the grade chip shows score, grade and a tone; an incomplete scan says the score could be lower", () => {
  assert.deepEqual(gradeView({ score: 92, grade: "A", incomplete: false }), { score: 92, grade: "A", tone: "good", label: "92 / 100", note: "" });
  assert.equal(gradeView({ score: 55, grade: "D" }).tone, "warn");
  assert.equal(gradeView({ score: 12, grade: "F" }).tone, "bad");
  assert.match(gradeView({ score: 80, grade: "B", incomplete: true }).note, /incomplete scan, so the real score could be lower/);
  assert.equal(gradeView(null), null);
  assert.equal(gradeView({}), null);
  assert.deepEqual(Object.keys(GRADE_TONE), ["A", "B", "C", "D", "F"]);
});

test("counts by severity always list the four levels in order", () => {
  assert.deepEqual(severityRows({ counts: { critical: 1, high: 2, medium: 0, low: 5, info: 9 } }).map(r => [r.level, r.count]),
    [["critical", 1], ["high", 2], ["medium", 0], ["low", 5]]);
  assert.deepEqual(severityRows(undefined).map(r => r.count), [0, 0, 0, 0]);
});

test("the Risk line carries the severity and the CVE with its score", () => {
  assert.equal(riskText({ severity: "high", cve_id: "CVE-2021-23017", cvss_score: 7.7 }), "High (CVE-2021-23017, CVSS 7.7)");
  assert.equal(riskText({ severity: "low" }), "Low");
  assert.equal(riskText({ severity: "critical", cvss_score: 9.8 }), "Critical (CVSS 9.8)");
});

test("every finding shows Where, You have, You should have, Risk, Why it matters and How to fix, in that order, without empty rows", () => {
  const rows = reportFields(f({ location: "example.com:443", you_have: "nginx 1.18.0", you_should_have: "nginx 1.26 or later", why: "Old.", how_to_fix: "Update it." }));
  assert.deepEqual(rows.map(r => r.label), ["Where", "You have", "You should have", "Risk", "Why it matters", "How to fix"]);
  assert.deepEqual(reportFields(f({ location: "x", you_have: null, you_should_have: "  ", why: "", how_to_fix: undefined })).map(r => r.label), ["Where", "Risk"]);
});

test("the report groups Confirmed (Info last) and Needs checking; needs-checking items are never mixed into confirmed", () => {
  const list = [f({ title: "maybe", severity: "critical", confidence: "possible", group: "needs_checking" }), f({ title: "fyi", severity: "info" }),
    f({ title: "bad", severity: "high" }), f({ title: "ok", severity: "low" })];
  const { confirmed, needsChecking } = reportGroups(list);
  assert.deepEqual(confirmed.map(x => x.title), ["bad", "ok", "fyi"]);
  assert.deepEqual(needsChecking.map(x => x.title), ["maybe"]);
});

test("certificate expiry reads in plain words with a tone", () => {
  assert.equal(certificateView({ days_left: 90, expires_at: "2027-02-20T00:00:00+00:00" }).tone, "good");
  assert.equal(certificateView({ days_left: 20, expires_at: "2026-12-20T00:00:00+00:00" }).tone, "warn");
  assert.equal(certificateView({ days_left: 5, expires_at: "2026-12-01T00:00:00+00:00" }).text, "Expires on 2026-12-01 (5 days left)");
  assert.equal(certificateView({ days_left: 1, expires_at: "2026-11-27T00:00:00+00:00" }).text, "Expires on 2026-11-27 (1 day left)");
  assert.equal(certificateView({ days_left: -3, expires_at: "2026-11-01T00:00:00+00:00" }).text, "Expired on 2026-11-01");
  assert.equal(certificateView(null).tone, "muted");
  assert.match(certificateView(undefined).text, /Not available/);
});

test("scan duration is shown in seconds or minutes", () => {
  assert.equal(scanDuration({ started_at: "2026-11-26T10:00:00Z", ended_at: "2026-11-26T10:00:42Z" }), "42 seconds");
  assert.equal(scanDuration({ started_at: "2026-11-26T10:00:00Z", ended_at: "2026-11-26T10:03:00Z" }), "3 minutes");
  assert.equal(scanDuration({}), "");
});

test("the website page has exactly the four tabs in order", () => {
  assert.deepEqual(TABS.map(t => t.label), ["Monitor", "Detect", "Vulnerabilities", "Report"]);
});

// --- manual verification -----------------------------------------------------------------------------------------------------

test("a typed reason of at least 10 characters is required and shorter ones are refused", () => {
  assert.equal(MANUAL_REASON_MIN, 10);
  assert.equal(manualReasonOk("Owner present at demo and gave consent"), true);
  for (const bad of ["", "short", "         ", "x".repeat(301), null, undefined]) assert.equal(manualReasonOk(bad), false, String(bad));
  assert.equal(manualReasonOk("  ten chars!  "), true);
});

test("time left on a manual verification", () => {
  const now = Date.parse("2026-11-26T10:00:00Z");
  assert.equal(manualTimeLeft("2026-11-27T10:00:00Z", now), "24 hours left");
  assert.equal(manualTimeLeft("2026-11-26T11:30:00Z", now), "2 hours left");
  assert.equal(manualTimeLeft("2026-11-26T10:20:00Z", now), "20 minutes left");
  assert.equal(manualTimeLeft("2026-11-26T09:59:00Z", now), "expired");
  assert.equal(manualTimeLeft("garbage", now), "expired");
});

test("a manually verified website is labelled 'Manually verified by admin' and says it lasts 24 hours", () => {
  const now = Date.parse("2026-11-26T10:00:00Z");
  const view = verificationView({ verification_status: "verified", verification_method: "manual", manual_verification: { expires_at: "2026-11-27T10:00:00Z" } }, now);
  assert.equal(view.label, "Manually verified by admin");
  assert.equal(view.tone, "info");
  assert.match(view.text, /24 hours left/);
  assert.match(view.text, /verify with DNS, a file or a meta tag/);
  assert.equal(verificationView({ verification_status: "verified", verification_method: "dns" }).label, "Verified");
  assert.match(verificationView({ verification_status: "verified", verification_method: "test_target" }).text, /at most 10 scans per day/);
});

import { pdfAllowed } from "../src/lib/report.js";

test("the PDF button follows the plan setting pdf_report and an unknown plan never gets it", () => {
  assert.equal(pdfAllowed({ pdf_report: true }), true);
  assert.equal(pdfAllowed({ pdf_report: false }), false);
  assert.equal(pdfAllowed({}), false);
  assert.equal(pdfAllowed(null), false);
  assert.equal(pdfAllowed({ pdf_report: "yes" }), false);
});
