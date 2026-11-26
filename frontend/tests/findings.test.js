import { test } from "node:test";
import assert from "node:assert/strict";
import { checksNotFinished, cvssText, emptyText, engineProgress, groupFindings, lifecycleTier, reasonText, severityCounts, sourceLabel, summaryText }
  from "../src/lib/findings.js";

let counter = 0;
const f = (over = {}) => ({ fingerprint: `fp${counter += 1}`, title: "t", severity: "high", confidence: "confirmed", group: "findings", scored: true, cvss_score: null, ...over });

test("confirmed findings are sorted by severity then score; possible ones go to Needs checking; info is separate", () => {
  const list = [f({ title: "low", severity: "low" }), f({ title: "crit", severity: "critical", cvss_score: 9.8 }), f({ title: "high9", severity: "high", cvss_score: 8.1 }),
    f({ title: "high7", severity: "high", cvss_score: 7.2 }), f({ title: "maybe", severity: "critical", confidence: "possible", group: "needs_checking", scored: false }),
    f({ title: "fyi", severity: "info" })];
  const g = groupFindings(list);
  assert.deepEqual(g.confirmed.map(x => x.title), ["crit", "high9", "high7", "low"]);
  assert.deepEqual(g.needsChecking.map(x => x.title), ["maybe"]);
  assert.deepEqual(g.info.map(x => x.title), ["fyi"]);
});

test("possible findings never count in the severity counts or the summary headline", () => {
  const list = [f({ severity: "critical", group: "needs_checking", confidence: "possible" }), f({ severity: "high" })];
  assert.deepEqual(severityCounts(list), { critical: 0, high: 1, medium: 0, low: 0 });
  assert.equal(summaryText(list), "1 finding (1 high); 1 needs your check");
  assert.equal(summaryText([f({ severity: "critical" }), f({ severity: "medium" }), f({ severity: "medium" })]), "3 findings (1 critical, 2 medium)");
});

test("no findings is worded as 'no findings from these checks', never 'safe' or 'clean'", () => {
  const done = { steps: { configuration: { state: "ok" }, vulnerabilities: { state: "ok" }, lifecycle: { state: "ok" } } };
  const text = summaryText([]) + " " + emptyText(done, false);
  assert.match(text, /No findings from these checks/);
  assert.match(text, /does not prove/);
  assert.doesNotMatch(text, /\b(is safe|are safe|clean|all clear|secure)\b/i);
});

test("when a check did not finish, an empty list is NOT presented as nothing found", () => {
  const unfinished = { steps: { configuration: { state: "ok" }, vulnerabilities: { state: "could_not_check", failed: [{ item: "OpenSSH 6.6.1p1", reason: "timeout" }] }, lifecycle: { state: "ok" } } };
  const text = emptyText(unfinished, false);
  assert.match(text, /did not finish/);
  assert.doesNotMatch(text, /No findings from these checks/);
  assert.equal(emptyText({ steps: {} }, true), "Checking…");
});

test("checks that did not finish are listed in plain words with the reason", () => {
  const result = { steps: {
    configuration: { state: "could_not_check", unchecked: ["TLSv1 on port 443"] },
    vulnerabilities: { state: "could_not_check", failed: [{ item: "Apache 2.4.7", source: "nvd", reason: "http_429" }, { item: "PHP 5.5.9", reason: "timeout", used_old_data: true }] },
    lifecycle: { state: "ok" } } };
  const rows = checksNotFinished(result);
  assert.deepEqual(rows.map(r => r.key), ["configuration", "vulnerabilities"]);
  assert.deepEqual(rows[0].details, ["TLSv1 on port 443: could not be checked"]);
  assert.match(rows[1].details[0], /Apache 2.4.7: the database asked us to slow down/);
  assert.match(rows[1].details[1], /older saved data was used/);
  assert.equal(checksNotFinished({ steps: { lifecycle: { state: "skipped" } } })[0].text, "Not run because the port check did not finish");
  assert.equal(checksNotFinished({ steps: { lifecycle: { state: "stopped" } } })[0].text, "Stopped before it finished");
  assert.deepEqual(checksNotFinished({ steps: {} }), []);
});

test("checks not run yet say 'Not checked yet' while running and 'Not checked' after a stop", () => {
  assert.equal(engineProgress({ steps: { configuration: { state: "ok" } } }, true).text, "Not checked yet.");
  assert.match(engineProgress({ steps: {} }, false).text, /^Not checked: the scan stopped/);
  assert.equal(engineProgress({ steps: { configuration: { state: "ok" }, vulnerabilities: { state: "ok" }, lifecycle: { state: "ok" } } }, false).notChecked, false);
});

test("the two end-of-life tiers use different wording", () => {
  assert.equal(lifecycleTier({ kind: "lifecycle", details: { tier: "ended" } }), "No longer receives security updates");
  assert.equal(lifecycleTier({ kind: "lifecycle", details: { tier: "paid_only" } }), "Only paid extended support remains");
  assert.equal(lifecycleTier({ kind: "vulnerability", details: {} }), null);
});

test("scores, sources and unknown reasons are shown safely", () => {
  assert.equal(cvssText({ cvss_score: 9.8, severity: "critical" }), "CVSS 9.8 (Critical)");
  assert.equal(cvssText({ cvss_score: null }), "");
  assert.equal(sourceLabel("nvd"), "NVD (US National Vulnerability Database)");
  assert.equal(sourceLabel("<script>"), "<script>");           // returned as text; React escapes it
  assert.equal(reasonText("something_new"), "the check did not finish");
});
