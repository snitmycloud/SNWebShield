import { test } from "node:test";
import assert from "node:assert/strict";
import { ACCEPT_PERIODS, DEFAULT_ACCEPT_DAYS, changesText, groupFindings, reasonProblem, reviewSoon, severityCounts, stateOf, stateText } from "../src/lib/findings.js";
import { reportGroups } from "../src/lib/report.js";

let n = 0;
const f = (over = {}) => ({ fingerprint: `fp${n += 1}`, title: "t", severity: "high", confidence: "confirmed", group: "findings", ...over });

test("changes summary reads 'N new, N fixed, N unchanged' and mentions unconfirmed ones only when there are some", () => {
  assert.equal(changesText({ new: 2, fixed: 3, unchanged: 14, could_not_confirm: 0 }), "2 new, 3 fixed, 14 unchanged");
  assert.equal(changesText({ new: 0, fixed: 0, unchanged: 5, could_not_confirm: 2 }), "0 new, 0 fixed, 5 unchanged, 2 could not be confirmed");
  assert.equal(changesText(null), "");
});

test("fixed and accepted findings are listed apart and never counted", () => {
  const list = [f({ title: "open" }), f({ title: "acc", state: { status: "accepted", accepted: { until: "2026-12-01T00:00:00Z" } } }),
    f({ title: "fix", state: { status: "fixed", fixed_how: "recheck", fixed_at: "2026-11-02T10:00:00Z" } })];
  const g = groupFindings(list);
  assert.deepEqual(g.confirmed.map(x => x.title), ["open"]);
  assert.deepEqual(g.accepted.map(x => x.title), ["acc"]);
  assert.deepEqual(g.fixed.map(x => x.title), ["fix"]);
  assert.equal(severityCounts(list).high, 1);
  assert.equal(reportGroups(list).fixed.length, 1);
});

test("state text says how a fix was confirmed, until when a risk is accepted, and when it came back", () => {
  assert.equal(stateText(f({ state: { status: "fixed", fixed_how: "recheck", fixed_at: "2026-11-02T10:00:00Z" } })), "Fixed on 2026-11-02 (confirmed by a re-check)");
  assert.equal(stateText(f({ state: { status: "fixed", fixed_how: "full_scan", fixed_at: "2026-11-02T10:00:00Z" } })), "Fixed on 2026-11-02 (confirmed by a full scan)");
  assert.equal(stateText(f({ state: { status: "accepted", accepted: { until: "2027-01-05T00:00:00Z" } } })), "Accepted risk until 2027-01-05");
  assert.match(stateText(f({ state: { status: "open", reopened: true } })), /came back/);
  assert.equal(stateOf(f()), "open");
  assert.equal(reviewSoon(f({ state: { status: "accepted", accepted: { review_soon: true } } })), true);
  assert.equal(reviewSoon(f({ state: { status: "open" } })), false);
});

test("risk acceptance offers 30, 90, 180 and 365 days (90 by default) and a reason of 10 to 300 characters", () => {
  assert.deepEqual(ACCEPT_PERIODS, [30, 90, 180, 365]);
  assert.equal(DEFAULT_ACCEPT_DAYS, 90);
  assert.ok(reasonProblem("short"));
  assert.equal(reasonProblem("Handled by our WAF."), "");
  assert.ok(reasonProblem("x".repeat(301)));
});
