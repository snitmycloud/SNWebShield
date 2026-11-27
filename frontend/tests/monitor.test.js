import { test } from "node:test";
import assert from "node:assert/strict";
import { parseHash, roleView, scheduleText, trendGeometry, trendSummary, uptimeView, workersSummary } from "../src/lib/monitor.js";

test("uptime says Up with the answer time and 30-day figure, Down since when, and never claims anything before the first check", () => {
  assert.deepEqual(uptimeView(null).label, "Not checked yet");
  assert.equal(uptimeView({ status: "unknown" }).tone, "muted");
  const up = uptimeView({ status: "up", response_ms: 120, uptime_30d: 100 });
  assert.equal(up.label, "Up");
  assert.match(up.text, /Answered in 120 ms/);
  assert.match(up.text, /100% over 30 days/);
  assert.match(uptimeView({ status: "up", response_ms: 9, uptime_30d: 99.5 }).text, /99\.50% over 30 days/);
  const down = uptimeView({ status: "down", down_since: "2026-11-27T10:00:00Z" });
  assert.equal(down.tone, "bad");
  assert.match(down.text, /Not answering since/);
});

test("the schedule text names the plan's rhythm and the next scan", () => {
  assert.match(scheduleText({ every_hours: 168, next_scan_at: "2026-12-01T10:00:00Z" }), /weekly.*Next one around/);
  assert.match(scheduleText({ every_hours: 24, next_scan_at: null }), /daily\.$/);
  assert.equal(scheduleText(null), "");
});

test("the trend needs two scans, draws one dot per scan and keeps scores inside the chart", () => {
  assert.equal(trendGeometry([{ score: 80 }]).enough, false);
  const geo = trendGeometry([{ score: 100, grade: "A" }, { score: 50, grade: "D" }, { score: 250, grade: "A" }, { score: -5, grade: "F" }], 560, 160, 10);
  assert.equal(geo.enough, true);
  assert.equal(geo.dots.length, 4);
  assert.ok(geo.dots.every(d => d.y >= 10 && d.y <= 150 && d.x >= 10 && d.x <= 550));
  assert.ok(geo.dots[0].y < geo.dots[1].y);   // a higher score is drawn higher up
  assert.match(geo.path, /^M[\d.]+ [\d.]+ L/);
});

test("the trend sentence compares the last two scans", () => {
  assert.equal(trendSummary([{ score: 70 }]), "The trend appears after two scans.");
  assert.equal(trendSummary([{ score: 70 }, { score: 83 }]), "Score up 13 points since the scan before.");
  assert.equal(trendSummary([{ score: 83 }, { score: 82 }]), "Score down 1 point since the scan before.");
  assert.equal(trendSummary([{ score: 83 }, { score: 83 }]), "Score unchanged since the scan before.");
});

test("links from alert emails open the website, the finding or the alert settings, and nothing else", () => {
  assert.deepEqual(parseHash("#/websites/12"), { page: "websites", openId: 12, finding: null });
  assert.deepEqual(parseHash("#/websites/12/findings/abc123"), { page: "websites", openId: 12, finding: "abc123" });
  assert.deepEqual(parseHash("#/settings/alerts/site_down_up"), { page: "settings", alert: "site_down_up" });
  assert.deepEqual(parseHash("#/settings"), { page: "settings", alert: null });
  for (const bad of ["", "#", "#/admin", "#/websites/x", "#/websites/", "#/../etc"]) assert.equal(parseHash(bad), null);
});

test("worker health uses plain words, shows restarts and never calls a silent role running", () => {
  assert.equal(roleView({ state: "running", restarts: 0 }).label, "Running");
  assert.equal(roleView({ state: "stale", age_seconds: 300 }).tone, "bad");
  assert.match(roleView({ state: "stale", age_seconds: 300 }).detail, /last sign of life 300s ago/);
  assert.match(roleView({ state: "running", restarts: 2 }).detail, /restarted 2 times/);
  assert.equal(roleView({ state: "not_started" }).label, "Not started");
  assert.equal(workersSummary({ healthy: true, roles: [] }), "All roles are running.");
  assert.equal(workersSummary({ healthy: false, roles: [{ state: "running" }, { state: "stale" }] }), "1 role(s) need attention.");
});

import { auditLine } from "../src/lib/audit.js";

test("audit lines show owner, consent and reason of a manual verification, and say so when an older entry did not record them", () => {
  const recorded = auditLine({ action: "manual_verification", detail: { recorded_details: true, owner_name: "Asha Rao", consent_label: "Email", reason: "She emailed her consent", admin: "a@example.com", expires_at: "2026-11-28T10:00:00Z" } });
  assert.equal(recorded.title, "Manually verified by an administrator");
  assert.ok(recorded.lines.includes("Owner or company: Asha Rao") && recorded.lines.includes("How consent was given: Email") && recorded.lines.includes("Reason: She emailed her consent"));
  assert.ok(recorded.lines.includes("Done by: a@example.com"));
  const old = auditLine({ action: "manual_verification", detail: { recorded_details: false, reason: "admin only" } });
  assert.match(old.lines[0], /were not recorded/);
  assert.ok(old.lines.includes("Done by: an administrator"));
  assert.equal(auditLine({ action: "something_new" }).title, "something new");
  assert.equal(auditLine({ action: "verification_reset", detail: { why: "not real proof" } }).tone, "warn");
});
