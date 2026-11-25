import test from "node:test";
import assert from "node:assert/strict";
import { buildDisable, buildEnable, describeChange, intervalLabel, portState, watchStatus } from "../src/lib/portWatch.js";
import { portWatchLine } from "../src/lib/lifecycle.js";

const ready = { can_enable: true };
const good = { interval: 21600, attested: true };

test("enabling needs permission, a valid interval and the written-permission attestation", () => {
  assert.deepEqual(buildEnable(ready, good).payload,
    { interval_seconds: 21600, network_permission_confirmed: true, human_validation_confirmed: true });
  assert.equal(buildEnable({ can_enable: false, cannot_enable_reason: "The authorisation is expired or not yet valid (UTC dates)." }, good).error,
    "The authorisation is expired or not yet valid (UTC dates).");
  assert.match(buildEnable({ can_enable: false }, good).error, /Permission is not valid/);
  assert.match(buildEnable(null, good).error, /Permission is not valid/);
  for (const bad of [{ ...good, attested: false }, { ...good, interval: 60 }, { ...good, interval: 604801 }, { ...good, interval: "x" },
    { ...good, interval: 3600.5 }, { ...good, interval: undefined }]) assert.ok(buildEnable(ready, bad).error, JSON.stringify(bad));
});

test("disabling needs a real reason", () => {
  assert.deepEqual(buildDisable({ reason: "  Scanning window ended.  " }).payload, { reason: "Scanning window ended." });
  assert.ok(buildDisable({ reason: "short" }).error);
  assert.ok(buildDisable({}).error);
});

test("changes are described from fixed words and digit-only ports, never remote text", () => {
  assert.equal(describeChange({ changes: [{ port: "443", from: "closed", to: "open" }, { port: "80", from: null, to: "filtered" }] }),
    "TCP 443: closed → open · TCP 80: unknown → filtered");
  const hostile = describeChange({ changes: [{ port: "<b>8080</b>", from: "<script>", to: "open" }] });
  assert.doesNotMatch(hostile, /[<>]/);
  assert.equal(hostile, "TCP 8080: unknown → open");
  assert.equal(describeChange(null), "");
  assert.equal(portState("<x>"), "unknown");
});

test("status wording covers never enabled, paused, blocked and active", () => {
  assert.match(watchStatus({ configured: false }), /never been enabled/);
  assert.match(watchStatus({ configured: true, enabled: false }), /paused/);
  assert.match(watchStatus({ configured: true, enabled: true, state: "blocked", blocked_reason_text: "The authorisation is expired." }), /Blocked: The authorisation is expired\. It resumes/);
  assert.equal(watchStatus({ configured: true, enabled: true, state: "active" }), "Active.");
  assert.equal(intervalLabel(21600), "Every 6 hours");
  assert.equal(intervalLabel(7200), "Every 2 hours");
});

test("the lifecycle summary line reflects every port watch state", () => {
  assert.equal(portWatchLine(null), "Port watch is not enabled.");
  assert.equal(portWatchLine({ enabled: false }), "Port watch is paused.");
  assert.match(portWatchLine({ enabled: true, state: "blocked" }), /blocked/);
  assert.match(portWatchLine({ enabled: true, state: "active", last_outcome: "changed" }), /state changed/);
  assert.match(portWatchLine({ enabled: true, state: "active", last_outcome: null }), /waiting for the first run/);
  assert.doesNotMatch(portWatchLine({ enabled: true, state: "active", last_outcome: "<script>" }), /script/);
});
