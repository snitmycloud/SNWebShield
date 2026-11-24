import test from "node:test";
import assert from "node:assert/strict";
import { runGate, defaultNote } from "../src/lib/runGate.js";

const ready = { profile_id: "p", network_execution: false, ready: true, authorization_id: 7 };
const net = { ...ready, profile_id: "n", network_execution: true };
const blocked = { profile_id: "b", network_execution: true, ready: false, authorization_id: null, reason: "The authorisation is expired or not yet valid (UTC dates)." };

test("no website or readiness result disables the action", () => {
  assert.equal(runGate({ site: "", readiness: [], profileId: "p" }).enabled, false);
  assert.equal(runGate({ site: "1", readiness: null, profileId: "p" }).enabled, false);
});
test("a blocked profile shows the server's exact reason and never enables", () => {
  const gate = runGate({ site: "1", readiness: [blocked], profileId: "b", attested: true });
  assert.equal(gate.enabled, false);
  assert.equal(gate.reason, blocked.reason);
});
test("a ready flag without an authorisation id is still rejected", () => {
  assert.equal(runGate({ site: "1", readiness: [{ ...ready, authorization_id: null }], profileId: "p" }).enabled, false);
});
test("network profiles need the attestation; preflight does not", () => {
  assert.equal(runGate({ site: "1", readiness: [net], profileId: "n", attested: false }).enabled, false);
  assert.equal(runGate({ site: "1", readiness: [net], profileId: "n", attested: true }).enabled, true);
  assert.equal(runGate({ site: "1", readiness: [ready], profileId: "p" }).enabled, true);
});
test("busy disables and unknown profile is rejected", () => {
  assert.equal(runGate({ site: "1", readiness: [ready], profileId: "p", busy: true }).enabled, false);
  assert.equal(runGate({ site: "1", readiness: [ready], profileId: "zzz" }).enabled, false);
});
test("default note meets the 20 character server minimum", () => {
  assert.ok(defaultNote("a.io", "X").length >= 20);
});
