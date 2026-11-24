import { afterEach, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { api } from "../src/lib/api.js";

const tokenKey = "snwebshield_access_token";
const expiryKey = "snwebshield_access_token_expiry";
let storage, events, calls;

function response(payload, status = 200) {
  return { ok: status < 400, status, text: async () => JSON.stringify(payload) };
}

function session() {
  storage.set(tokenKey, "synthetic-unit-test-token");
  storage.set(expiryKey, String(Date.now() + 60000));
}

beforeEach(() => {
  storage = new Map(); events = []; calls = [];
  globalThis.sessionStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
    removeItem: key => storage.delete(key),
  };
  globalThis.window = { dispatchEvent: event => events.push(event.type) };
  globalThis.fetch = async (url, options) => { calls.push([url, options]); return response({ id: 1 }); };
});

afterEach(() => api.logout());

test("locally expired sessions notify App and do not send a protected request", async () => {
  session(); storage.set(expiryKey, String(Date.now() - 1));
  await assert.rejects(api.getCurrentAdmin(), /expired/);
  assert.equal(storage.has(tokenKey), false);
  assert.ok(events.includes("snwebshield:session-expired"));
  assert.equal(calls.length, 0);
});

test("protected 401 clears session and notifies App", async () => {
  session();
  globalThis.fetch = async () => response({ detail: "Credentials expired" }, 401);
  await assert.rejects(api.getCurrentAdmin(), /Credentials expired/);
  assert.equal(api.hasSession(), false);
  assert.ok(events.includes("snwebshield:session-expired"));
});

test("invalid or missing expiry is not accepted", () => {
  for (const expiry of ["invalid", "", "0"]) {
    session(); storage.set(expiryKey, expiry);
    assert.equal(api.hasSession(), false);
  }
});

test("idle timer expires a saved session without an API request", async () => {
  globalThis.fetch = async () => response({ access_token: "synthetic-unit-token", expires_in: 0.02 });
  await api.login({ email: "synthetic@example.com", password: "synthetic-password" });
  await new Promise(resolve => setTimeout(resolve, 60));
  assert.equal(storage.has(tokenKey), false);
  assert.ok(events.includes("snwebshield:session-expired"));
});

test("failed login does not signal expiry or save a token", async () => {
  globalThis.fetch = async () => response({ detail: "Incorrect email or password" }, 401);
  await assert.rejects(api.login({}), /Incorrect email or password/);
  assert.equal(events.length, 0);
  assert.equal(storage.size, 0);
});

test("lists retrieve all pages beyond 100 and retain filters", async () => {
  session();
  globalThis.fetch = async url => {
    calls.push(url);
    const offset = Number(new URL(url).searchParams.get("offset"));
    return response(Array.from({ length: offset === 0 ? 100 : 5 }, (_, i) => ({ id: offset + i })));
  };
  const rows = await api.getAuthorizations({ websiteId: 7, status: "pending" });
  assert.equal(rows.length, 105);
  assert.equal(calls.length, 2);
  assert.equal(new URL(calls[1]).searchParams.get("website_id"), "7");
  assert.equal(new URL(calls[1]).searchParams.get("status"), "pending");
});

test("public health check works without a session", async () => {
  await api.health();
  assert.equal(calls[0][1].headers.Authorization, undefined);
});

test("late successful responses cannot restore data after logout", async () => {
  session();
  let finish;
  globalThis.fetch = () => new Promise(resolve => { finish = resolve; });
  const pending = api.getCurrentAdmin();
  api.logout();
  finish(response({ id: 1 }));
  await assert.rejects(pending, /session has changed/);
});

test("network errors preserve a still-valid session", async () => {
  session();
  globalThis.fetch = async () => { throw new TypeError("Synthetic connection failure"); };
  await assert.rejects(api.getCurrentAdmin(), /Cannot reach/);
  assert.equal(api.hasSession(), true);
  assert.equal(events.length, 0);
});


test("monitoring management authenticates POST requests and history preserves pagination", async () => {
  session();
  const payload = { evidence_id: "synthetic-document", monitoring_permission_reviewed: true };
  await api.configureMonitoring(7, payload);
  assert.equal(new URL(calls[0][0]).pathname, "/api/v1/websites/7/monitoring/configure");
  assert.equal(calls[0][1].method, "POST");
  assert.equal(calls[0][1].headers.Authorization, "Bearer synthetic-unit-test-token");
  assert.deepEqual(JSON.parse(calls[0][1].body), payload);
  await api.monitoringHistory(7, "attempts", 50);
  const historyURL = new URL(calls[1][0]);
  assert.equal(historyURL.pathname, "/api/v1/websites/7/monitoring/attempts");
  assert.equal(historyURL.searchParams.get("offset"), "50");
  assert.equal(historyURL.searchParams.get("limit"), "50");
  await api.stopMonitoring();
  assert.equal(new URL(calls[2][0]).pathname, "/api/v1/monitoring/stop");
  assert.equal(calls[2][1].method, "POST");
});


test("assessment requests preserve explicit intent, identity and cancellation reasons", async () => {
  session();
  const payload = { website_id: 7, authorization_id: 9, profile_id: "authorization-preflight-v1", explicitly_requested: true, idempotency_key: "synthetic-key", note: "Synthetic preflight request." };
  await api.requestAssessment(payload);
  assert.equal(new URL(calls[0][0]).pathname, "/api/v1/assessments");
  assert.equal(calls[0][1].method, "POST");
  assert.deepEqual(JSON.parse(calls[0][1].body), payload);
  await api.getAssessments(7, 50);
  const url = new URL(calls[1][0]);
  assert.equal(url.searchParams.get("website_id"), "7");
  assert.equal(url.searchParams.get("offset"), "50");
  await api.cancelAssessment("synthetic-id", { reason: "Cancel synthetic preflight." });
  assert.equal(new URL(calls[2][0]).pathname, "/api/v1/assessments/synthetic-id/cancel");
  assert.deepEqual(JSON.parse(calls[2][1].body), { reason: "Cancel synthetic preflight." });
});


test("local assessment preserves separate network consent", async () => {
  session();
  const payload={website_id:7,authorization_id:9,profile_id:"local-http-headers-v1",explicitly_requested:true,network_permission_confirmed:true,note:"Explicit synthetic network permission",idempotency_key:"synthetic-local"};
  await api.requestAssessment(payload);
  assert.equal(calls[0][1].headers.Authorization,"Bearer synthetic-unit-test-token");
  assert.deepEqual(JSON.parse(calls[0][1].body),payload);
});

test("analyst review preserves revision, evidence and authenticated export requests", async () => {
  session();
  const payload = { expected_revision: 2, disposition: "confirmed", human_validation_confirmed: true,
    supporting_evidence: "Synthetic analyst evidence", owner: "Test owner", remediation_status: "open" };
  await api.reviewObservation("request-id", "csp", payload);
  assert.equal(new URL(calls[0][0]).pathname, "/api/v1/assessments/request-id/reviews/csp");
  assert.equal(calls[0][1].headers.Authorization, "Bearer synthetic-unit-test-token");
  assert.deepEqual(JSON.parse(calls[0][1].body), payload);
  await api.observationReviewHistory("request-id", "csp", 50);
  assert.equal(new URL(calls[1][0]).searchParams.get("offset"), "50");
  await api.createReviewedReport("request-id");
  assert.equal(calls[2][1].method, "POST");
  assert.equal(new URL(calls[2][0]).pathname, "/api/v1/assessments/request-id/reviewed-reports");
});

test("findings filters and deadline revisions preserve authenticated requests", async () => {
  session();
  await api.getFindings({ owner: "Ops & QA", severity: "high", overdue_only: true, status: "" }, 50);
  const url = new URL(calls[0][0]);
  assert.equal(url.pathname, "/api/v1/findings");
  assert.equal(url.searchParams.get("owner"), "Ops & QA");
  assert.equal(url.searchParams.get("offset"), "50");
  assert.equal(url.searchParams.get("overdue_only"), "true");
  assert.equal(url.searchParams.has("status"), false);
  const payload = { expected_revision: 2, expected_review_revision: 3, due_date: null, note: "Clear a synthetic deadline." };
  await api.setFindingDeadline("synthetic-id", "csp", payload);
  assert.equal(calls[1][1].headers.Authorization, "Bearer synthetic-unit-test-token");
  assert.deepEqual(JSON.parse(calls[1][1].body), payload);
});

test("signOut clears the browser session first, then revokes the token on the server", async () => {
  session();
  globalThis.fetch = async (url, options) => { calls.push([url, options]); assert.equal(storage.has(tokenKey), false); return { ok: true, status: 204, text: async () => "" }; };
  await api.signOut();
  assert.equal(api.hasSession(), false);
  assert.equal(calls.length, 1);
  assert.match(calls[0][0], /\/auth\/logout$/);
  assert.equal(calls[0][1].method, "POST");
  assert.equal(calls[0][1].headers.Authorization, "Bearer synthetic-unit-test-token");
  await api.signOut();  // nothing to revoke, no request
  assert.equal(calls.length, 1);
});

test("signOut still signs the person out when the server cannot be reached", async () => {
  session();
  globalThis.fetch = async () => { throw new TypeError("Synthetic connection failure"); };
  await api.signOut();
  assert.equal(storage.has(tokenKey), false);
  assert.equal(events.length, 0);
});

test("throttled logins show the server message and when to retry, without saving anything", async () => {
  globalThis.fetch = async () => ({ ok: false, status: 429, headers: { get: name => (name === "Retry-After" ? "600" : null) },
    text: async () => JSON.stringify({ detail: "Too many failed sign-in attempts; try again later" }) });
  await assert.rejects(api.login({ email: "a@example.com", password: "x" }), /Too many failed sign-in attempts.*retry in about 10 min/);
  assert.equal(storage.size, 0);
  assert.equal(events.length, 0);
});
