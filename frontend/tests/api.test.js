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
