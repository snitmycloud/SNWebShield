import { afterEach, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { api, apiError } from "../src/lib/api.js";
import { authRoute, checkView, isStaff, passwordHint, planLimit, removalConfirmed, scanView, verificationView } from "../src/lib/account.js";

let calls, storage;
beforeEach(() => {
  calls = [];
  storage = new Map([["snwebshield_access_token", "synthetic-unit-test-token"],
    ["snwebshield_access_token_expiry", String(Date.now() + 60000)]]);
  globalThis.sessionStorage = { getItem: k => storage.get(k) ?? null, setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k) };
  globalThis.window = { dispatchEvent: () => {} };
  globalThis.fetch = async (url, options) => { calls.push([url, options]); return { ok: true, status: 200, text: async () => "{}" }; };
});
afterEach(() => api.logout());

test("email links are recognised and carry their token", () => {
  assert.deepEqual(authRoute("/verify-email", "?token=abc_-1"), { mode: "verify-email", token: "abc_-1" });
  assert.deepEqual(authRoute("/reset-password/", "?token=xyz"), { mode: "reset-password", token: "xyz" });
  assert.deepEqual(authRoute("/", ""), { mode: null, token: "" });
  assert.equal(authRoute("/verify-email", "").token, "");
});

test("the plan-limit answer becomes an upgrade message, other errors do not", () => {
  const detail = { code: "plan_limit", max: 5, plan: "free", plan_label: "Free",
    message: "Your Free plan includes up to 5 websites. Upgrade to add more." };
  const error = apiError(402, detail);
  assert.equal(error.message, detail.message);
  assert.equal(error.status, 402);
  assert.deepEqual(planLimit(error), detail);
  assert.equal(planLimit(apiError(409, "You have already added example.com.")), null);
  assert.equal(planLimit(null), null);
});

test("unverified email logins expose their code", () => {
  const error = apiError(403, { code: "email_not_verified", message: "Please confirm your email address first." });
  assert.equal(error.code, "email_not_verified");
  assert.match(error.message, /confirm your email/);
});

test("verification states read in plain language", () => {
  assert.equal(verificationView({ verification_status: "unverified" }).label, "Not verified");
  assert.equal(verificationView({ verification_status: "verified", verification_method: "dns" }).tone, "good");
  assert.match(verificationView({ verification_status: "verified", verification_method: "parent" }).text, /main domain/);
  const lost = verificationView({ verification_status: "lost" });
  assert.equal(lost.tone, "bad");
  assert.match(lost.text, /paused/);
});

test("an approved test target is labelled as one and explains who may scan it", () => {
  const view = verificationView({ verification_status: "verified", verification_method: "test_target" });
  assert.equal(view.label, "Test target");
  assert.match(view.text, /admin/i);
  assert.match(view.text, /10 scans per day/);
  assert.equal(verificationView({ verification_status: "verified", verification_method: "dns" }).label, "Verified");
});

test("a scan is never shown as safe or clean", () => {
  assert.equal(scanView(null).label, "No scan yet");
  const running = scanView({ status: "running", progress: { message: "Finding your website's addressâ€¦" } });
  assert.equal(running.active, true);
  assert.match(running.text, /address/);
  const incomplete = scanView({ status: "incomplete", message: "This scan is incomplete. It does not mean your website is safe." });
  assert.equal(incomplete.label, "Incomplete");
  assert.equal(scanView({ status: "weird" }).label, "Could not check");
  for (const status of ["queued", "running", "completed", "incomplete", "refused", "x"]) {
    assert.doesNotMatch(scanView({ status }).label, /safe|clean/i);
  }
});

test("failed checks show found and expected, and no HTTPS points to DNS", () => {
  const view = checkView({ ok: false, state: "no_https", expected: "abc", found: [], message: "No HTTPS.",
    hint: "Use the DNS TXT method instead." });
  assert.equal(view.ok, false);
  assert.equal(view.suggestDns, true);
  assert.deepEqual(view.found, ["Nothing matching was found."]);
  assert.equal(view.expected, "abc");
  const missing = checkView({ ok: false, state: "not_found", expected: "snwebshield-verify=x", found: ["v=spf1 -all"] });
  assert.equal(missing.suggestDns, false);
  assert.deepEqual(missing.found, ["v=spf1 -all"]);
  assert.equal(checkView({ ok: true, message: "Ownership confirmed." }).ok, true);
});

test("password hints match the server's rules", () => {
  assert.deepEqual(passwordHint("A-strong-test-password-123!"), []);
  assert.ok(passwordHint("short").length >= 1);
  assert.ok(passwordHint("alllowercaseletters").some(p => /three of/.test(p)));
  assert.ok(passwordHint("Asha-Rao-Password-1", "asharao@example.com").length === 0);
  assert.ok(passwordHint("Xasharao-Password-1", "asharao@example.com").some(p => /email name/.test(p)));
});

test("only staff roles see the read-only legacy pages", () => {
  assert.equal(isStaff({ role: "user" }), false);
  for (const role of ["admin", "lead_analyst", "analyst"]) assert.equal(isStaff({ role }), true);
});

test("account endpoints: public ones send no token, private ones do", async () => {
  await api.signUp({ email: "a@example.com", password: "x", full_name: "" });
  await api.verifyEmail("tok");
  await api.forgotPassword("a@example.com");
  await api.resetPassword("tok", "New-password-123!");
  for (const [, options] of calls) assert.equal(options.headers.Authorization, undefined);
  assert.deepEqual(calls.map(([url]) => new URL(url).pathname),
    ["/api/v1/auth/signup", "/api/v1/auth/verify-email", "/api/v1/auth/forgot-password", "/api/v1/auth/reset-password"]);
  assert.deepEqual(JSON.parse(calls[3][1].body), { token: "tok", new_password: "New-password-123!" });

  calls.length = 0;
  await api.addWebsite("www.example.com");
  await api.verifyWebsite(7, "dns");
  await api.websiteScans(7);
  await api.setUserPlan(3, "pro");
  await api.setUserActive(3, false);
  assert.deepEqual(calls.map(([url]) => new URL(url).pathname), ["/api/v1/websites", "/api/v1/websites/7/verify",
    "/api/v1/websites/7/scans", "/api/v1/admin/users/3/plan", "/api/v1/admin/users/3/disable"]);
  assert.ok(calls.every(([, options]) => options.headers.Authorization === "Bearer synthetic-unit-test-token"));
  assert.deepEqual(JSON.parse(calls[0][1].body), { domain: "www.example.com" });
  assert.deepEqual(JSON.parse(calls[1][1].body), { method: "dns" });
});

test("changing the password keeps this session by saving the new token", async () => {
  globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ access_token: "fresh-token", expires_in: 600 }) });
  await api.changePassword("old", "New-password-123!");
  assert.equal(storage.get("snwebshield_access_token"), "fresh-token");
});


test("removing a website needs its domain typed exactly (case, spaces and a final dot are ignored)", () => {
  const site = { domain: "www.snitsolutions.in" };
  assert.equal(removalConfirmed(site, "www.snitsolutions.in"), true);
  assert.equal(removalConfirmed(site, "  WWW.SnitSolutions.IN. "), true);
  for (const wrong of ["", "   ", "snitsolutions.in", "www.snitsolutions.i", "www.snitsolutions.in.evil.net", undefined, null]) {
    assert.equal(removalConfirmed(site, wrong), false, String(wrong));
  }
  assert.equal(removalConfirmed({ domain: "" }, ""), false);
  assert.equal(removalConfirmed(null, "x"), false);
});

test("removing a website posts the typed domain to the authenticated remove endpoint", async () => {
  await api.removeWebsite(7, "example.com");
  assert.equal(new URL(calls[0][0]).pathname, "/api/v1/websites/7/remove");
  assert.equal(calls[0][1].method, "POST");
  assert.equal(calls[0][1].headers.Authorization, "Bearer synthetic-unit-test-token");
  assert.deepEqual(JSON.parse(calls[0][1].body), { confirm_domain: "example.com" });
});