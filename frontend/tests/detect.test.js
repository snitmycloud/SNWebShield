import { afterEach, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { api, apiError } from "../src/lib/api.js";
import { describePort, dnsText, exposedText, isActiveScan, isFriendlyLimit, resultBanner, scanNowText, sectionNote, softwareText,
  stepProblems, stepState } from "../src/lib/detect.js";

let calls;
beforeEach(() => {
  calls = [];
  const storage = new Map([["snwebshield_access_token", "synthetic-unit-test-token"],
    ["snwebshield_access_token_expiry", String(Date.now() + 60000)]]);
  globalThis.sessionStorage = { getItem: k => storage.get(k) ?? null, setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k) };
  globalThis.window = { dispatchEvent: () => {} };
  globalThis.fetch = async (url, options) => { calls.push([url, options]); return { ok: true, status: 200, text: async () => "{}" }; };
});
afterEach(() => api.logout());

test("ports are described in plain language, never as TCP/port jargon", () => {
  assert.equal(describePort({ port: 3306, service: "mysql", product: "MySQL" }).sentence, "Your database port is open to the internet.");
  assert.equal(describePort({ port: 6379, service: "redis" }).group, "database");
  assert.equal(describePort({ port: 27017 }).label, "MongoDB database");
  assert.match(describePort({ port: 23, service: "telnet" }).sentence, /unencrypted remote login/);
  assert.match(describePort({ port: 3389 }).sentence, /Remote Desktop is open to the internet/);
  assert.match(describePort({ port: 443, service: "https", http: { over_tls: true } }).sentence, /Your website is reachable securely on port 443/);
  assert.equal(describePort({ port: 80, service: "http" }).label, "Website (HTTP)");
  assert.match(describePort({ port: 2375, service: "docker" }).sentence, /Docker.s remote control port is open to the internet/);
  assert.equal(describePort({ port: 11211, service: "memcached" }).sentence, "Your database port is open to the internet.");
  for (const port of [5984, 9300, 9200, 27017, 6379]) assert.equal(describePort({ port }).sentence, "Your database port is open to the internet.", String(port));
  assert.match(describePort({ port: 2376 }).sentence, /encrypted remote control port is open to the internet/);
  assert.match(describePort({ port: 5601 }).sentence, /Kibana dashboard.*open to the internet/);
  assert.match(describePort({ port: 2379 }).sentence, /etcd store.*open to the internet/);
  assert.match(describePort({ port: 10250 }).sentence, /kubelet.*open to the internet/);
  assert.match(describePort({ port: 15672 }).sentence, /RabbitMQ.*open to the internet/);
  assert.match(describePort({ port: 9929, service: "nping-echo" }).sentence, /guessed from the port number/);
  for (const port of [21, 22, 25, 445, 3306, 3389, 8080, 31337]) assert.doesNotMatch(describePort({ port }).sentence, /TCP\//);
});

test("software and versions: disclosed, not disclosed, or not identified", () => {
  assert.equal(softwareText({ product: "nginx", version: "1.18.0" }), "nginx 1.18.0");
  assert.equal(softwareText({ product: "nginx", version: null }), "nginx (version not disclosed)");
  assert.equal(softwareText({ service: "ssh", service_guess: true }), "Not identified");
  assert.equal(softwareText({ service: "ssh", service_guess: false }), "Version not disclosed");
});

test("steps that did not finish are listed as could not check, never as clean", () => {
  const result = { steps: { ports: { state: "ok" }, versions: { state: "could_not_check" }, dns: { state: "stopped" },
    subdomains: { state: "could_not_check" }, exposed: { state: "not_applicable" } } };
  assert.deepEqual(stepProblems(result).map(p => [p.key, p.text]), [["versions", "Could not check"], ["dns", "Stopped before it finished"],
    ["subdomains", "Could not check"]]);
  assert.deepEqual(stepProblems(null), []);
  assert.equal(stepState(result, "ports"), "ok");
  assert.equal(stepState(result, "technologies"), "missing");
});

test("email and DNS records read in plain words", () => {
  assert.equal(dnsText({ key: "spf", status: "present", data: { policy: "softfail" } }).status, "Found");
  assert.match(dnsText({ key: "spf", status: "present", data: { policy: "softfail" } }).detail, /Soft/);
  assert.equal(dnsText({ key: "dmarc", status: "missing", data: {} }).status, "Not found");
  assert.equal(dnsText({ key: "caa", status: "could_not_check", data: {} }).status, "Could not check");
  assert.equal(dnsText({ key: "caa", status: "could_not_check", data: {} }).tone, "muted");
  assert.match(dnsText({ key: "dkim", status: "present", data: { selectors_found: ["google"] } }).detail, /google/);
  assert.match(dnsText({ key: "dkim", status: "missing", data: {} }).detail, /common selectors/);
});

test("exposed files are explained, and unknown signatures still give a safe sentence", () => {
  assert.match(exposedText({ signature: "env-file" }), /passwords/);
  assert.match(exposedText({ signature: "git-head" }), /Git repository/);
  assert.match(exposedText({ signature: "something-new" }), /should probably not be public/);
});

test("the Scan now line shows the scans left, and the reason when it is unavailable", () => {
  assert.equal(scanNowText({ allowed: true, remaining: 1, limit: 1 }), "1 of 1 scan left today");
  assert.equal(scanNowText({ allowed: true, remaining: 4, limit: 5 }), "4 of 5 scans left today");
  assert.equal(scanNowText({ allowed: false, reason: "limit_reached", remaining: 0, limit: 1 }), "No scans left today");
  assert.equal(scanNowText({ allowed: false, reason: "scan_running", remaining: 0, limit: 1 }), "A scan is running.");
  assert.equal(scanNowText({ allowed: false, reason: "not_verified" }), "Verify ownership to scan.");
  assert.equal(scanNowText(null), "");
});

test("a scan limit is a friendly message, other errors are not", () => {
  const limit = apiError(429, { code: "scan_limit", message: "You have used all 1 manual scans for this website today on the Free plan.", remaining: 0 });
  assert.equal(isFriendlyLimit(limit), true);
  assert.match(limit.message, /Free plan/);
  assert.equal(isFriendlyLimit(apiError(402, { code: "plan_feature", message: "Full port scans are available on Pro." })), true);
  assert.equal(isFriendlyLimit(apiError(409, "Verify ownership of this website first.")), false);
  assert.equal(isFriendlyLimit(null), false);
});

test("result banners never call an incomplete or refused scan clean", () => {
  assert.equal(resultBanner({ status: "incomplete", message: "x" }).tone, "warn");
  assert.equal(resultBanner({ status: "refused", message: "x" }).tone, "bad");
  assert.equal(resultBanner({ status: "completed", message: "y" }).title, "Scan finished");
  assert.equal(resultBanner({ status: "running" }), null);
  for (const status of ["completed", "incomplete", "refused"]) assert.doesNotMatch(resultBanner({ status, message: "m" }).title, /safe|clean|secure/i);
  assert.equal(isActiveScan({ status: "running" }), true);
  assert.equal(isActiveScan({ status: "completed" }), false);
});

test("scan endpoints are authenticated and send the scan type", async () => {
  await api.scanNow(7);
  await api.scanNow(7, "full");
  await api.scanDetail(7, "abc/def");
  assert.deepEqual(calls.map(([url]) => new URL(url).pathname), ["/api/v1/websites/7/scan", "/api/v1/websites/7/scan", "/api/v1/websites/7/scans/abc%2Fdef"]);
  assert.deepEqual(JSON.parse(calls[0][1].body), { scan_type: "standard" });
  assert.deepEqual(JSON.parse(calls[1][1].body), { scan_type: "full" });
  assert.ok(calls.every(([, o]) => o.headers.Authorization === "Bearer synthetic-unit-test-token"));
});


test("a section with no result is never shown as 'nothing found'", () => {
  assert.deepEqual(sectionNote("missing", { running: true, hasData: false }), { kind: "unchecked", text: "Not checked yet." });
  assert.match(sectionNote("missing", { running: false, hasData: false }).text, /scan stopped before this part/);
  for (const state of ["could_not_check", "stopped", "skipped"]) assert.equal(sectionNote(state, { hasData: true }).kind, "problem");
  assert.equal(sectionNote("ok", { hasData: false }).kind, "empty");
  assert.equal(sectionNote("not_applicable", { hasData: false }).kind, "empty");
  assert.equal(sectionNote("ok", { hasData: true }).kind, "data");
  assert.equal(sectionNote("missing", { running: true, hasData: true }).kind, "data");  // partial results found so far are shown
});