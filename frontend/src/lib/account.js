// Plain-language helpers for the self-service screens. No network access here, so they are unit-tested.

// Links in emails open /verify-email?token=... and /reset-password?token=...
export function authRoute(pathname = "", search = "") {
  const path = String(pathname).replace(/\/+$/, "");
  const token = new URLSearchParams(search).get("token") || "";
  if (path.endsWith("/verify-email")) return { mode: "verify-email", token };
  if (path.endsWith("/reset-password")) return { mode: "reset-password", token };
  return { mode: null, token: "" };
}

// The API answers a reached plan limit with HTTP 402 and {code: "plan_limit", message, max, plan_label}.
export function planLimit(error) {
  return error && error.code === "plan_limit" ? error.detail : null;
}

export const METHODS = [
  { id: "dns", label: "DNS TXT record", short: "DNS record", needsHttps: false },
  { id: "file", label: "Upload a file", short: "File", needsHttps: true },
  { id: "meta", label: "Homepage meta tag", short: "Meta tag", needsHttps: true },
];

// "23 hours left" / "45 minutes left" / "expired" for a manual verification.
export function manualTimeLeft(expiresAt, now = Date.now()) {
  const ms = new Date(expiresAt).getTime() - now;
  if (!Number.isFinite(ms) || ms <= 0) return "expired";
  const minutes = Math.round(ms / 60000);
  return minutes >= 90 ? `${Math.round(minutes / 60)} hours left` : `${minutes} minute${minutes === 1 ? "" : "s"} left`;
}

export const MANUAL_REASON_MIN = 20;
export const CONSENT_METHODS = [["email", "Email"], ["written_letter", "Written letter"], ["in_person", "In person"]];
// Words that are not an answer ("admin only", "test", "demo" ...). The server applies the same rules and has the last word.
const FILLER = new Set(["admin", "only", "test", "testing", "tests", "demo", "ok", "okay", "none", "na", "n/a", "nil", "owner", "me", "self", "myself", "yes", "no",
  "company", "name", "asdf", "qwerty", "xxx", "abc", "temp", "temporary", "just", "because", "needed", "need", "for", "the", "a", "is", "i", "am"]);
const words = text => String(text || "").toLowerCase().match(/[a-z0-9']+/g) || [];

export function manualReasonOk(reason) {
  const text = String(reason || "").trim(), list = words(text);
  return text.length >= MANUAL_REASON_MIN && text.length <= 300 && list.length >= 4 && new Set(list).size >= 3 && list.filter(w => !FILLER.has(w)).length >= 2;
}

export function manualOwnerOk(name) {
  const text = String(name || "").trim(), squashed = text.toLowerCase().replace(/[^a-z0-9]/g, "");
  return text.length >= 2 && text.length <= 120 && /[a-z]/i.test(text) && !FILLER.has(squashed) && !words(text).every(w => FILLER.has(w));
}

// The first thing wrong with the three required fields, in plain words (empty when all are fine).
export function manualDetailsProblem({ ownerName, consent, reason }) {
  if (!manualOwnerOk(ownerName)) return "Enter the name of the website's owner or their company (not \u201cadmin\u201d, \u201ctest\u201d or \u201cowner\u201d).";
  if (!CONSENT_METHODS.some(([value]) => value === consent)) return "Say how the owner gave consent: email, written letter or in person.";
  if (!manualReasonOk(reason)) return `Write a reason of at least ${MANUAL_REASON_MIN} characters that says what the owner agreed to. \u201cadmin only\u201d or \u201ctest\u201d is not a reason.`;
  return "";
}

export function verificationView(website, now = Date.now()) {
  const status = website?.verification_status;
  if (status === "verified" && website.verification_method === "manual") {
    const left = website.manual_verification?.expires_at ? manualTimeLeft(website.manual_verification.expires_at, now) : "";
    return { label: "Manually verified by admin", tone: "info",
      text: `An administrator verified this website by hand${left ? ` (${left})` : ""}. This lasts 24 hours; after that, verify with DNS, a file or a meta tag to keep scanning.` };
  }
  if (status === "verified" && website.verification_method === "test_target") {
    return { label: "Test target", tone: "info", text: "An approved SNWebShield test target. Only admin accounts can scan it, at most 10 scans per day." };
  }
  if (status === "verified") {
    const how = website.verification_method === "parent"
      ? "covered by your verified main domain"
      : `verified by ${(METHODS.find(m => m.id === website.verification_method)?.short || "check").toLowerCase()}`;
    return { label: "Verified", tone: "good", text: `Ownership ${how}.` };
  }
  if (status === "lost") {
    return { label: "Verification lost", tone: "bad",
      text: "We can no longer find your verification, so scans are paused. Put it back, then click Verify." };
  }
  return { label: "Not verified", tone: "warn", text: "Prove you own this website to start scanning." };
}

const SCAN_LABELS = {
  queued: { label: "Waiting to start", tone: "info" },
  running: { label: "Scanning", tone: "info" },
  completed: { label: "Completed", tone: "good" },
  incomplete: { label: "Incomplete", tone: "warn" },
  refused: { label: "Not run", tone: "bad" },
};

export function scanView(scan) {
  if (!scan) return { label: "No scan yet", tone: "muted", text: "The first scan starts automatically after verification.", active: false };
  const base = SCAN_LABELS[scan.status] || { label: "Could not check", tone: "warn" };
  const active = scan.status === "queued" || scan.status === "running";
  const text = active ? (scan.progress?.message || "Working…") : (scan.message || "Could not check.");
  return { ...base, text, active };
}

// What to show after "Verify": found vs expected, and the advice. No HTTPS -> point to DNS.
export function checkView(check) {
  if (!check) return null;
  if (check.ok) return { ok: true, title: check.message || "Ownership confirmed.", found: check.found || [], expected: check.expected };
  return {
    ok: false,
    title: check.message || "We could not confirm ownership yet.",
    found: check.found?.length ? check.found : ["Nothing matching was found."],
    expected: check.expected,
    hint: check.hint || "",
    suggestDns: check.state === "no_https",
  };
}

// Removing a website needs its domain typed exactly (the server checks again). Case, spaces and a final dot are ignored.
export function removalConfirmed(site, typed) {
  const domain = String(site?.domain || "").trim().toLowerCase();
  return domain !== "" && String(typed || "").trim().toLowerCase().replace(/\.$/, "") === domain;
}

export function passwordHint(password = "", email = "") {
  const problems = [];
  if (password.length < 12) problems.push("at least 12 characters");
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(r => r.test(password)).length;
  if (classes < 3) problems.push("three of: lowercase, uppercase, numbers, symbols");
  const local = String(email).split("@")[0].toLowerCase();
  if (local.length >= 4 && password.toLowerCase().includes(local)) problems.push("not your email name");
  return problems;
}

export function isStaff(account) {
  return ["admin", "lead_analyst", "analyst"].includes(account?.role);
}
