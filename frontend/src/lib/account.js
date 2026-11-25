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

export function verificationView(website) {
  const status = website?.verification_status;
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
