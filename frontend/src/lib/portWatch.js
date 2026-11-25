// Port watch helpers. Enabling is the explicit act that allows recurring TCP 80/443 checks, so the form
// refuses to build a request without a real interval and the written-permission attestation. The server
// repeats every check; this only avoids sending a request that is certain to be refused.
export const INTERVALS = [[3600, "Every hour"], [21600, "Every 6 hours"], [86400, "Every day"], [604800, "Every week"]];
export const MIN_INTERVAL = 3600, MAX_INTERVAL = 604800;

export function buildEnable(state, form) {
  if (!state?.can_enable) return { error: state?.cannot_enable_reason ?? "Permission is not valid for a port assessment." };
  const interval = Number(form.interval);
  if (!Number.isInteger(interval) || interval < MIN_INTERVAL || interval > MAX_INTERVAL) return { error: "Choose how often to check." };
  if (!form.attested) return { error: "Confirm that you inspected written permission for recurring port checks." };
  return { payload: { interval_seconds: interval, network_permission_confirmed: true, human_validation_confirmed: true } };
}

export function buildDisable(form) {
  const reason = (form.reason ?? "").trim();
  if (reason.length < 10) return { error: "Explain why in at least 10 characters." };
  return { payload: { reason } };
}

const WORD = { open: "open", closed: "closed", filtered: "filtered" };
export const portState = value => WORD[value] ?? "unknown";

// Only fixed words and port numbers from the server's own enumeration are shown, never free text.
export function describeChange(change) {
  return (change?.changes ?? []).map(c => `TCP ${String(c.port).replace(/\D/g, "")}: ${portState(c.from)} → ${portState(c.to)}`).join(" · ");
}

export function watchStatus(state) {
  if (!state?.configured) return "Port watch has never been enabled for this website.";
  if (!state.enabled) return "Port watch is paused.";
  if (state.state === "blocked") return "Blocked: " + (state.blocked_reason_text ?? "permission is no longer valid") + " It resumes by itself at the next slot once permission is valid again.";
  return "Active.";
}

export function intervalLabel(seconds) {
  return (INTERVALS.find(([value]) => value === seconds) ?? [0, `Every ${Math.round(seconds / 3600)} hours`])[1];
}
