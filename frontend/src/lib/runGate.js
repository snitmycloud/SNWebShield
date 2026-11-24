// Decides whether "Run assessment" may be pressed. The server's readiness result is the only source of
// authorisation choice; the browser never picks an authorisation itself. The server and the assessment
// worker re-check permission again, so this gate is a convenience, not a security control.
export function runGate({ site, readiness, profileId, attested, busy }) {
  if (!site) return { enabled: false, reason: "Choose a website first." };
  if (!readiness) return { enabled: false, reason: "Checking permission…" };
  const item = readiness.find(p => p.profile_id === profileId);
  if (!item) return { enabled: false, reason: "Choose an assessment profile." };
  if (!item.ready || item.authorization_id == null) return { enabled: false, reason: item.reason ?? "Permission check failed.", item };
  if (item.network_execution && !attested) return { enabled: false, reason: "Confirm that written permission is on file for this real network check.", item };
  if (busy) return { enabled: false, reason: "Working…", item };
  return { enabled: true, reason: null, item };
}

export function defaultNote(host, profileName) {
  const text = `Requested ${profileName} for ${host}`;
  return text.length >= 20 ? text.slice(0, 2000) : text.padEnd(20, ".");
}
