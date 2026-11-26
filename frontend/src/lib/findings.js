// Plain-language presentation of scan findings. Pure functions (unit-tested). Nothing here ever says "safe" or "clean":
// no findings means "No findings from these checks", and a check that did not finish is "Could not check".

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const SEVERITY_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
export const ENGINE_STEPS = { configuration: "Security settings", vulnerabilities: "Known vulnerabilities", lifecycle: "End of life" };   // core
// Optional engines add depth. If one is off or cannot run, the scan and its core results are unaffected; it is only mentioned when it failed.
export const OPTIONAL_ENGINES = { nuclei: "Extra template checks (Nuclei)" };

const SOURCES = { nvd: "NVD (US National Vulnerability Database)", osv: "OSV (Open Source Vulnerabilities)",
  "endoflife.date": "endoflife.date", snwebshield: "SNWebShield checks", nuclei: "Nuclei" };
const REASONS = {
  timeout: "the database did not answer in time", connection: "the database could not be reached",
  http_429: "the database asked us to slow down", http_500: "the database had an error", http_502: "the database had an error",
  http_503: "the database was busy", http_504: "the database did not answer in time", circuit_open: "the database was not answering, so we stopped asking for a minute",
  budget: "the time set aside for these checks ran out", too_large: "the answer was too large to handle safely", malformed: "the answer could not be understood",
  redirect: "the database sent us somewhere else, which we do not follow", blocked: "the database address was not allowed",
  eol_data_unavailable: "our end-of-life data could not be read", timed_out: "the check took too long", unexpected_error: "the check failed unexpectedly",
};

export function sourceLabel(source) {
  return SOURCES[source] || String(source);
}

export function reasonText(code) {
  return REASONS[code] || "the check did not finish";
}

// Only confirmed findings above "info" count in the score. "Needs checking" findings never do.
// A finding's life (set by the server): open, fixed (and how it was confirmed) or an accepted risk (with a reason and an end date).
export function stateOf(finding) {
  return finding?.state?.status || "open";
}

const dateOnly = iso => (iso ? String(iso).slice(0, 10) : "");

export function stateText(finding) {
  const state = finding?.state || {};
  if (state.status === "fixed") return `Fixed on ${dateOnly(state.fixed_at)} ${state.fixed_how === "recheck" ? "(confirmed by a re-check)" : "(confirmed by a full scan)"}`;
  if (state.status === "accepted") return `Accepted risk until ${dateOnly(state.accepted?.until)}`;
  if (state.reopened) return "Open again (it came back after being fixed)";
  return "Open";
}

export function reviewSoon(finding) {
  return stateOf(finding) === "accepted" && finding.state.accepted?.review_soon === true;
}

// "2 new, 3 fixed, 14 unchanged" - the short summary at the top of a report. Nothing is said when there is no earlier scan to compare with.
export function changesText(changes) {
  if (!changes) return "";
  const parts = [`${changes.new || 0} new`, `${changes.fixed || 0} fixed`, `${changes.unchanged || 0} unchanged`];
  if (changes.could_not_confirm) parts.push(`${changes.could_not_confirm} could not be confirmed`);
  return parts.join(", ");
}

export const ACCEPT_PERIODS = [30, 90, 180, 365];
export const DEFAULT_ACCEPT_DAYS = 90;
export const REASON_RANGE = [10, 300];

export function reasonProblem(reason) {
  const length = String(reason || "").trim().length;
  return length >= REASON_RANGE[0] && length <= REASON_RANGE[1] ? "" : `Please give a reason of ${REASON_RANGE[0]} to ${REASON_RANGE[1]} characters.`;
}

export function groupFindings(findings) {
  const all = Array.isArray(findings) ? findings : [];
  const accepted = all.filter(f => stateOf(f) === "accepted"), fixed = all.filter(f => stateOf(f) === "fixed");
  // Fixed and accepted findings stay on the page but are not counted: they are listed in their own sections.
  const list = all.filter(f => stateOf(f) === "open");
  const rank = f => SEVERITIES.indexOf(f.severity) * 1000 - (f.cvss_score || 0);
  const sorted = [...list].sort((a, b) => rank(a) - rank(b) || String(a.title).localeCompare(String(b.title)));
  return {
    accepted: [...accepted].sort((a, b) => rank(a) - rank(b)), fixed: [...fixed].sort((a, b) => rank(a) - rank(b)),
    confirmed: sorted.filter(f => f.group === "findings" && f.severity !== "info"),
    needsChecking: sorted.filter(f => f.group === "needs_checking"),
    info: sorted.filter(f => f.group === "findings" && f.severity === "info"),
  };
}

export function severityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of groupFindings(findings).confirmed) if (counts[f.severity] !== undefined) counts[f.severity] += 1;
  return counts;
}

export function summaryText(findings) {
  const { confirmed, needsChecking } = groupFindings(findings);
  const counts = severityCounts(findings);
  const parts = ["critical", "high", "medium", "low"].filter(k => counts[k]).map(k => `${counts[k]} ${SEVERITY_LABEL[k].toLowerCase()}`);
  const head = confirmed.length ? `${confirmed.length} finding${confirmed.length === 1 ? "" : "s"} (${parts.join(", ")})` : "No findings from these checks";
  return needsChecking.length ? `${head}; ${needsChecking.length} need${needsChecking.length === 1 ? "s" : ""} your check` : head;
}

// Which finding steps ran, and which did not finish. A step that did not finish is listed, never counted as "nothing found".
export function checksNotFinished(result) {
  const steps = result?.steps || {};
  const rows = [];
  for (const [key, label] of Object.entries(ENGINE_STEPS)) {
    const step = steps[key];
    if (!step) continue;
    if (["could_not_check", "stopped", "skipped"].includes(step.state)) {
      const why = step.state === "stopped" ? "Stopped before it finished"
        : step.state === "skipped" ? "Not run because the port check did not finish"
        : (step.reason ? `Could not check: ${reasonText(step.reason)}` : "Could not check");
      const details = [];
      for (const item of step.unchecked || []) details.push(`${item}: could not be checked`);
      for (const item of step.failed || []) {
        details.push(item.used_old_data ? `${item.item}: ${reasonText(item.reason)}, so older saved data was used` : `${item.item}: ${reasonText(item.reason)}`);
      }
      rows.push({ key, label, text: why, details });
    }
  }
  for (const [key, label] of Object.entries(OPTIONAL_ENGINES)) {
    const step = steps[key];
    if (step && ["could_not_check", "stopped"].includes(step.state)) {
      const reasons = { selftest_failed: "its safety self-test did not pass, so it stayed off", binary_hash_mismatch: "the installed program did not match its pinned checksum",
        binary_not_installed: "it is not installed", template_set_changed: "its template set did not match the reviewed list", template_hash_mismatch: "a template did not match its reviewed checksum" };
      rows.push({ key, label, text: `Did not run: ${reasons[step.reason] || reasonText(step.reason)}. Your other results are not affected.`, details: [], optional: true });
    }
  }
  return rows;
}

export function engineProgress(result, scanRunning) {
  const steps = result?.steps || {};
  const pending = Object.keys(ENGINE_STEPS).filter(key => !steps[key]);
  return { pending, notChecked: pending.length > 0, text: pending.length === 0 ? "" : (scanRunning ? "Not checked yet." : "Not checked: the scan stopped before these checks.") };
}

// The list inside a grouped finding ("Login or admin pages found: 4"). Everything is plain text from a scan, shown escaped.
export function panelItems(finding) {
  const list = Array.isArray(finding?.details?.panels) ? finding.details.panels : [];
  return list.slice(0, 100).map(p => ({ name: String(p.name ?? ""), path: String(p.path ?? ""), key: `${p.template}:${p.path}` }));
}

export function cvssText(finding) {
  if (finding.cvss_score === null || finding.cvss_score === undefined) return "";
  return `CVSS ${Number(finding.cvss_score).toFixed(1)} (${SEVERITY_LABEL[finding.severity] || ""})`;
}

// The two end-of-life tiers are worded differently on purpose.
export function lifecycleTier(finding) {
  if (finding.kind !== "lifecycle") return null;
  return finding.details?.tier === "paid_only" ? "Only paid extended support remains" : "No longer receives security updates";
}

export function emptyText(result, running) {
  const steps = result?.steps || {};
  const unfinished = Object.keys(ENGINE_STEPS).some(key => !steps[key] || ["could_not_check", "stopped", "skipped"].includes(steps[key].state));
  if (unfinished) return running ? "Checking…" : "Some checks did not finish, so this list may be incomplete. That is not the same as “nothing found”.";
  return "No findings from these checks. This does not prove that your website has no weaknesses.";
}
