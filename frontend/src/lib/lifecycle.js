// Display model for the per-website lifecycle view. The server decides the next step; this only maps
// it to a page and words. All text comes from fixed strings and counts, never from remote content.
export const STEP_PAGES = {
  set_up_monitoring: ["monitoring", "Open Monitoring"],
  run_assessment: ["assessments", "Open Assessments"],
  fix_permission: ["authorizations", "Open Authorizations"],
  wait_for_assessment: ["assessments", "Open Assessments"],
  review_port_change: ["assessments", "Open Assessments"],
  review_findings: ["workbench", "Open the analyst workbench"],
  sign_off_fix: ["remediation", "Open Remediation"],
  wait_for_retest: ["remediation", "Open Remediation"],
  request_retest: ["remediation", "Open Remediation"],
  track_remediation: ["remediation", "Open Remediation"],
  generate_report: ["reports", "Open VAPT reports"],
  all_clear: [null, null],
};

export function stepTarget(step) {
  const [page, label] = STEP_PAGES[step?.code] ?? [null, null];
  return page ? { page, label } : null;
}

const MONITOR_TEXT = {
  not_configured: "Monitoring is not set up.", disabled: "Monitoring is switched off.",
  blocked: "Monitoring is blocked: consent or evidence is no longer valid.",
  stale: "Monitoring has stopped reporting. Check that the monitoring worker is running.",
  healthy: "Monitoring is healthy.", up: "Monitoring is healthy.", down: "The site is down.", unknown: "Waiting for the first check.",
};

const PORT_OUTCOME = { baseline: "baseline recorded", unchanged: "no change", changed: "state changed", failed: "last run failed",
  invalid_report: "last report unreadable" };

export function portWatchLine(watch) {
  if (!watch) return "Port watch is not enabled.";
  if (!watch.enabled) return "Port watch is paused.";
  if (watch.state === "blocked") return "Port watch is blocked: permission is no longer valid.";
  const outcome = PORT_OUTCOME[watch.last_outcome] ?? "waiting for the first run";
  return `Port watch (TCP 80 and 443) is on: ${outcome}.`;
}

export function pillars(view) {
  if (!view) return [];
  const { monitor, detect, validate, protect } = view;
  const latest = detect.latest;
  return [
    { key: "monitors", title: "MONITORS", lines: [MONITOR_TEXT[monitor.state] ?? "Monitoring status unavailable.",
      monitor.last_checked_at ? `Last check ${new Date(monitor.last_checked_at).toLocaleString()}` : "No check recorded yet.",
      portWatchLine(monitor.port_watch)] },
    { key: "detects", title: "DETECTS", lines: [
      latest ? `Latest assessment: ${latest.status}` : "No assessment has been run.",
      `${detect.total_assessments} assessment(s) in total`,
      detect.can_run ? "Permission is valid for an assessment." : (detect.blocked_reason ?? "Permission is not valid.")] },
    { key: "validates", title: "VALIDATES", lines: [
      `${validate.awaiting_review} observation(s) awaiting analyst review`,
      `${validate.confirmed} confirmed · ${validate.false_positive} false positive · ${validate.not_applicable} not applicable`] },
    { key: "protects", title: "PROTECTS", lines: [
      `${protect.confirmed} confirmed finding(s), ${protect.unresolved} unresolved`,
      protect.awaiting_signoff ? `${protect.awaiting_signoff} fix(es) awaiting second-person sign-off` : "No fix awaiting sign-off.",
      protect.latest_report ? `Latest report: ${protect.latest_report.status} (revision ${protect.latest_report.revision})` : "No report yet."] },
  ];
}
