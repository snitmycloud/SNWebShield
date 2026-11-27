// Plain-language lines for a website's audit history. Pure functions (unit-tested). Everything in an event came from our own server,
// but names and reasons were typed by people, so they are always shown as escaped text (React does that).

const date = iso => (iso ? new Date(iso).toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" }) : "");
const CONSENT = { email: "Email", written_letter: "Written letter", in_person: "In person" };

export function auditLine(event) {
  const d = event?.detail || {};
  switch (event?.action) {
    case "website_added": return { title: "Website added", lines: [] };
    case "ownership_verified": return { title: "Ownership verified", lines: [d.method ? `Method: ${d.method}` : ""].filter(Boolean) };
    case "ownership_check": return { title: "Ownership checked", lines: [d.method ? `Method: ${d.method}` : "", d.state ? `Result: ${d.state}` : ""].filter(Boolean) };
    case "manual_verification": {
      const lines = [];
      if (d.recorded_details) {
        lines.push(`Owner or company: ${d.owner_name}`, `How consent was given: ${d.consent_label || CONSENT[d.consent_method] || d.consent_method || "—"}`);
      } else {
        lines.push("Owner and how consent was given were not recorded (this was done before they were required).");
      }
      lines.push(`Reason: ${d.reason || "—"}`);
      if (d.admin) lines.push(`Done by: ${d.admin}`); else lines.push("Done by: an administrator");
      if (d.expires_at) lines.push(`Valid until: ${date(d.expires_at)}`);
      return { title: "Manually verified by an administrator", lines, tone: "info" };
    }
    case "verification_reset": return { title: "Verification reset", lines: [d.why || "", d.previous?.reason ? `It had been: ${d.previous.method} (${d.previous.reason})` : ""].filter(Boolean), tone: "warn" };
    case "website_removed": return { title: "Website removed", lines: [] };
    case "scan_requested": return { title: `Scan requested (${d.trigger || "scan"})`, lines: [] };
    case "manual_scan_requested": return { title: "Scan now pressed", lines: [] };
    case "recheck_requested": return { title: "Re-scan to confirm fix", lines: [] };
    case "risk_accepted": return { title: `Risk accepted for ${d.days || "?"} days`, lines: d.reason ? [`Reason: ${d.reason}`] : [] };
    case "risk_unaccepted": return { title: "Accepted risk stopped", lines: [] };
    case "risk_acceptance_expired": return { title: "Accepted risk ended", lines: [] };
    case "finding_fixed": return { title: `Finding fixed (${d.how === "recheck" ? "re-check" : "full scan"})`, lines: [] };
    case "finding_reopened": return { title: "A fixed finding came back", lines: [] };
    case "alert_sent": return { title: "Alert email sent", lines: [d.alert_type ? `Type: ${d.alert_type}` : ""].filter(Boolean) };
    default: return { title: String(event?.action || "Event").replace(/_/g, " "), lines: [] };
  }
}
