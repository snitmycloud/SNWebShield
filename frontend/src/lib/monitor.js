// Presentation helpers for Phase 5 (MONITOR): uptime, score trend, next scan, links from alert emails, worker health.
// Pure functions (unit-tested). Nothing here says "safe": "Up" only means the website answered the last check.

const when = iso => (iso ? new Date(iso).toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" }) : "");

export function uptimeView(uptime) {
  if (!uptime || uptime.status === "unknown") return { label: "Not checked yet", tone: "muted", text: "The first uptime check runs within a few minutes.", pct: "" };
  const pct = uptime.uptime_30d == null ? "" : `${Number(uptime.uptime_30d).toFixed(uptime.uptime_30d === 100 ? 0 : 2)}% over 30 days`;
  if (uptime.status === "down") return { label: "Down", tone: "bad", text: uptime.down_since ? `Not answering since ${when(uptime.down_since)}.` : "Not answering.", pct };
  const speed = uptime.response_ms != null ? `${uptime.response_ms} ms` : "";
  return { label: "Up", tone: "good", text: [speed && `Answered in ${speed}`, pct].filter(Boolean).join(" · "), pct };
}

export function scheduleText(schedule) {
  if (!schedule) return "";
  const every = schedule.every_hours >= 168 ? "weekly" : schedule.every_hours >= 24 ? "daily" : `every ${schedule.every_hours} hours`;
  return schedule.next_scan_at ? `Automatic scan: ${every}. Next one around ${when(schedule.next_scan_at)}.` : `Automatic scan: ${every}.`;
}

// Chart geometry for a list of {score}. Returns SVG path data and dot positions (y grows downwards; 0..100 maps to the full height).
export function trendGeometry(points, width = 560, height = 160, pad = 10, padLeft = 32) {
  const list = Array.isArray(points) ? points.filter(p => typeof p.score === "number") : [];
  if (list.length < 2) return { enough: false, path: "", dots: [] };
  const x = i => padLeft + (i * (width - padLeft - pad)) / (list.length - 1);
  const y = score => pad + ((100 - Math.max(0, Math.min(100, score))) * (height - 2 * pad)) / 100;
  const dots = list.map((p, i) => ({ x: Math.round(x(i) * 10) / 10, y: Math.round(y(p.score) * 10) / 10, score: p.score, grade: p.grade, at: p.at, incomplete: Boolean(p.incomplete) }));
  return { enough: true, path: dots.map((d, i) => `${i ? "L" : "M"}${d.x} ${d.y}`).join(" "), dots };
}

export function trendSummary(points) {
  const list = Array.isArray(points) ? points.filter(p => typeof p.score === "number") : [];
  if (list.length < 2) return "The trend appears after two scans.";
  const change = list[list.length - 1].score - list[list.length - 2].score;
  if (change === 0) return "Score unchanged since the scan before.";
  return `Score ${change > 0 ? "up" : "down"} ${Math.abs(change)} point${Math.abs(change) === 1 ? "" : "s"} since the scan before.`;
}

// Links in alert emails and on dashboard cards: #/websites/12, #/websites/12/findings/<fingerprint>, #/websites/12/tab/<tab>[/print],
// #/settings, #/settings/alerts/<type>. Anything else is ignored.
export const SITE_TABS = ["monitor", "detect", "vulnerabilities", "report"];

export function parseHash(hash) {
  const parts = String(hash || "").replace(/^#\/?/, "").split("/").filter(Boolean);
  if (parts[0] === "websites" && /^\d+$/.test(parts[1] || "")) {
    const tab = parts[2] === "tab" && SITE_TABS.includes(parts[3]) ? parts[3] : parts[2] === "findings" ? "vulnerabilities" : null;
    return { page: "websites", openId: Number(parts[1]), finding: parts[2] === "findings" ? parts[3] || null : null, tab, print: tab === "report" && parts[4] === "print" };
  }
  if (parts[0] === "settings") return { page: "settings", alert: parts[1] === "alerts" ? parts[2] || null : null };
  return null;
}

export const ROLE_TONE = { running: "good", stale: "bad", not_started: "bad", not_running: "bad", external: "info", restarting: "warn", stopped: "bad" };

export function roleView(role) {
  const labels = { running: "Running", stale: "Not responding", not_started: "Not started", not_running: "Not running", external: "Running (started by hand)", restarting: "Restarting", stopped: "Stopped", failed_to_start: "Could not start" };
  const detail = [];
  if (role.age_seconds != null && role.state !== "running") detail.push(`last sign of life ${role.age_seconds}s ago`);
  if (role.restarts) detail.push(`restarted ${role.restarts} time${role.restarts === 1 ? "" : "s"}`);
  return { label: labels[role.state] || role.state, tone: ROLE_TONE[role.state] || "warn", detail: detail.join(", ") };
}

export function workersSummary(data) {
  if (!data) return "";
  return data.healthy ? "All roles are running." : `${data.roles.filter(r => r.state !== "running").length} role(s) need attention.`;
}
