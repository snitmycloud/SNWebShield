// The four pillar cards at the top of the dashboard, worked out from ALL of a person's websites. Pure functions (unit-tested).
// Nothing here says "safe": counts are what automated checks found, and a website with no scan yet is "not scanned yet".

export const CERT_WARN_DAYS = 14;
const verified = site => site?.verification_status === "verified";
const domainOf = site => site?.domain || site?.name || `website ${site?.id}`;

function certificateDays(site) {
  const days = [site?.uptime?.certificate_days_left, site?.summary?.certificate?.days_left].filter(d => typeof d === "number");
  return days.length ? Math.min(...days) : null;
}

// MONITOR: how many websites answer, and whose certificate ends soon.
export function monitorPillar(websites) {
  const sites = websites.filter(verified);
  const down = sites.filter(s => s.uptime?.status === "down");
  const up = sites.filter(s => s.uptime?.status === "up");
  const unknown = sites.length - up.length - down.length;
  const expiring = sites.map(s => ({ site: s, days: certificateDays(s) })).filter(x => x.days !== null && x.days <= CERT_WARN_DAYS).sort((a, b) => a.days - b.days);
  const focus = down[0] || expiring[0]?.site || sites[0] || null;
  return {
    key: "monitor", title: "MONITOR", sites: sites.length, up: up.length, down: down.length, unknown,
    downSites: down.map(s => ({ id: s.id, domain: domainOf(s) })),
    expiring: expiring.map(x => ({ id: x.site.id, domain: domainOf(x.site), days: x.days })),
    headline: sites.length === 0 ? "No verified websites yet" : down.length ? `${down.length} down` : unknown === sites.length ? "Not checked yet" : `${up.length} up`,
    tone: down.length ? "bad" : expiring.length ? "warn" : sites.length ? "good" : "muted",
    link: focus ? { id: focus.id, tab: "monitor" } : null,
  };
}

// DETECT: open ports and technologies found by each website's latest scan.
export function detectPillar(websites) {
  const scanned = websites.filter(s => verified(s) && s.detect);
  const ports = scanned.reduce((sum, s) => sum + s.detect.open_ports, 0);
  const technologies = scanned.reduce((sum, s) => sum + s.detect.technologies, 0);
  const most = [...scanned].sort((a, b) => b.detect.open_ports - a.detect.open_ports)[0] || null;
  return {
    key: "detect", title: "DETECT", scanned: scanned.length, ports, technologies,
    headline: scanned.length === 0 ? "Not scanned yet" : `${ports} open port${ports === 1 ? "" : "s"}`,
    tone: scanned.length === 0 ? "muted" : "info",
    incomplete: scanned.filter(s => s.detect.complete === false).length,
    link: most ? { id: most.id, tab: "detect" } : null,
  };
}

// VULNERABILITIES: open confirmed findings by severity (accepted and fixed ones are not counted, as in the score).
export function vulnerabilitiesPillar(websites) {
  const scanned = websites.filter(s => verified(s) && s.summary);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  let needsChecking = 0;
  for (const s of scanned) {
    for (const level of Object.keys(counts)) counts[level] += s.summary.counts?.[level] || 0;
    needsChecking += s.summary.needs_checking || 0;
  }
  const weight = s => (s.summary.counts?.critical || 0) * 1000 + (s.summary.counts?.high || 0) * 100 + (s.summary.counts?.medium || 0) * 10 + (s.summary.counts?.low || 0);
  const worst = [...scanned].sort((a, b) => weight(b) - weight(a))[0] || null;
  const confirmed = counts.critical + counts.high + counts.medium + counts.low;
  return {
    key: "vulnerabilities", title: "VULNERABILITIES", scanned: scanned.length, counts, needsChecking, confirmed,
    headline: scanned.length === 0 ? "Not scanned yet" : confirmed === 0 ? "No confirmed findings" : `${confirmed} open finding${confirmed === 1 ? "" : "s"}`,
    tone: scanned.length === 0 ? "muted" : counts.critical || counts.high ? "bad" : confirmed ? "warn" : "good",
    link: worst ? { id: worst.id, tab: "vulnerabilities" } : null,
  };
}

// REPORT: the latest report (latest finished scan) of each website, newest first.
export function latestReports(websites) {
  return websites.filter(s => verified(s) && s.summary && s.summary.scanned_at)
    .map(s => ({ id: s.id, domain: domainOf(s), score: s.summary.score, grade: s.summary.grade, incomplete: Boolean(s.summary.incomplete), scannedAt: s.summary.scanned_at }))
    .sort((a, b) => String(b.scannedAt).localeCompare(String(a.scannedAt)));
}

export function reportPillar(websites) {
  const reports = latestReports(websites);
  return {
    key: "report", title: "REPORT", reports: reports.slice(0, 3), total: reports.length,
    headline: reports.length === 0 ? "No reports yet" : `${reports.length} report${reports.length === 1 ? "" : "s"}`,
    tone: reports.length ? "info" : "muted",
    link: reports[0] ? { id: reports[0].id, tab: "report" } : null,
  };
}

export const buildPillars = websites => {
  const list = Array.isArray(websites) ? websites : [];
  return [monitorPillar(list), detectPillar(list), vulnerabilitiesPillar(list), reportPillar(list)];
};
