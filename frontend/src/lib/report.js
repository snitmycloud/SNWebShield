// Presentation helpers for the website report, the dashboard score card and the Monitor tab. Pure functions (unit-tested).
// Nothing here ever says "safe" or "clean": a score is a summary of what was found, not a verdict.
import { SEVERITY_LABEL, groupFindings } from "./findings.js";

export const GRADE_TONE = { A: "good", B: "good", C: "warn", D: "warn", F: "bad" };
export const SEVERITY_LEVELS = ["critical", "high", "medium", "low"];

export function gradeView(summary) {
  if (!summary || typeof summary.score !== "number") return null;
  const grade = String(summary.grade || "");
  return {
    score: summary.score, grade, tone: GRADE_TONE[grade] || "muted", label: `${summary.score} / 100`,
    note: summary.incomplete ? "Based on an incomplete scan, so the real score could be lower." : "",
  };
}

export function severityRows(summary) {
  const counts = summary?.counts || {};
  return SEVERITY_LEVELS.map(level => ({ level, label: SEVERITY_LABEL[level], count: counts[level] || 0 }));
}

// "High (CVE-2021-23017, CVSS 7.7)" - the Risk line of a finding.
export function riskText(finding) {
  const parts = [];
  if (finding.cve_id) parts.push(finding.cve_id);
  if (finding.cvss_score !== null && finding.cvss_score !== undefined) parts.push(`CVSS ${Number(finding.cvss_score).toFixed(1)}`);
  const level = SEVERITY_LABEL[finding.severity] || "Info";
  return parts.length ? `${level} (${parts.join(", ")})` : level;
}

// The fields the report shows for every finding, in this order. Empty ones are left out.
export function reportFields(finding) {
  const rows = [
    ["Where", finding.location],
    ["You have", finding.you_have],
    ["You should have", finding.you_should_have],
    ["Risk", riskText(finding)],
    ["Why it matters", finding.why],
    ["How to fix", finding.how_to_fix],
  ];
  return rows.filter(([, value]) => value !== null && value !== undefined && String(value).trim() !== "").map(([label, value]) => ({ label, value: String(value) }));
}

// Confirmed findings (Info ones last), and the ones that need a human check. Needs-checking items never count in the score.
export function reportGroups(findings) {
  const { confirmed, needsChecking, info } = groupFindings(findings);
  return { confirmed: [...confirmed, ...info], needsChecking };
}

export function certificateView(certificate, now = Date.now()) {
  if (!certificate || typeof certificate.days_left !== "number") return { text: "Not available (no secure connection was found to check)", tone: "muted", days: null };
  const days = certificate.days_left;
  const date = (certificate.expires_at || "").slice(0, 10);
  if (days < 0) return { text: `Expired on ${date}`, tone: "bad", days };
  const tone = days < 14 ? "bad" : days < 30 ? "warn" : "good";
  return { text: `Expires on ${date} (${days} day${days === 1 ? "" : "s"} left)`, tone, days };
}

export function scanDuration(scan) {
  if (!scan?.started_at || !scan?.ended_at) return "";
  const seconds = Math.round((new Date(scan.ended_at) - new Date(scan.started_at)) / 1000);
  if (!Number.isFinite(seconds) || seconds < 0) return "";
  return seconds < 90 ? `${seconds} seconds` : `${Math.round(seconds / 60)} minutes`;
}

export const REPORT_DISCLAIMER = "This report lists what automated checks found. It is not a security verdict, and a good score does not prove that a website has no weaknesses.";
export const TABS = [
  { id: "monitor", label: "Monitor" },
  { id: "detect", label: "Detect" },
  { id: "vulnerabilities", label: "Vulnerabilities" },
  { id: "report", label: "Report" },
];
