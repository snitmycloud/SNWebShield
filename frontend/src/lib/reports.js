// Pure helpers for VAPT reports. They mirror the server's gates so the UI fails early and never offers
// an action the API would refuse, but the API remains the authority for every rule.
export const REPORT_STATUSES = ["draft", "pending_approval", "approved", "rejected", "superseded"];
export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"];

const STATUS_LABELS = {
  draft: "Draft · awaiting human approval",
  pending_approval: "Pending approval",
  approved: "Approved · official release",
  rejected: "Rejected",
  superseded: "Superseded by a newer revision",
};
export const statusLabel = status => STATUS_LABELS[status] ?? "Unknown status";

const REASON_LABELS = {
  unassessed: "No risk assessment yet",
  unconfirmed: "Assessed but not signed off",
  dismissed: "Dismissed (false positive or not applicable)",
  stale_or_missing_signoff: "Confirmed but the sign-off is stale or missing",
  evidence_integrity_failed: "Evidence failed its integrity check",
};
export const reasonLabel = reason => REASON_LABELS[reason] ?? "Not eligible";

export function eligibilitySummary(check) {
  if (!check) return "";
  const { eligible_count: eligible, excluded_count: excluded } = check;
  return `${eligible} eligible · ${excluded} excluded`;
}

// Generation needs at least one eligible finding; the server enforces this too.
export const canGenerate = check => Boolean(check && check.can_generate && check.eligible_count > 0);

// The official PDF exists only for an approved report whose release hash was recorded.
export const canDownloadOfficial = report =>
  Boolean(report && report.status === "approved" && report.can_download_official === true && report.official_pdf_sha256);

export const canDecide = report =>
  Boolean(report && ["draft", "pending_approval"].includes(report.status) && report.can_decide === true);

export function buildDecision(report, form) {
  if (!canDecide(report)) return { error: "Only an undecided report can be approved or rejected." };
  if (!form.attested) return { error: "Confirm that you personally reviewed this report." };
  const justification = (form.justification ?? "").trim();
  if (justification.length < 20) return { error: "Explain the decision in at least 20 characters." };
  if (justification.length > 4000) return { error: "Keep the justification under 4000 characters." };
  return { payload: { human_validation_confirmed: true, justification } };
}

export const pdfFileName = (report, official) => {
  const id = String(report?.id ?? "").replace(/[^0-9a-f-]/gi, "").slice(0, 36);
  return official ? `vapt-report-${id}.pdf` : `vapt-report-${id}-DRAFT-not-for-release.pdf`;
};

export const severityRows = report =>
  SEVERITY_ORDER.map(severity => ({ severity, count: Number(report?.severity_counts?.[severity] ?? 0) }));

export const shortHash = value => (typeof value === "string" && value ? `${value.slice(0, 16)}…` : "not recorded");

// Only completed assessments from a header profile can carry findings.
export const reportableAssessment = row =>
  Boolean(row && row.job?.status === "completed" && ["local_http", "remote_docker"].includes(row.mode));
