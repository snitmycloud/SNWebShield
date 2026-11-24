// Pure helpers for the vulnerability workbench. They mirror the server's validation so
// the form fails early, but the API remains the authority for every rule.
export const STATES = ["unconfirmed", "confirmed", "false_positive", "not_applicable"];
export const SEVERITIES = ["critical", "high", "medium", "low", "informational"];
export const MAX_SUPPRESSION_DAYS = 365;

const STATE_LABELS = {
  unconfirmed: "Unconfirmed — awaiting analyst validation",
  confirmed: "Confirmed by analyst",
  false_positive: "False positive",
  not_applicable: "Not applicable",
};
const DECISION_LABELS = {
  confirmed: "Confirm vulnerability",
  false_positive: "Mark false positive and suppress",
  not_applicable: "Mark not applicable and suppress",
  unconfirmed: "Reopen for validation",
};

export const stateLabel = state => STATE_LABELS[state] ?? "Unknown state";
export const decisionLabel = decision => DECISION_LABELS[decision] ?? "Unknown decision";

// Date input (YYYY-MM-DD) → end of that day in the browser's timezone, as an aware ISO string.
export function suppressionExpiry(dateValue, now = new Date()) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateValue ?? "")) return { error: "Choose a suppression expiry date." };
  const [year, month, day] = dateValue.split("-").map(Number);
  const expiry = new Date(year, month - 1, day, 23, 59, 59);
  if (Number.isNaN(expiry.getTime()) || expiry.getDate() !== day) return { error: "Choose a valid date." };
  if (expiry <= now) return { error: "The suppression expiry must be in the future." };
  if (expiry - now > MAX_SUPPRESSION_DAYS * 86400000) return { error: `Suppressions can last at most ${MAX_SUPPRESSION_DAYS} days.` };
  return { value: expiry.toISOString() };
}

export function buildDecision(vulnerability, form, now = new Date()) {
  const decision = form.decision;
  if (!vulnerability?.allowed_decisions?.includes(decision)) return { error: "That decision is not available for this state." };
  if (form.attested !== true) return { error: "Confirm that you personally validated the evidence." };
  const justification = (form.justification ?? "").trim();
  if (justification.length < 20) return { error: "Give a justification of at least 20 characters." };
  const payload = { expected_revision: vulnerability.revision, decision, human_validation_confirmed: true, justification };
  if (decision === "confirmed") {
    const steps = (form.reproduction_steps ?? "").trim();
    if (!SEVERITIES.includes(form.severity)) return { error: "Choose an analyst severity." };
    if (steps.length < 20) return { error: "Describe reproduction steps of at least 20 characters." };
    return { payload: { ...payload, severity: form.severity, reproduction_steps: steps } };
  }
  if (decision === "false_positive" || decision === "not_applicable") {
    const expiry = suppressionExpiry(form.suppress_until, now);
    if (expiry.error) return expiry;
    return { payload: { ...payload, suppress_until: expiry.value } };
  }
  return { payload };
}

export function confidenceSummary(vulnerability) {
  const factors = Array.isArray(vulnerability?.confidence_factors) ? vulnerability.confidence_factors : [];
  const text = factors
    .filter(f => typeof f?.factor === "string" && Number.isFinite(f?.effect))
    .map(f => `${f.factor.replaceAll("_", " ")} ${f.effect > 0 ? "+" : ""}${f.effect}`)
    .join(", ");
  return `${vulnerability?.confidence ?? "unknown"} (${vulnerability?.confidence_score ?? "?"}/100)${text ? ` — ${text}` : ""}`;
}
