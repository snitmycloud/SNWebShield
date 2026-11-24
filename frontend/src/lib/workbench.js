// Pure helpers for the analyst workbench. They mirror the server's rules so forms fail early,
// but the API remains the authority for every rule (matrix, gating, revision checks).
import { SEVERITIES, suppressionExpiry } from "./vulnerabilities.js";

export const LIKELIHOODS = ["rare", "unlikely", "possible", "likely", "almost_certain"];
export const IMPACTS = ["negligible", "minor", "moderate", "major", "severe"];
export const PRIORITIES = ["immediate", "short_term", "planned", "monitor"];
export const STAGES = ["needs_assessment", "ready_for_signoff", "report_eligible", "dismissed", "all"];
export const MAX_EVIDENCE_CHARS = 20000;

const STAGE_LABELS = {
  needs_assessment: "Needs risk assessment",
  ready_for_signoff: "Ready for sign-off",
  report_eligible: "Signed off · report eligible",
  signed_off: "Confirmed · not report eligible",
  dismissed: "Dismissed by analyst",
  all: "All records",
};
export const stageLabel = stage => STAGE_LABELS[stage] ?? "Unknown stage";
export const humanize = value => (typeof value === "string" ? value.replaceAll("_", " ") : "Not recorded");

// Likelihood x business impact (1-5 each): the same matrix the server uses.
export function calculateRating(likelihood, impact) {
  const l = LIKELIHOODS.indexOf(likelihood), i = IMPACTS.indexOf(impact);
  if (l < 0 || i < 0) return null;
  const product = (l + 1) * (i + 1);
  return product <= 2 ? "informational" : product <= 6 ? "low" : product <= 12 ? "medium" : product <= 16 ? "high" : "critical";
}

export function buildAssessment(vulnerability, form) {
  if (!vulnerability?.can_assess) return { error: "Only unconfirmed vulnerabilities can be assessed; reopen it first." };
  if (!LIKELIHOODS.includes(form.likelihood)) return { error: "Choose a likelihood." };
  if (!IMPACTS.includes(form.business_impact)) return { error: "Choose a business impact." };
  if (!PRIORITIES.includes(form.remediation_priority)) return { error: "Choose a remediation priority." };
  const context = (form.business_context ?? "").trim(), remediation = (form.remediation ?? "").trim();
  if (context.length < 20) return { error: "Describe the business context in at least 20 characters." };
  if (remediation.length < 20) return { error: "Write tailored remediation guidance of at least 20 characters." };
  const calculated = calculateRating(form.likelihood, form.business_impact);
  const rating = form.risk_rating || calculated;
  if (!SEVERITIES.includes(rating)) return { error: "Choose a risk rating." };
  const payload = { expected_revision: vulnerability.revision, likelihood: form.likelihood,
    business_impact: form.business_impact, business_context: context, risk_rating: rating,
    remediation, remediation_priority: form.remediation_priority };
  if (rating !== calculated) {
    const reason = (form.override_reason ?? "").trim();
    if (reason.length < 20) return { error: `The rating differs from the calculated "${calculated}". Explain the override in at least 20 characters.` };
    payload.override_reason = reason;
  }
  return { payload, calculated };
}

// Which sign-off actions the server will accept for this record. The UI never offers more.
export function allowedSignoffs(vulnerability) {
  if (!vulnerability) return [];
  if (vulnerability.validation_state === "unconfirmed") return vulnerability.can_approve ? ["approve", "reject"] : ["reject"];
  return vulnerability.allowed_decisions?.includes("unconfirmed") ? ["reopen"] : [];
}

const SIGNOFF_LABELS = { approve: "Approve and confirm", reject: "Reject and suppress", reopen: "Reopen for validation" };
export const signoffLabel = action => SIGNOFF_LABELS[action] ?? "Unknown action";

export function buildSignoff(vulnerability, form, now = new Date()) {
  const decision = form.decision;
  if (!allowedSignoffs(vulnerability).includes(decision)) return { error: "That sign-off is not available for this record." };
  if (form.attested !== true) return { error: "Confirm that you personally reviewed the evidence." };
  const justification = (form.justification ?? "").trim();
  if (justification.length < 20) return { error: "Give a justification of at least 20 characters." };
  const payload = { expected_revision: vulnerability.revision, decision, human_validation_confirmed: true, justification };
  if (decision === "approve") {
    const steps = (form.reproduction_steps ?? "").trim();
    if (steps.length < 20) return { error: "Record reproduction steps of at least 20 characters." };
    return { payload: { ...payload, reproduction_steps: steps } };
  }
  if (decision === "reject") {
    if (!["false_positive", "not_applicable"].includes(form.rejection_outcome)) return { error: "Choose a rejection outcome." };
    const expiry = suppressionExpiry(form.suppress_until, now);
    if (expiry.error) return expiry;
    return { payload: { ...payload, rejection_outcome: form.rejection_outcome, suppress_until: expiry.value } };
  }
  return { payload };
}

// Scanner evidence is derived from untrusted target responses. It is only ever shown as inert text
// inside a React text node (never as HTML); this also removes control and bidi-override characters
// that could disguise content, and bounds the size.
const UNSAFE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g;
export function safeText(value, limit = MAX_EVIDENCE_CHARS) {
  const text = typeof value === "string" ? value : value === undefined ? "" : (() => {
    try { return JSON.stringify(value, null, 2) ?? ""; } catch { return "[unserialisable evidence]"; }
  })();
  const cleaned = text.replace(UNSAFE, "�");
  return cleaned.length > limit ? `${cleaned.slice(0, limit)}\n… truncated (${cleaned.length - limit} more characters)` : cleaned;
}

export function auditLine(event) {
  const who = event?.actor_name ?? (event?.actor_id ? `Administrator #${event.actor_id}` : "System");
  const move = event?.to_state && event.from_state !== event.to_state ? ` · ${humanize(event.from_state ?? "new")} → ${humanize(event.to_state)}` : "";
  return `#${event?.sequence} · ${event?.occurred_at ?? "unknown time"} · ${humanize(event?.action)}${move} · ${who}`;
}
