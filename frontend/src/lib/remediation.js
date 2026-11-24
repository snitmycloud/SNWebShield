// Pure helpers for remediation, retesting and closure. They mirror the server's gates so the UI never
// offers an action the API would refuse, but the API remains the authority for every rule.
export const REMEDIATION_STATUSES = ["open", "in_progress", "fix_submitted", "retest_requested", "verified_fixed", "reopened", "risk_accepted"];
export const BLOCKING_STATUSES = ["open", "in_progress", "fix_submitted", "retest_requested", "reopened"];
export const UPDATE_STATUSES = ["open", "in_progress", "fix_submitted", "risk_accepted"];

const STATUS_LABELS = {
  open: "Open",
  in_progress: "In progress",
  fix_submitted: "Fix submitted · awaiting retest",
  retest_requested: "Retest requested",
  verified_fixed: "Verified fixed",
  reopened: "Reopened",
  risk_accepted: "Risk accepted",
};
export const statusLabel = status => STATUS_LABELS[status] ?? "Unknown status";

const OUTCOME_LABELS = {
  verified_fixed: "Verified fixed: the weakness was no longer detected",
  still_present: "Still present: the finding was reopened automatically",
  inconclusive: "Inconclusive: no applicable observation",
};
export const outcomeLabel = (retest) => {
  if (!retest) return "";
  if (retest.status === "requested") return "Waiting for the scanner worker";
  if (retest.status === "failed") return "Did not complete: no target evidence was recorded";
  return OUTCOME_LABELS[retest.outcome] ?? "Unknown outcome";
};

export const isBlocking = status => BLOCKING_STATUSES.includes(status);

// Statuses a user may move this finding to by hand, taken from the server's list for the current state.
export const updateOptions = item => (item?.allowed_statuses ?? []).filter(status => UPDATE_STATUSES.includes(status));

export function buildUpdate(item, form) {
  if (!updateOptions(item).includes(form.status)) return { error: "That status change is not allowed from the current state." };
  const note = (form.note ?? "").trim();
  const accepting = form.status === "risk_accepted";
  if (note.length < (accepting ? 20 : 10)) {
    return { error: accepting ? "Justify the risk acceptance in at least 20 characters." : "Add a remediation note of at least 10 characters." };
  }
  if (note.length > 4000) return { error: "Keep the note under 4000 characters." };
  if (accepting && !form.attested) return { error: "Confirm that the business owner formally accepts this risk." };
  const payload = { expected_version: item.version, status: form.status, note };
  if (form.target_date) payload.target_date = form.target_date;
  if (accepting) payload.human_validation_confirmed = true;
  return { payload };
}

// A retest needs a submitted fix, no retest in flight, an explicit request and an authorisation.
export function buildRetest(item, form) {
  if (!item?.can_request_retest) return { error: "A retest needs a submitted fix and no retest already in progress." };
  if (!form.authorization_id) return { error: "Choose the written authorisation that covers this target." };
  if (!form.confirmed) return { error: "Explicitly request this one HEAD retest of the authorised target." };
  const note = (form.note ?? "").trim();
  if (note.length < 20) return { error: "Describe what should be verified in at least 20 characters." };
  return { payload: { expected_version: item.version, authorization_id: Number(form.authorization_id), note,
    explicitly_requested: true, network_permission_confirmed: true } };
}

export function buildReopen(item, form) {
  if (!item?.can_reopen) return { error: "Only verified, accepted or fix-submitted findings can be reopened." };
  const reason = (form.reason ?? "").trim();
  if (reason.length < 20) return { error: "Explain why the issue is unresolved in at least 20 characters." };
  return { payload: { expected_version: item.version, reason } };
}

// Closing needs the server to report no blockers, plus an attested justification.
export const canClose = state => Boolean(state && state.can_close === true && !state.closed && !(state.blockers?.length));

export function buildClosure(state, form) {
  if (!canClose(state)) return { error: state?.closed ? "This assessment is already closed." : "Resolve every blocking finding first." };
  if (!form.attested) return { error: "Confirm that you reviewed the final remediation state." };
  const justification = (form.justification ?? "").trim();
  if (justification.length < 20) return { error: "Justify the closure in at least 20 characters." };
  return { payload: { human_validation_confirmed: true, justification } };
}

export const closureSummary = state => {
  if (!state) return "";
  if (state.closed) return "Closed";
  return state.can_close ? "Ready to close" : "Blocked";
};

export const reportableAssessment = row => Boolean(row && row.job?.status === "completed");
