import React, { useState } from "react";
import { api } from "./lib/api.js";

const name = check => ({ csp: "CSP", hsts: "HSTS", x_frame_options: "X-Frame-Options",
  csp_frame_ancestors: "CSP frame-ancestors", x_content_type_options: "X-Content-Type-Options",
  referrer_policy: "Referrer-Policy", permissions_policy: "Permissions-Policy", server_disclosure: "Server disclosure",
  tcp_port_80: "TCP port 80", tcp_port_443: "TCP port 443" }[check] ?? check);
const label = value => value.replaceAll("_", " ");

export function ReviewForm({ assessmentId, item, busy, onSave }) {
  const check = item.observation.check, title = name(check), saved = item.review;
  const [decision, setDecision] = useState(saved?.disposition ?? "");
  const [severity, setSeverity] = useState(saved?.severity ?? item.observation.severity_suggestion);
  const [notes, setNotes] = useState(saved?.notes ?? ""), [evidence, setEvidence] = useState(saved?.supporting_evidence ?? "");
  const [recommendation, setRecommendation] = useState(saved?.recommendation ?? ""), [owner, setOwner] = useState(saved?.owner ?? "");
  const [status, setStatus] = useState(saved?.remediation_status ?? "open");
  const [resolution, setResolution] = useState(saved?.resolution_notes ?? ""), [retest, setRetest] = useState(saved?.retest_assessment_id ?? "");
  const [attested, setAttested] = useState(false), [history, setHistory] = useState(null);
  const [historyOffset, setHistoryOffset] = useState(0), [historyError, setHistoryError] = useState(""), [loadingHistory, setLoadingHistory] = useState(false);
  const confirmed = decision === "confirmed";
  async function loadHistory(offset) {
    setLoadingHistory(true); setHistoryError("");
    try { setHistory(await api.observationReviewHistory(assessmentId, check, offset)); setHistoryOffset(offset); }
    catch (error) { setHistoryError(error.message); }
    finally { setLoadingHistory(false); }
  }
  return <details className="observation-review">
    <summary>{title}: {saved ? `${label(saved.disposition)} · ${label(saved.remediation_status)} · revision ${saved.revision}` : "Awaiting analyst review"}</summary>
    {saved && <p>Last reviewed by administrator #{saved.reviewer_id} on {new Date(saved.reviewed_at).toLocaleString()}.</p>}
    <form aria-label={`${title} analyst review`} onSubmit={event => {
      event.preventDefault();
      onSave(check, { expected_revision: saved?.revision ?? 0, human_validation_confirmed: attested,
        disposition: decision, severity: confirmed ? severity : "informational", notes, supporting_evidence: evidence,
        recommendation: confirmed ? recommendation : "", owner: confirmed ? owner : "",
        remediation_status: confirmed ? status : "not_applicable", resolution_notes: confirmed ? resolution : "",
        retest_assessment_id: confirmed && retest.trim() ? retest.trim() : null });
    }}>
      <fieldset disabled={busy}>
        <legend>{title} review decision</legend>
        <label>{title} disposition<select required value={decision} onChange={event => {
          setDecision(event.target.value); setAttested(false); if (status === "not_applicable") setStatus("open");
        }}><option value="">Choose a decision</option><option value="confirmed">Confirmed</option><option value="not_applicable">Not applicable</option><option value="dismissed">Dismissed</option></select></label>
        <label>{title} review notes<textarea required minLength={20} maxLength={4000} value={notes} onChange={event => setNotes(event.target.value)} /></label>
        <label>{title} supporting evidence<textarea required minLength={20} maxLength={8000} value={evidence} onChange={event => setEvidence(event.target.value)} /></label>
        <p>Describe the evidence you inspected and its reference. The source report hash is attached automatically. Keep credentials and secrets out of notes.</p>
        {confirmed && <>
          <label>{title} analyst severity<select value={severity} onChange={event => setSeverity(event.target.value)}>{["informational", "low", "medium", "high", "critical"].map(value => <option key={value}>{value}</option>)}</select></label>
          <label>{title} recommended fix<textarea required minLength={20} maxLength={4000} value={recommendation} onChange={event => setRecommendation(event.target.value)} /></label>
          <label>{title} remediation owner<input required maxLength={150} value={owner} onChange={event => setOwner(event.target.value)} /></label>
          <label>{title} resolution status<select value={status} onChange={event => setStatus(event.target.value)}>{["open", "in_progress", "ready_for_retest", "resolved"].map(value => <option key={value} value={value}>{label(value)}</option>)}</select></label>
          <label>{title} retest assessment ID<input required={status === "resolved"} value={retest} onChange={event => setRetest(event.target.value)} placeholder="Later successful assessment UUID" /></label>
          <label>{title} resolution notes<textarea required={status === "resolved"} minLength={status === "resolved" ? 20 : undefined} maxLength={4000} value={resolution} onChange={event => setResolution(event.target.value)} /></label>
        </>}
        <label className="assessment-check"><input type="checkbox" required checked={attested} onChange={event => setAttested(event.target.checked)} />I personally reviewed the supporting evidence for {title} and attest to this decision.</label>
        <button className="primary-button" disabled={!attested || !decision}>Save {title} review</button>
      </fieldset>
    </form>
    <button type="button" disabled={busy || loadingHistory} onClick={() => loadHistory(0)}>Show {title} review history</button>
    {historyError && <p role="alert">{historyError}</p>}
    {history && <section aria-label={`${title} review history`}>
      {!history.length && <p>No earlier decisions.</p>}
      {history.map(review => <details key={review.id}><summary>Revision {review.revision}: {label(review.disposition)} · {label(review.remediation_status)} · administrator #{review.reviewer_id} · {new Date(review.reviewed_at).toLocaleString()}</summary>
        <p>Severity: {review.severity}</p><p>Notes: {review.notes}</p><p>Supporting evidence: {review.supporting_evidence}</p>
        <p>Fix: {review.recommendation || "Not applicable"} · Owner: {review.owner || "Not applicable"}</p>
        <p>Resolution: {review.resolution_notes || "Not recorded"} · Retest: {review.retest_assessment_id || "Not linked"}</p>
      </details>)}
      <div className="assessment-pagination"><button disabled={!historyOffset || loadingHistory} onClick={() => loadHistory(historyOffset - 50)}>Previous {title} reviews</button><span>Page {historyOffset / 50 + 1}</span><button disabled={history.length < 50 || loadingHistory} onClick={() => loadHistory(historyOffset + 50)}>Next {title} reviews</button></div>
    </section>}
  </details>;
}

export default function AssessmentReviews({ assessmentId, summary, busy, onSave, onExport, onDownload }) {
  return <section aria-label="Analyst review and remediation" className="analyst-reviews">
    <h3>Analyst review and remediation</h3>
    <p>{summary.reviewed} of {summary.total} observations reviewed. Decisions and revisions are stored separately from the original scanner report.</p>
    <p>To retest fixes, queue another explicitly authorised assessment using the request form above. Resolving a confirmed issue requires its later successful assessment ID and your resolution notes.</p>
    {summary.observations.map(item => <ReviewForm key={`${assessmentId}:${item.observation.check}:${item.review?.revision ?? 0}`} assessmentId={assessmentId} item={item} busy={busy} onSave={onSave} />)}
    <button disabled={busy || summary.reviewed !== summary.total || !summary.total} onClick={onExport}>Export reviewed report</button>
    <p>Review all observations to export a private JSON snapshot. Later decisions do not alter an earlier export.</p>
    {summary.exports.length > 0 && <section aria-label="Reviewed report exports"><h4>Recent reviewed exports</h4>{summary.exports.map(item => <p key={item.id}>
      {new Date(item.created_at).toLocaleString()} · Administrator #{item.created_by} · <button disabled={busy} onClick={() => onDownload(item.id)}>Download reviewed snapshot {item.id}</button>
    </p>)}<p>Showing the latest 20 exports. Previously downloaded snapshots remain available at their authenticated download URLs.</p></section>}
  </section>;
}
