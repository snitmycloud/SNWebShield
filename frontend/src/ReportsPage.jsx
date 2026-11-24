import React, { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./lib/api.js";
import { humanize, safeText } from "./lib/workbench.js";
import { REPORT_STATUSES, buildDecision, canDecide, canDownloadOfficial, canGenerate, eligibilitySummary,
  pdfFileName, reasonLabel, reportableAssessment, severityRows, shortHash, statusLabel } from "./lib/reports.js";
import "./assessments.css";
import "./findings.css";

const when = value => value ? new Date(value).toLocaleString() : "Not recorded";

function save(blob, filename) {
  const url = URL.createObjectURL(blob), link = document.createElement("a");
  link.href = url; link.download = filename; document.body.appendChild(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function DecisionForm({ report, busy, onApprove, onReject }) {
  const [form, setForm] = useState({ attested: false, justification: "" });
  const [error, setError] = useState("");
  if (!canDecide(report)) return <p>This report has been {report.status === "superseded" ? "superseded" : "decided"}; no further decision is possible.</p>;
  const submit = handler => {
    const result = buildDecision(report, form);
    if (result.error) { setError(result.error); return; }
    setError(""); handler(result.payload);
  };
  return <form aria-label="Report decision" onSubmit={event => event.preventDefault()}>
    <fieldset disabled={busy}><legend>Human approval (required before any official release)</legend>
      {error && <p role="alert" className="form-error">{error}</p>}
      <label>Justification<textarea aria-label="Report decision justification" required minLength={20} maxLength={4000}
        value={form.justification} onChange={event => setForm({ ...form, justification: event.target.value })} /></label>
      <label className="assessment-check"><input type="checkbox" checked={form.attested}
        onChange={event => setForm({ ...form, attested: event.target.checked })} />I personally reviewed this report, its findings and its evidence, and I take responsibility for this decision.</label>
      <button type="button" className="primary-button" onClick={() => submit(onApprove)}>Approve and publish official report</button>{" "}
      <button type="button" onClick={() => submit(onReject)}>Reject report</button>
    </fieldset></form>;
}

export default function ReportsPage() {
  const [assessments, setAssessments] = useState([]), [assessmentId, setAssessmentId] = useState("");
  const [check, setCheck] = useState(null), [list, setList] = useState(null), [status, setStatus] = useState("");
  const [selected, setSelected] = useState(null), [events, setEvents] = useState([]);
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [notice, setNotice] = useState("");
  const listVersion = useRef(0), detailVersion = useRef(0), checkVersion = useRef(0);

  const loadList = useCallback(async () => {
    const version = ++listVersion.current;
    const result = await api.reports({ status });
    if (version === listVersion.current) setList(result);
  }, [status]);
  useEffect(() => {
    let alive = true;
    loadList().catch(failure => { if (alive) setError(failure.message); });
    return () => { alive = false; listVersion.current++; };
  }, [loadList]);
  useEffect(() => {
    let alive = true;
    api.getAssessments().then(rows => { if (alive) setAssessments(rows.filter(reportableAssessment)); })
      .catch(failure => { if (alive) setError(failure.message); });
    return () => { alive = false; detailVersion.current++; checkVersion.current++; };
  }, []);

  async function choose(id) {
    const version = ++checkVersion.current;
    setAssessmentId(id); setCheck(null);
    if (!id) return;
    const result = await api.reportEligibility(id);
    if (version === checkVersion.current) setCheck(result);
  }
  async function open(id) {
    const version = ++detailVersion.current;
    const [report, trail] = await Promise.all([api.report(id), api.reportEvents(id)]);
    if (version === detailVersion.current) { setSelected(report); setEvents(trail); }
  }
  async function run(action, message) {
    setBusy(true); setError(""); setNotice("");
    try { await action(); await loadList(); if (message) setNotice(message); }
    catch (failure) { setError(failure.message); }
    finally { setBusy(false); }
  }

  return <section className="assessment-page findings-page">
    <div className="eyebrow">VAPT REPORTING</div><h1>VAPT reports</h1>
    <p>Reports contain only findings that an analyst confirmed and signed off against their current revision. A report stays a draft until a human approves it; only an approved report has an official PDF. Target data in reports is untrusted and shown as plain text.</p>
    {error && <p role="alert" className="form-error">{error}</p>}{notice && <p role="status">{notice}</p>}

    <div className="panel">
      <h2>Generate a draft report</h2>
      <label>Completed assessment<select aria-label="Report assessment" value={assessmentId} onChange={event => run(() => choose(event.target.value))}>
        <option value="">Choose a completed header assessment</option>
        {assessments.map(row => <option key={row.id} value={row.id}>{row.target_host} · {when(row.requested_at)} · {row.id.slice(0, 8)}</option>)}
      </select></label>
      {check && <>
        <p aria-label="Eligible versus excluded findings"><strong>{eligibilitySummary(check)}</strong></p>
        {check.excluded_count > 0 && <ul aria-label="Excluded findings by reason">{Object.entries(check.excluded_reasons).map(([reason, count]) =>
          <li key={reason}>{count} × {reasonLabel(reason)}</li>)}</ul>}
        {!canGenerate(check) && <p>No finding in this assessment is report eligible yet. Confirm and sign off findings in the analyst workbench first.</p>}
        <button className="primary-button" disabled={busy || !canGenerate(check)}
          onClick={() => run(async () => { const report = await api.generateReport(assessmentId); await choose(assessmentId); await open(report.id); }, "Draft report generated. It is not approved and cannot be released yet.")}>Generate draft report</button>
      </>}
    </div>

    <form className="panel findings-filters" aria-label="Report filters" onSubmit={event => event.preventDefault()}>
      <label>Status<select aria-label="Report status filter" value={status} onChange={event => { setSelected(null); setStatus(event.target.value); }}>
        <option value="">All reports</option>{REPORT_STATUSES.map(value => <option key={value} value={value}>{statusLabel(value)}</option>)}</select></label>
    </form>
    {list && <div className="panel table-scroll"><table><thead><tr><th>Report</th><th>Status</th><th>Findings</th><th>Created</th><th>Open</th></tr></thead><tbody>
      {list.items.map(item => <tr key={item.id}><td>{safeText(item.title, 300)}<br />Revision {item.revision}</td><td>{statusLabel(item.status)}</td>
        <td>{item.eligible_count} included · {item.excluded_count} excluded</td><td>{when(item.created_at)}<br />{safeText(item.created_by_name)}</td>
        <td><button disabled={busy} onClick={() => run(() => open(item.id))}>Review report</button></td></tr>)}
    </tbody></table>{!list.items.length && <p>No reports yet.</p>}</div>}

    {selected && <article className="panel assessment-detail" aria-label="Report detail">
      <h2>{safeText(selected.title, 300)} · revision {selected.revision}</h2>
      <p><strong>{statusLabel(selected.status)}</strong> · created {when(selected.created_at)} by {safeText(selected.created_by_name)}</p>
      <p>Content SHA-256 <code>{shortHash(selected.content_sha256)}</code> · Official PDF SHA-256 <code>{shortHash(selected.official_pdf_sha256)}</code></p>
      <h3>Executive summary</h3><p>{safeText(selected.executive_summary, 4000)}</p>
      <h3>Scope</h3>
      <p>{safeText(selected.scope.client_name)} · {safeText(selected.scope.target_url)} · authorised domains: {selected.scope.authorized_domains.map(d => safeText(d, 253)).join(", ")}</p>
      <h3>Severity breakdown</h3>
      <p aria-label="Severity breakdown">{severityRows(selected).map(row => `${row.severity}: ${row.count}`).join(" · ")}</p>
      <h3>Included findings ({selected.eligible_count})</h3>
      <section aria-label="Included findings">{selected.findings.map(item => <details key={item.vulnerability_id}>
        <summary>{safeText(item.title, 200)} · {item.severity} · {humanize(item.remediation_priority)} priority · signed off by {safeText(item.signoff_analyst)}</summary>
        <h4>Evidence (untrusted target data)</h4><pre aria-label="Finding evidence (untrusted, shown as text)">{safeText(item.evidence)}</pre>
        <h4>Reproduction steps</h4><pre>{safeText(item.reproduction_steps)}</pre>
        <h4>Remediation</h4><pre>{safeText(item.remediation)}</pre>
      </details>)}</section>
      <p>{selected.excluded_count} finding(s) excluded: {[...new Set(selected.excluded.map(item => reasonLabel(item.reason)))].join("; ") || "none"}.</p>

      <h3>Downloads</h3>
      <button disabled={busy} onClick={() => run(async () => save(await api.downloadReportPdf(selected.id, false), pdfFileName(selected, false)))}>Download draft preview (not for release)</button>{" "}
      <button className="primary-button" disabled={busy || !canDownloadOfficial(selected)}
        onClick={() => run(async () => save(await api.downloadReportPdf(selected.id, true), pdfFileName(selected, true)))}>Download official PDF</button>
      {!canDownloadOfficial(selected) && <p>The official PDF is available only after a human approves this report.</p>}

      <h3>Approval</h3>
      {selected.approval && <p>{humanize(selected.approval.decision)} by {safeText(selected.decided_by_name)} on {when(selected.approval.occurred_at)} · {safeText(selected.approval.justification, 500)}</p>}
      <DecisionForm key={`${selected.id}:${selected.status}`} report={selected} busy={busy}
        onApprove={payload => run(async () => { await api.approveReport(selected.id, payload); await open(selected.id); }, "Report approved. The official PDF is now available.")}
        onReject={payload => run(async () => { await api.rejectReport(selected.id, payload); await open(selected.id); }, "Report rejected. No official PDF will be issued.")} />

      <h3>Immutable report audit trail</h3>
      <section aria-label="Report audit trail">{events.map(item => <p key={item.id}>{when(item.occurred_at)} · {humanize(item.action)} · {safeText(item.actor_name)}</p>)}</section>
    </article>}
  </section>;
}
