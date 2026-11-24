import React, { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./lib/api.js";
import { humanize, safeText } from "./lib/workbench.js";
import { REMEDIATION_STATUSES, buildClosure, buildClosureReopening, buildReopen, buildRetest, buildUpdate, canClose, closureSummary,
  outcomeLabel, reportableAssessment, statusLabel, updateOptions } from "./lib/remediation.js";
import "./assessments.css";
import "./findings.css";

const when = value => value ? new Date(value).toLocaleString() : "Not recorded";

function UpdateForm({ item, busy, onSubmit }) {
  const options = updateOptions(item);
  const [form, setForm] = useState({ status: options[0] ?? "", note: "", target_date: item.target_date ?? "", attested: false });
  const [error, setError] = useState("");
  if (!options.length) return <p>No manual status change is available from “{statusLabel(item.status)}”.</p>;
  return <form aria-label="Remediation update" onSubmit={event => {
    event.preventDefault();
    const result = buildUpdate(item, form);
    if (result.error) { setError(result.error); return; }
    setError(""); onSubmit(result.payload);
  }}><fieldset disabled={busy}><legend>Record a remediation update</legend>
    {error && <p role="alert" className="form-error">{error}</p>}
    <label>New status<select aria-label="Remediation status" value={form.status} onChange={event => setForm({ ...form, status: event.target.value })}>
      {options.map(value => <option key={value} value={value}>{statusLabel(value)}</option>)}</select></label>
    <label>Client remediation note<textarea aria-label="Remediation note" required minLength={10} maxLength={4000} value={form.note}
      onChange={event => setForm({ ...form, note: event.target.value })} /></label>
    <label>Target remediation date<input aria-label="Target remediation date" type="date" value={form.target_date}
      onChange={event => setForm({ ...form, target_date: event.target.value })} /></label>
    {form.status === "risk_accepted" && <label className="assessment-check"><input type="checkbox" checked={form.attested}
      onChange={event => setForm({ ...form, attested: event.target.checked })} />The business owner formally accepts this risk and I have recorded their justification above.</label>}
    <button className="primary-button">Save update</button>
  </fieldset></form>;
}

function RetestForm({ item, authorizations, busy, onSubmit }) {
  const [form, setForm] = useState({ authorization_id: "", note: "", confirmed: false });
  const [error, setError] = useState("");
  if (!item.can_request_retest) return <p>{item.active_retest_id ? "A retest is in progress." : "A retest can be requested once a fix has been submitted."}</p>;
  return <form aria-label="Request retest" onSubmit={event => {
    event.preventDefault();
    const result = buildRetest(item, form);
    if (result.error) { setError(result.error); return; }
    setError(""); onSubmit(result.payload);
  }}><fieldset disabled={busy}><legend>Request a scoped retest</legend>
    {error && <p role="alert" className="form-error">{error}</p>}
    <p>One authorised HEAD request to {safeText(item.target_url, 300)}. The scanner worker revalidates the written authorisation, exact domain and methods immediately before it runs; there is no local fallback.</p>
    <label>Written authorisation<select aria-label="Retest authorisation" value={form.authorization_id} onChange={event => setForm({ ...form, authorization_id: event.target.value })}>
      <option value="">Choose a currently valid approval</option>
      {authorizations.map(a => <option key={a.id} value={a.id}>{safeText(a.authorization_reference, 100)} · #{a.id}</option>)}</select></label>
    <label>What should be verified<textarea aria-label="Retest note" required minLength={20} maxLength={1500} value={form.note}
      onChange={event => setForm({ ...form, note: event.target.value })} /></label>
    <label className="assessment-check"><input type="checkbox" checked={form.confirmed}
      onChange={event => setForm({ ...form, confirmed: event.target.checked })} />I explicitly request this retest of the authorised target.</label>
    <button className="primary-button">Request retest</button>
  </fieldset></form>;
}

function ReopenForm({ item, busy, onSubmit }) {
  const [reason, setReason] = useState(""), [error, setError] = useState("");
  if (!item.can_reopen) return null;
  return <form aria-label="Reopen finding" onSubmit={event => {
    event.preventDefault();
    const result = buildReopen(item, { reason });
    if (result.error) { setError(result.error); return; }
    setError(""); onSubmit(result.payload);
  }}><fieldset disabled={busy}><legend>Reopen an unresolved issue</legend>
    {error && <p role="alert" className="form-error">{error}</p>}
    <label>Reason<textarea aria-label="Reopen reason" required minLength={20} maxLength={4000} value={reason} onChange={event => setReason(event.target.value)} /></label>
    <button>Reopen finding</button>
  </fieldset></form>;
}

function ClosurePanel({ assessments, busy, onChanged }) {
  const [assessmentId, setAssessmentId] = useState(""), [state, setState] = useState(null);
  const [form, setForm] = useState({ justification: "", attested: false }), [error, setError] = useState(""), [notice, setNotice] = useState("");
  const [reopenForm, setReopenForm] = useState({ justification: "", attested: false });
  const version = useRef(0);
  async function choose(id) {
    const mine = ++version.current;
    setAssessmentId(id); setState(null); setError(""); setNotice("");
    if (!id) return;
    try { const result = await api.assessmentClosure(id); if (mine === version.current) setState(result); }
    catch (failure) { setError(failure.message); }
  }
  async function submit(event) {
    event.preventDefault();
    const result = buildClosure(state, form);
    if (result.error) { setError(result.error); return; }
    setError("");
    try { await api.closeAssessment(assessmentId, result.payload); setNotice("Assessment closed. The closure record is immutable."); await choose(assessmentId); onChanged(); }
    catch (failure) { setError(failure.message); }
  }
  async function reopenClosure(event) {
    event.preventDefault();
    const result = buildClosureReopening(state, reopenForm);
    if (result.error) { setError(result.error); return; }
    setError("");
    try { await api.reopenClosure(assessmentId, result.payload); setReopenForm({ justification: "", attested: false });
      setNotice("Closure reopened and recorded in the audit trail. Findings can be changed again."); await choose(assessmentId); onChanged(); }
    catch (failure) { setError(failure.message); }
  }
  return <div className="panel">
    <h2>Assessment closure</h2>
    <label>Assessment<select aria-label="Closure assessment" value={assessmentId} onChange={event => choose(event.target.value)}>
      <option value="">Choose a completed assessment</option>
      {assessments.map(row => <option key={row.id} value={row.id}>{safeText(row.target_host, 253)} · {when(row.requested_at)} · {row.id.slice(0, 8)}</option>)}</select></label>
    {error && <p role="alert" className="form-error">{error}</p>}{notice && <p role="status">{notice}</p>}
    {state && <>
      <p aria-label="Closure status"><strong>{closureSummary(state)}</strong> · {state.confirmed_count} confirmed finding(s)
        {state.unreviewed_count > 0 && ` · ${state.unreviewed_count} detected finding(s) have not been reviewed by an analyst`}</p>
      {state.blocking_reasons.length > 0 && <ul aria-label="Why this assessment cannot be closed">{state.blocking_reasons.map(reason => <li key={reason}>{reason}</li>)}</ul>}
      {state.blockers.length > 0 && <ul aria-label="Blocking findings">{state.blockers.map(b => <li key={b.vulnerability_id}>{safeText(b.title, 200)} · {statusLabel(b.status)}</li>)}</ul>}
      {state.closure && <p>Closed by {safeText(state.closure.closed_by_name)} on {when(state.closure.closed_at)} · record SHA-256 <code>{state.closure.content_sha256.slice(0, 16)}…</code></p>}
      {state.closed && <form aria-label="Reopen closure" onSubmit={reopenClosure}><fieldset disabled={busy}>
        <legend>Closed assessments are locked. Reopen the closure to change its findings.</legend>
        <label>Reason for reopening<textarea aria-label="Closure reopening reason" required minLength={20} maxLength={4000} value={reopenForm.justification}
          onChange={event => setReopenForm({ ...reopenForm, justification: event.target.value })} /></label>
        <label className="assessment-check"><input type="checkbox" checked={reopenForm.attested}
          onChange={event => setReopenForm({ ...reopenForm, attested: event.target.checked })} />I am deliberately reopening this closure.</label>
        <button>Reopen closure</button>
      </fieldset></form>}
      {!state.closed && <form aria-label="Close assessment" onSubmit={submit}><fieldset disabled={busy || !canClose(state)}>
        <legend>Close this assessment</legend>
        <label>Justification<textarea aria-label="Closure justification" required minLength={20} maxLength={4000} value={form.justification}
          onChange={event => setForm({ ...form, justification: event.target.value })} /></label>
        <label className="assessment-check"><input type="checkbox" checked={form.attested}
          onChange={event => setForm({ ...form, attested: event.target.checked })} />I reviewed the final remediation state of every confirmed finding.</label>
        <button className="primary-button">Close assessment</button>
      </fieldset></form>}
    </>}
  </div>;
}

export default function RemediationPage({ websites = [] }) {
  const [status, setStatus] = useState(""), [website, setWebsite] = useState(""), [search, setSearch] = useState(""), [offset, setOffset] = useState(0);
  const [data, setData] = useState(null), [selected, setSelected] = useState(null), [assessments, setAssessments] = useState([]);
  const [authorizations, setAuthorizations] = useState([]);
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [notice, setNotice] = useState("");
  const generation = useRef(0), detailVersion = useRef(0);

  const load = useCallback(async () => {
    const version = ++generation.current;
    const result = await api.remediationList({ status, website_id: website, search: search.trim() }, offset);
    if (version === generation.current) setData(result);
  }, [status, website, search, offset]);
  useEffect(() => {
    let alive = true;
    load().catch(failure => { if (alive) setError(failure.message); });
    return () => { alive = false; generation.current++; };
  }, [load]);
  useEffect(() => {
    let alive = true;
    api.getAssessments().then(rows => { if (alive) setAssessments(rows.filter(reportableAssessment)); })
      .catch(failure => { if (alive) setError(failure.message); });
    return () => { alive = false; detailVersion.current++; };
  }, []);

  async function open(id, siteId) {
    const version = ++detailVersion.current;
    const [detail, permissions] = await Promise.all([api.remediation(id), api.getAuthorizations({ websiteId: siteId })]);
    if (version === detailVersion.current) {
      setSelected(detail);
      setAuthorizations(permissions.filter(a => a.status === "approved" && a.effective_status === "active"));
    }
  }
  async function run(action, message) {
    setBusy(true); setError(""); setNotice("");
    try { await action(); await load(); if (message) setNotice(message); }
    catch (failure) { setError(failure.message); }
    finally { setBusy(false); }
  }
  const choose = changes => { detailVersion.current++; setSelected(null); setOffset(0); changes(); };
  const refreshSelected = () => selected ? open(selected.vulnerability_id, selected.website_id) : Promise.resolve();

  return <section className="assessment-page findings-page">
    <div className="eyebrow">REMEDIATION AND RETESTING</div><h1>Remediation and retesting</h1>
    <p>Track the fix for every confirmed finding, request a scoped retest once a fix is submitted, and close an assessment when each confirmed finding is verified fixed or formally risk accepted. A retest is one authorised request that the scanner worker revalidates; a finding that still reproduces is reopened automatically.</p>
    {error && <p role="alert" className="form-error">{error}</p>}{notice && <p role="status">{notice}</p>}

    <form className="panel findings-filters" aria-label="Remediation filters" onSubmit={event => event.preventDefault()}>
      <label>Status<select aria-label="Remediation status filter" value={status} onChange={event => choose(() => setStatus(event.target.value))}>
        <option value="">All confirmed findings</option>{REMEDIATION_STATUSES.map(value => <option key={value} value={value}>{statusLabel(value)}</option>)}</select></label>
      <label>Website<select aria-label="Remediation website filter" value={website} onChange={event => choose(() => setWebsite(event.target.value))}>
        <option value="">All websites</option>{websites.map(site => <option key={site.id} value={site.id}>{site.name}</option>)}</select></label>
      <label>Search<input aria-label="Search remediation" value={search} maxLength={200} onChange={event => choose(() => setSearch(event.target.value))} placeholder="Title, check, host, website or client" /></label>
    </form>
    {data && <>
      <div className="findings-counts" aria-label="Remediation totals">{REMEDIATION_STATUSES.map(key => <div className="panel" key={key}><span>{statusLabel(key)}</span><strong>{data.summary[key] ?? 0}</strong></div>)}</div>
      <div className="panel table-scroll"><table><thead><tr><th>Finding</th><th>Client / website</th><th>Severity</th><th>Status</th><th>Target date</th><th>Open</th></tr></thead><tbody>{data.items.map(item => <tr key={item.vulnerability_id}>
        <td>{safeText(item.title, 200)}<br /><code>{item.check_id}</code></td><td>{safeText(item.client_name, 200)}<br />{safeText(item.website_name, 200)}</td>
        <td>{item.severity}</td><td>{statusLabel(item.status)}{item.retest_attempts > 0 && ` · ${item.retest_attempts} retest(s)`}</td><td>{item.target_date ?? "None set"}</td>
        <td><button disabled={busy} onClick={() => run(() => open(item.vulnerability_id, item.website_id))}>Manage remediation</button></td></tr>)}</tbody></table>
        {!data.items.length && <p>No confirmed findings match. Findings appear here once an analyst confirms them in the workbench.</p>}</div>
      <div className="assessment-pagination"><button disabled={!offset || busy} onClick={() => { setSelected(null); setOffset(offset - 50); }}>Previous findings</button><span>Showing {data.items.length} · offset {offset}</span><button disabled={data.items.length < 50 || busy} onClick={() => { setSelected(null); setOffset(offset + 50); }}>Next findings</button></div>
    </>}

    {selected && <article className="panel assessment-detail" aria-label="Remediation detail">
      <h2>{safeText(selected.title, 200)}</h2>
      <p><strong>{statusLabel(selected.status)}</strong> · severity {selected.severity} · {selected.retest_attempts} conclusive retest(s) · target date {selected.target_date ?? "none set"}</p>
      <p>Target: {safeText(selected.target_url, 300)} · {safeText(selected.client_name)} / {safeText(selected.website_name)}</p>
      {selected.client_note && <><h3>Latest client note</h3><pre>{safeText(selected.client_note, 4000)}</pre></>}
      {selected.risk_acceptance_reason && <p>Risk accepted {when(selected.risk_accepted_at)}: {safeText(selected.risk_acceptance_reason, 1000)}</p>}

      <h3>Retest history</h3>
      <section aria-label="Retest history">{selected.retests.map(retest => <p key={retest.id}>Attempt {retest.attempt} · {when(retest.requested_at)} · {outcomeLabel(retest)}{retest.completed_at ? ` · finished ${when(retest.completed_at)}` : ""}</p>)}
        {!selected.retests.length && <p>No retests yet.</p>}</section>

      <UpdateForm key={`u:${selected.vulnerability_id}:${selected.version}`} item={selected} busy={busy}
        onSubmit={payload => run(async () => { await api.updateRemediation(selected.vulnerability_id, payload); await refreshSelected(); }, "Remediation update recorded in the audit history.")} />
      <RetestForm key={`t:${selected.vulnerability_id}:${selected.version}`} item={selected} authorizations={authorizations} busy={busy}
        onSubmit={payload => run(async () => { await api.requestRetest(selected.vulnerability_id, payload); await refreshSelected(); }, "Retest queued. The scanner worker will revalidate the authorisation before it runs.")} />
      <ReopenForm key={`r:${selected.vulnerability_id}:${selected.version}`} item={selected} busy={busy}
        onSubmit={payload => run(async () => { await api.reopenRemediation(selected.vulnerability_id, payload); await refreshSelected(); }, "Finding reopened.")} />
      <button disabled={busy} onClick={() => run(refreshSelected)}>Refresh retest status</button>

      <h3>Immutable remediation audit trail</h3>
      <section aria-label="Remediation audit trail">{selected.events.map(item => <p key={item.id}>{when(item.occurred_at)} · {humanize(item.action)} · {item.from_status ? `${statusLabel(item.from_status)} → ` : ""}{statusLabel(item.to_status)} · {safeText(item.actor_name)}{item.note ? ` · ${safeText(item.note, 300)}` : ""}</p>)}</section>
    </article>}

    <ClosurePanel assessments={assessments} busy={busy} onChanged={load} />
  </section>;
}
