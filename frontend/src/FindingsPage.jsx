import React, { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./lib/api.js";
import { ReviewForm } from "./AssessmentReviews.jsx";
import "./assessments.css";
import "./findings.css";

const label = value => value?.replaceAll("_", " ") ?? "Not recorded";
const blank = { client_id: "", website_id: "", severity: "", status: "", owner: "", search: "", overdue_only: false };

function DeadlineForm({ detail, busy, onSave }) {
  const [date, setDate] = useState(detail.deadline?.due_date ?? ""), [note, setNote] = useState("");
  return <form aria-label="Finding deadline" onSubmit={event => {
    event.preventDefault(); onSave({ due_date: date || null, note,
      expected_revision: detail.deadline?.revision ?? 0, expected_review_revision: detail.review.revision });
  }}><fieldset disabled={busy}><legend>Remediation due date</legend>
    <label>Finding due date<input type="date" value={date} onChange={event => setDate(event.target.value)} /></label>
    <label>Due-date change note<textarea required minLength={10} maxLength={2000} value={note} onChange={event => setNote(event.target.value)} /></label>
    <p>Leave the date empty to clear it. Dates use Asia/Kolkata; due today is not overdue.</p>
    <button className="primary-button">Save due date</button>
  </fieldset></form>;
}

export default function FindingsPage({ clients, websites, onOpenAssessment }) {
  const [draft, setDraft] = useState(blank), [filters, setFilters] = useState(blank), [offset, setOffset] = useState(0);
  const [data, setData] = useState(null), [selected, setSelected] = useState(null), [history, setHistory] = useState([]);
  const [historyOffset, setHistoryOffset] = useState(0), [busy, setBusy] = useState(false), [loading, setLoading] = useState(false);
  const [error, setError] = useState(""), [notice, setNotice] = useState("");
  const generation = useRef(0), detailGeneration = useRef(0);
  const load = useCallback(async () => {
    const version = ++generation.current; setLoading(true);
    try { const result = await api.getFindings(filters, offset); if (version === generation.current) setData(result); }
    finally { if (version === generation.current) setLoading(false); }
  }, [filters, offset]);
  useEffect(() => {
    let alive = true;
    load().catch(error => { if (alive) setError(error.message); });
    return () => { alive = false; generation.current++; };
  }, [load]);
  useEffect(() => () => { detailGeneration.current++; }, []);
  async function open(item, page = 0) {
    const version = ++detailGeneration.current;
    const [detail, dates] = await Promise.all([api.findingDetail(item.assessment_id, item.check_id),
      api.findingDeadlineHistory(item.assessment_id, item.check_id, page)]);
    if (version === detailGeneration.current) { setSelected(detail); setHistory(dates); setHistoryOffset(page); }
  }
  async function run(action, message) {
    setBusy(true); setError(""); setNotice("");
    try { await action(); await load(); if (message) setNotice(message); }
    catch (error) { setError(error.message); }
    finally { setBusy(false); }
  }
  function apply(values) {
    detailGeneration.current++; setSelected(null); setFilters({ ...values }); setOffset(0); setError(""); setNotice("");
  }
  return <section className="assessment-page findings-page">
    <div className="eyebrow">REMEDIATION WORK QUEUE</div><h1>Findings and remediation</h1>
    <p>Current analyst-confirmed issues across clients and websites. Each assessment observation is tracked separately; findings from different assessments are not automatically merged.</p>
    {error && <p role="alert" className="form-error">{error}</p>}{notice && <p role="status">{notice}</p>}
    <button disabled={busy || loading} onClick={() => run(async () => { detailGeneration.current++; setSelected(null); }, "Findings refreshed.")}>Refresh findings</button>
    {loading && <p role="status">Loading findings…</p>}
    <form className="panel findings-filters" aria-label="Finding filters" onSubmit={event => { event.preventDefault(); apply(draft); }}>
      <label>Findings client<select aria-label="Findings client" value={draft.client_id} onChange={event => setDraft({ ...draft, client_id: event.target.value, website_id: "" })}><option value="">All clients</option>{clients.map(client => <option key={client.id} value={client.id}>{client.company_name}</option>)}</select></label>
      <label>Findings website<select aria-label="Findings website" value={draft.website_id} onChange={event => setDraft({ ...draft, website_id: event.target.value })}><option value="">All websites</option>{websites.filter(site => !draft.client_id || String(site.client_id) === draft.client_id).map(site => <option key={site.id} value={site.id}>{site.name}</option>)}</select></label>
      <label>Finding severity<select aria-label="Finding severity" value={draft.severity} onChange={event => setDraft({ ...draft, severity: event.target.value })}><option value="">All severities</option>{["critical", "high", "medium", "low", "informational"].map(value => <option key={value}>{value}</option>)}</select></label>
      <label>Finding status<select aria-label="Finding status" value={draft.status} onChange={event => setDraft({ ...draft, status: event.target.value })}><option value="">All statuses</option>{["open", "in_progress", "ready_for_retest", "resolved"].map(value => <option key={value} value={value}>{label(value)}</option>)}</select></label>
      <label>Finding owner<input value={draft.owner} maxLength={150} onChange={event => setDraft({ ...draft, owner: event.target.value })} /></label>
      <label>Search findings<input value={draft.search} maxLength={200} onChange={event => setDraft({ ...draft, search: event.target.value })} placeholder="Client, website, domain or check" /></label>
      <label className="assessment-check"><input type="checkbox" checked={draft.overdue_only} onChange={event => setDraft({ ...draft, overdue_only: event.target.checked })} />Overdue findings only</label>
      <div><button className="primary-button" disabled={busy}>Apply finding filters</button> <button type="button" disabled={busy} onClick={() => { setDraft(blank); apply(blank); }}>Clear finding filters</button></div>
    </form>
    {data && <>
      <div className="findings-counts" aria-label="Finding totals">{["total", "open", "in_progress", "ready_for_retest", "resolved", "overdue"].map(key => <div className="panel" key={key}><span>{label(key)}</span><strong>{data.summary[key]}</strong></div>)}</div>
      <p>Totals cover every matching finding, including other pages. Overdue dates use {data.timezone}; today is {data.today}.</p>
      <div className="panel table-scroll"><table><thead><tr><th>Client / website</th><th>Issue</th><th>Severity</th><th>Owner / status</th><th>Due</th><th>Details</th></tr></thead><tbody>{data.items.map(item => <tr key={`${item.assessment_id}:${item.check_id}`}>
        <td>{item.client_name}<br />{item.website_name}</td><td>{label(item.check_id)}</td><td>{item.review.severity}</td><td>{item.review.owner}<br />{label(item.review.remediation_status)}</td>
        <td>{item.deadline?.due_date ?? "Not set"}{item.overdue && <strong className="finding-overdue">Overdue</strong>}</td>
        <td><button disabled={busy} onClick={() => run(() => open(item))}>Open finding</button></td>
      </tr>)}</tbody></table>{!data.items.length && <p>No analyst-confirmed findings match these filters.</p>}</div>
      <div className="assessment-pagination"><button disabled={!offset || busy || loading} onClick={() => { setSelected(null); detailGeneration.current++; setOffset(offset - 50); }}>Previous findings</button><span>Page {offset / 50 + 1} · {data.summary.total} matching findings</span><button disabled={offset + 50 >= data.summary.total || busy || loading} onClick={() => { setSelected(null); detailGeneration.current++; setOffset(offset + 50); }}>Next findings</button></div>
    </>}
    {selected && <article className="panel assessment-detail" aria-label="Finding details">
      <h2>{label(selected.check_id)}</h2><p>Target: {selected.target_url}</p>
      <p>Assessment: {selected.assessment_id} · Latest reviewer: administrator #{selected.review.reviewer_id}</p>
      <p>Source report SHA-256: <code>{selected.source_report_sha256}</code></p>
      <p>Evidence: {selected.review.supporting_evidence}</p><p>Recommended fix: {selected.review.recommendation}</p>
      <button onClick={() => onOpenAssessment(selected.assessment_id)}>Open source assessment and reports</button>
      {selected.review.retest_assessment_id && <button onClick={() => onOpenAssessment(selected.review.retest_assessment_id)}>Open linked retest</button>}
      <h3>Review, owner and remediation status</h3>
      <ReviewForm key={`${selected.assessment_id}:${selected.check_id}:${selected.review.revision}`} assessmentId={selected.assessment_id}
        item={{ observation: selected.observation, review: selected.review }} busy={busy} onSave={(check, payload) => run(async () => {
          const item = selected, version = detailGeneration.current;
          await api.reviewObservation(item.assessment_id, check, payload);
          if (version === detailGeneration.current) {
            if (payload.disposition === "confirmed") await open(item);
            else { detailGeneration.current++; setSelected(null); }
          }
        }, "Finding review saved; its source assessment uses the same revision history.")} />
      <DeadlineForm key={`${selected.assessment_id}:${selected.check_id}:${selected.deadline?.revision ?? 0}:${selected.review.revision}`} detail={selected} busy={busy} onSave={payload => run(async () => {
        const item = selected, version = detailGeneration.current;
        await api.setFindingDeadline(item.assessment_id, item.check_id, payload);
        if (version === detailGeneration.current) await open(item);
      }, "Finding due date saved with revision history.")} />
      <h3>Due-date history</h3><section aria-label="Finding due-date history">{history.length ? history.map(item => <p key={item.id}>
        Revision {item.revision}: {item.due_date ?? "Date cleared"} · Administrator #{item.updated_by} · {new Date(item.updated_at).toLocaleString()} · {item.note}
      </p>) : <p>No due-date changes recorded.</p>}</section>
      <div className="assessment-pagination"><button disabled={!historyOffset || busy} onClick={() => run(() => open(selected, historyOffset - 50))}>Previous deadline changes</button><span>History page {historyOffset / 50 + 1}</span><button disabled={history.length < 50 || busy} onClick={() => run(() => open(selected, historyOffset + 50))}>Next deadline changes</button></div>
    </article>}
  </section>;
}
