import React, { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./lib/api.js";
import { SEVERITIES, STATES, buildDecision, confidenceSummary, decisionLabel, stateLabel } from "./lib/vulnerabilities.js";
import "./assessments.css";
import "./findings.css";

const label = value => value?.replaceAll("_", " ") ?? "Not recorded";
const when = value => value ? new Date(value).toLocaleString() : "Not recorded";
const blank = { state: "", severity: "", confidence: "", website_id: "", suppressed: "", search: "" };

function DecisionForm({ item, busy, onSubmit }) {
  const [form, setForm] = useState({ decision: item.allowed_decisions[0], attested: false, justification: "",
    severity: item.scanner_severity, reproduction_steps: "", suppress_until: "" });
  const [error, setError] = useState("");
  const set = changes => setForm({ ...form, ...changes });
  return <form aria-label="Validation decision" onSubmit={event => {
    event.preventDefault();
    const result = buildDecision(item, form);
    if (result.error) { setError(result.error); return; }
    setError(""); onSubmit(result.payload);
  }}><fieldset disabled={busy}><legend>Analyst validation decision</legend>
    {error && <p role="alert" className="form-error">{error}</p>}
    <label>Decision<select aria-label="Validation decision type" value={form.decision} onChange={event => set({ decision: event.target.value })}>
      {item.allowed_decisions.map(value => <option key={value} value={value}>{decisionLabel(value)}</option>)}</select></label>
    {form.decision === "confirmed" && <>
      <label>Analyst severity<select aria-label="Analyst severity" value={form.severity} onChange={event => set({ severity: event.target.value })}>
        {SEVERITIES.map(value => <option key={value}>{value}</option>)}</select></label>
      <label>Reproduction steps<textarea aria-label="Reproduction steps" required minLength={20} maxLength={8000} value={form.reproduction_steps} onChange={event => set({ reproduction_steps: event.target.value })} /></label>
    </>}
    {(form.decision === "false_positive" || form.decision === "not_applicable") &&
      <label>Suppress until<input aria-label="Suppress until" type="date" required value={form.suppress_until} onChange={event => set({ suppress_until: event.target.value })} /></label>}
    <label>Justification<textarea aria-label="Decision justification" required minLength={20} maxLength={4000} value={form.justification} onChange={event => set({ justification: event.target.value })} /></label>
    <label className="assessment-check"><input type="checkbox" checked={form.attested} onChange={event => set({ attested: event.target.checked })} />I personally inspected the stored evidence and validated this decision.</label>
    <button className="primary-button">Record decision</button>
  </fieldset></form>;
}

function CommentForm({ busy, onSubmit }) {
  const [text, setText] = useState("");
  return <form aria-label="Analyst comment" onSubmit={event => { event.preventDefault(); onSubmit(text, () => setText("")); }}>
    <fieldset disabled={busy}><legend>Add analyst comment</legend>
      <label>Comment<textarea aria-label="Analyst comment text" required minLength={5} maxLength={4000} value={text} onChange={event => setText(event.target.value)} /></label>
      <button>Add comment</button>
    </fieldset></form>;
}

export default function VulnerabilitiesPage({ websites, onOpenAssessment }) {
  const [draft, setDraft] = useState(blank), [filters, setFilters] = useState(blank), [offset, setOffset] = useState(0);
  const [data, setData] = useState(null), [selected, setSelected] = useState(null);
  const [occurrences, setOccurrences] = useState([]), [events, setEvents] = useState([]);
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [notice, setNotice] = useState("");
  const generation = useRef(0), detailGeneration = useRef(0);
  const load = useCallback(async () => {
    const version = ++generation.current;
    const result = await api.getVulnerabilities(filters, offset);
    if (version === generation.current) setData(result);
  }, [filters, offset]);
  useEffect(() => {
    let alive = true;
    load().catch(failure => { if (alive) setError(failure.message); });
    return () => { alive = false; generation.current++; };
  }, [load]);
  useEffect(() => () => { detailGeneration.current++; }, []);
  async function open(id) {
    const version = ++detailGeneration.current;
    const [detail, seen, history] = await Promise.all([api.vulnerability(id), api.vulnerabilityHistory(id, "occurrences"), api.vulnerabilityHistory(id, "events")]);
    if (version === detailGeneration.current) { setSelected(detail); setOccurrences(seen); setEvents(history); }
  }
  async function run(action, message) {
    setBusy(true); setError(""); setNotice("");
    try { await action(); await load(); if (message) setNotice(message); }
    catch (failure) { setError(failure.message); }
    finally { setBusy(false); }
  }
  function apply(values) { detailGeneration.current++; setSelected(null); setFilters({ ...values }); setOffset(0); }

  return <section className="assessment-page findings-page">
    <div className="eyebrow">VULNERABILITY MANAGEMENT</div><h1>Vulnerabilities</h1>
    <p>Each record is one check on one exact target, deduplicated across assessments and scanner profiles. Scanner output is never a confirmed vulnerability: every record stays unconfirmed until an analyst records an attested decision.</p>
    {error && <p role="alert" className="form-error">{error}</p>}{notice && <p role="status">{notice}</p>}
    {data && <p>{data.pending_ingestion ? `${data.pending_ingestion} completed assessment report(s) not yet ingested.` : "All completed assessment reports are ingested."}</p>}
    <button disabled={busy} onClick={() => run(async () => {
      const result = await api.ingestVulnerabilities();
      const rejected = result.results.filter(item => item.status === "rejected").length;
      setNotice(`Ingested ${result.processed - rejected} report(s)${rejected ? `; ${rejected} rejected (see assessment events)` : ""}.`);
    })}>Ingest completed reports</button>
    <form className="panel findings-filters" aria-label="Vulnerability filters" onSubmit={event => { event.preventDefault(); apply(draft); }}>
      <label>Validation state<select aria-label="Validation state filter" value={draft.state} onChange={event => setDraft({ ...draft, state: event.target.value })}><option value="">All states</option>{STATES.map(value => <option key={value} value={value}>{label(value)}</option>)}</select></label>
      <label>Severity<select aria-label="Vulnerability severity filter" value={draft.severity} onChange={event => setDraft({ ...draft, severity: event.target.value })}><option value="">All severities</option>{SEVERITIES.map(value => <option key={value}>{value}</option>)}</select></label>
      <label>Confidence<select aria-label="Confidence filter" value={draft.confidence} onChange={event => setDraft({ ...draft, confidence: event.target.value })}><option value="">All confidence</option>{["high", "medium", "low"].map(value => <option key={value}>{value}</option>)}</select></label>
      <label>Website<select aria-label="Vulnerability website filter" value={draft.website_id} onChange={event => setDraft({ ...draft, website_id: event.target.value })}><option value="">All websites</option>{websites.map(site => <option key={site.id} value={site.id}>{site.name}</option>)}</select></label>
      <label>Suppression<select aria-label="Suppression filter" value={draft.suppressed} onChange={event => setDraft({ ...draft, suppressed: event.target.value })}><option value="">Any</option><option value="true">Actively suppressed</option><option value="false">Not suppressed</option></select></label>
      <label>Search<input aria-label="Search vulnerabilities" value={draft.search} maxLength={200} onChange={event => setDraft({ ...draft, search: event.target.value })} placeholder="Title, check, host, website or client" /></label>
      <div><button className="primary-button" disabled={busy}>Apply vulnerability filters</button> <button type="button" disabled={busy} onClick={() => { setDraft(blank); apply(blank); }}>Clear vulnerability filters</button></div>
    </form>
    {data && <>
      <div className="findings-counts" aria-label="Vulnerability totals">{["total", "unconfirmed", "confirmed", "false_positive", "not_applicable"].map(key => <div className="panel" key={key}><span>{label(key)}</span><strong>{data.summary[key]}</strong></div>)}</div>
      <div className="panel table-scroll"><table><thead><tr><th>Vulnerability</th><th>Client / website</th><th>Severity</th><th>Confidence</th><th>State</th><th>Seen</th><th>Details</th></tr></thead><tbody>{data.items.map(item => <tr key={item.id}>
        <td>{item.title}<br /><code>{item.check_id}</code></td><td>{item.client_name}<br />{item.website_name}</td>
        <td>{item.effective_severity}{item.validation_state !== "confirmed" && " (scanner suggestion)"}</td>
        <td>{item.confidence} ({item.confidence_score})</td>
        <td>{label(item.validation_state)}{item.suppression?.status === "active" && <><br />Suppressed until {when(item.suppression.expires_at)}</>}</td>
        <td>{item.detection_count}× · last {when(item.last_seen_at)}</td>
        <td><button disabled={busy} onClick={() => run(() => open(item.id))}>Open vulnerability</button></td>
      </tr>)}</tbody></table>{!data.items.length && <p>No vulnerabilities match these filters.</p>}</div>
      <div className="assessment-pagination"><button disabled={!offset || busy} onClick={() => { setSelected(null); setOffset(offset - 50); }}>Previous vulnerabilities</button><span>Page {offset / 50 + 1} · {data.summary.total} matching</span><button disabled={offset + 50 >= data.summary.total || busy} onClick={() => { setSelected(null); setOffset(offset + 50); }}>Next vulnerabilities</button></div>
    </>}
    {selected && <article className="panel assessment-detail" aria-label="Vulnerability details">
      <h2>{selected.title}</h2>
      <p><strong>{stateLabel(selected.validation_state)}</strong> · Revision {selected.revision}</p>
      <p>Target: {selected.target_url} · {selected.client_name} / {selected.website_name}</p>
      <p>Scanner severity suggestion: {selected.scanner_severity} · Analyst severity: {selected.analyst_severity ?? "not set"}</p>
      <p>Confidence: {confidenceSummary(selected)}</p>
      <p>Detected {selected.detection_count}× · Not detected {selected.not_detected_count}× · Latest result: {label(selected.last_result)} · First seen {when(selected.first_seen_at)}</p>
      {selected.suppression && <p>Suppression ({label(selected.suppression.decision)}): {selected.suppression.status} · expires {when(selected.suppression.expires_at)}</p>}
      <p>Fingerprint: <code>{selected.fingerprint}</code></p>
      <h3>Reproduction steps</h3>
      {selected.reproduction_steps && <section aria-label="Analyst reproduction steps"><p>Analyst-recorded steps:</p><pre>{selected.reproduction_steps}</pre></section>}
      <ol aria-label="Generated reproduction steps">{selected.reproduction_template.map((step, index) => <li key={index}>{step}</li>)}</ol>
      <h3>Evidence from scanner reports</h3>
      <section aria-label="Vulnerability occurrences">{occurrences.map(item => <details key={item.id}>
        <summary>{when(item.observed_at)} · {label(item.result)}{item.suppressed ? " · suppressed" : ""} · evidence SHA-256 <code>{item.evidence_sha256.slice(0, 16)}…</code></summary>
        <button type="button" onClick={() => onOpenAssessment(item.assessment_id)}>Open source assessment</button>
        <pre>{JSON.stringify(item.evidence, null, 2)}</pre>
      </details>)}</section>
      <h3>Validation</h3>
      <DecisionForm key={`${selected.id}:${selected.revision}`} item={selected} busy={busy} onSubmit={payload => run(async () => {
        await api.decideVulnerability(selected.id, payload); await open(selected.id);
      }, "Validation decision recorded in the audit history.")} />
      <CommentForm busy={busy} onSubmit={(text, reset) => run(async () => {
        await api.commentVulnerability(selected.id, text); reset(); await open(selected.id);
      }, "Comment added.")} />
      <h3>Audit history</h3>
      <section aria-label="Vulnerability history">{events.map(item => <p key={item.id}>
        #{item.sequence} · {when(item.occurred_at)} · {label(item.action)}{item.from_state !== item.to_state && item.to_state ? ` · ${label(item.from_state ?? "new")} → ${label(item.to_state)}` : ""} · {item.actor_id ? `Administrator #${item.actor_id}` : "System"}{item.comment ? ` · ${item.comment}` : ""}
      </p>)}</section>
    </article>}
  </section>;
}
