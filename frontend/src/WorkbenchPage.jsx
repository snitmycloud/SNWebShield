import React, { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./lib/api.js";
import { SEVERITIES } from "./lib/vulnerabilities.js";
import { IMPACTS, LIKELIHOODS, PRIORITIES, STAGES, allowedSignoffs, auditLine, buildAssessment, buildSignoff,
  calculateRating, humanize, safeText, signoffLabel, stageLabel } from "./lib/workbench.js";
import "./assessments.css";
import "./findings.css";

const when = value => value ? new Date(value).toLocaleString() : "Not recorded";

// Untrusted scanner evidence: rendered only as an escaped text node inside <pre>. No HTML injection.
function Evidence({ occurrence }) {
  return <details>
    <summary>{when(occurrence.observed_at)} · {humanize(occurrence.result)}{occurrence.suppressed ? " · suppressed" : ""} · SHA-256 <code>{String(occurrence.evidence_sha256).slice(0, 16)}…</code></summary>
    <pre aria-label="Raw scanner evidence (untrusted, shown as text)">{safeText(occurrence.evidence)}</pre>
  </details>;
}

function AssessmentForm({ item, busy, onSubmit }) {
  const seed = item.current_assessment ?? item.assessments?.[0];
  const [form, setForm] = useState({ likelihood: seed?.likelihood ?? "possible", business_impact: seed?.business_impact ?? "moderate",
    business_context: seed?.business_context ?? "", risk_rating: "", override_reason: "",
    remediation: seed?.remediation ?? "", remediation_priority: seed?.remediation_priority ?? "planned" });
  const [error, setError] = useState("");
  const set = changes => setForm({ ...form, ...changes });
  const calculated = calculateRating(form.likelihood, form.business_impact);
  const rating = form.risk_rating || calculated;
  return <form aria-label="Risk assessment" onSubmit={event => {
    event.preventDefault();
    const result = buildAssessment(item, form);
    if (result.error) { setError(result.error); return; }
    setError(""); onSubmit(result.payload);
  }}><fieldset disabled={busy || !item.can_assess}><legend>Risk, business impact and remediation</legend>
    {error && <p role="alert" className="form-error">{error}</p>}
    <label>Likelihood<select aria-label="Likelihood" value={form.likelihood} onChange={event => set({ likelihood: event.target.value, risk_rating: "" })}>{LIKELIHOODS.map(v => <option key={v} value={v}>{humanize(v)}</option>)}</select></label>
    <label>Business impact<select aria-label="Business impact" value={form.business_impact} onChange={event => set({ business_impact: event.target.value, risk_rating: "" })}>{IMPACTS.map(v => <option key={v} value={v}>{humanize(v)}</option>)}</select></label>
    <label>Business context<textarea aria-label="Business context" required minLength={20} maxLength={4000} value={form.business_context} onChange={event => set({ business_context: event.target.value })} /></label>
    <label>Risk rating (calculated: {calculated})<select aria-label="Risk rating" value={rating} onChange={event => set({ risk_rating: event.target.value })}>{SEVERITIES.map(v => <option key={v}>{v}</option>)}</select></label>
    {rating !== calculated && <label>Override reason<textarea aria-label="Override reason" required minLength={20} maxLength={2000} value={form.override_reason} onChange={event => set({ override_reason: event.target.value })} /></label>}
    <label>Tailored remediation recommendation<textarea aria-label="Remediation recommendation" required minLength={20} maxLength={8000} value={form.remediation} onChange={event => set({ remediation: event.target.value })} /></label>
    <label>Remediation priority<select aria-label="Remediation priority" value={form.remediation_priority} onChange={event => set({ remediation_priority: event.target.value })}>{PRIORITIES.map(v => <option key={v} value={v}>{humanize(v)}</option>)}</select></label>
    <button className="primary-button">Save assessment</button>
  </fieldset></form>;
}

function SignoffForm({ item, busy, onSubmit }) {
  const actions = allowedSignoffs(item);
  const [form, setForm] = useState({ decision: actions[0], attested: false, justification: "", reproduction_steps: "",
    rejection_outcome: "false_positive", suppress_until: "" });
  const [error, setError] = useState("");
  const set = changes => setForm({ ...form, ...changes });
  if (!actions.length) return <p>No sign-off action is available for this record.</p>;
  return <form aria-label="Analyst sign-off" onSubmit={event => {
    event.preventDefault();
    const result = buildSignoff(item, form);
    if (result.error) { setError(result.error); return; }
    setError(""); onSubmit(result.payload);
  }}><fieldset disabled={busy}><legend>Analyst sign-off (approve or reject)</legend>
    {error && <p role="alert" className="form-error">{error}</p>}
    {item.validation_state === "unconfirmed" && !item.can_approve && <p>Approval is locked until a risk assessment is saved for the current revision.</p>}
    <label>Decision<select aria-label="Sign-off decision" value={form.decision} onChange={event => set({ decision: event.target.value })}>{actions.map(v => <option key={v} value={v}>{signoffLabel(v)}</option>)}</select></label>
    {form.decision === "approve" && <label>Reproduction steps<textarea aria-label="Reproduction steps" required minLength={20} maxLength={8000} value={form.reproduction_steps} onChange={event => set({ reproduction_steps: event.target.value })} /></label>}
    {form.decision === "reject" && <>
      <label>Rejection outcome<select aria-label="Rejection outcome" value={form.rejection_outcome} onChange={event => set({ rejection_outcome: event.target.value })}><option value="false_positive">False positive</option><option value="not_applicable">Not applicable</option></select></label>
      <label>Suppress until<input aria-label="Suppress until" type="date" required value={form.suppress_until} onChange={event => set({ suppress_until: event.target.value })} /></label></>}
    <label>Justification<textarea aria-label="Sign-off justification" required minLength={20} maxLength={4000} value={form.justification} onChange={event => set({ justification: event.target.value })} /></label>
    <label className="assessment-check"><input type="checkbox" checked={form.attested} onChange={event => set({ attested: event.target.checked })} />I personally reviewed the stored evidence and take responsibility for this decision.</label>
    <button className="primary-button">Record sign-off</button>
  </fieldset></form>;
}

export default function WorkbenchPage({ websites = [] }) {
  const [stage, setStage] = useState("needs_assessment"), [search, setSearch] = useState(""), [severity, setSeverity] = useState("");
  const [website, setWebsite] = useState(""), [offset, setOffset] = useState(0);
  const [data, setData] = useState(null), [selected, setSelected] = useState(null);
  const [occurrences, setOccurrences] = useState([]), [audit, setAudit] = useState(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [notice, setNotice] = useState("");
  const generation = useRef(0), detailGeneration = useRef(0);
  const load = useCallback(async () => {
    const version = ++generation.current;
    const result = await api.workbenchQueue({ stage, search: search.trim(), severity, website_id: website }, offset);
    if (version === generation.current) setData(result);
  }, [stage, search, severity, website, offset]);
  useEffect(() => {
    let alive = true;
    load().catch(failure => { if (alive) setError(failure.message); });
    return () => { alive = false; generation.current++; };
  }, [load]);
  useEffect(() => () => { detailGeneration.current++; }, []);
  async function open(id) {
    const version = ++detailGeneration.current;
    const [detail, seen, trail] = await Promise.all([api.workbenchDetail(id), api.vulnerabilityHistory(id, "occurrences"), api.workbenchAudit(id)]);
    if (version === detailGeneration.current) { setSelected(detail); setOccurrences(seen); setAudit(trail); }
  }
  async function run(action, message) {
    setBusy(true); setError(""); setNotice("");
    try { await action(); await load(); if (message) setNotice(message); }
    catch (failure) { setError(failure.message); }
    finally { setBusy(false); }
  }
  const choose = changes => { detailGeneration.current++; setSelected(null); setOffset(0); changes(); };

  return <section className="assessment-page findings-page">
    <div className="eyebrow">ANALYST WORKBENCH</div><h1>Security analyst workbench</h1>
    <p>Review unconfirmed findings, author risk and remediation guidance, and record an attested approval or rejection. Nothing is confirmed or eligible for VAPT reporting without your sign-off. Scanner evidence is untrusted and shown only as plain text.</p>
    {error && <p role="alert" className="form-error">{error}</p>}{notice && <p role="status">{notice}</p>}
    <form className="panel findings-filters" aria-label="Workbench queue filters" onSubmit={event => event.preventDefault()}>
      <label>Queue<select aria-label="Workbench stage" value={stage} onChange={event => choose(() => setStage(event.target.value))}>{STAGES.map(v => <option key={v} value={v}>{stageLabel(v)}</option>)}</select></label>
      <label>Severity<select aria-label="Workbench severity filter" value={severity} onChange={event => choose(() => setSeverity(event.target.value))}><option value="">All severities</option>{SEVERITIES.map(v => <option key={v}>{v}</option>)}</select></label>
      <label>Website<select aria-label="Workbench website filter" value={website} onChange={event => choose(() => setWebsite(event.target.value))}><option value="">All websites</option>{websites.map(site => <option key={site.id} value={site.id}>{site.name}</option>)}</select></label>
      <label>Search<input aria-label="Search workbench" value={search} maxLength={200} onChange={event => choose(() => setSearch(event.target.value))} placeholder="Title, check, host, website or client" /></label>
    </form>
    {data && <>
      <div className="findings-counts" aria-label="Workbench totals">{["needs_assessment", "ready_for_signoff", "report_eligible", "dismissed"].map(key => <div className="panel" key={key}><span>{stageLabel(key)}</span><strong>{data.summary[key]}</strong></div>)}</div>
      <div className="panel table-scroll"><table><thead><tr><th>Finding</th><th>Client / website</th><th>Severity</th><th>Stage</th><th>Open</th></tr></thead><tbody>{data.items.map(item => <tr key={item.id}>
        <td>{item.title}<br /><code>{item.check_id}</code></td><td>{item.client_name}<br />{item.website_name}</td>
        <td>{item.effective_severity}{item.validation_state !== "confirmed" && " (scanner suggestion)"}</td>
        <td>{stageLabel(item.stage)}</td>
        <td><button disabled={busy} onClick={() => run(() => open(item.id))}>Review finding</button></td>
      </tr>)}</tbody></table>{!data.items.length && <p>No findings in this queue.</p>}</div>
      <div className="assessment-pagination"><button disabled={!offset || busy} onClick={() => { setSelected(null); setOffset(offset - 50); }}>Previous findings</button><span>Showing {data.items.length} · offset {offset}</span><button disabled={data.items.length < 50 || busy} onClick={() => { setSelected(null); setOffset(offset + 50); }}>Next findings</button></div>
    </>}
    {selected && <article className="panel assessment-detail" aria-label="Workbench finding">
      <h2>{selected.title}</h2>
      <p><strong>{humanize(selected.validation_state)}</strong> · Revision {selected.revision} · {selected.report_eligible ? "Eligible for VAPT reporting" : "Not eligible for VAPT reporting"}</p>
      <p>Target: {safeText(selected.target_url)} · {selected.client_name} / {selected.website_name}</p>
      <p>Scanner suggestion: {selected.scanner_severity} · Analyst rating: {selected.analyst_severity ?? "not set"} · Confidence {selected.confidence} ({selected.confidence_score}/100)</p>
      <h3>Evidence (untrusted scanner data)</h3>
      <section aria-label="Scanner evidence">{occurrences.map(item => <Evidence key={item.id} occurrence={item} />)}</section>
      <h3>Assessment</h3>
      {selected.current_assessment && <p>Current: version {selected.current_assessment.version} by {safeText(selected.current_assessment.author_name)} · rating <strong>{selected.current_assessment.risk_rating}</strong> · priority {humanize(selected.current_assessment.remediation_priority)}</p>}
      {selected.current_assessment && <section aria-label="Saved remediation"><pre>{safeText(selected.current_assessment.remediation)}</pre></section>}
      <AssessmentForm key={`a:${selected.id}:${selected.revision}:${selected.assessments.length}`} item={selected} busy={busy}
        onSubmit={payload => run(async () => { await api.saveWorkbenchAssessment(selected.id, payload); await open(selected.id); }, "Assessment saved to the audit history.")} />
      <h3>Sign-off</h3>
      <SignoffForm key={`s:${selected.id}:${selected.revision}:${selected.assessments.length}`} item={selected} busy={busy}
        onSubmit={payload => run(async () => { await api.signoffWorkbench(selected.id, payload); await open(selected.id); }, "Sign-off recorded in the audit history.")} />
      <h3>Immutable analyst audit trail</h3>
      <section aria-label="Analyst audit trail">{audit?.events.map(item => <p key={item.id}>
        {auditLine(item)}{item.comment ? ` · ${safeText(item.comment, 500)}` : ""}
      </p>)}</section>
    </article>}
  </section>;
}
