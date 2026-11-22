import React, { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./lib/api.js";
import "./monitoring.css";

const date = value => value ? new Date(value).toLocaleString() : "Not available";
const localFuture = () => { const d = new Date(Date.now() + 7*86400000); return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16); };

function ResponseChart({ results }) {
  const points = [...results].reverse().filter(r => Number.isFinite(r.payload.response_ms));
  if (!points.length) return <p>No response-time samples yet.</p>;
  const max = Math.max(1, ...points.map(r => r.payload.response_ms));
  const xy = points.map((r,i) => `${40+i*700/Math.max(1,points.length-1)},${160-r.payload.response_ms/max*130}`);
  return <figure><svg viewBox="0 0 800 210" role="img" aria-label="Recent monitoring response times in milliseconds">
    <title>Check duration, including DNS and TLS, in milliseconds</title>
    <path d="M40 20V160H750" fill="none" stroke="#bdcbd7" />
    <text x="40" y="15">{max.toFixed(0)} ms</text><text x="5" y="164">0</text>
    <polyline points={xy.join(" ")} fill="none" stroke="#087f78" strokeWidth="3" />
    {points.map((r,i) => <circle key={r.job_id} cx={xy[i].split(",")[0]} cy={xy[i].split(",")[1]} r="3" fill="#087f78"><title>{date(r.recorded_at)}: {r.payload.response_ms} ms</title></circle>)}
    <text x="40" y="190">Oldest sample</text><text x="640" y="190">Latest sample</text>
  </svg><figcaption>Samples on this history page. Availability is not a security assessment.</figcaption></figure>;
}

function HistoryDetails({ row, collection }) {
  if (collection === "results") {
    const p = row.payload;
    return <><strong>{p.state}</strong><p>HTTP {p.http_status ?? "unavailable"} · Duration {p.response_ms ?? "—"} ms · DNS {p.dns_ok ? "resolved" : "not resolved"}</p><p>TLS expiry: {date(p.certificate_expires_at)}</p>{p.error && <p>Reason: {p.error.replaceAll("_", " ")}</p>}</>;
  }
  if (collection === "incidents") return <><strong>{row.closed_at ? "Recovered" : "Open incident"}</strong><p>Started: {date(row.opened_at)} · Recovered: {date(row.closed_at)}</p></>;
  if (collection === "jobs") return <><strong>{row.status}</strong><p>Attempts: {row.attempts}/{row.max_attempts} · Due: {date(row.due_at)} · Completed: {date(row.completed_at)}</p></>;
  if (collection === "attempts") return <><strong>Attempt {row.number}: {row.outcome.replaceAll("_", " ")}</strong><p>Started: {date(row.started_at)} · Ended: {date(row.ended_at)}</p></>;
  if (collection === "notifications") return <><strong>{row.event.replaceAll("_", " ")} · {row.status}</strong><p>Delivery attempts: {row.attempts} · {row.last_error?.replaceAll("_", " ")}</p></>;
  if (collection === "consents") return <><strong>{row.reference}</strong><p>{row.revoked_at ? "Revoked" : "Recorded"} · Reviewer #{row.reviewed_by} · Expires {date(row.expires_at)}</p><p>{row.url}</p><p>Evidence: {row.evidence_id}</p></>;
  return <><strong>{row.action.replaceAll("_", " ")}</strong><p>{row.actor_id ? `Administrator #${row.actor_id}` : "Background process"}</p><details><summary>Execution details</summary><pre>{JSON.stringify(row.detail,null,2)}</pre></details></>;
}

export default function MonitoringPage({ websites }) {
  const [overview,setOverview] = useState(null), [selected,setSelected] = useState("");
  const [collection,setCollection] = useState("results"), [history,setHistory] = useState([]), [offset,setOffset] = useState(0);
  const [documents,setDocuments] = useState([]), [busy,setBusy] = useState(false), [error,setError] = useState(""), [notice,setNotice] = useState("");
  const [form,setForm] = useState({ evidence_id:"", consent_reference:"", expires_at:localFuture(), interval_seconds:300, timeout_seconds:10, failure_threshold:2, recovery_threshold:1, reviewed:false });
  const generation = useRef(0);
  const load = useCallback(async () => {
    const request = ++generation.current;
    const [summary,rows] = await Promise.all([api.monitoringOverview(), selected ? api.monitoringHistory(selected,collection,offset) : Promise.resolve([])]);
    if (request === generation.current) { setOverview(summary); setHistory(rows); }
  }, [selected,collection,offset]);
  useEffect(() => { let active=true; const refresh=()=>load().catch(e=>{if(active)setError(e.message)});
    refresh(); const timer=setInterval(refresh,15000); return()=>{active=false;generation.current++;clearInterval(timer)};
  },[load]);
  useEffect(() => {
    let active=true; setDocuments([]); setForm(f=>({...f,evidence_id:"",reviewed:false}));
    if(selected) api.getAuthorizations({websiteId:selected}).then(async rows => {
      const sets=await Promise.all(rows.map(r=>api.getEvidence(r.id)));
      if(active)setDocuments(sets.flatMap(s=>s.documents).filter(d=>d.state==="available"));
    }).catch(e=>{if(active)setError(e.message)});
    return()=>{active=false};
  },[selected]);
  async function run(action, message) {setBusy(true);setError("");setNotice("");try{await action();await load();setNotice(message)}catch(e){setError(e.message)}finally{setBusy(false)}}
  const current=overview?.websites.find(w=>String(w.website_id)===selected);
  const change=key=>e=>setForm(f=>({...f,[key]:e.target.value}));
  return <section className="monitor-page">
    <div className="monitor-heading"><div><div className="eyebrow">OPERATIONS</div><h1>Website monitoring</h1><p>Permitted availability, DNS and TLS checks. No vulnerability scanning.</p></div>
      <button className="secondary-button" disabled={busy} onClick={()=>run(load,"Monitoring data refreshed.")}>Refresh monitoring</button>
      <button className="monitor-danger" disabled={busy} onClick={()=>run(()=>api.stopMonitoring(),"All monitoring disabled; pending execution cancelled.")}>Stop all monitoring</button>
    </div>
    {error&&<p role="alert" className="form-error">{error}</p>}{notice&&<p role="status" className="monitor-notice">{notice}</p>}
    <div className="monitor-workers"><strong>Background processes</strong>{['scheduler','monitoring-worker','notification-dispatcher'].map(name=>{
      const w=overview?.workers.find(x=>x.name===name);const alive=w&&Date.now()-new Date(w.seen_at).getTime()<90000;
      return <span key={name}>{name}: {alive?"Recent heartbeat":"Not running / stale"} · {date(w?.seen_at)}</span>;
    })}</div>
    <div className="panel table-scroll"><table><thead><tr><th>Website</th><th>Status</th><th>Last check</th><th>HTTP</th><th>Duration</th><th>DNS</th><th>TLS expiry</th></tr></thead><tbody>
      {overview?.websites.map(w=><tr key={w.website_id}><td><button className="text-button" onClick={()=>{setSelected(String(w.website_id));setOffset(0)}}>{w.name}</button></td><td><span className={`monitor-state ${w.state}`}>{w.state.replaceAll("_"," ")}</span></td>
        <td>{date(w.latest?.recorded_at)}</td><td>{w.latest?.payload.http_status??"—"}</td><td>{w.latest?.payload.response_ms!=null?`${w.latest.payload.response_ms} ms`:"—"}</td>
        <td>{w.latest?.payload.dns_ok===true?"Resolved":w.latest?.payload.dns_ok===false?"Failed / blocked":"—"}</td><td>{date(w.latest?.payload.certificate_expires_at)}</td></tr>)}
    </tbody></table></div>
    <label className="monitor-selection">Manage website<select aria-label="Monitoring website" value={selected} onChange={e=>{setSelected(e.target.value);setOffset(0)}}><option value="">Choose a website</option>{websites.map(w=><option key={w.id} value={w.id}>{w.name} · #{w.id}</option>)}</select></label>
    {selected&&<>
      <div className="monitor-controls"><strong>Current state: {current?.state??"Loading"}</strong>
        {['enable','disable','check-now','revoke-consent'].map(action=><button className="secondary-button" type="button" key={action} disabled={busy||!current?.config} onClick={()=>run(()=>api.monitoringAction(selected,action),`${action} request accepted.`)}>{action.replaceAll("-"," ")}</button>)}</div>
      {current?.config && <p>Configured interval: {current.config.interval_seconds} seconds · Timeout: {current.config.timeout_seconds} seconds · Consent expires: {date(current.consent?.expires_at)}</p>}
      <form className="panel monitor-form" onSubmit={e=>{e.preventDefault();run(()=>api.configureMonitoring(selected,{
        evidence_id:form.evidence_id,consent_reference:form.consent_reference,monitoring_permission_reviewed:form.reviewed,
        expires_at:new Date(form.expires_at).toISOString(),interval_seconds:Number(form.interval_seconds),timeout_seconds:Number(form.timeout_seconds),
        failure_threshold:Number(form.failure_threshold),recovery_threshold:Number(form.recovery_threshold),
      }),"Configuration saved disabled. Explicitly enable monitoring when ready.")}}>
        <h2>Monitoring permission and configuration</h2><p>Saving this form creates a new permission record and disables monitoring. The signed document must explicitly permit these recurring HTTP, DNS and TLS checks.</p>
        <div className="monitor-grid"><label>Reviewed permission document<select required value={form.evidence_id} onChange={change("evidence_id")}><option value="">Choose available evidence</option>{documents.map(d=><option key={d.id} value={d.id}>{d.filename} · {d.id}</option>)}</select></label>
        <label>Monitoring agreement reference<input required minLength={10} maxLength={150} value={form.consent_reference} onChange={change("consent_reference")}/></label>
        <label>Consent expires (your local time)<input required type="datetime-local" value={form.expires_at} onChange={change("expires_at")}/></label>
        <label>Interval<select value={form.interval_seconds} onChange={change("interval_seconds")}>{[[60,"1 minute"],[300,"5 minutes"],[900,"15 minutes"],[3600,"1 hour"]].map(([v,t])=><option key={v} value={v}>{t}</option>)}</select></label>
        <label>Overall probe timeout (2–20 seconds)<input type="number" required min={2} max={20} value={form.timeout_seconds} onChange={change("timeout_seconds")}/></label>
        <label>Failures before incident<input type="number" required min={1} max={5} value={form.failure_threshold} onChange={change("failure_threshold")}/></label>
        <label>Successes before recovery<input type="number" required min={1} max={5} value={form.recovery_threshold} onChange={change("recovery_threshold")}/></label></div>
        <label className="monitor-attestation"><input type="checkbox" required checked={form.reviewed} onChange={e=>setForm(f=>({...f,reviewed:e.target.checked}))}/>I reviewed this document and confirm it explicitly permits recurring monitoring of this exact website until the selected expiry. Existing testing approval alone is insufficient.</label>
        <button className="primary-button" disabled={busy||!form.reviewed}>Save monitoring configuration</button>
      </form>
      <div className="monitor-history-heading"><h2>Monitoring history</h2><select aria-label="Monitoring history type" value={collection} onChange={e=>{setCollection(e.target.value);setOffset(0)}}>{['results','jobs','attempts','incidents','events','notifications','consents'].map(t=><option key={t}>{t}</option>)}</select></div>
      {collection==="results"&&<ResponseChart results={history}/>}
      <div className="panel table-scroll"><table><thead><tr><th>Record</th><th>Details</th></tr></thead><tbody>{history.map((row,i)=><tr key={row.id||row.job_id||i}><td>{row.id||row.job_id}<br/>{date(row.recorded_at||row.created_at||row.occurred_at||row.opened_at)}</td><td><HistoryDetails row={row} collection={collection}/></td></tr>)}</tbody></table>{!history.length&&<p className="monitor-empty">No records on this page.</p>}</div>
      <div className="monitor-controls"><button disabled={offset===0||busy} onClick={()=>setOffset(Math.max(0,offset-50))}>Previous history page</button><span>Records {offset+1} onward</span><button disabled={history.length<50||busy} onClick={()=>setOffset(offset+50)}>Next history page</button></div>
    </>}
  </section>;
}
