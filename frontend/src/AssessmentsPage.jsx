import React, { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./lib/api.js";
import AssessmentReviews from "./AssessmentReviews.jsx";
import "./assessments.css";

const date = value => value ? new Date(value).toLocaleString() : "Not recorded";
const label = value => value?.replaceAll("_", " ") ?? "Unknown";

export default function AssessmentsPage({ websites, initialAssessmentId = null }) {
  const [site, setSite] = useState("");
  const [authorizations, setAuthorizations] = useState([]), [profiles, setProfiles] = useState([]);
  const [authorization, setAuthorization] = useState(""), [profile, setProfile] = useState("");
  const [note, setNote] = useState(""), [confirmed, setConfirmed] = useState(false);
  const [rows, setRows] = useState([]), [offset, setOffset] = useState(0), [selected, setSelected] = useState(null);
  const [events, setEvents] = useState([]), [attempts, setAttempts] = useState([]), [worker, setWorker] = useState(null);
  const [error, setError] = useState(""), [notice, setNotice] = useState(""), [busy, setBusy] = useState(false);
  const [reason, setReason] = useState("");
  const [networkConfirmed, setNetworkConfirmed] = useState(false);
  const [reviews, setReviews] = useState(null);
  const chosenProfile = profiles.find(p => p.id === profile);
  const isNetwork = chosenProfile?.network_execution === true;
  const isRemote = chosenProfile?.mode === "remote_docker";
  const isNmap = chosenProfile?.mode === "remote_nmap";
  const generation = useRef(0), key = useRef(null), detailGeneration = useRef(0);

  const refresh = useCallback(async () => {
    const version = ++generation.current;
    const [history, status, permissions] = await Promise.all([
      api.getAssessments(site, offset), api.assessmentWorkerStatus(),
      site ? api.getAuthorizations({ websiteId: site }) : Promise.resolve([]),
    ]);
    if (version === generation.current) {
      setRows(history); setWorker(status.worker); setAuthorizations(permissions);
      setAuthorization(current => permissions.some(a => String(a.id) === current && a.status === "approved" && a.effective_status === "active") ? current : "");
    }
  }, [site, offset]);
  useEffect(() => {
    let alive = true;
    const load = () => refresh().catch(e => { if (alive) setError(e.message); });
    load(); const timer = setInterval(load, 10000);
    return () => { alive = false; generation.current++; clearInterval(timer); };
  }, [refresh]);
  useEffect(() => {
    let alive = true;
    api.assessmentProfiles().then(values => { if (alive) { setProfiles(values); setProfile(values[0]?.id ?? ""); } }).catch(e => { if (alive) setError(e.message); });
    return () => { alive = false; };
  }, []);
  useEffect(() => {
    let alive = true;
    setAuthorizations([]); setAuthorization(""); setConfirmed(false); setSelected(null); detailGeneration.current++;
    if (site) api.getAuthorizations({ websiteId: site }).then(values => { if (alive) setAuthorizations(values); }).catch(e => { if (alive) setError(e.message); });
    return () => { alive = false; };
  }, [site]);
  useEffect(() => { key.current = null; setConfirmed(false); setNetworkConfirmed(false); }, [site, authorization, profile, note]);
  useEffect(() => () => { detailGeneration.current++; }, []);
  useEffect(() => {
    if (initialAssessmentId) open(initialAssessmentId).catch(error => setError(error.message));
  }, [initialAssessmentId]);

  async function open(id) {
    const version = ++detailGeneration.current;
    const [row, history, executions] = await Promise.all([api.getAssessment(id), api.assessmentHistory(id, "events"), api.assessmentHistory(id, "attempts")]);
    const reviewData = row.result?.payload.report ? await api.assessmentReviews(id) : null;
    if (version === detailGeneration.current) { setSelected(row); setEvents(history); setAttempts(executions); setReviews(reviewData); }
  }
  function download(blob, filename) {
    const url = URL.createObjectURL(blob), link = document.createElement("a");
    link.href = url; link.download = filename; document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function run(action, successMessage) {
    setBusy(true); setError(""); setNotice("");
    try { await action(); await refresh(); if (successMessage) setNotice(successMessage); } catch (e) { setNotice(""); setError(e.message); } finally { setBusy(false); }
  }
  const workerRecent = worker && Date.now() - new Date(worker.seen_at).getTime() < 90000;
  return <section className="assessment-page">
    <div className="eyebrow">ASSESSMENT CONTROLS · STAGE ONE</div>
    <h1>Assessment requests</h1>
    <p className="assessment-banner">Permission preflight is network-free. HTTP profiles perform one authorised HEAD. Nmap checks only TCP ports 80 and 443 on one explicitly approved public IPv4 address, behind a container firewall. All observations require human validation.</p>
    <p>Assessment worker: {workerRecent ? "Recent heartbeat" : "Not running / stale"} · {date(worker?.seen_at)}</p>
    {error && <p role="alert" className="form-error">{error}</p>}{notice && <p role="status">{notice}</p>}
    <button className="secondary-button" disabled={busy} onClick={() => run(async () => { if (selected) await open(selected.id); }, "Assessment data refreshed. Worker heartbeat changes only when the worker runs.")}>Refresh assessments</button>
    <form className="panel assessment-form" onSubmit={e => { e.preventDefault(); run(async () => {
      key.current ??= crypto.randomUUID();
      const row = await api.requestAssessment({ website_id: Number(site), authorization_id: Number(authorization), profile_id: profile,
        explicitly_requested: confirmed, network_permission_confirmed: networkConfirmed, note, idempotency_key: key.current });
      key.current = null;
      setNotice(isNmap ? "Restricted TCP assessment recorded. Ports 80 and 443 may be checked when claimed." : isNetwork ? "HTTP assessment recorded. One authorised HEAD may run when claimed." : "Permission preflight request recorded. No security scan has started."); await open(row.id);
    }); }}>
      <h2>{isNmap ? "Request restricted Nmap assessment" : isRemote ? "Request Azure header analysis" : isNetwork ? "Request local HTTP assessment" : "Request permission preflight"}</h2>
      <label>Assessment website<select aria-label="Assessment website" required value={site} onChange={e => { setSite(e.target.value); setOffset(0); }}>
        <option value="">Choose a website</option>{websites.map(w => <option key={w.id} value={w.id}>{w.name} · #{w.id}</option>)}
      </select></label>
      <label>Assessment authorisation<select aria-label="Assessment authorisation" required value={authorization} onChange={e => setAuthorization(e.target.value)}>
        <option value="">Choose currently valid approval</option>{authorizations.filter(a => a.status === "approved" && a.effective_status === "active").map(a => <option key={a.id} value={a.id}>{a.authorization_reference} · #{a.id}</option>)}
      </select></label>
      <p>The approval must include automated non-intrusive scanning and its current accepted evidence. Monitoring consent and passive reconnaissance permission alone are insufficient. The backend checks live permission again.</p>
      {isNmap && <p>Nmap additionally requires TCP port discovery permission. Both the exact hostname and the public IPv4 address being scanned must appear in the reviewed authorisation scope. Web-only permission does not grant approval to scan shared hosting or CDN infrastructure.</p>}
      <label>Assessment profile<select aria-label="Assessment profile" required value={profile} onChange={e => setProfile(e.target.value)}>{profiles.map(p => <option key={p.id} value={p.id} disabled={p.available === false}>{p.name} · version {p.version}</option>)}</select></label>
      <label>Assessment request note<textarea required minLength={20} maxLength={2000} value={note} onChange={e => setNote(e.target.value)} /></label>
      <label className="assessment-check"><input type="checkbox" required checked={confirmed} onChange={e => setConfirmed(e.target.checked)} />{isNmap ? "I explicitly request this TCP port assessment for the selected authorisation and profile." : isNetwork ? "I explicitly request this HTTP assessment for the selected authorisation and profile." : "I explicitly request this permission preflight for the selected authorisation and profile. This does not execute a scan."}</label>
      {isNetwork && <label className="assessment-check"><input type="checkbox" required checked={networkConfirmed} onChange={e => setNetworkConfirmed(e.target.checked)} />{isNmap ? "I inspected genuine written permission to discover TCP ports 80 and 443 on the scoped hostname and explicitly approved server IP." : "I inspected genuine written permission for this real network request. Synthetic preflight evidence is insufficient."}</label>}
      <button className="primary-button" disabled={busy || !confirmed || !authorization || chosenProfile?.available === false || (isNetwork && !networkConfirmed)}>{isNmap ? "Queue restricted Nmap assessment" : isRemote ? "Queue Azure header analysis" : isNetwork ? "Queue local HTTP assessment" : "Queue permission preflight"}</button>
    </form>
    <h2>Assessment history</h2><p>Completion is profile-specific. Header observations are not confirmed vulnerabilities or a security rating.</p>
    <div className="panel table-scroll"><table><thead><tr><th>Request</th><th>Website</th><th>Status</th><th>Requested</th><th>Details</th></tr></thead><tbody>{rows.map(row => <tr key={row.id}>
      <td>{row.id}</td><td>{row.target_host}</td><td>{row.job.status === "completed" ? row.mode === "remote_nmap" ? "TCP port assessment completed" : ["local_http", "remote_docker"].includes(row.mode) ? "Header assessment completed" : "Preflight completed" : label(row.job.status)}</td><td>{date(row.requested_at)}</td>
      <td><button disabled={busy} onClick={() => run(() => open(row.id))}>Open assessment</button></td>
    </tr>)}</tbody></table>{!rows.length && <p>No assessment requests on this page.</p>}</div>
    <div className="assessment-pagination"><button disabled={!offset || busy} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous assessments</button><span>Page {offset / 50 + 1}</span><button disabled={rows.length < 50 || busy} onClick={() => setOffset(offset + 50)}>Next assessments</button></div>
    {selected && <article className="panel assessment-detail" aria-label="Assessment details"><h2>{selected.mode === "remote_nmap" ? "Nmap TCP port assessment details" : selected.mode === "remote_docker" ? "Azure header analysis details" : selected.mode === "local_http" ? "Local HTTP assessment details" : "Permission preflight details"}</h2>
      <p>Request {selected.id} · {label(selected.job.status)} · {selected.mode === "remote_nmap" ? "One approved public IPv4; TCP 80 and 443 only" : selected.mode === "remote_docker" ? "One local HEAD; networkless Azure analysis" : selected.mode === "local_http" ? "One bounded HEAD; no scanner tools" : "No scanner execution"}</p>
      <p>Target: {selected.target_url} · Authorisation #{selected.authorization_id} · Requested by administrator #{selected.requested_by}</p>
      <p>Profile: {selected.profile_id} · Attempts: {selected.job.attempts}/{selected.job.max_attempts}</p>
      {selected.result && <p>Outcome: {label(selected.result.payload.outcome ?? selected.result.payload.error)}</p>}
      {selected.result?.payload.report && <section aria-label={selected.mode === "remote_nmap" ? "Port observations" : "Header observations"}>
        <h3>{selected.mode === "remote_nmap" ? "TCP port observations" : "Header observations"} — human validation required</h3>
        <p>{selected.mode === "remote_nmap" ? `Pinned IPv4: ${selected.result.payload.report.transport.connected_ip} · TCP ports: 80, 443` : `HTTP status: ${selected.result.payload.report.transport.status}`} · Response: {selected.result.payload.report.transport.response_ms} ms</p>
        {selected.result.payload.report.execution && <p>
          Container execution: {selected.result.payload.report.execution.container_duration_ms} ms · Runner: {selected.result.payload.report.execution.duration_ms} ms · {selected.mode === "remote_nmap" ? `Scanner CPU: ${selected.result.payload.report.execution.scanner_cpu_seconds} s · Scanner peak memory: ${Math.round(selected.result.payload.report.execution.scanner_peak_rss_bytes / 1024)} KiB` : `Analyzer CPU: ${selected.result.payload.report.execution.analyzer_cpu_seconds} s · Analyzer peak memory: ${Math.round(selected.result.payload.report.execution.analyzer_peak_rss_bytes / 1024)} KiB`} · Cleanup: {selected.result.payload.report.execution.cleanup_confirmed ? "confirmed" : "unconfirmed"}
        </p>}
        <ul>{selected.result.payload.report.analysis.observations.map(item => <li key={item.check}>
          {label(item.check)}: {item.port_state ?? (item.observed === null ? "not applicable" : item.observed ? "observed" : "review needed")} · Suggested severity: {item.severity_suggestion}. {item.explanation}
        </li>)}</ul>
        <button disabled={busy} onClick={() => run(async () => {
          const blob = await api.downloadAssessmentReport(selected.id), url = URL.createObjectURL(blob);
          const link = document.createElement("a"); link.href = url; link.download = `assessment-${selected.id}.json`;
          document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url),1000);
        })}>Download private assessment report</button>
      </section>}
      {reviews && <AssessmentReviews assessmentId={selected.id} summary={reviews} busy={busy}
        onSave={(check, payload) => run(async () => {
          const id = selected.id, version = detailGeneration.current;
          await api.reviewObservation(id, check, payload);
          if (version === detailGeneration.current) await open(id);
          setNotice("Analyst review saved with its revision history.");
        })}
        onExport={() => run(async () => {
          const id = selected.id, version = detailGeneration.current;
          const exported = await api.createReviewedReport(id);
          download(await api.downloadReviewedReport(id, exported.id), `reviewed-assessment-${exported.id}.json`);
          if (version === detailGeneration.current) await open(id);
          setNotice("Reviewed report snapshot created and downloaded.");
        })}
        onDownload={exportId => run(async () => download(await api.downloadReviewedReport(selected.id, exportId), `reviewed-assessment-${exportId}.json`))}
      />}
      {["queued", "running"].includes(selected.job.status) && <div>
        <label>Assessment cancellation reason<textarea minLength={10} maxLength={1000} value={reason} onChange={e => setReason(e.target.value)} /></label>
        <button disabled={busy || reason.trim().length < 10} onClick={() => run(async () => { await api.cancelAssessment(selected.id, { reason }); await open(selected.id); setNotice("Assessment request cancelled."); })}>Cancel assessment request</button>
      </div>}
      <h3>Execution attempts</h3>{attempts.length ? attempts.map(a => <p key={a.id}>Attempt {a.number}: {label(a.outcome)} · {date(a.started_at)} → {date(a.ended_at)}</p>) : <p>No execution attempts recorded.</p>}
      <h3>Assessment audit events</h3>{events.map(event => <p key={event.id}>{date(event.occurred_at)} · {label(event.action)} · {event.actor_id ? `Administrator #${event.actor_id}` : "Worker"}{event.detail.reason ? ` · ${label(event.detail.reason)}` : ""}{event.detail.error ? ` · ${label(event.detail.error)}` : ""}{event.detail.execution?.id ? ` · Remote cleanup ${event.detail.execution.cleanup_confirmed ? "confirmed" : "unconfirmed; inspect VM"}` : ""}</p>)}
      <p>Showing the latest 50 events and attempts for this request. Full history is available through the paginated API.</p>
    </article>}
  </section>;
}
