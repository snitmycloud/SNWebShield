import React, { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./lib/api.js";
import { describeIsolation, describeOrphanReport, describeRedirect, describeTls } from "./lib/scanner.js";
import AssessmentReviews from "./AssessmentReviews.jsx";
import { runGate, defaultNote } from "./lib/runGate.js";
import "./assessments.css";

const date = value => value ? new Date(value).toLocaleString() : "Not recorded";
const label = value => value?.replaceAll("_", " ") ?? "Unknown";

export default function AssessmentsPage({ websites, initialAssessmentId = null }) {
  const [site, setSite] = useState("");
  const [readiness, setReadiness] = useState(null), [orphans, setOrphans] = useState(null), [profiles, setProfiles] = useState([]);
  const [profile, setProfile] = useState(""), [note, setNote] = useState("");
  const [rows, setRows] = useState([]), [offset, setOffset] = useState(0), [selected, setSelected] = useState(null);
  const [events, setEvents] = useState([]), [attempts, setAttempts] = useState([]), [worker, setWorker] = useState(null), [workerInfo, setWorkerInfo] = useState(null);
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
    const [history, status, ready] = await Promise.all([
      api.getAssessments(site, offset), api.assessmentWorkerStatus(),
      site ? api.assessmentReadiness(site) : Promise.resolve(null),
    ]);
    if (version === generation.current) { setRows(history); setWorker(status.worker); setWorkerInfo(status); setReadiness(ready); }
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
    setReadiness(null); setSelected(null); detailGeneration.current++;
    return () => { alive = false; };
  }, [site]);
  useEffect(() => { key.current = null; setNetworkConfirmed(false); }, [site, profile, note]);
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
  const gate = runGate({ site, readiness, profileId: profile, attested: networkConfirmed, busy });
  const workerState = workerInfo?.state ?? "unknown";
  const workerMessage = { running: "Running", stale: "Stale: no heartbeat recently, the worker has stopped or is blocked",
    not_started: "Not started: no heartbeat has ever been recorded", unknown: "Status unavailable" }[workerState];
  return <section className="assessment-page">
    <div className="eyebrow">ASSESSMENT CONTROLS · STAGE ONE</div>
    <h1>Assessment requests</h1>
    <p className="assessment-banner">Permission preflight is network-free. HTTP profiles perform one authorised HEAD. Nmap checks only TCP ports 80 and 443 on one explicitly approved public IPv4 address, behind a container firewall. All observations require human validation.</p>
    <p data-testid="worker-status" data-state={workerState}>Assessment worker: {workerMessage} · last heartbeat {date(worker?.seen_at)}</p>
    {(workerState === "stale" || workerState === "not_started") && <p data-testid="worker-hint">Queued assessments will not run until the worker is started. In a terminal in the <b>backend</b> folder run: <code>{workerInfo.start_command}</code></p>}
    {error && <p role="alert" className="form-error">{error}</p>}{notice && <p role="status">{notice}</p>}
    <button className="secondary-button" disabled={busy} onClick={() => run(async () => { if (selected) await open(selected.id); }, "Assessment data refreshed. Worker heartbeat changes only when the worker runs.")}>Refresh assessments</button>
    <form className="panel assessment-form" onSubmit={e => { e.preventDefault(); if (!gate.enabled) return; run(async () => {
      key.current ??= crypto.randomUUID();
      const host = websites.find(w => String(w.id) === String(site))?.name ?? "website";
      const row = await api.requestAssessment({ website_id: Number(site), authorization_id: gate.item.authorization_id, profile_id: profile,
        explicitly_requested: true, network_permission_confirmed: isNetwork && networkConfirmed,
        note: note.trim().length >= 20 ? note.trim() : defaultNote(host, chosenProfile.name), idempotency_key: key.current });
      key.current = null;
      setNotice(isNmap ? "Restricted TCP assessment queued. Ports 80 and 443 may be checked when the worker claims it." : isNetwork ? "HTTP assessment queued. One authorised HEAD may run when the worker claims it." : "Permission preflight queued. No security scan has started."); await open(row.id);
    }); }}>
      <h2>Run an assessment</h2>
      <label>1. Website<select aria-label="Assessment website" required value={site} onChange={e => { setSite(e.target.value); setOffset(0); }}>
        <option value="">Choose a website</option>{websites.map(w => <option key={w.id} value={w.id}>{w.name} · #{w.id}</option>)}
      </select></label>
      <label>2. Assessment profile<select aria-label="Assessment profile" required value={profile} onChange={e => setProfile(e.target.value)}>{profiles.map(p => <option key={p.id} value={p.id}>{p.name} · version {p.version}</option>)}</select></label>
      {site && <p data-testid="permission-status" data-ready={gate.item?.ready ? "true" : "false"}>
        {gate.item?.ready ? <>Permission: <b>valid</b> · authorisation {gate.item.authorization_reference} (#{gate.item.authorization_id}) until {date(gate.item.valid_until)}. Checked now without any network request; checked again before anything runs.</>
          : <>Permission: <b>blocked</b> · {gate.item?.reason ?? gate.reason}</>}
      </p>}
      {isNmap && <p>Nmap checks TCP 80 and 443 on the one approved public IPv4 address only. Web-only permission does not cover shared hosting or CDN infrastructure.</p>}
      <label>Note (optional)<textarea maxLength={2000} placeholder="Defaults to a generated description" value={note} onChange={e => setNote(e.target.value)} /></label>
      {isNetwork && <label className="assessment-check"><input type="checkbox" checked={networkConfirmed} onChange={e => setNetworkConfirmed(e.target.checked)} />{isNmap ? "I inspected genuine written permission to discover TCP ports 80 and 443 on the scoped hostname and approved server IP." : "I inspected genuine written permission for this real network request."}</label>}
      <button className="primary-button" disabled={!gate.enabled}>3. Run assessment</button>
      {!gate.enabled && site && <p role="note" data-testid="run-blocked-reason">{gate.reason}</p>}
    </form>
    <section className="panel" aria-label="Scanner VM housekeeping">
      <h2>Scanner VM housekeeping</h2>
      <p>Lists leftover SNWebShield scanner containers on the Azure VM. This is read-only: nothing is stopped or removed, and it runs only when you press the button.</p>
      <button disabled={busy} onClick={() => run(async () => setOrphans(await api.orphanContainers()), "VM container check finished. Nothing was changed.")}>Check VM for leftover containers</button>
      {orphans && <div data-testid="orphan-report">{describeOrphanReport(orphans).map(row => <p key={row.scanner} data-status={row.status}><b>{row.scanner}:</b> {row.text}</p>)}
        <p>{orphans.guidance}</p></div>}
    </section>
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
        {selected.result.payload.report.execution && ["remote_docker", "remote_nmap"].includes(selected.mode) && <p>{describeIsolation(selected.result.payload.report.execution)}</p>}
        {selected.mode !== "remote_nmap" && <p>{describeTls(selected.result.payload.report.transport)}{describeRedirect(selected.result.payload.report.transport) ? ` · ${describeRedirect(selected.result.payload.report.transport)}` : ""}</p>}
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
