import React, { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./lib/api.js";
import { describeIsolation, describeOrphanReport, describeRedirect, describeTls } from "./lib/scanner.js";
import AssessmentReviews from "./AssessmentReviews.jsx";
import "./assessments.css";

const date = value => value ? new Date(value).toLocaleString() : "Not recorded";
const label = value => value?.replaceAll("_", " ") ?? "Unknown";

export default function AssessmentsPage({ websites, initialAssessmentId = null }) {
  const [site, setSite] = useState("");
  const [orphans, setOrphans] = useState(null);
  const [rows, setRows] = useState([]), [offset, setOffset] = useState(0), [selected, setSelected] = useState(null);
  const [events, setEvents] = useState([]), [attempts, setAttempts] = useState([]), [worker, setWorker] = useState(null), [workerInfo, setWorkerInfo] = useState(null);
  const [error, setError] = useState(""), [notice, setNotice] = useState(""), [busy, setBusy] = useState(false);
  const [reason, setReason] = useState("");

  const [reviews, setReviews] = useState(null);
  const generation = useRef(0), detailGeneration = useRef(0);

  const refresh = useCallback(async () => {
    const version = ++generation.current;
    const [history, status] = await Promise.all([api.getAssessments(site, offset), api.assessmentWorkerStatus()]);
    if (version === generation.current) { setRows(history); setWorker(status.worker); setWorkerInfo(status); }
  }, [site, offset]);
  useEffect(() => {
    let alive = true;
    const load = () => refresh().catch(e => { if (alive) setError(e.message); });
    load(); const timer = setInterval(load, 10000);
    return () => { alive = false; generation.current++; clearInterval(timer); };
  }, [refresh]);
  useEffect(() => {
    let alive = true;
    setSelected(null); detailGeneration.current++;
    return () => { alive = false; };
  }, [site]);

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

  const workerState = workerInfo?.state ?? "unknown";
  const workerMessage = { running: "Running", stale: "Stale: no heartbeat recently, the worker has stopped or is blocked",
    not_started: "Not started: no heartbeat has ever been recorded", unknown: "Status unavailable" }[workerState];
  return <section className="assessment-page">
    <div className="eyebrow">LEGACY · READ-ONLY</div>
    <h1>Past assessments</h1>
    <p className="assessment-banner">These are assessments from the earlier analyst workflow. They are kept for reference and can no longer be started. New scans start automatically when a website owner verifies ownership.</p>
    <p data-testid="worker-status" data-state={workerState}>Assessment worker: {workerMessage} · last heartbeat {date(worker?.seen_at)}</p>
    {(workerState === "stale" || workerState === "not_started") && <p data-testid="worker-hint">Queued assessments will not run until the worker is started. In a terminal in the <b>backend</b> folder run: <code>{workerInfo.start_command}</code></p>}
    {error && <p role="alert" className="form-error">{error}</p>}{notice && <p role="status">{notice}</p>}
    <button className="secondary-button" disabled={busy} onClick={() => run(async () => { if (selected) await open(selected.id); }, "Assessment data refreshed. Worker heartbeat changes only when the worker runs.")}>Refresh assessments</button>
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
      {selected.recovery && <p role="note" data-testid="recovery-note" data-state={selected.recovery.state}>{selected.recovery.message}</p>}
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
