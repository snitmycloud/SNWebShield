import React, { useEffect, useRef, useState } from "react";
import { LoaderCircle, RefreshCw } from "lucide-react";
import { api } from "./lib/api.js";
import { ACCEPT_PERIODS, DEFAULT_ACCEPT_DAYS, REASON_RANGE, reasonProblem, reviewSoon, stateOf, stateText } from "./lib/findings.js";

// Status line and the owner's buttons for one finding: "Re-scan to confirm fix", "Accept risk..." and "Stop accepting".
// Only the owner sees the buttons (the server enforces it as well). The reason and all server text are shown as escaped text.

function useRecheck(site, finding, onChanged) {
  const [busy, setBusy] = useState(false), [message, setMessage] = useState(""), [tone, setTone] = useState("info");
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const run = async () => {
    setBusy(true); setMessage(""); setTone("info");
    try {
      const { scan } = await api.recheckFinding(site.id, finding.fingerprint);
      for (let i = 0; i < 90 && alive.current; i += 1) {   // a re-check is short (the server stops it after two minutes)
        await new Promise(resolve => setTimeout(resolve, 2000));
        const done = await api.scanDetail(site.id, scan.id);
        if (!["queued", "running"].includes(done.scan.status)) {
          if (alive.current) { setMessage(done.scan.message || ""); setTone(done.scan.result?.recheck?.outcome === "fixed" ? "good" : done.scan.status === "incomplete" ? "warn" : "info"); }
          break;
        }
      }
      if (alive.current) onChanged?.();
    } catch (error) {
      if (alive.current) { setMessage(error.message); setTone("warn"); }
    } finally { if (alive.current) setBusy(false); }
  };
  return { busy, message, tone, run };
}

export default function FindingActions({ site, finding, onChanged }) {
  const [accepting, setAccepting] = useState(false), [reason, setReason] = useState(""), [days, setDays] = useState(DEFAULT_ACCEPT_DAYS);
  const [error, setError] = useState(""), [working, setWorking] = useState(false);
  const recheck = useRecheck(site, finding, onChanged);
  // The server only sends `scan_now` to the verified website's owner, so it also tells us whether the buttons make sense.
  const status = stateOf(finding), canAct = Boolean(site?.scan_now);

  const accept = async event => {
    event.preventDefault();
    const problem = reasonProblem(reason);
    if (problem) { setError(problem); return; }
    setWorking(true); setError("");
    try { await api.acceptRisk(site.id, finding.fingerprint, reason.trim(), days); setAccepting(false); setReason(""); onChanged?.(); }
    catch (err) { setError(err.message); } finally { setWorking(false); }
  };
  const stop = async () => {
    setWorking(true); setError("");
    try { await api.stopAcceptingRisk(site.id, finding.fingerprint); onChanged?.(); }
    catch (err) { setError(err.message); } finally { setWorking(false); }
  };

  return <div className="sw-factions" data-testid="finding-actions">
    <p className={`sw-state state-${status}`} data-testid="finding-state">{stateText(finding)}
      {reviewSoon(finding) && <b className="sw-review-soon" data-testid="review-soon"> Review soon</b>}</p>
    {status === "accepted" && <p className="sw-note" data-testid="accepted-reason">Reason: {finding.state.accepted.reason}</p>}
    {canAct && status !== "fixed" && <div className="sw-fbuttons">
      {finding.recheckable && <button type="button" className="secondary-button" onClick={recheck.run} disabled={recheck.busy} data-testid="recheck-button">
        {recheck.busy ? <LoaderCircle className="spin" size={14} /> : <RefreshCw size={14} />}Re-scan to confirm fix</button>}
      {status !== "accepted" && !accepting && <button type="button" className="secondary-button" onClick={() => setAccepting(true)} data-testid="accept-button">Accept risk…</button>}
      {status === "accepted" && <>
        <button type="button" className="secondary-button" onClick={() => { setAccepting(true); setReason(""); }} disabled={working} data-testid="accept-again-button">Accept again…</button>
        <button type="button" className="secondary-button" onClick={stop} disabled={working} data-testid="unaccept-button">Stop accepting</button></>}
    </div>}
    {recheck.message && <p className={`sw-note-line ${recheck.tone}`} role="status" data-testid="recheck-message">{recheck.message}</p>}
    {accepting && <form className="sw-accept" onSubmit={accept} data-testid="accept-form">
      <label>Why are you accepting this risk? ({REASON_RANGE[0]}–{REASON_RANGE[1]} characters)
        <textarea value={reason} onChange={e => setReason(e.target.value)} maxLength={REASON_RANGE[1]} rows={3} data-testid="accept-reason" /></label>
      <label>For how long?
        <select value={days} onChange={e => setDays(Number(e.target.value))} data-testid="accept-days">
          {ACCEPT_PERIODS.map(d => <option key={d} value={d}>{d} days{d === DEFAULT_ACCEPT_DAYS ? " (recommended)" : ""}</option>)}</select></label>
      <p className="sw-note">It stays listed but is not counted in your score. When the time is up it becomes Open again and counts again. You can look at it again 7 days before.</p>
      <div className="sw-fbuttons"><button className="primary-button" disabled={working} data-testid="accept-submit">Accept risk</button>
        <button type="button" className="secondary-button" onClick={() => { setAccepting(false); setError(""); }}>Cancel</button></div>
    </form>}
    {error && <p className="form-error" role="alert">{error}</p>}
  </div>;
}
