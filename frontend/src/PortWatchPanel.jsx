import React, { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./lib/api.js";
import { INTERVALS, buildDisable, buildEnable, describeChange, intervalLabel, portState, watchStatus } from "./lib/portWatch.js";

const when = value => value ? new Date(value).toLocaleString() : "Not yet";

export default function PortWatchPanel({ websites }) {
  const [site, setSite] = useState(""), [state, setState] = useState(null), [error, setError] = useState(""), [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false), [form, setForm] = useState({ interval: 21600, attested: false }), [reason, setReason] = useState("");
  const generation = useRef(0);
  const load = useCallback(async id => {
    const version = ++generation.current;
    if (!id) { setState(null); return; }
    try { const result = await api.portWatch(id); if (version === generation.current) setState(result); }
    catch (e) { if (version === generation.current) { setState(null); setError(e.message); } }
  }, []);
  useEffect(() => { setError(""); setNotice(""); setForm(f => ({ ...f, attested: false })); load(site); return () => { generation.current++; }; }, [site, load]);
  async function run(action, message) {
    setBusy(true); setError(""); setNotice("");
    try { await action(); await load(site); setNotice(message); } catch (e) { setError(e.message); } finally { setBusy(false); }
  }
  return <section className="panel" aria-label="Port watch">
    <h2>Port watch</h2>
    <p>Recurring checks of TCP ports 80 and 443 on the website's one approved public IP address, run on the isolated scanner VM. It starts only when you enable it here, re-checks written permission before every run, and alerts when a port changes state. A change is an observation for an analyst to review, not a confirmed vulnerability.</p>
    <label>Website<select aria-label="Port watch website" value={site} onChange={e => setSite(e.target.value)}>
      <option value="">Choose a website</option>{websites.map(w => <option key={w.id} value={w.id}>{w.name} · #{w.id}</option>)}</select></label>
    {error && <p role="alert" className="form-error">{error}</p>}{notice && <p role="status">{notice}</p>}
    {state && <div data-testid="port-watch-state" data-state={state.enabled ? state.state : "off"}>
      <p><strong>{watchStatus(state)}</strong></p>
      {state.enabled && <>
        <p>{intervalLabel(state.interval_seconds)} · next run {when(state.next_due)} · last result {state.last_outcome ? state.last_outcome.replaceAll("_", " ") : "none yet"} ({when(state.last_checked_at)})</p>
        {state.baseline && <p>Last known state: TCP 80 {portState(state.baseline["80"])} · TCP 443 {portState(state.baseline["443"])}</p>}
      </>}
      {state.changes.length > 0 && <section aria-label="Port changes"><h3>Port changes</h3>
        {state.changes.map(c => <p key={c.id}>{when(c.detected_at)} · {describeChange(c)}</p>)}</section>}
      {!state.enabled && <form aria-label="Enable port watch" onSubmit={e => { e.preventDefault();
        const result = buildEnable(state, form); if (result.error) { setError(result.error); return; }
        run(() => api.enablePortWatch(site, result.payload), "Port watch enabled. The first run records the baseline and raises no alert."); }}>
        <fieldset disabled={busy}><legend>Enable port watch</legend>
          {!state.can_enable && <p role="note" data-testid="port-watch-blocked">{state.cannot_enable_reason}</p>}
          <label>How often<select aria-label="Port watch interval" value={form.interval} onChange={e => setForm({ ...form, interval: Number(e.target.value) })}>
            {INTERVALS.map(([value, text]) => <option key={value} value={value}>{text}</option>)}</select></label>
          <label className="assessment-check"><input type="checkbox" checked={form.attested} onChange={e => setForm({ ...form, attested: e.target.checked })} />I inspected genuine written permission for recurring TCP 80 and 443 checks of this website's approved IP address.</label>
          <button className="primary-button" disabled={!state.can_enable || !form.attested}>Enable port watch</button>
        </fieldset></form>}
      {state.enabled && <form aria-label="Disable port watch" onSubmit={e => { e.preventDefault();
        const result = buildDisable({ reason }); if (result.error) { setError(result.error); return; }
        run(async () => { await api.disablePortWatch(site, result.payload); setReason(""); }, "Port watch disabled. No further checks will run."); }}>
        <fieldset disabled={busy}><legend>Disable port watch</legend>
          <label>Reason<input aria-label="Port watch disable reason" value={reason} minLength={10} maxLength={500} onChange={e => setReason(e.target.value)} /></label>
          <button>Disable port watch</button></fieldset></form>}
    </div>}
  </section>;
}
