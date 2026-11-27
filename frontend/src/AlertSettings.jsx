import React, { useCallback, useEffect, useState } from "react";
import { BellRing, CheckCircle2, LoaderCircle, ShieldAlert } from "lucide-react";
import { api } from "./lib/api.js";

// Settings > Alerts: one switch per alert type, and "Send me a test alert". The link at the bottom of every alert email opens this
// page with that alert type highlighted ("Turn off this kind of alert").

export default function AlertSettings({ focus }) {
  const [data, setData] = useState(null), [error, setError] = useState(""), [busy, setBusy] = useState(""), [note, setNote] = useState("");
  const load = useCallback(() => api.alertPreferences().then(setData).catch(e => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);
  const toggle = async (type, enabled) => {
    setBusy(type); setError(""); setNote("");
    try { const next = await api.setAlertPreference(type, enabled); setData(d => ({ ...d, alerts: next.alerts })); }
    catch (e) { setError(e.message); } finally { setBusy(""); }
  };
  const test = async () => {
    setBusy("test"); setError(""); setNote("");
    try { const r = await api.sendTestAlert(); setNote(r.channel === "smtp" ? "Test alert sent to your email address." : "Test alert written to the outbox folder (email sending is not set up yet)."); }
    catch (e) { setError(e.message); } finally { setBusy(""); }
  };
  return <section className="panel sw-box" id="alerts" aria-label="Alerts" data-testid="alert-settings">
    <h2><BellRing size={16} /> Email alerts</h2>
    {!data ? <div className="loading-rows"><div /><div /></div> : <>
      <p className="sw-note">We email {data.email} when something needs you. The same alert is never sent more than once in 24 hours.
        {data.delivery !== "smtp" && " Email sending is not set up yet, so alerts are saved to the outbox folder instead."}</p>
      {!data.email_included && <p className="sw-unknown">Email alerts are not included in your plan.</p>}
      <ul className="sw-alert-list">{data.alerts.map(a => <li key={a.type} className={focus === a.type ? "focus" : ""} data-testid={`alert-${a.type}`}>
        <label><input type="checkbox" checked={a.enabled} disabled={busy === a.type} onChange={e => toggle(a.type, e.target.checked)} />
          <span><b>{a.label}</b><small>{a.help}</small></span></label>
        {focus === a.type && <em className="sw-focus-note">You came here from an email. Untick this box to stop this kind of alert.</em>}</li>)}</ul>
      <button type="button" className="secondary-button" onClick={test} disabled={busy === "test"} data-testid="send-test-alert">
        {busy === "test" && <LoaderCircle className="spin" size={14} />}Send me a test alert</button>
      {note && <p className="sw-done" role="status"><CheckCircle2 size={15} />{note}</p>}
    </>}
    {error && <div className="form-error" role="alert"><ShieldAlert size={15} />{error}</div>}
  </section>;
}
