import React, { useCallback, useEffect, useState } from "react";
import { Activity, ShieldAlert } from "lucide-react";
import { api } from "./lib/api.js";
import { roleView, workersSummary } from "./lib/monitor.js";

// Admin > Workers: is each background role running? The server decides from heartbeats (its own clock); this page only shows it.

export default function WorkersPanel() {
  const [data, setData] = useState(null), [error, setError] = useState("");
  const load = useCallback(() => api.adminWorkers().then(d => { setData(d); setError(""); }).catch(e => setError(e.message)), []);
  useEffect(() => { load(); const timer = setInterval(load, 10000); return () => clearInterval(timer); }, [load]);
  return <section className="panel sw-workers" data-testid="workers-panel">
    <h3><Activity size={15} /> Workers</h3>
    {error && <div className="form-error" role="alert"><ShieldAlert size={15} />{error}</div>}
    {!data ? <div className="loading-rows"><div /><div /></div> : <>
      <p className={`sw-workers-summary ${data.healthy ? "good" : "bad"}`} data-testid="workers-summary">{workersSummary(data)}</p>
      <ul className="sw-worker-list">{data.roles.map(role => {
        const v = roleView(role);
        return <li key={role.role} data-testid={`worker-${role.role}`}>
          <div><b>{role.label}</b><small>{role.text}</small></div>
          <div className="sw-worker-state"><span className={`sw-badge ${v.tone}`}><span />{v.label}</span>{v.detail && <small>{v.detail}</small>}</div></li>;
      })}</ul></>}
  </section>;
}
