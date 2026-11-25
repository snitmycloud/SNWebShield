import React, { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./lib/api.js";
import { pillars, stepTarget } from "./lib/lifecycle.js";
import "./lifecycle.css";

export default function LifecyclePage({ websites, onNavigate }) {
  const [site, setSite] = useState(""), [view, setView] = useState(null), [error, setError] = useState(""), [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const load = useCallback(async id => {
    const version = ++generation.current;
    if (!id) { setView(null); return; }
    setBusy(true); setError("");
    try { const result = await api.websiteLifecycle(id); if (version === generation.current) setView(result); }
    catch (e) { if (version === generation.current) { setView(null); setError(e.message); } }
    finally { if (version === generation.current) setBusy(false); }
  }, []);
  useEffect(() => { if (!site && websites.length) setSite(String(websites[0].id)); }, [websites, site]);
  useEffect(() => { load(site); return () => { generation.current++; }; }, [site, load]);
  const target = view && stepTarget(view.next_step);
  return <section className="lifecycle-page">
    <div className="eyebrow">WEBSITE LIFECYCLE</div>
    <h1>Monitors. Detects. Validates. Protects.</h1>
    <p>One view of where a website stands and what to do next. It only reads existing records: it runs no scan and changes nothing.</p>
    <label>Website<select aria-label="Lifecycle website" value={site} onChange={e => setSite(e.target.value)}>
      <option value="">Choose a website</option>{websites.map(w => <option key={w.id} value={w.id}>{w.name} · #{w.id}</option>)}</select></label>
    <button className="secondary-button" disabled={busy || !site} onClick={() => load(site)}>Refresh</button>
    {error && <p role="alert" className="form-error">{error}</p>}
    {view && <>
      <div className="panel lifecycle-next" data-testid="next-step" data-code={view.next_step.code}>
        <h2>Next step</h2><p>{view.next_step.message}</p>
        {target && <button className="primary-button" onClick={() => onNavigate(target.page)}>{target.label}</button>}
      </div>
      <div className="lifecycle-grid">{pillars(view).map(p => <article key={p.key} className="panel lifecycle-card" aria-label={p.title} data-testid={`pillar-${p.key}`}>
        <h2>{p.title}</h2>{p.lines.map((line, i) => <p key={i}>{line}</p>)}</article>)}</div>
    </>}
    {!view && !error && !busy && <p>Choose a website to see its lifecycle.</p>}
  </section>;
}
