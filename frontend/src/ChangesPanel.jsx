import React, { useEffect, useState } from "react";
import { GitCompare } from "lucide-react";
import { api } from "./lib/api.js";
import { changesText } from "./lib/findings.js";

// "Changes since last scan": what is new, fixed and unchanged compared with the scan before. Titles come from our own rules and are
// shown as escaped text. A finding is only called fixed if the check behind it finished; otherwise it is "could not be confirmed".

export function useComparison(siteId, scan) {
  const [data, setData] = useState(null);
  const scanId = scan?.id, status = scan?.status;
  useEffect(() => {
    let alive = true;
    setData(null);
    if (!scanId || !["completed", "incomplete"].includes(status)) return undefined;
    api.scanComparison(siteId, scanId).then(d => alive && setData(d)).catch(() => alive && setData(null));
    return () => { alive = false; };
  }, [siteId, scanId, status]);
  return data;
}

function List({ title, items }) {
  return items.length ? <details className="sw-changes-list"><summary>{title} ({items.length})</summary>
    <ul>{items.map(f => <li key={f.fingerprint}><span className={`sw-sev sev-${f.severity}`}>{f.severity}</span> {f.title} <code>{f.location}</code></li>)}</ul></details> : null;
}

export default function ChangesPanel({ site, scan, data, compact = false }) {
  const comparison = useComparison(site.id, scan);
  if (!comparison) return null;
  if (!comparison.previous) return <section className="panel sw-changes" data-testid="changes-panel">
    <h3><GitCompare size={15} /> Changes since last scan</h3>
    <p className="sw-note">This is the first scan of this website, so there is nothing to compare with yet.</p></section>;
  return <section className="panel sw-changes" data-testid="changes-panel">
    <h3><GitCompare size={15} /> Changes since last scan</h3>
    <p className="sw-changes-summary" data-testid="changes-summary">{changesText(comparison.counts)}</p>
    {!compact && <>
      <List title="New" items={comparison.new} />
      <List title="Checked for the first time (the last scan did not run this check)" items={comparison.first_checked || []} />
      <List title="Fixed" items={comparison.fixed} />
      <List title="Could not be confirmed" items={comparison.could_not_confirm} />
      <List title="Unchanged" items={comparison.unchanged} />
    </>}
  </section>;
}
