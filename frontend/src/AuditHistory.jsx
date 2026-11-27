import React, { useEffect, useState } from "react";
import { History } from "lucide-react";
import { api } from "./lib/api.js";
import { auditLine } from "./lib/audit.js";

// The website's audit history: who verified it and how (owner, consent, reason), scans, accepted risks and alerts. Newest first.

export default function AuditHistory({ siteId, refreshKey }) {
  const [events, setEvents] = useState(null);
  useEffect(() => {
    let alive = true;
    api.websiteAudit(siteId).then(d => alive && setEvents(d.events || [])).catch(() => alive && setEvents([]));
    return () => { alive = false; };
  }, [siteId, refreshKey]);
  if (events === null) return null;
  const when = iso => (iso ? new Date(iso).toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" }) : "");
  return <details className="panel sw-audit" data-testid="audit-history">
    <summary><History size={15} /> Audit history ({events.length})</summary>
    {events.length === 0 ? <p className="sw-note">Nothing recorded yet.</p> : <ul className="sw-audit-list">
      {events.map((event, i) => {
        const line = auditLine(event);
        return <li key={`${event.at}-${i}`} className={line.tone || ""} data-testid="audit-event">
          <div><b>{line.title}</b><small>{when(event.at)}</small></div>
          {line.lines.map((text, j) => <p key={j}>{text}</p>)}</li>;
      })}</ul>}
  </details>;
}
