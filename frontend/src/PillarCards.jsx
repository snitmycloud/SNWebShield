import React from "react";
import { Activity, Bug, FileText, Radar } from "lucide-react";
import { buildPillars } from "./lib/pillars.js";
import { SEVERITY_LABEL } from "./lib/findings.js";

// The four pillars across ALL of the person's websites. Each card links to the website (and tab) where the details are.
// Counts are what automated checks found; a website with no scan yet says so, and nothing here says "safe".

const ICONS = { monitor: Activity, detect: Radar, vulnerabilities: Bug, report: FileText };
const when = iso => (iso ? new Date(iso).toLocaleDateString("en-IN", { dateStyle: "medium" }) : "");

function Link({ onOpen, id, tab, children }) {
  return <button type="button" className="text-button sw-pillar-link" onClick={() => onOpen(id, tab)}>{children}</button>;
}

function Body({ pillar, onOpen }) {
  switch (pillar.key) {
    case "monitor": return <>
      <p className="sw-pillar-line">{pillar.sites ? `${pillar.up} up, ${pillar.down} down${pillar.unknown ? `, ${pillar.unknown} not checked yet` : ""}` : "Add and verify a website to start monitoring."}</p>
      {pillar.downSites.map(s => <p key={s.id} className="sw-pillar-line bad"><Link onOpen={onOpen} id={s.id} tab="monitor">{s.domain}</Link> is not answering</p>)}
      <p className="sw-pillar-line">{pillar.expiring.length ? "Certificates ending soon:" : "No certificate ends within 14 days."}</p>
      {pillar.expiring.slice(0, 3).map(x => <p key={x.id} className="sw-pillar-line warn"><Link onOpen={onOpen} id={x.id} tab="monitor">{x.domain}</Link> {x.days < 0 ? "has ended" : `in ${x.days} day${x.days === 1 ? "" : "s"}`}</p>)}
    </>;
    case "detect": return <>
      <p className="sw-pillar-line">{pillar.scanned ? `${pillar.technologies} technolog${pillar.technologies === 1 ? "y" : "ies"} found on ${pillar.scanned} website${pillar.scanned === 1 ? "" : "s"}` : "Your first scan finds open ports and technologies."}</p>
      {pillar.incomplete > 0 && <p className="sw-pillar-line warn">{pillar.incomplete} scan{pillar.incomplete === 1 ? " was" : "s were"} incomplete, so there may be more.</p>}
    </>;
    case "vulnerabilities": return <>
      {pillar.scanned > 0 ? <ul className="sw-pillar-sev" aria-label="Open findings by severity">{["critical", "high", "medium", "low"].map(k => <li key={k}><span className={`sw-sev sev-${k}`}>{SEVERITY_LABEL[k]}</span> <b>{pillar.counts[k]}</b></li>)}</ul>
        : <p className="sw-pillar-line">Findings appear after the first scan.</p>}
      {pillar.needsChecking > 0 && <p className="sw-pillar-line">{pillar.needsChecking} more need your check.</p>}
    </>;
    default: return pillar.reports.length ? <ul className="sw-pillar-reports">{pillar.reports.map(r => <li key={r.id}>
      <Link onOpen={onOpen} id={r.id} tab="report">{r.domain}</Link><span className="sw-muted">{r.grade} {r.score}/100{r.incomplete ? " *" : ""} · {when(r.scannedAt)}</span></li>)}</ul>
      : <p className="sw-pillar-line">A report is ready as soon as a scan finishes.</p>;
  }
}

export default function PillarCards({ websites, onOpen, loading }) {
  const pillars = buildPillars(websites);
  return <section className="sw-pillars" aria-label="Your websites by pillar" data-testid="pillars">
    {pillars.map(p => {
      const Icon = ICONS[p.key];
      return <article key={p.key} className={`panel sw-pillar tone-${p.tone}`} data-testid={`pillar-${p.key}`}>
        <header><span className="sw-pillar-icon"><Icon size={18} /></span><h2>{p.title}</h2></header>
        {loading ? <div className="loading-rows"><div /><div /></div> : <>
          <p className="sw-pillar-headline" data-testid={`pillar-${p.key}-headline`}>{p.headline}</p>
          <Body pillar={p} onOpen={onOpen} />
          {p.link && <button type="button" className="secondary-button sw-pillar-open" onClick={() => onOpen(p.link.id, p.link.tab)}>See details</button>}
        </>}
      </article>;
    })}
  </section>;
}
