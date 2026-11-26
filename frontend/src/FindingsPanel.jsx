import React from "react";
import { AlertTriangle, ShieldAlert } from "lucide-react";
import { SEVERITY_LABEL, checksNotFinished, cvssText, emptyText, engineProgress, groupFindings, lifecycleTier, severityCounts, sourceLabel, summaryText } from "./lib/findings.js";

// Every field here came from our own rules or from public vulnerability databases. It is untrusted text and is shown as
// escaped plain text (React escapes it), never as HTML.

const SHOWN_FIRST = 10; // the highest-scored ones; the rest sit behind one click so the page stays readable

function Detail({ label, children }) {
  return children ? <div className="sw-fd-row"><dt>{label}</dt><dd>{children}</dd></div> : null;
}

function FindingCard({ finding, possible }) {
  const tier = lifecycleTier(finding);
  return <li className={`sw-finding sev-${finding.severity}${possible ? " possible" : ""}`} data-testid="finding">
    <details>
      <summary>
        <span className={`sw-sev sev-${finding.severity}`}>{SEVERITY_LABEL[finding.severity]}</span>
        <span className="sw-finding-title">{finding.title}</span>
        <span className="sw-finding-where">{finding.location}</span>
      </summary>
      {possible && finding.caveat && <p className="sw-caveat" role="note"><AlertTriangle size={14} />{finding.caveat}</p>}
      {!possible && finding.caveat && <p className="sw-caveat" role="note">{finding.caveat}</p>}
      <dl className="sw-fd">
        {tier && <Detail label="Status">{tier}</Detail>}
        <Detail label="What you have">{finding.you_have}</Detail>
        <Detail label="What you should have">{finding.you_should_have}</Detail>
        <Detail label="Why it matters">{finding.why}</Detail>
        <Detail label="How to fix it">{finding.how_to_fix}</Detail>
        <Detail label="What we saw">{finding.evidence}</Detail>
        {finding.cve_id && <Detail label="Reference">{finding.cve_id}{finding.cvss_score != null ? ` · ${cvssText(finding)}` : ""}</Detail>}
        <Detail label="Affected versions">{finding.affected_range}</Detail>
        <Detail label="First fixed in">{finding.first_fixed}</Detail>
        <Detail label="Source">{(finding.sources || []).map(sourceLabel).join(", ")}</Detail>
      </dl>
      {finding.cvss_vector && <p className="sw-note">Score details: <code>{finding.cvss_vector}</code></p>}
      {finding.details?.more_not_shown > 0 && <p className="sw-note">{finding.details.more_not_shown} more known issues for this software are not shown.</p>}
    </details>
  </li>;
}

export default function FindingsPanel({ findings, result, running }) {
  const { confirmed, needsChecking, info } = groupFindings(findings);
  const counts = severityCounts(findings);
  const problems = checksNotFinished(result);
  const progress = engineProgress(result, running);
  const nothing = confirmed.length === 0 && needsChecking.length === 0;

  return <section className="panel sw-findings" data-testid="findings-panel">
    <h3><ShieldAlert size={15} /> Findings</h3>
    {progress.notChecked && !problems.length && <p className="sw-unknown"><AlertTriangle size={14} />{progress.text}</p>}
    {!progress.notChecked && (!nothing || problems.length === 0) && <p className="sw-summary" data-testid="findings-summary">{summaryText(findings)}</p>}
    {confirmed.length > 0 && <div className="sw-chips">
      {["critical", "high", "medium", "low"].filter(k => counts[k]).map(k => <span key={k} className={`sw-sev sev-${k}`}>{counts[k]} {SEVERITY_LABEL[k]}</span>)}
    </div>}

    {problems.length > 0 && <div className="sw-cnc" data-testid="could-not-check">
      <h4><AlertTriangle size={14} /> Could not check</h4>
      <p className="sw-note">These checks did not finish. That is not the same as “nothing found”.</p>
      <ul>{problems.map(p => <li key={p.key}><b>{p.label}:</b> {p.text}
        {p.details.length > 0 && <ul>{p.details.map(d => <li key={d}>{d}</li>)}</ul>}</li>)}</ul>
    </div>}

    {confirmed.length > 0 && <ul className="sw-flist">{confirmed.map(f => <FindingCard key={f.fingerprint} finding={f} />)}</ul>}
    {nothing && !progress.notChecked && <p className="sw-none" data-testid="no-findings">{emptyText(result, running)}</p>}

    {needsChecking.length > 0 && <div className="sw-needs" data-testid="needs-checking">
      <h4>Needs checking ({needsChecking.length})</h4>
      <p className="sw-note">We could not be sure these apply to your server, for example because your system may have fixed them without changing the version number. They are not counted in your findings until confirmed. Each one says how to check.</p>
      <ul className="sw-flist">{needsChecking.slice(0, SHOWN_FIRST).map(f => <FindingCard key={f.fingerprint} finding={f} possible />)}</ul>
      {needsChecking.length > SHOWN_FIRST && <details className="sw-more" data-testid="needs-checking-more">
        <summary>Show the other {needsChecking.length - SHOWN_FIRST} (lower scores)</summary>
        <ul className="sw-flist">{needsChecking.slice(SHOWN_FIRST).map(f => <FindingCard key={f.fingerprint} finding={f} possible />)}</ul>
      </details>}
    </div>}

    {info.length > 0 && <details className="sw-goodtoknow">
      <summary>Good to know ({info.length})</summary>
      <ul className="sw-flist">{info.map(f => <FindingCard key={f.fingerprint} finding={f} />)}</ul>
    </details>}
  </section>;
}
