import React from "react";
import { AlertTriangle, Download, Info } from "lucide-react";
import { SEVERITY_LABEL, cvssText, lifecycleTier, sourceLabel, checksNotFinished } from "./lib/findings.js";
import { REPORT_DISCLAIMER, certificateView, gradeView, pdfAllowed, reportFields, reportGroups, scanDuration, severityRows } from "./lib/report.js";

// The website report. Everything from a scan is untrusted text and is shown escaped (React escapes it).
// A print stylesheet (console.css) hides the app chrome, so "Download PDF" is the browser's own Save as PDF.

function FindingBlock({ finding, possible }) {
  const tier = lifecycleTier(finding);
  return <article className={`sw-rfinding sev-${finding.severity}${possible ? " possible" : ""}`} data-testid="report-finding">
    <h4><span className={`sw-sev sev-${finding.severity}`}>{SEVERITY_LABEL[finding.severity]}</span> {finding.title}</h4>
    {finding.caveat && <p className="sw-caveat"><AlertTriangle size={14} />{finding.caveat}</p>}
    <dl className="sw-fd">
      {tier && <div className="sw-fd-row"><dt>Status</dt><dd>{tier}</dd></div>}
      {reportFields(finding).map(row => <div className="sw-fd-row" key={row.label}><dt>{row.label}</dt><dd>{row.value}</dd></div>)}
      {finding.cvss_score != null && <div className="sw-fd-row"><dt>Score details</dt><dd>{cvssText(finding)}</dd></div>}
      <div className="sw-fd-row"><dt>Source</dt><dd>{(finding.sources || []).map(sourceLabel).join(", ")}</dd></div>
    </dl>
  </article>;
}

export default function ReportView({ site, data, plan }) {
  if (!data) return <div className="loading-rows"><div /><div /></div>;
  const summary = data.summary, grade = gradeView(summary);
  const { confirmed, needsChecking } = reportGroups(data.findings || []);
  const result = data.scan.result || {};
  const unfinished = checksNotFinished(result);
  const when = data.scan.ended_at ? new Date(data.scan.ended_at).toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" }) : "";
  const cert = certificateView(summary?.certificate);
  return <section className="sw-report" data-testid="report">
    <div className="sw-report-head sw-noprint">
      {pdfAllowed(plan)
        ? <><p>Print this page or save it as a PDF to share it.</p>
          <button className="primary-button" onClick={() => window.print()} data-testid="download-pdf"><Download size={15} />Download PDF</button></>
        : <p data-testid="pdf-not-included">PDF download is not included in your plan. You can still read this report on screen.</p>}
    </div>
    <header className="sw-report-title">
      <div className="sw-report-brand">SNWebShield website security report</div>
      <h2>{site.domain}</h2>
      <p>Scanned {when}{scanDuration(data.scan) ? ` (took ${scanDuration(data.scan)})` : ""}. {data.scan.status === "incomplete" ? "Some checks did not finish." : ""}</p>
    </header>

    <div className="sw-report-summary">
      {grade ? <div className={`sw-grade ${grade.tone}`} data-testid="report-grade"><span className="sw-grade-letter">{grade.grade}</span>
        <span className="sw-grade-score">{grade.label}</span></div> : <div className="sw-grade muted"><span className="sw-grade-letter">{"—"}</span></div>}
      <div className="sw-report-counts">
        <h3>Findings</h3>
        <ul>{severityRows(summary).map(row => <li key={row.level}><span className={`sw-sev sev-${row.level}`}>{row.label}</span> <b>{row.count}</b></li>)}
          <li><span className="sw-sev sev-info">Needs checking</span> <b>{summary?.needs_checking ?? 0}</b></li></ul>
        {grade?.note && <p className="sw-note-line warn"><Info size={15} />{grade.note}</p>}
        <p className="sw-note">Score: starts at 100; each confirmed finding takes off 25 (Critical), 10 (High), 4 (Medium) or 1 (Low). Items that need checking are not counted.</p>
      </div>
      <div className="sw-report-meta"><h3>Certificate</h3><p className={`tone-${cert.tone}`}>{cert.text}</p></div>
    </div>

    {(result.notes || []).map((note, i) => <p key={i} className={`sw-note-line ${note.tone || "info"}`}><Info size={15} />{note.text}</p>)}
    {unfinished.length > 0 && <div className="sw-cnc"><h4><AlertTriangle size={14} /> Could not check</h4>
      <ul>{unfinished.map(p => <li key={p.key}><b>{p.label}:</b> {p.text}</li>)}</ul></div>}

    <h3 className="sw-report-h">Confirmed findings ({confirmed.length})</h3>
    {confirmed.length === 0 ? <p className="sw-none" data-testid="report-none">No confirmed findings from these checks. This does not prove that your website has no weaknesses.</p>
      : confirmed.map(f => <FindingBlock key={f.fingerprint} finding={f} />)}

    <h3 className="sw-report-h">Needs checking ({needsChecking.length})</h3>
    <p className="sw-note">We could not be sure these apply to your server, for example because your system may have fixed them without changing the version number. They are not counted in the score. Each one says how to check.</p>
    {needsChecking.slice(0, 20).map(f => <FindingBlock key={f.fingerprint} finding={f} possible />)}
    {needsChecking.length > 20 && <p className="sw-note">{needsChecking.length - 20} more lower-scored items are listed on the Vulnerabilities tab.</p>}

    <p className="sw-report-foot">{REPORT_DISCLAIMER}</p>
  </section>;
}
