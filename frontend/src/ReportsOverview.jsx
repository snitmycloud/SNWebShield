import React from "react";
import { Download, FileText, Globe2 } from "lucide-react";
import { latestReports } from "./lib/pillars.js";
import { gradeView, pdfAllowed } from "./lib/report.js";
import { EmptyState, Skeleton } from "./Placeholders.jsx";

// Reports: the latest report of every website. "View" opens the website's Report tab; "Download PDF" opens it and the browser's
// print dialog (Save as PDF). The PDF button follows the plan setting `pdf_report`.

const when = iso => (iso ? new Date(iso).toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" }) : "");

export default function ReportsOverview({ websites, plan, loading, onOpen, onAdd }) {
  const reports = latestReports(websites);
  const waiting = websites.filter(w => w.verification_status === "verified" && !reports.some(r => r.id === w.id));
  return <>
    <header className="page-heading"><div><div className="eyebrow">REPORTS</div><h1>Reports</h1>
      <p>The latest report of each website. A new report is made every time a scan finishes.</p></div></header>
    <section className="panel table-panel" data-testid="reports-list">
      {loading ? <Skeleton rows={3} />
        : reports.length === 0 ? <EmptyState icon={FileText} title="No reports yet"
          text={websites.length ? "A report appears here as soon as the first scan of a website finishes." : "Add your first website. When its first scan finishes, its report appears here."}
          action={websites.length ? null : <button className="primary-button" onClick={onAdd}>Add website</button>} />
          : <div className="table-scroll"><table className="sw-stack">
            <thead><tr><th>Website</th><th>Score</th><th>Report from</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>{reports.map(r => {
              const grade = gradeView({ score: r.score, grade: r.grade, incomplete: r.incomplete });
              return <tr key={r.id} data-testid="report-row">
                <td data-label="Website"><div className="website-cell"><div className="site-icon"><Globe2 size={16} /></div><strong>{r.domain}</strong></div></td>
                <td data-label="Score">{grade && <span className={`sw-grade-chip ${grade.tone}`}><b>{grade.grade}</b> {grade.label}{r.incomplete ? " *" : ""}</span>}</td>
                <td data-label="Report from">{when(r.scannedAt)}{r.incomplete && <small className="sw-muted"> Some checks did not finish.</small>}</td>
                <td className="sw-row-actions">
                  <button className="secondary-button" onClick={() => onOpen(r.id, "report")} data-testid="report-view">View</button>
                  {pdfAllowed(plan) ? <button className="secondary-button" onClick={() => onOpen(r.id, "report", true)} data-testid="report-pdf"><Download size={14} />Download PDF</button>
                    : <span className="sw-muted" data-testid="pdf-not-included">PDF is not in your plan</span>}</td></tr>;
            })}</tbody></table></div>}
      {waiting.length > 0 && !loading && <p className="table-footnote">{waiting.map(w => w.domain).join(", ")} {waiting.length === 1 ? "has" : "have"} no finished scan yet.</p>}
    </section>
  </>;
}
