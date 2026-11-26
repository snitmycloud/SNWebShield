import React, { useEffect, useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, Info, LoaderCircle } from "lucide-react";
import { api } from "./lib/api.js";
import FindingsPanel from "./FindingsPanel.jsx";
import { describePort, dnsText, exposedText, isActiveScan, resultBanner, sectionNote, softwareText, stepProblems, stepState } from "./lib/detect.js";

// Everything below comes from the scanned server and is shown as escaped text (React escapes it), never as HTML.

function Section({ title, state, hasData, running, children, empty }) {
  const note = sectionNote(state, { running, hasData });
  return <section className="panel sw-detect-section">
    <h3>{title}</h3>
    {note.kind === "problem" || note.kind === "unchecked"
      ? <p className="sw-unknown"><AlertTriangle size={14} />{note.text}</p>
      : note.kind === "empty" ? <p className="sw-none">{empty}</p> : children}
  </section>;
}

export default function DetectResults({ siteId, scan }) {
  const [data, setData] = useState(null), [error, setError] = useState("");
  const alive = useRef(true);
  const scanId = scan?.id, status = scan?.status, endedAt = scan?.ended_at;

  useEffect(() => {
    alive.current = true; setData(null); setError("");
    if (!scanId || status === "queued") return undefined;
    const load = () => api.scanDetail(siteId, scanId).then(d => alive.current && setData(d)).catch(e => alive.current && setError(e.message));
    load();
    const timer = isActiveScan({ status }) ? setInterval(load, 3000) : null;
    return () => { alive.current = false; if (timer) clearInterval(timer); };
  }, [siteId, scanId, status, endedAt]);

  if (!scan) return null;
  if (error) return <div className="form-error" role="alert"><AlertTriangle size={15} />{error}</div>;
  if (!data) return scan.status === "queued" ? null : <div className="loading-rows"><div /><div /></div>;

  const result = data.scan.result || {};
  const banner = resultBanner(data.scan);
  const problems = stepProblems(result);
  const running = isActiveScan(data.scan);
  const web = data.ports.filter(p => p.http);

  return <div className="sw-detect" data-testid="detect-results">
    {banner && <div className={`sw-result ${banner.tone === "info" ? "good" : "bad"} ${banner.tone === "warn" ? "warn" : ""}`} role="status">
      <strong>{banner.tone === "info" ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}{banner.title}</strong>
      <p>{banner.text}</p>
      {problems.length > 0 && <ul className="sw-problems">{problems.map(p => <li key={p.key}><b>{p.label}:</b> {p.text}</li>)}</ul>}
    </div>}
    {running && <p className="sw-partial"><LoaderCircle className="spin" size={14} /> Results so far (the scan is still running).</p>}

    <FindingsPanel findings={data.findings || []} result={result} running={running} />

    <Section title="Open ports" state={stepState(result, "ports")} hasData={data.ports.length > 0} running={running} empty="No open ports were found among the ports we checked.">
      {data.ports.length > 0 && <div className="table-scroll"><table><thead><tr><th>What it is</th><th>Port</th><th>Software</th><th /></tr></thead><tbody>
        {data.ports.map(p => { const d = describePort(p);
          return <tr key={p.port}><td><strong>{d.label}</strong><div className="cell-secondary">{d.sentence}</div></td><td>{p.port}</td>
            <td>{softwareText(p)}</td><td>{p.tls ? <span className="sw-badge info"><span />Encrypted (TLS)</span> : null}</td></tr>; })}
      </tbody></table></div>}
      {result.ports && <p className="sw-note">Checked {result.ports.scanned} of {result.ports.planned} ports: {result.ports.open} open, {result.ports.closed} closed, {result.ports.filtered} not answering.</p>}
    </Section>

    <Section title="Technologies and versions" state={stepState(result, "technologies")} hasData={data.technologies.length > 0} running={running}
      empty={stepState(result, "technologies") === "not_applicable" ? "No website was found to examine." : "No technologies were recognised."}>
      {data.technologies.length > 0 && <div className="table-scroll"><table><thead><tr><th>Technology</th><th>Type</th><th>Version</th></tr></thead><tbody>
        {data.technologies.map(t => <tr key={t.name}><td><strong>{t.name}</strong></td><td>{t.category}</td><td>{t.version || "Not disclosed"}</td></tr>)}
      </tbody></table></div>}
    </Section>

    <Section title="Email and DNS security" state={stepState(result, "dns")} hasData={data.dns.length > 0} running={running} empty="No DNS information.">
      {data.dns.length > 0 && <ul className="sw-dns">{data.dns.map(row => { const t = dnsText(row);
        return <li key={row.key}><span className={`sw-badge ${t.tone}`}><span />{t.status}</span><div><strong>{t.title}</strong> <small>{t.what}</small>{t.detail && <div className="cell-secondary">{t.detail}</div>}</div></li>; })}</ul>}
    </Section>

    <Section title="Exposed files and pages" state={stepState(result, "exposed")} hasData={data.exposed.length > 0} running={running}
      empty={stepState(result, "exposed") === "not_applicable" ? "No website was found to check." : "None of the files and pages we looked for were found."}>
      {data.exposed.length > 0 && <ul className="sw-dns">{data.exposed.map(item =>
        <li key={item.path}><span className="sw-badge warn"><span />Found</span><div><strong>{item.path}</strong><div className="cell-secondary">{exposedText(item)}</div></div></li>)}</ul>}
    </Section>

    <Section title="Subdomains" state={stepState(result, "subdomains")} hasData={data.subdomains.length > 0} running={running} empty="No subdomains were listed in public certificate records.">
      {data.subdomains.length > 0 && <><p className="sw-note">Listed from public certificate records. They are only listed, not scanned.</p>
        <ul className="sw-subs">{data.subdomains.map(name => <li key={name}>{name}</li>)}</ul></>}
    </Section>

    <details className="panel sw-detect-section"><summary>Technical details</summary>
      <p className="sw-note"><Info size={13} /> Scanned address <code>{data.scan.resolved_ip}</code>. Text below was sent by the scanned server and is shown as plain text.</p>
      {data.ports.map(p => <div key={p.port} className="sw-tech">
        <strong>Port {p.port}</strong> â€” {p.service || "unknown"}{p.service_guess ? " (guessed from the port number)" : ""}
        {p.banner && <pre>{p.banner}</pre>}
        {p.tls && <p className="cell-secondary">TLS {p.tls.version} Â· {p.tls.cipher}{p.tls.certificate ? ` Â· certificate for ${p.tls.certificate.subject_cn || "?"}, issued by ${p.tls.certificate.issuer_cn || "?"}, expires ${(p.tls.certificate.not_after || "").slice(0, 10)}${p.tls.certificate.self_signed ? " (self-signed)" : ""}` : ""}</p>}
        {p.http && <pre>{Object.entries(p.http.headers || {}).map(([k, v]) => `${k}: ${v}`).join("\n")}</pre>}
      </div>)}
      {web.length === 0 && data.ports.length === 0 && <p className="sw-none">No services to show.</p>}
    </details>
  </div>;
}
