import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, AlertTriangle, ArrowUpRight, Bug, Check, CheckCircle2, ChevronRight, Copy, FileText, Globe2,
  LayoutDashboard, LoaderCircle, LogOut, Plus, RefreshCw, Settings2, Shield, ShieldAlert, ShieldCheck, Users,
  UserCheck, X,
} from "lucide-react";
import { api } from "./lib/api.js";
import { METHODS, MANUAL_REASON_MIN, CONSENT_METHODS, checkView, isStaff, manualDetailsProblem, passwordHint, planLimit, removalConfirmed, scanView, verificationView } from "./lib/account.js";
import { DetectSections, ScanBanner, useScanDetail } from "./DetectResults.jsx";
import FindingsPanel from "./FindingsPanel.jsx";
import ErrorBoundary from "./ErrorBoundary.jsx";
import ReportView from "./ReportView.jsx";
import ChangesPanel from "./ChangesPanel.jsx";
import TrendChart from "./TrendChart.jsx";
import AuditHistory from "./AuditHistory.jsx";
import AlertSettings from "./AlertSettings.jsx";
import WorkersPanel from "./WorkersPanel.jsx";
import { parseHash, scheduleText, uptimeView } from "./lib/monitor.js";
import { certificateView, gradeView, scanDuration, TABS } from "./lib/report.js";
import { isFriendlyLimit, scanNowText } from "./lib/detect.js";
import "./console.css";

const MAIN_NAV = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "websites", label: "Websites", icon: Globe2 },
  { id: "settings", label: "Settings", icon: Settings2 },
];

const when = value => {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : new Intl.DateTimeFormat("en-IN", { dateStyle: "medium", timeStyle: "short" }).format(date);
};

function Badge({ tone, children }) {
  return <span className={`sw-badge ${tone}`}><span />{children}</span>;
}

function Heading({ eyebrow, title, text, action }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1>{text && <p>{text}</p>}</div>{action}</div>;
}

function UpgradeNotice({ detail, onUpgrade, onClose }) {
  if (!detail) return null;
  return <div className="sw-upgrade" role="status" data-testid="upgrade-message">
    <ArrowUpRight size={18} />
    <div><strong>You have reached your plan limit</strong><span>{detail.message}</span></div>
    <button className="primary-button" onClick={onUpgrade}>Upgrade</button>
    <button className="icon-button" aria-label="Dismiss" onClick={onClose}><X size={15} /></button>
  </div>;
}

function RemoveDialog({ site, onClose, onRemoved }) {
  const [typed, setTyped] = useState(""), [busy, setBusy] = useState(false), [error, setError] = useState("");
  useEffect(() => {
    const onKey = event => { if (event.key === "Escape" && !busy) onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, busy]);
  const ready = removalConfirmed(site, typed);
  const submit = async event => {
    event.preventDefault();
    if (!ready) return;
    setBusy(true); setError("");
    try { const result = await api.removeWebsite(site.id, typed.trim()); onRemoved(result); }
    catch (err) { setError(err.message); setBusy(false); }
  };
  return <div className="modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget && !busy) onClose(); }}>
    <form className="modal-card sw-remove" role="dialog" aria-modal="true" aria-labelledby="sw-remove-title" onSubmit={submit}>
      <div className="modal-heading"><div><h2 id="sw-remove-title">Remove {site.domain}?</h2>
        <p>This frees one of your website slots.</p></div>
        <button type="button" className="icon-button" onClick={onClose} disabled={busy} aria-label="Close"><X size={19} /></button></div>
      <div className="modal-form">
        <ul className="sw-remove-list">
          <li>Its ownership verification is deleted. To scan it again later, you add it and verify it again.</li>
          <li>Scans that have not finished are cancelled.</li>
          <li>Your past scan records and the audit log are kept.</li>
        </ul>
        <label className="form-field"><span>Type <b>{site.domain}</b> to confirm</span>
          <input value={typed} onChange={e => setTyped(e.target.value)} autoFocus autoComplete="off" spellCheck="false" maxLength={2048} aria-label="Type the domain to confirm" /></label>
        {error && <div className="form-error" role="alert"><ShieldAlert size={15} />{error}</div>}
        <div className="modal-actions">
          <button type="button" className="secondary-button" onClick={onClose} disabled={busy}>Keep website</button>
          <button className="sw-danger" disabled={!ready || busy}>{busy && <LoaderCircle className="spin" size={14} />}Remove website</button>
        </div>
      </div>
    </form>
  </div>;
}

function CopyValue({ value, label }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* clipboard unavailable */ }
  };
  return <div className="sw-copy"><code aria-label={label}>{value}</code>
    <button type="button" className="secondary-button" onClick={copy}>{copied ? <Check size={14} /> : <Copy size={14} />}{copied ? "Copied" : "Copy"}</button></div>;
}

// ---- Dashboard -----------------------------------------------------------------------------------

function DashboardView({ account, websites, plan, loading, onOpen, onAdd }) {
  const verified = websites.filter(w => w.verification_status === "verified").length;
  const waiting = websites.filter(w => w.verification_status !== "verified").length;
  return <>
    <Heading eyebrow="DASHBOARD" title={`Hello${account.full_name ? `, ${account.full_name.split(" ")[0]}` : ""}`}
      text="Your websites at a glance."
      action={<button className="primary-button" onClick={onAdd}><Plus size={16} /> Add website</button>} />
    <div className="stats-grid sw-stats">
      <div className="stat-card"><div className="stat-icon teal"><Globe2 size={19} /></div><div className="stat-label">Websites</div>
        <div className="stat-value">{loading ? <span className="skeleton-value" /> : websites.length}</div>
        <div className="stat-detail">{plan ? `${plan.label} plan: up to ${plan.max_websites}` : " "}</div></div>
      <div className="stat-card"><div className="stat-icon blue"><ShieldCheck size={19} /></div><div className="stat-label">Ownership verified</div>
        <div className="stat-value">{loading ? <span className="skeleton-value" /> : verified}</div><div className="stat-detail">Scans run only on these</div></div>
      <div className="stat-card"><div className="stat-icon amber"><AlertTriangle size={19} /></div><div className="stat-label">Waiting for verification</div>
        <div className="stat-value">{loading ? <span className="skeleton-value" /> : waiting}</div><div className="stat-detail">Verify to start scanning</div></div>
    </div>
    {loading ? <div className="sw-cards">{[0, 1, 2].map(i => <div key={i} className="panel sw-card sw-skeleton" />)}</div>
      : websites.length === 0 ? <div className="panel"><div className="empty-state">
        <div className="empty-icon"><Globe2 size={22} /></div><strong>Add your first website</strong>
        <p>Enter your domain, prove you own it in about a minute, and the first scan starts automatically.</p>
        <button className="primary-button" onClick={onAdd}><Plus size={15} /> Add website</button></div></div>
      : <div className="sw-cards">{websites.map(site => {
        const v = verificationView(site), s = scanView(site.latest_scan);
        return <button key={site.id} className="panel sw-card" onClick={() => onOpen(site.id)}>
          <div className="sw-card-top"><div className="site-icon"><Globe2 size={17} /></div><strong>{site.domain || site.name}</strong>
            {site.test_target && <Badge tone="info">Test target</Badge>}<ChevronRight size={16} /></div>
          <div className="sw-card-row"><span>Ownership</span><Badge tone={v.tone}>{v.label}</Badge></div>
          <div className="sw-card-row"><span>Last scan</span><Badge tone={s.tone}>{s.label}</Badge></div>
          <div className="sw-card-row sw-card-score"><span>Security score</span>{(() => { const g = gradeView(site.summary);
            return g ? <span className={`sw-grade-chip ${g.tone}`} data-testid="card-grade" title={g.note || undefined}><b>{g.grade}</b> {g.score}/100{site.summary.incomplete ? " *" : ""}</span>
              : <span className="sw-muted">{"\u2014"}</span>; })()}</div>
          {site.uptime && <div className="sw-card-row"><span>Uptime</span><span className={`tone-${uptimeView(site.uptime).tone}`} data-testid="card-uptime">{uptimeView(site.uptime).label}</span></div>}
          {site.summary && <div className="sw-card-row"><span>Certificate</span><span className={`tone-${certificateView(site.summary.certificate).tone}`}>
            {site.summary.certificate ? (site.summary.certificate.days_left < 0 ? "Expired" : `${site.summary.certificate.days_left} days left`) : "\u2014"}</span></div>}
          <p className="sw-card-text">{site.verification_status === "verified" ? s.text : v.text}</p>
          <div className="sw-card-foot">{site.latest_scan ? `Scan ${when(site.latest_scan.ended_at || site.latest_scan.requested_at)}` : "No scan yet"}</div>
        </button>;
      })}</div>}
  </>;
}

// ---- Websites ------------------------------------------------------------------------------------

function AddWebsite({ plan, count, onAdded, onLimit }) {
  const [domain, setDomain] = useState(""), [busy, setBusy] = useState(false), [error, setError] = useState("");
  const submit = async e => {
    e.preventDefault(); setBusy(true); setError("");
    try { const site = await api.addWebsite(domain.trim()); setDomain(""); onAdded(site); }
    catch (err) { const limit = planLimit(err); if (limit) onLimit(limit); else setError(err.message); }
    finally { setBusy(false); }
  };
  return <form className="panel sw-add" onSubmit={submit} aria-label="Add website">
    <label htmlFor="sw-domain"><strong>Add a website</strong><span>Enter the address, for example www.example.com</span></label>
    <div className="sw-add-row">
      <input id="sw-domain" value={domain} onChange={e => setDomain(e.target.value)} placeholder="www.example.com" maxLength={2048} required autoComplete="off" />
      <button className="primary-button" disabled={busy}>{busy ? <LoaderCircle className="spin" size={15} /> : <Plus size={15} />}Add website</button>
    </div>
    {plan && <small>{count} of {plan.max_websites} websites used on your {plan.label} plan.</small>}
    {error && <div className="form-error" role="alert"><ShieldAlert size={15} />{error}</div>}
  </form>;
}

function Step({ n, children }) {
  return <li><span className="sw-step-n">{n}</span><div>{children}</div></li>;
}

function ManualVerify({ site, onDone }) {
  const [open, setOpen] = useState(false), [reason, setReason] = useState(""), [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [ownerName, setOwnerName] = useState(""), [consent, setConsent] = useState("");
  const problem = manualDetailsProblem({ ownerName, consent, reason });
  const submit = async e => {
    e.preventDefault(); setBusy(true); setError("");
    try { const response = await api.verifyManually(site.id, { ownerName: ownerName.trim(), consent, reason: reason.trim() }); setOpen(false); setReason(""); setOwnerName(""); setConsent(""); onDone(response); }
    catch (err) { setError(err.message); } finally { setBusy(false); }
  };
  if (!open) return <button type="button" className="secondary-button sw-manual-open" data-testid="verify-manually-open" onClick={() => setOpen(true)}>
    <UserCheck size={15} />Verify manually (admin)</button>;
  return <form className="sw-manual" onSubmit={submit} aria-label="Verify manually">
    <strong>Verify manually (admin only)</strong>
    <p>Use this only when the website's owner has agreed to the scan. It lasts <b>24 hours</b>, is shown as {"\u201c"}Manually verified by admin{"\u201d"}, and is written to the audit history with your name, the owner, how they agreed, this reason and the time.</p>
    <label htmlFor="sw-manual-owner">Owner name or company (required)</label>
    <input id="sw-manual-owner" value={ownerName} onChange={e => setOwnerName(e.target.value)} maxLength={120} placeholder="For example: Asha Rao, Excel Logics" data-testid="manual-owner" required />
    <label htmlFor="sw-manual-consent">How consent was given (required)</label>
    <select id="sw-manual-consent" value={consent} onChange={e => setConsent(e.target.value)} data-testid="manual-consent" required>
      <option value="">Choose...</option>{CONSENT_METHODS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>
    <label htmlFor="sw-manual-reason">Reason (required, at least {MANUAL_REASON_MIN} characters)</label>
    <textarea id="sw-manual-reason" value={reason} onChange={e => setReason(e.target.value)} maxLength={300} rows={3}
      placeholder={"For example: Asha Rao emailed on 26 Nov allowing a scan of the website for the customer demo"} data-testid="manual-reason" required />
    <small>{problem || "Ready."}</small>
    {error && <div className="form-error" role="alert"><ShieldAlert size={15} />{error}</div>}
    <div className="sw-manual-actions">
      <button className="primary-button" disabled={busy || Boolean(problem)}>{busy ? <LoaderCircle className="spin" size={15} /> : <ShieldCheck size={15} />}Verify for 24 hours</button>
      <button type="button" className="secondary-button" onClick={() => setOpen(false)}>Cancel</button></div>
  </form>;
}

function VerifyPanel({ site, onVerified }) {
  const [method, setMethod] = useState(site.verification_method && !["parent", "manual"].includes(site.verification_method) ? site.verification_method : "dns");
  const [busy, setBusy] = useState(false), [result, setResult] = useState(null), [error, setError] = useState(""), [tries, setTries] = useState(0);
  const info = site.instructions || {};
  const verify = async () => {
    setBusy(true); setError(""); setResult(null);
    try { const response = await api.verifyWebsite(site.id, method); setResult(checkView(response.check)); setTries(n => n + 1); onVerified(response); }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  };
  if (!site.instructions) return null;
  const www = site.domain?.startsWith("www.") ? site.domain.slice(4) : `www.${site.domain}`;
  return <section className="panel sw-verify" aria-label="Verify ownership">
    <h2>Prove you own {site.domain}</h2>
    <p>Pick one way. It usually takes about a minute. Then press <b>{tries ? "Check again" : "Check now"}</b>.</p>
    <div className="sw-kv"><span>Your code</span><CopyValue value={site.verification_code} label="Your verification code" /></div>
    <div className="sw-tabs" role="tablist">{METHODS.map(m => <button key={m.id} role="tab" aria-selected={method === m.id}
      className={method === m.id ? "active" : ""} onClick={() => { setMethod(m.id); setResult(null); }}>{m.label}</button>)}</div>
    {method === "dns" && <ol className="sw-ol">
      <Step n={1}>Sign in where you manage your domain's DNS (your domain registrar or hosting company).</Step>
      <Step n={2}>Add a <b>TXT</b> record with this name and value:
        <div className="sw-kv"><span>Name / host</span><CopyValue value={info.dns.host} label="TXT record name" /></div>
        <div className="sw-kv"><span>Value</span><CopyValue value={info.dns.value} label="TXT record value" /></div>
        <small>If your provider asks for a name relative to your domain, use {"\u201c"}@{"\u201d"} for the main domain.</small></Step>
      <Step n={3}>Save it, wait a few minutes (DNS can be slow), then press {tries ? "Check again" : "Check now"}.</Step>
    </ol>}
    {method === "file" && <ol className="sw-ol">
      <Step n={1}>Create a plain text file with exactly this name:
        <div className="sw-kv"><span>File name</span><CopyValue value={info.file.file_name} label="Verification file name" /></div></Step>
      <Step n={2}>Put only this code inside it (nothing else):
        <div className="sw-kv"><span>File content</span><CopyValue value={info.file.content} label="Verification file content" /></div></Step>
      <Step n={3}>Upload it to the folder <code>{info.file.folder}</code> so it opens at this address:
        <div className="sw-kv"><span>Address</span><CopyValue value={info.file.url} label="Verification file address" /></div>
        <small>Your website needs working HTTPS for this method. If it does not, use the DNS method.</small></Step>
      <Step n={4}>Press {tries ? "Check again" : "Check now"}.</Step>
    </ol>}
    {method === "meta" && <ol className="sw-ol">
      <Step n={1}>Copy this tag:<div className="sw-kv"><span>Tag</span><CopyValue value={info.meta.tag} label="Verification meta tag" /></div></Step>
      <Step n={2}>Paste it inside the <code>&lt;head&gt;</code> of your home page ({info.meta.page}). If your site caches pages, clear the cache.</Step>
      <Step n={3}>Press {tries ? "Check again" : "Check now"}.</Step>
    </ol>}
    {method !== "dns" && <p className="sw-note">If <b>{site.domain}</b> and <b>{www}</b> send visitors to each other, no problem: we check both and tell you exactly what we found.</p>}
    <div className="sw-verify-actions">
      <button className="primary-button" onClick={verify} disabled={busy} data-testid="check-now">{busy ? <LoaderCircle className="spin" size={15} /> : <ShieldCheck size={15} />}{busy ? "Checking\u2026" : tries ? "Check again" : "Check now"}</button>
      {site.can_verify_manually && <ManualVerify site={site} onDone={response => { onVerified(response); }} />}
    </div>
    {error && <div className="form-error" role="alert"><ShieldAlert size={15} />{error}</div>}
    {result && <div className={`sw-result ${result.ok ? "good" : "bad"}`} role="status" data-testid="verify-result">
      <strong>{result.ok ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}{result.title}</strong>
      {!result.ok && <>
        <div className="sw-kv"><span>We expected</span><code>{result.expected}</code></div>
        <div className="sw-kv"><span>We found</span><div className="sw-found">{result.found.map((f, i) => <code key={i}>{f}</code>)}</div></div>
        {result.hint && <p>{result.hint}</p>}
        {result.suggestDns && method !== "dns" && <button className="secondary-button" onClick={() => { setMethod("dns"); setResult(null); }}>Use the DNS TXT method instead</button>}
      </>}
      {result.ok && <p>Your first scan has started. You can follow it below.</p>}
    </div>}
  </section>;
}

function MonitorTab({ site, data, refreshKey }) {
  const summary = data.summary, grade = gradeView(summary), cert = certificateView(summary?.certificate), scan = data.scan, v = verificationView(site);
  return <section className="panel sw-monitor" data-testid="monitor-tab">
    <div className="sw-monitor-grid">
      <div><span className="sw-label">Security score</span>{grade ? <span className={`sw-grade-chip big ${grade.tone}`} data-testid="monitor-grade"><b>{grade.grade}</b> {grade.label}</span> : <span className="sw-muted">{"\u2014"}</span>}
        {grade?.note && <small>{grade.note}</small>}</div>
      <div><span className="sw-label">Last scan</span><strong>{when(scan.ended_at || scan.requested_at)}</strong>
        <small>{scanView(scan).label}{scanDuration(scan) ? ` \u00b7 took ${scanDuration(scan)}` : ""}</small></div>
      <div><span className="sw-label">Certificate</span><strong className={`tone-${cert.tone}`}>{cert.text}</strong></div>
      <div><span className="sw-label">Ownership</span><strong>{v.label}</strong><small>{site.verification_status === "verified" ? "Scans can run." : "Scans are paused."}</small></div>
      <div><span className="sw-label">Open ports</span><strong>{data.ports.length}</strong></div>
      <div><span className="sw-label">Findings</span><strong>{summary ? `${summary.confirmed} confirmed, ${summary.needs_checking} to check` : "\u2014"}</strong></div>
      {site.uptime && <div><span className="sw-label">Uptime</span><strong className={`tone-${uptimeView(site.uptime).tone}`} data-testid="monitor-uptime">{uptimeView(site.uptime).label}</strong>
        <small>{uptimeView(site.uptime).text}</small></div>}
      {site.schedule && <div><span className="sw-label">Next automatic scan</span><strong>{site.schedule.next_scan_at ? when(site.schedule.next_scan_at) : "\u2014"}</strong>
        <small data-testid="schedule-text">{scheduleText(site.schedule)}</small></div>}
    </div>
    <TrendChart siteId={site.id} refreshKey={refreshKey} />
  </section>;
}

function ScanTabs({ site, scan, plan }) {
  const [tab, setTab] = useState(() => (typeof window !== "undefined" && window.location.hash.includes("/findings/") ? "vulnerabilities" : "monitor"));   // an alert email links straight to the finding
  const [version, setVersion] = useState(0);
  const { data, error } = useScanDetail(site.id, scan, version);
  const refresh = () => setVersion(v => v + 1);
  if (error) return <div className="form-error" role="alert"><AlertTriangle size={15} />{error}</div>;
  if (!data) return scan.status === "queued" ? null : <div className="loading-rows"><div /><div /></div>;
  const running = ["queued", "running"].includes(data.scan.status);
  return <>
    <ScanBanner data={data} running={running} />
    <div className="sw-tabs sw-site-tabs" role="tablist" aria-label="Website sections">{TABS.map(t =>
      <button key={t.id} role="tab" aria-selected={tab === t.id} data-testid={`tab-${t.id}`} className={tab === t.id ? "active" : ""} onClick={() => setTab(t.id)}>{t.label}</button>)}</div>
    {tab === "monitor" && <MonitorTab site={site} data={data} refreshKey={scan.id} />}
    {tab === "detect" && <DetectSections data={data} running={running} />}
    {tab === "vulnerabilities" && <><ChangesPanel site={site} scan={scan} data={data} /><FindingsPanel findings={data.findings || []} result={data.scan.result || {}} running={running} site={site} onChanged={refresh} /></>}
    {tab === "report" && <ReportView site={site} data={data} plan={plan} scan={scan} />}
  </>;
}

function ScanPanel({ site, scans, onScanNow, busy, limitNote, onUpgrade, plan }) {
  const latest = scans[0];
  const view = scanView(latest);
  const scanNow = site.scan_now;
  const showButton = site.verification_status === "verified" && scanNow;
  const limitReached = scanNow?.reason === "limit_reached";
  return <section className="panel sw-scan" aria-label="Scans">
    <div className="sw-scan-head"><h2>Scans</h2>
      {showButton && <div className="sw-scan-action">
        <span className="sw-remaining" data-testid="scans-left">{scanNowText(scanNow)}</span>
        <button className="primary-button" onClick={onScanNow} disabled={busy || !scanNow.allowed}>
          {busy ? <LoaderCircle className="spin" size={15} /> : <RefreshCw size={15} />}Scan now</button></div>}
    </div>
    {(limitNote || (limitReached && scanNow.message)) && <div className="sw-limit" role="status" data-testid="scan-limit-message">
      <ArrowUpRight size={16} /><span>{limitNote || scanNow.message}</span>
      {!site.test_target && <button className="secondary-button" onClick={onUpgrade}>Upgrade</button>}</div>}
    <div className="sw-scan-now"><Badge tone={view.tone}>{view.label}</Badge>
      {view.active && <LoaderCircle className="spin" size={15} />}
      <span data-testid="scan-status">{view.active || !["completed", "incomplete", "refused"].includes(latest?.status) ? view.text : ""}</span></div>
    {latest && <ScanTabs site={site} scan={latest} plan={plan} />}
    {scans.length > 1 && <ul className="sw-history">{scans.slice(1).map(scan => {
      const v = scanView(scan);
      return <li key={scan.id}><Badge tone={v.tone}>{v.label}</Badge><span>{when(scan.ended_at || scan.requested_at)}</span></li>;
    })}</ul>}
  </section>;
}

function WebsiteDetail({ id, onBack, onChanged, onRemoved, onUpgrade, plan }) {
  const [site, setSite] = useState(null), [scans, setScans] = useState([]), [error, setError] = useState("");
  const [removing, setRemoving] = useState(false), [scanBusy, setScanBusy] = useState(false), [limitNote, setLimitNote] = useState("");
  const alive = useRef(true);
  const load = useCallback(async () => {
    const [detail, history] = await Promise.all([api.website(id), api.websiteScans(id)]);
    if (alive.current) { setSite(detail); setScans(history); }
    return history;
  }, [id]);
  useEffect(() => {
    alive.current = true;
    load().catch(e => alive.current && setError(e.message));
    return () => { alive.current = false; };
  }, [load]);
  // Follow a running scan.
  const active = scans[0] && ["queued", "running"].includes(scans[0].status);
  useEffect(() => {
    if (!active) return undefined;
    const timer = setInterval(() => load().catch(() => {}), 2000);
    return () => clearInterval(timer);
  }, [active, load]);
  const scanNow = async () => {
    setScanBusy(true); setLimitNote(""); setError("");
    try { await api.scanNow(id); await load(); }
    catch (err) {
      if (isFriendlyLimit(err)) { setLimitNote(err.message); await load().catch(() => {}); }  // a limit is a normal answer, not a failure
      else setError(err.message);
    } finally { setScanBusy(false); }
  };
  if (error) return <div className="form-error" role="alert"><ShieldAlert size={15} />{error}</div>;
  if (!site) return <div className="loading-rows"><div /><div /><div /></div>;
  const v = verificationView(site);
  return <>
    <button className="text-button sw-back" onClick={onBack}>← All websites</button>
    <Heading eyebrow="WEBSITE" title={site.domain || site.name} text={v.text}
      action={<div className="sw-heading-actions">{site.test_target && <Badge tone="info">Test target</Badge>}
        {!site.test_target && <Badge tone={v.tone}>{v.label}</Badge>}
        {site.manual_verification && <span className="sw-muted" data-testid="manual-detail" title={site.manual_verification.reason}>
          {site.manual_verification.owner_name ? `Owner: ${site.manual_verification.owner_name} \u00b7 Consent: ${site.manual_verification.consent_label || "\u2014"} \u00b7 ` : ""}Reason: {site.manual_verification.reason}</span>}
        <button className="secondary-button sw-remove-button" onClick={() => setRemoving(true)}>Remove website</button></div>} />
    {removing && <RemoveDialog site={site} onClose={() => setRemoving(false)} onRemoved={onRemoved} />}
    {site.verification_status === "lost" && site.verification_result?.message && <div className="sw-result bad" role="alert">
      <strong><AlertTriangle size={16} />Scans are paused</strong><p>{site.verification_result.message}</p>
      {site.verification_result.hint && <p>{site.verification_result.hint}</p>}</div>}
    {site.verification_status !== "verified" && <VerifyPanel site={site} onVerified={() => { load(); onChanged(); }} />}
    <AuditHistory siteId={site.id} refreshKey={`${site.verification_status}-${site.verified_at}-${scans[0]?.id}`} />
    <ScanPanel site={site} scans={scans} onScanNow={scanNow} busy={scanBusy} limitNote={limitNote} onUpgrade={onUpgrade} plan={plan} />
  </>;
}

function WebsitesView({ websites, plan, loading, openId, onOpen, onAdded, onLimit, onChanged, onRemoved, onUpgrade }) {
  const [removing, setRemoving] = useState(null);
  if (openId) return <WebsiteDetail id={openId} onBack={() => onOpen(null)} onChanged={onChanged} onRemoved={onRemoved} onUpgrade={onUpgrade} plan={plan} />;
  return <>
    {removing && <RemoveDialog site={removing} onClose={() => setRemoving(null)} onRemoved={result => { setRemoving(null); onRemoved(result); }} />}
    <Heading eyebrow="WEBSITES" title="Websites" text="Add a website, prove you own it, and we scan it automatically." />
    <AddWebsite plan={plan} count={websites.length} onAdded={site => { onAdded(site); onOpen(site.id); }} onLimit={onLimit} />
    <section className="panel table-panel"><div className="table-scroll"><table>
      <thead><tr><th>Website</th><th>Ownership</th><th>Last scan</th><th>Added</th><th /></tr></thead>
      <tbody>{loading ? <tr><td colSpan={5}><div className="loading-rows"><div /><div /></div></td></tr>
        : websites.length ? websites.map(site => {
          const v = verificationView(site), s = scanView(site.latest_scan);
          return <tr key={site.id}><td><div className="website-cell"><div className="site-icon"><Globe2 size={16} /></div><strong>{site.domain || site.name}</strong>
              {site.test_target && <Badge tone="info">Test target</Badge>}</div></td>
            <td><Badge tone={v.tone}>{v.label}</Badge></td><td><Badge tone={s.tone}>{s.label}</Badge></td><td>{when(site.created_at)}</td>
            <td className="sw-row-actions"><button className="secondary-button" onClick={() => onOpen(site.id)}>{site.verification_status === "verified" ? "Open" : "Verify"}</button>
              <button className="secondary-button sw-remove-button" aria-label={`Remove ${site.domain || site.name}`} onClick={() => setRemoving(site)}>Remove</button></td></tr>;
        }) : <tr><td colSpan={5}><div className="empty-state"><div className="empty-icon"><Globe2 size={22} /></div>
          <strong>No websites yet</strong><p>Type your website address above and click “Add website”.</p></div></td></tr>}</tbody>
    </table></div></section>
  </>;
}

// ---- Settings ------------------------------------------------------------------------------------

function SettingsView({ account, plan, alertFocus }) {
  const [current, setCurrent] = useState(""), [next, setNext] = useState("");
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [done, setDone] = useState("");
  const submit = async e => {
    e.preventDefault(); setError(""); setDone("");
    const problems = passwordHint(next, account.email);
    if (problems.length) { setError("Choose a stronger password: " + problems.join(", ") + "."); return; }
    setBusy(true);
    try { await api.changePassword(current, next); setCurrent(""); setNext(""); setDone("Password changed. Other signed-in devices have been signed out."); }
    catch (err) { setError(err.message); } finally { setBusy(false); }
  };
  return <>
    <Heading eyebrow="SETTINGS" title="Settings" text="Your account and plan." />
    <div className="sw-settings">
      <section className="panel sw-box"><h2>Account</h2>
        <p><span>Name</span><b>{account.full_name}</b></p><p><span>Email</span><b>{account.email}</b></p></section>
      <section className="panel sw-box" id="plan" aria-label="Your plan"><h2>Your plan: {plan?.label || account.plan}</h2>
        {plan && <ul className="sw-plan">
          <li>Up to <b>{plan.max_websites}</b> websites ({plan.websites_used} used)</li>
          <li>Automatic scan: <b>{plan.automatic_scan}</b></li>
          <li>Scan history kept for <b>{plan.history_days} days</b></li>
        </ul>}
        <div className="sw-upgrade-note"><ArrowUpRight size={16} /><span>Pro (25 websites, daily scans, PDF reports) and Business plans are coming soon.
          Until then, contact us and we will upgrade your account.</span></div></section>
      <AlertSettings focus={alertFocus} />
      <form className="panel sw-box" onSubmit={submit} aria-label="Change password"><h2>Change password</h2>
        <label className="form-field"><span>Current password</span><input type="password" value={current} onChange={e => setCurrent(e.target.value)} autoComplete="current-password" required /></label>
        <label className="form-field"><span>New password</span><input type="password" value={next} onChange={e => setNext(e.target.value)} autoComplete="new-password" required placeholder="At least 12 characters" /></label>
        <button className="primary-button" disabled={busy}>{busy && <LoaderCircle className="spin" size={14} />}Change password</button>
        {error && <div className="form-error" role="alert"><ShieldAlert size={15} />{error}</div>}
        {done && <p className="sw-done" role="status"><CheckCircle2 size={15} />{done}</p>}
      </form>
    </div>
  </>;
}

// ---- Admin ---------------------------------------------------------------------------------------

function AdminView({ account }) {
  const [data, setData] = useState(null), [error, setError] = useState(""), [busy, setBusy] = useState(false);
  const load = useCallback(() => api.adminUsers().then(setData).catch(e => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);
  const act = async action => { setBusy(true); setError(""); try { await action(); await load(); } catch (e) { setError(e.message); } finally { setBusy(false); } };
  return <>
    <Heading eyebrow="ADMIN" title="Users" text="Change plans and disable accounts. Every change is recorded in the audit log." />
    <WorkersPanel />
    {error && <div className="form-error" role="alert"><ShieldAlert size={15} />{error}</div>}
    <section className="panel table-panel"><div className="table-scroll"><table>
      <thead><tr><th>User</th><th>Role</th><th>Plan</th><th>Websites</th><th>Email confirmed</th><th>Status</th><th /></tr></thead>
      <tbody>{!data ? <tr><td colSpan={7}><div className="loading-rows"><div /><div /></div></td></tr> : data.users.map(user =>
        <tr key={user.id}><td><div className="cell-primary">{user.full_name}</div><div className="cell-secondary">{user.email}</div></td>
          <td>{user.role}</td>
          <td><select aria-label={`Plan for ${user.email}`} value={user.plan} disabled={busy} onChange={e => act(() => api.setUserPlan(user.id, e.target.value))}>
            {data.plans.map(p => <option key={p} value={p}>{p}</option>)}</select></td>
          <td>{user.websites}</td><td>{user.email_verified ? "Yes" : "Not yet"}</td>
          <td><Badge tone={user.is_active ? "good" : "bad"}>{user.is_active ? "Active" : "Disabled"}</Badge></td>
          <td>{user.id !== account.id && <button className="secondary-button" disabled={busy}
            onClick={() => act(() => api.setUserActive(user.id, !user.is_active))}>{user.is_active ? "Disable" : "Enable"}</button>}</td></tr>)}</tbody>
    </table></div></section>
  </>;
}

// ---- Shell ---------------------------------------------------------------------------------------

export default function Console({ account, onLogout }) {
  const staff = isStaff(account);
  const linked = useMemo(() => parseHash(typeof window !== "undefined" ? window.location.hash : ""), []);   // links in alert emails
  const [page, setPage] = useState(linked?.page || "dashboard"), [openId, setOpenId] = useState(linked?.openId ?? null);
  const [alertFocus] = useState(linked?.alert || null);
  const [websites, setWebsites] = useState([]), [plan, setPlan] = useState(null), [loading, setLoading] = useState(true);
  const [error, setError] = useState(""), [limit, setLimit] = useState(null), [notice, setNotice] = useState("");
  const load = useCallback(async () => {
    setError("");
    try {
      const [rows, myPlan] = await Promise.all([api.myWebsites(), api.myPlan()]);
      setWebsites(rows); setPlan(myPlan);
    } catch (e) { setError(e.message); } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); const timer = setInterval(load, 30000); return () => clearInterval(timer); }, [load]);

  const go = id => { setPage(id); setOpenId(null); setError(""); setNotice(""); };
  useEffect(() => {
    if (!notice) return undefined;
    const timer = setTimeout(() => setNotice(""), 6000);
    return () => clearTimeout(timer);
  }, [notice]);
  const removed = result => {
    setOpenId(null); setLimit(null); setNotice(result.message || "Website removed.");
    setWebsites(rows => rows.filter(site => site.domain !== result.domain));
    load();
  };
  const nav = useMemo(() => [...MAIN_NAV, ...(account.role === "admin" ? [{ id: "admin", label: "Admin", icon: Users }] : [])], [account.role]);
  const title = nav.find(item => item.id === page)?.label || "Dashboard";

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand-lockup"><div className="brand-mark"><ShieldCheck size={22} strokeWidth={2.2} /></div>
        <div><div className="brand-name">SNWebShield</div><div className="brand-caption">WEBSITE SECURITY</div></div></div>
      <nav className="main-nav" aria-label="Main navigation">{nav.map(({ id, label, icon: Icon }) =>
        <button key={id} className={`nav-item ${page === id ? "active" : ""}`} onClick={() => go(id)}><Icon size={18} /><span>{label}</span>
          {id === "websites" && <span className="nav-count">{websites.length}</span>}</button>)}</nav>
      <div className="sidebar-bottom"><div className="profile-row"><div className="profile-avatar">{(account.full_name || "S")[0].toUpperCase()}</div>
        <div className="profile-copy"><strong>{account.full_name}</strong><span>{account.email}</span></div></div></div>
    </aside>
    <main className="main-panel">
      <header className="topbar">
        <div className="breadcrumb"><span>SNWebShield</span><ChevronRight size={14} /><strong>{title}</strong></div>
        <div className="topbar-actions">
          <button className="icon-button" aria-label="Refresh" onClick={load}><RefreshCw size={17} /></button>
          <button type="button" className="logout-button" onClick={onLogout}><LogOut size={15} /><span>Sign out</span></button>
        </div>
      </header>
      <div className="content-area"><ErrorBoundary key={`${page}-${openId}`}>
        {error && <div className="alert alert-error" role="alert"><ShieldAlert size={18} /><div><strong>Something went wrong</strong><span>{error}</span></div>
          <button className="alert-action" onClick={load}>Try again</button></div>}
        {notice && <div className="sw-notice" role="status" data-testid="notice"><CheckCircle2 size={16} />{notice}
          <button className="icon-button" aria-label="Dismiss" onClick={() => setNotice("")}><X size={14} /></button></div>}
        <UpgradeNotice detail={limit} onClose={() => setLimit(null)} onUpgrade={() => { setLimit(null); go("settings"); }} />
        {page === "dashboard" && <DashboardView account={account} websites={websites} plan={plan} loading={loading}
          onOpen={id => { setPage("websites"); setOpenId(id); }} onAdd={() => go("websites")} />}
        {page === "websites" && <WebsitesView websites={websites} plan={plan} loading={loading} openId={openId} onOpen={setOpenId}
          onAdded={site => { setWebsites(rows => [site, ...rows]); load(); }} onLimit={setLimit} onChanged={load} onRemoved={removed} onUpgrade={() => go("settings")} />}
        {page === "settings" && <SettingsView account={account} plan={plan} alertFocus={alertFocus} />}
        {page === "admin" && account.role === "admin" && <AdminView account={account} />}
        </ErrorBoundary>
        <footer className="content-footer"><span>SNWebShield</span><span><Shield size={13} /> We only scan websites whose ownership you have verified.</span></footer>
      </div>
    </main>
  </div>;
}
