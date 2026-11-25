import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, AlertTriangle, ArrowUpRight, Bug, Check, CheckCircle2, ChevronRight, Copy, FileText, Globe2,
  LayoutDashboard, LoaderCircle, LogOut, Plus, RefreshCw, Settings2, Shield, ShieldAlert, ShieldCheck, Users,
  UserCheck, X,
} from "lucide-react";
import { api } from "./lib/api.js";
import { METHODS, checkView, isStaff, passwordHint, planLimit, scanView, verificationView } from "./lib/account.js";
import MonitoringPage from "./MonitoringPage.jsx";
import AssessmentsPage from "./AssessmentsPage.jsx";
import FindingsPage from "./FindingsPage.jsx";
import VulnerabilitiesPage from "./VulnerabilitiesPage.jsx";
import WorkbenchPage from "./WorkbenchPage.jsx";
import ReportsPage from "./ReportsPage.jsx";
import RemediationPage from "./RemediationPage.jsx";
import LifecyclePage from "./LifecyclePage.jsx";
import "./console.css";

const MAIN_NAV = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "websites", label: "Websites", icon: Globe2 },
  { id: "settings", label: "Settings", icon: Settings2 },
];
const LEGACY_NAV = [
  { id: "legacy-monitoring", label: "Monitoring", icon: Activity },
  { id: "legacy-assessments", label: "Assessments", icon: FileText },
  { id: "legacy-vulnerabilities", label: "Vulnerabilities", icon: Bug },
  { id: "legacy-workbench", label: "Analyst workbench", icon: UserCheck },
  { id: "legacy-reports", label: "VAPT reports", icon: FileText },
  { id: "legacy-remediation", label: "Remediation", icon: RefreshCw },
  { id: "legacy-findings", label: "Findings", icon: ShieldAlert },
  { id: "legacy-lifecycle", label: "Website lifecycle", icon: Shield },
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
          <div className="sw-card-top"><div className="site-icon"><Globe2 size={17} /></div><strong>{site.domain || site.name}</strong><ChevronRight size={16} /></div>
          <div className="sw-card-row"><span>Ownership</span><Badge tone={v.tone}>{v.label}</Badge></div>
          <div className="sw-card-row"><span>Last scan</span><Badge tone={s.tone}>{s.label}</Badge></div>
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

function VerifyPanel({ site, onVerified }) {
  const [method, setMethod] = useState(site.verification_method && site.verification_method !== "parent" ? site.verification_method : "dns");
  const [busy, setBusy] = useState(false), [result, setResult] = useState(null), [error, setError] = useState("");
  const info = site.instructions || {};
  const verify = async () => {
    setBusy(true); setError(""); setResult(null);
    try { const response = await api.verifyWebsite(site.id, method); setResult(checkView(response.check)); onVerified(response); }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  };
  if (!site.instructions) return null;
  return <section className="panel sw-verify" aria-label="Verify ownership">
    <h2>Prove you own {site.domain}</h2>
    <p>Pick one method. It usually takes about a minute. Your code: <code>{site.verification_code}</code></p>
    <div className="sw-tabs" role="tablist">{METHODS.map(m => <button key={m.id} role="tab" aria-selected={method === m.id}
      className={method === m.id ? "active" : ""} onClick={() => { setMethod(m.id); setResult(null); }}>{m.label}</button>)}</div>
    {method === "dns" && <div className="sw-steps">
      <p>At your DNS provider, add a <b>TXT</b> record:</p>
      <div className="sw-kv"><span>Name / host</span><CopyValue value={info.dns.host} label="TXT record name" /></div>
      <div className="sw-kv"><span>Value</span><CopyValue value={info.dns.value} label="TXT record value" /></div>
      <small>{info.dns.note} If your provider asks for the host relative to your domain, use “@” for the main domain.</small>
    </div>}
    {method === "file" && <div className="sw-steps">
      <p>Create a plain text file at this exact address:</p>
      <div className="sw-kv"><span>Address</span><CopyValue value={info.file.url} label="Verification file address" /></div>
      <div className="sw-kv"><span>File content</span><CopyValue value={info.file.content} label="Verification file content" /></div>
      <small>{info.file.note}</small>
    </div>}
    {method === "meta" && <div className="sw-steps">
      <p>Add this tag inside the <code>&lt;head&gt;</code> of {info.meta.page}:</p>
      <div className="sw-kv"><span>Tag</span><CopyValue value={info.meta.tag} label="Verification meta tag" /></div>
      <small>{info.meta.note}</small>
    </div>}
    <button className="primary-button" onClick={verify} disabled={busy}>{busy ? <LoaderCircle className="spin" size={15} /> : <ShieldCheck size={15} />}{busy ? "Checking…" : "Verify now"}</button>
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

function ScanPanel({ scans }) {
  const latest = scans[0];
  const view = scanView(latest);
  return <section className="panel sw-scan" aria-label="Scans">
    <h2>Scans</h2>
    <div className="sw-scan-now"><Badge tone={view.tone}>{view.label}</Badge>
      {view.active && <LoaderCircle className="spin" size={15} />}<span data-testid="scan-status">{view.text}</span></div>
    {latest?.resolved_ip && <details><summary>Technical details</summary>
      <p>Scanned address: <code>{latest.resolved_ip}</code> · started {when(latest.started_at)} · finished {when(latest.ended_at)}</p></details>}
    {scans.length > 1 && <ul className="sw-history">{scans.slice(1).map(scan => {
      const v = scanView(scan);
      return <li key={scan.id}><Badge tone={v.tone}>{v.label}</Badge><span>{when(scan.ended_at || scan.requested_at)}</span></li>;
    })}</ul>}
  </section>;
}

function WebsiteDetail({ id, onBack, onChanged }) {
  const [site, setSite] = useState(null), [scans, setScans] = useState([]), [error, setError] = useState("");
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
    const timer = setInterval(() => load().catch(() => {}), 3000);
    return () => clearInterval(timer);
  }, [active, load]);
  if (error) return <div className="form-error" role="alert"><ShieldAlert size={15} />{error}</div>;
  if (!site) return <div className="loading-rows"><div /><div /><div /></div>;
  const v = verificationView(site);
  return <>
    <button className="text-button sw-back" onClick={onBack}>← All websites</button>
    <Heading eyebrow="WEBSITE" title={site.domain || site.name} text={v.text} action={<Badge tone={v.tone}>{v.label}</Badge>} />
    {site.verification_status === "lost" && site.verification_result?.message && <div className="sw-result bad" role="alert">
      <strong><AlertTriangle size={16} />Scans are paused</strong><p>{site.verification_result.message}</p>
      {site.verification_result.hint && <p>{site.verification_result.hint}</p>}</div>}
    {site.verification_status !== "verified" && <VerifyPanel site={site} onVerified={() => { load(); onChanged(); }} />}
    <ScanPanel scans={scans} />
  </>;
}

function WebsitesView({ websites, plan, loading, openId, onOpen, onAdded, onLimit, onChanged }) {
  if (openId) return <WebsiteDetail id={openId} onBack={() => onOpen(null)} onChanged={onChanged} />;
  return <>
    <Heading eyebrow="WEBSITES" title="Websites" text="Add a website, prove you own it, and we scan it automatically." />
    <AddWebsite plan={plan} count={websites.length} onAdded={site => { onAdded(site); onOpen(site.id); }} onLimit={onLimit} />
    <section className="panel table-panel"><div className="table-scroll"><table>
      <thead><tr><th>Website</th><th>Ownership</th><th>Last scan</th><th>Added</th><th /></tr></thead>
      <tbody>{loading ? <tr><td colSpan={5}><div className="loading-rows"><div /><div /></div></td></tr>
        : websites.length ? websites.map(site => {
          const v = verificationView(site), s = scanView(site.latest_scan);
          return <tr key={site.id}><td><div className="website-cell"><div className="site-icon"><Globe2 size={16} /></div><strong>{site.domain || site.name}</strong></div></td>
            <td><Badge tone={v.tone}>{v.label}</Badge></td><td><Badge tone={s.tone}>{s.label}</Badge></td><td>{when(site.created_at)}</td>
            <td><button className="secondary-button" onClick={() => onOpen(site.id)}>{site.verification_status === "verified" ? "Open" : "Verify"}</button></td></tr>;
        }) : <tr><td colSpan={5}><div className="empty-state"><div className="empty-icon"><Globe2 size={22} /></div>
          <strong>No websites yet</strong><p>Type your website address above and click “Add website”.</p></div></td></tr>}</tbody>
    </table></div></section>
  </>;
}

// ---- Settings ------------------------------------------------------------------------------------

function SettingsView({ account, plan }) {
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
  const [page, setPage] = useState("dashboard"), [openId, setOpenId] = useState(null);
  const [websites, setWebsites] = useState([]), [plan, setPlan] = useState(null), [loading, setLoading] = useState(true);
  const [legacySites, setLegacySites] = useState([]), [clients, setClients] = useState([]);
  const [error, setError] = useState(""), [limit, setLimit] = useState(null);
  const load = useCallback(async () => {
    setError("");
    try {
      const [rows, myPlan] = await Promise.all([api.myWebsites(), api.myPlan()]);
      setWebsites(rows); setPlan(myPlan);
    } catch (e) { setError(e.message); } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); const timer = setInterval(load, 30000); return () => clearInterval(timer); }, [load]);
  useEffect(() => {
    if (!staff || !page.startsWith("legacy-")) return;
    api.allWebsites().then(setLegacySites).catch(e => setError(e.message));
    if (page === "legacy-findings") api.getClients().then(setClients).catch(() => setClients([]));
  }, [staff, page]);

  const go = id => { setPage(id); setOpenId(null); setError(""); };
  const nav = useMemo(() => [...MAIN_NAV, ...(account.role === "admin" ? [{ id: "admin", label: "Admin", icon: Users }] : [])], [account.role]);
  const title = [...nav, ...LEGACY_NAV].find(item => item.id === page)?.label || "Dashboard";

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand-lockup"><div className="brand-mark"><ShieldCheck size={22} strokeWidth={2.2} /></div>
        <div><div className="brand-name">SNWebShield</div><div className="brand-caption">WEBSITE SECURITY</div></div></div>
      <nav className="main-nav" aria-label="Main navigation">{nav.map(({ id, label, icon: Icon }) =>
        <button key={id} className={`nav-item ${page === id ? "active" : ""}`} onClick={() => go(id)}><Icon size={18} /><span>{label}</span>
          {id === "websites" && <span className="nav-count">{websites.length}</span>}</button>)}</nav>
      {staff && <>
        <div className="nav-label tools-label">EARLIER WORKFLOW · READ-ONLY</div>
        <nav className="main-nav" aria-label="Legacy pages">{LEGACY_NAV.map(({ id, label, icon: Icon }) =>
          <button key={id} className={`nav-item ${page === id ? "active" : ""}`} onClick={() => go(id)}><Icon size={18} /><span>{label}</span></button>)}</nav>
      </>}
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
      <div className="content-area">
        {error && <div className="alert alert-error" role="alert"><ShieldAlert size={18} /><div><strong>Something went wrong</strong><span>{error}</span></div>
          <button className="alert-action" onClick={load}>Try again</button></div>}
        <UpgradeNotice detail={limit} onClose={() => setLimit(null)} onUpgrade={() => { setLimit(null); go("settings"); }} />
        {page === "dashboard" && <DashboardView account={account} websites={websites} plan={plan} loading={loading}
          onOpen={id => { setPage("websites"); setOpenId(id); }} onAdd={() => go("websites")} />}
        {page === "websites" && <WebsitesView websites={websites} plan={plan} loading={loading} openId={openId} onOpen={setOpenId}
          onAdded={site => { setWebsites(rows => [site, ...rows]); load(); }} onLimit={setLimit} onChanged={load} />}
        {page === "settings" && <SettingsView account={account} plan={plan} />}
        {page === "admin" && account.role === "admin" && <AdminView account={account} />}
        {staff && page.startsWith("legacy-") && <div className="sw-legacy-note"><Shield size={15} />Earlier analyst workflow: read-only. Nothing can be started from these pages.</div>}
        {staff && page === "legacy-monitoring" && <MonitoringPage websites={legacySites} />}
        {staff && page === "legacy-assessments" && <AssessmentsPage websites={legacySites} />}
        {staff && page === "legacy-vulnerabilities" && <VulnerabilitiesPage websites={legacySites} onOpenAssessment={() => go("legacy-assessments")} />}
        {staff && page === "legacy-workbench" && <WorkbenchPage websites={legacySites} />}
        {staff && page === "legacy-reports" && <ReportsPage websites={legacySites} />}
        {staff && page === "legacy-remediation" && <RemediationPage websites={legacySites} />}
        {staff && page === "legacy-findings" && <FindingsPage clients={clients} websites={legacySites} onOpenAssessment={() => go("legacy-assessments")} />}
        {staff && page === "legacy-lifecycle" && <LifecyclePage websites={legacySites} onNavigate={target => go(`legacy-${target}`)} />}
        <footer className="content-footer"><span>SNWebShield</span><span><Shield size={13} /> We only scan websites whose ownership you have verified.</span></footer>
      </div>
    </main>
  </div>;
}
