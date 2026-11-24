import React, { useState, useEffect, useCallback, useMemo, useRef } from "react";
import LoginPage from "./LoginPage.jsx";
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  Bell,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Clock3,
  Command,
  ExternalLink,
  FileText,
  Globe2,
  LayoutDashboard,
  LoaderCircle,
  LogOut,
  ClipboardCheck,
  Plus,
  RefreshCw,
  Search,
  Server,
  Settings2,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Bug,
  Users,
  UserCheck,
  X,
} from "lucide-react";
import { api, API_BASE_URL } from "./lib/api.js";
import AuthorizationPage from "./AuthorizationPage.jsx";
import MonitoringPage from "./MonitoringPage.jsx";
import AssessmentsPage from "./AssessmentsPage.jsx";
import FindingsPage from "./FindingsPage.jsx";
import VulnerabilitiesPage from "./VulnerabilitiesPage.jsx";
import WorkbenchPage from "./WorkbenchPage.jsx";
import ReportsPage from "./ReportsPage.jsx";
import RemediationPage from "./RemediationPage.jsx";
 

const NAV_ITEMS = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "clients", label: "Clients", icon: Users },
  { id: "websites", label: "Websites", icon: Globe2 },
  { id: "authorizations", label: "Authorizations", icon: ClipboardCheck },
  { id: "monitoring", label: "Monitoring", icon: Activity },
  { id: "assessments", label: "Assessments", icon: FileText },
  { id: "vulnerabilities", label: "Vulnerabilities", icon: Bug },
  { id: "workbench", label: "Analyst workbench", icon: UserCheck },
  { id: "reports", label: "VAPT reports", icon: FileText },
  { id: "remediation", label: "Remediation", icon: RefreshCw },
  { id: "findings", label: "Findings", icon: ShieldAlert },
];

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "—"
    : new Intl.DateTimeFormat("en-IN", { day: "2-digit", month: "short", year: "numeric" }).format(date);
}

function initials(value = "SN") {
  return value
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("") || "SN";
}

function Dashboard({ admin, onLogout }) {
  const [activePage, setActivePage] = useState("overview");
  const [assessmentToOpen, setAssessmentToOpen] = useState(null);
  const [clients, setClients] = useState([]);
  const [websites, setWebsites] = useState([]);
  const [authorizationSummary, setAuthorizationSummary] = useState(null);
  const dataRequest = useRef(0);
  const [apiState, setApiState] = useState("checking");
  const [loading, setLoading] = useState(true);
  const [pageError, setPageError] = useState("");
  const [notice, setNotice] = useState("");
  const [modal, setModal] = useState(null);
  const [search, setSearch] = useState("");

  const loadData = useCallback(async () => {
    const requestId = ++dataRequest.current;
    setLoading(true);
    setPageError("");
    try {
      const [health, clientRows, websiteRows, summary] = await Promise.all([
        api.health(),
        api.getClients(),
        api.getWebsites(),
        api.getAuthorizationSummary(),
      ]);
      if (requestId !== dataRequest.current) return;
      setAuthorizationSummary(summary);
      setApiState(health?.status === "ok" ? "online" : "unknown");
      setClients(Array.isArray(clientRows) ? clientRows : []);
      setWebsites(Array.isArray(websiteRows) ? websiteRows : []);
    } catch (error) {
      if (requestId !== dataRequest.current) return;
      setAuthorizationSummary(null);
      setApiState("offline");
      setPageError(error.message || "Unable to load data from the API.");
    } finally {
      if (requestId === dataRequest.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const timer = window.setInterval(loadData, 60000);
    return () => { window.clearInterval(timer); dataRequest.current += 1; };
  }, [loadData]);

  useEffect(() => {
    if (!notice) return undefined;
    const timeout = window.setTimeout(() => setNotice(""), 4200);
    return () => window.clearTimeout(timeout);
  }, [notice]);

  const websitesByClient = useMemo(() => {
    return websites.reduce((result, website) => {
      result[website.client_id] = (result[website.client_id] || 0) + 1;
      return result;
    }, {});
  }, [websites]);

  const filteredClients = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return clients;
    return clients.filter((client) => [client.company_name, client.primary_contact_name, client.email, client.industry]
      .some((value) => String(value || "").toLowerCase().includes(query)));
  }, [clients, search]);

  const filteredWebsites = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return websites;
    return websites.filter((website) => {
      const client = clients.find((item) => item.id === website.client_id);
      return [website.name, website.url, website.platform, website.environment, client?.company_name]
        .some((value) => String(value || "").toLowerCase().includes(query));
    });
  }, [clients, search, websites]);

  const handleCreateClient = async (formData) => {
    const created = await api.createClient(formData);
    setClients((current) => [created, ...current.filter((item) => item.id !== created.id)]);
    setNotice(`Client “${created.company_name}” was registered successfully.`);
    setModal(null);
  };

  const handleCreateWebsite = async (formData) => {
    const created = await api.createWebsite(formData);
    setWebsites((current) => [created, ...current.filter((item) => item.id !== created.id)]);
    setNotice(`Website “${created.name}” was registered successfully.`);
    setModal(null);
  };

  const openCreate = (type) => {
    setModal(type);
    setPageError("");
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark"><ShieldCheck size={22} strokeWidth={2.2} /></div>
          <div>
            <div className="brand-name">SNWebShield</div>
            <div className="brand-caption">SECURITY CONSOLE</div>
          </div>
        </div>

        <div className="workspace-switcher">
          <div className="workspace-avatar">SN</div>
          <div className="workspace-copy">
            <strong>SNIT Cybersecurity</strong>
            <span>Internal workspace</span>
          </div>
          <ChevronDown size={15} />
        </div>

        <div className="nav-label">WORKSPACE</div>
        <nav className="main-nav" aria-label="Main navigation">
          {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
            <button
              className={`nav-item ${activePage === id ? "active" : ""}`}
              key={id}
              onClick={() => { setActivePage(id); setAssessmentToOpen(null); setSearch(""); setPageError(""); }}
            >
              <Icon size={18} />
              <span>{label}</span>
              {id === "clients" && <span className="nav-count">{clients.length}</span>}
              {id === "websites" && <span className="nav-count">{websites.length}</span>}
            </button>
          ))}
        </nav>

        <div className="nav-label tools-label">MANAGEMENT</div>
        <div className="nav-item nav-muted"><Activity size={18} /><span>Reports</span><span className="coming-soon">Soon</span></div>

        <div className="sidebar-bottom">
          <div className="help-card">
            <div className="help-icon"><CircleHelp size={17} /></div>
            <strong>Building securely</strong>
            <p>Assessment execution stays disabled until written authorisation is recorded.</p>
          </div>
          <div className="profile-row">
            <div className="profile-avatar">SN</div>
            <div className="profile-copy">
  <strong>{admin?.full_name || "SNIT Admin"}</strong>
  <span>{admin?.email || "Administrator"}</span>
</div>
            <Settings2 size={17} className="profile-settings" />
          </div>
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div className="breadcrumb">
  <span>Workspace</span>
  <ChevronRight size={14} />
  <strong>
    {{
      overview: "Overview",
      clients: "Clients",
      websites: "Websites",
      authorizations: "Authorizations",
      monitoring: "Monitoring",
      assessments: "Assessments",
      vulnerabilities: "Vulnerabilities",
      workbench: "Analyst workbench",
      reports: "VAPT reports",
      remediation: "Remediation and retesting",
      findings: "Findings",
    }[activePage] || "Overview"}
  </strong>
</div>
          <div className="topbar-actions">
            <div className={`api-indicator ${apiState}`}><span className="status-dot" />{apiState === "online" ? "API connected" : apiState === "checking" ? "Connecting…" : "API offline"}</div>
            <button className="icon-button" aria-label="Refresh data" onClick={loadData} disabled={loading}><RefreshCw size={17} className={loading ? "spin" : ""} /></button>
            <button className="icon-button notification-button" aria-label="Notifications"><Bell size={17} /><i /></button>
            <div className="top-avatar">
  {initials(admin?.full_name || "SN")}
</div>

<button
  type="button"
  className="logout-button"
  onClick={onLogout}
>
  <LogOut size={15} />
  <span>Sign out</span>
</button>
          </div>
        </header>

        <div className="content-area">
          {pageError && (
            <div className="alert alert-error" role="alert">
              <ShieldAlert size={18} />
              <div><strong>Could not load SNWebShield data</strong><span>{pageError}</span></div>
              <button className="alert-action" onClick={loadData}>Retry</button>
            </div>
          )}

          {activePage === "overview" && (
            <OverviewPage
              clients={clients}
              websites={websites}
              authorizationSummary={authorizationSummary}
              apiState={apiState}
              websitesByClient={websitesByClient}
              loading={loading}
              onNavigate={setActivePage}
              onCreate={openCreate}
            />
          )}
          {activePage === "clients" && (
            <ClientsPage
              clients={filteredClients}
              websitesByClient={websitesByClient}
              loading={loading}
              search={search}
              onSearch={setSearch}
              onCreate={() => openCreate("client")}
            />
          )}
          {activePage === "websites" && (
            <WebsitesPage
              websites={filteredWebsites}
              clients={clients}
              loading={loading}
              search={search}
              onSearch={setSearch}
              onCreate={() => openCreate("website")}
            />
          )}
{activePage === "authorizations" && (
  <AuthorizationPage
    admin={admin}
    websites={websites}
    clients={clients}
    onNotice={setNotice}
    onDecision={loadData}
  />
)}

          {activePage === "monitoring" && <MonitoringPage websites={websites} />}
          {activePage === "assessments" && <AssessmentsPage websites={websites} initialAssessmentId={assessmentToOpen} />}
          {activePage === "vulnerabilities" && <VulnerabilitiesPage websites={websites} onOpenAssessment={id => { setAssessmentToOpen(id); setActivePage("assessments"); }} />}
          {activePage === "workbench" && <WorkbenchPage websites={websites} />}
          {activePage === "reports" && <ReportsPage websites={websites} />}
          {activePage === "remediation" && <RemediationPage websites={websites} />}
          {activePage === "findings" && <FindingsPage clients={clients} websites={websites} onOpenAssessment={id => { setAssessmentToOpen(id); setActivePage("assessments"); }} />}

          <footer className="content-footer">
            <span>SNWebShield <b>v0.1.0</b></span>
            <span><Shield size={13} /> Internal development console · No security scans are initiated from this dashboard</span>
          </footer>
        </div>
      </main>

      {modal === "client" && <ClientModal onClose={() => setModal(null)} onSubmit={handleCreateClient} />}
      {modal === "website" && <WebsiteModal clients={clients} onClose={() => setModal(null)} onSubmit={handleCreateWebsite} />}
      {notice && <div className="toast" role="status"><span className="toast-check"><Check size={15} /></span>{notice}<button onClick={() => setNotice("")} aria-label="Dismiss notification"><X size={15} /></button></div>}
    </div>
  );
}

function PageHeading({ eyebrow, title, subtitle, action }) {
  return (
    <div className="page-heading">
      <div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{subtitle}</p></div>
      {action}
    </div>
  );
}

function OverviewPage({ clients, websites, authorizationSummary, apiState, websitesByClient, loading, onNavigate, onCreate }) {
  const pendingCount = authorizationSummary?.effective_counts?.pending ?? "—";
  const recentWebsites = [...websites].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 5);

  return (
    <>
      <PageHeading
        eyebrow="OVERVIEW"
        title="Good to see you, SNIT Admin"
        subtitle="Here’s the current picture of your website security operations."
        action={<button className="primary-button" onClick={() => onCreate("client")}><Plus size={17} /> Add client</button>}
      />
      <div className="welcome-banner">
        <div className="welcome-content">
          <div className="welcome-chip"><span /> INTERNAL WORKSPACE</div>
          <h2>Manage your client websites<br />with confidence.</h2>
          <p>Keep client records, website assets and assessment readiness organised in one place.</p>
          <button className="banner-button" onClick={() => onNavigate("websites")}>View websites <ArrowUpRight size={15} /></button>
        </div>
        <div className="banner-art" aria-hidden="true">
          <div className="orbit orbit-one" /><div className="orbit orbit-two" />
          <div className="shield-orb"><ShieldCheck size={68} strokeWidth={1.35} /></div>
          <div className="mini-tag tag-one"><Globe2 size={14} /> Website assets</div>
          <div className="mini-tag tag-two"><Check size={14} /> Scope-first workflow</div>
        </div>
      </div>

      <div className="section-title-row"><div><h2>Workspace summary</h2><p>Live counts from your local API</p></div><span className="updated-label"><span /> Updated from API</span></div>
      <div className="stats-grid">
        <StatCard icon={Users} label="Total clients" value={clients.length} detail="Registered organisations" tone="blue" loading={loading} onClick={() => onNavigate("clients")} />
        <StatCard icon={Globe2} label="Registered websites" value={websites.length} detail="Client-linked assets" tone="teal" loading={loading} onClick={() => onNavigate("websites")} />
        <StatCard icon={Clock3} label="Authorisation pending" value={pendingCount} detail="Requests awaiting review" tone="amber" loading={loading} onClick={() => onNavigate("authorizations")} />
        <StatCard icon={ShieldCheck} label="API status" value={loading ? "…" : apiState === "online" ? "Online" : "Offline"} detail="FastAPI development server" tone="violet" loading={false} />
      </div>

      <div className="dashboard-grid">
        <section className="panel recent-panel">
          <div className="panel-heading"><div><h3>Recently added websites</h3><p>Your latest registered website assets</p></div><button className="text-button" onClick={() => onNavigate("websites")}>View all <ChevronRight size={15} /></button></div>
          {loading ? <LoadingRows /> : recentWebsites.length ? (
            <div className="recent-list">
              {recentWebsites.map((website) => {
                const client = clients.find((item) => item.id === website.client_id);
                return <div className="recent-row" key={website.id}><div className="site-icon"><Globe2 size={18} /></div><div className="recent-main"><strong>{website.name}</strong><span>{website.url} · {client?.company_name || `Client #${website.client_id}`}</span></div><StatusPill status={website.effective_authorisation_status || "not_requested"} /><span className="recent-date">{formatDate(website.created_at)}</span></div>;
              })}
            </div>
          ) : <EmptyState icon={Globe2} title="No websites registered yet" text="Add a client website to start building your asset inventory." action={<button className="secondary-button" onClick={() => onCreate("website")}><Plus size={15} /> Add website</button>} />}
        </section>
        <section className="panel quick-panel">
          <div className="panel-heading"><div><h3>Quick actions</h3><p>Common workspace tasks</p></div></div>
          <button className="quick-action" onClick={() => onCreate("client")}><span className="quick-icon quick-blue"><Users size={18} /></span><span><strong>Register a client</strong><small>Add a new organisation and contact</small></span><ChevronRight size={17} /></button>
          <button className="quick-action" onClick={() => onCreate("website")}><span className="quick-icon quick-teal"><Globe2 size={18} /></span><span><strong>Register a website</strong><small>Link a website to an existing client</small></span><ChevronRight size={17} /></button>
          <div className="security-note"><ShieldCheck size={17} /><span><strong>Safety by default</strong><small>Website registration does not grant testing permission or start a scan.</small></span></div>
        </section>
      </div>
    </>
  );
}

function StatCard({ icon: Icon, label, value, detail, tone, loading, onClick }) {
  const content = <><div className={`stat-icon ${tone}`}><Icon size={19} /></div><div className="stat-label">{label}</div><div className="stat-value">{loading ? <span className="skeleton-value" /> : value}</div><div className="stat-detail">{detail}</div></>;
  return onClick ? <button className="stat-card clickable" onClick={onClick}>{content}<ArrowDownRight className="stat-arrow" size={16} /></button> : <div className="stat-card">{content}</div>;
}

function ClientsPage({ clients, websitesByClient, loading, search, onSearch, onCreate }) {
  return (
    <>
      <PageHeading eyebrow="CLIENT MANAGEMENT" title="Clients" subtitle="Manage the organisations and contacts you work with." action={<button className="primary-button" onClick={onCreate}><Plus size={17} /> Add client</button>} />
      <div className="list-toolbar"><div className="search-box"><Search size={17} /><input value={search} onChange={(event) => onSearch(event.target.value)} placeholder="Search clients, contacts or email" /></div><div className="toolbar-count">{clients.length} client{clients.length === 1 ? "" : "s"}</div></div>
      <section className="panel table-panel">
        <div className="table-scroll"><table><thead><tr><th>Organisation</th><th>Primary contact</th><th>Industry</th><th>Websites</th><th>Added</th></tr></thead><tbody>
          {loading ? <TableLoading columns={5} /> : clients.length ? clients.map((client) => (
            <tr key={client.id}><td><div className="table-company"><div className="company-avatar">{initials(client.company_name)}</div><div><strong>{client.company_name}</strong><small>Client ID #{client.id}</small></div></div></td><td><div className="cell-primary">{client.primary_contact_name}</div><div className="cell-secondary">{client.email}</div></td><td>{client.industry || "—"}</td><td><span className="count-badge">{websitesByClient[client.id] || 0}</span></td><td>{formatDate(client.created_at)}</td></tr>
          )) : <tr><td colSpan="5"><EmptyState icon={Users} title="No matching clients" text="Try another search or register a new client." action={<button className="secondary-button" onClick={onCreate}><Plus size={15} /> Add client</button>} /></td></tr>}
        </tbody></table></div>
      </section>
    </>
  );
}

function WebsitesPage({ websites, clients, loading, search, onSearch, onCreate }) {
  return (
    <>
      <PageHeading eyebrow="ASSET MANAGEMENT" title="Websites" subtitle="Track website assets registered under each client." action={<button className="primary-button" onClick={onCreate}><Plus size={17} /> Add website</button>} />
      <div className="list-toolbar"><div className="search-box"><Search size={17} /><input value={search} onChange={(event) => onSearch(event.target.value)} placeholder="Search websites, domains or clients" /></div><div className="toolbar-count">{websites.length} website{websites.length === 1 ? "" : "s"}</div></div>
      <section className="panel table-panel">
        <div className="table-scroll"><table><thead><tr><th>Website</th><th>Client</th><th>Platform</th><th>Environment</th><th>Authorisation</th><th>Added</th></tr></thead><tbody>
          {loading ? <TableLoading columns={6} /> : websites.length ? websites.map((website) => {
            const client = clients.find((item) => item.id === website.client_id);
            return <tr key={website.id}><td><div className="website-cell"><div className="site-icon"><Globe2 size={17} /></div><div><strong>{website.name}</strong><a href={website.url} target="_blank" rel="noreferrer">{website.url} <ExternalLink size={11} /></a></div></div></td><td>{client?.company_name || `Client #${website.client_id}`}</td><td>{website.platform || "Not specified"}</td><td><span className="environment-pill">{website.environment}</span></td><td><StatusPill status={website.effective_authorisation_status || "not_requested"} /></td><td>{formatDate(website.created_at)}</td></tr>;
          }) : <tr><td colSpan="6"><EmptyState icon={Globe2} title="No matching websites" text="Register a website and link it to one of your clients." action={<button className="secondary-button" onClick={onCreate}><Plus size={15} /> Add website</button>} /></td></tr>}
        </tbody></table></div>
        <div className="table-footnote"><ShieldCheck size={14} /> Only registered assets are shown here. Security testing requires separate written authorisation.</div>
      </section>
    </>
  );
}

function ClientModal({ onClose, onSubmit }) {
  const [form, setForm] = useState({ company_name: "", primary_contact_name: "", email: "", phone: "", industry: "", notes: "" });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const update = (key) => (event) => setForm((current) => ({ ...current, [key]: event.target.value }));
  const submit = async (event) => {
    event.preventDefault(); setSubmitting(true); setError("");
    try {
      const payload = Object.fromEntries(Object.entries(form).map(([key, value]) => [key, value.trim() || null]));
      payload.company_name = form.company_name.trim();
      payload.primary_contact_name = form.primary_contact_name.trim();
      payload.email = form.email.trim();
      await onSubmit(payload);
    } catch (err) { setError(err.message); }
    finally { setSubmitting(false); }
  };
  return (
    <ModalShell title="Register a client" subtitle="Add an organisation and its primary contact." onClose={onClose}>
      <form onSubmit={submit} className="modal-form">
        <div className="form-grid"><FormField label="Company name" required><input autoFocus value={form.company_name} onChange={update("company_name")} placeholder="e.g. ABC Technologies Pvt. Ltd." minLength={2} maxLength={200} required /></FormField><FormField label="Primary contact name" required><input value={form.primary_contact_name} onChange={update("primary_contact_name")} placeholder="Full name" minLength={2} maxLength={150} required /></FormField><FormField label="Email address" required><input type="email" value={form.email} onChange={update("email")} placeholder="name@company.com" maxLength={320} required /></FormField><FormField label="Phone number"><input value={form.phone} onChange={update("phone")} placeholder="Optional contact number" maxLength={40} /></FormField><FormField label="Industry"><input value={form.industry} onChange={update("industry")} placeholder="e.g. Education, E-commerce" maxLength={100} /></FormField><FormField label="Internal notes" wide><textarea value={form.notes} onChange={update("notes")} placeholder="Optional notes for your team" maxLength={5000} rows={3} /></FormField></div>
        {error && <div className="form-error"><ShieldAlert size={16} />{error}</div>}
        <div className="modal-actions"><button type="button" className="secondary-button" onClick={onClose}>Cancel</button><button type="submit" className="primary-button" disabled={submitting}>{submitting ? <LoaderCircle className="spin" size={16} /> : <Plus size={16} />}{submitting ? "Saving…" : "Register client"}</button></div>
      </form>
    </ModalShell>
  );
}

function WebsiteModal({ clients, onClose, onSubmit }) {
  const [form, setForm] = useState({ client_id: clients[0]?.id ? String(clients[0].id) : "", name: "", url: "", platform: "", environment: "production", hosting_provider: "", notes: "" });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const update = (key) => (event) => setForm((current) => ({ ...current, [key]: event.target.value }));
  const submit = async (event) => {
    event.preventDefault(); setSubmitting(true); setError("");
    try {
      const payload = {
        client_id: Number(form.client_id),
        name: form.name.trim(),
        url: form.url.trim(),
        platform: form.platform.trim() || null,
        environment: form.environment,
        hosting_provider: form.hosting_provider.trim() || null,
        notes: form.notes.trim() || null,
      };
      await onSubmit(payload);
    } catch (err) { setError(err.message); }
    finally { setSubmitting(false); }
  };
  return (
    <ModalShell title="Register a website" subtitle="Add a website asset to an existing client record." onClose={onClose}>
      {clients.length === 0 ? <div className="empty-client-warning"><Users size={22} /><strong>No clients available</strong><p>Register a client first, then add its website.</p><button className="secondary-button" onClick={onClose}>Close</button></div> : (
        <form onSubmit={submit} className="modal-form">
          <div className="form-grid"><FormField label="Client" required wide><select value={form.client_id} onChange={update("client_id")} required><option value="">Select a client</option>{clients.map((client) => <option key={client.id} value={client.id}>{client.company_name} · #{client.id}</option>)}</select></FormField><FormField label="Website name" required><input autoFocus value={form.name} onChange={update("name")} placeholder="e.g. Corporate website" minLength={2} maxLength={200} required /></FormField><FormField label="Website URL" required><input type="url" value={form.url} onChange={update("url")} placeholder="https://www.example.com" required /></FormField><FormField label="Platform / CMS"><input value={form.platform} onChange={update("platform")} placeholder="WordPress, Laravel, React…" maxLength={100} /></FormField><FormField label="Environment" required><select value={form.environment} onChange={update("environment")}><option value="production">Production</option><option value="staging">Staging</option><option value="development">Development</option></select></FormField><FormField label="Hosting provider"><input value={form.hosting_provider} onChange={update("hosting_provider")} placeholder="Optional" maxLength={150} /></FormField><FormField label="Internal notes" wide><textarea value={form.notes} onChange={update("notes")} placeholder="Do not include passwords or secrets. Record scope notes only." maxLength={5000} rows={3} /></FormField></div>
          <div className="form-info"><ShieldAlert size={16} /><span>Registration records the asset only. It does not grant permission to scan or test this website.</span></div>
          {error && <div className="form-error"><ShieldAlert size={16} />{error}</div>}
          <div className="modal-actions"><button type="button" className="secondary-button" onClick={onClose}>Cancel</button><button type="submit" className="primary-button" disabled={submitting}>{submitting ? <LoaderCircle className="spin" size={16} /> : <Plus size={16} />}{submitting ? "Saving…" : "Register website"}</button></div>
        </form>
      )}
    </ModalShell>
  );
}

function ModalShell({ title, subtitle, onClose, children }) {
  useEffect(() => {
    const onKeyDown = (event) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);
  return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section className="modal-card" role="dialog" aria-modal="true" aria-labelledby="modal-title"><div className="modal-heading"><div><h2 id="modal-title">{title}</h2><p>{subtitle}</p></div><button className="icon-button" onClick={onClose} aria-label="Close dialog"><X size={19} /></button></div>{children}</section></div>;
}

function FormField({ label, required, wide, children }) {
  return <label className={`form-field ${wide ? "wide" : ""}`}><span>{label}{required && <i> *</i>}</span>{children}</label>;
}

function StatusPill({ status }) {
  const labels = { active: "Currently valid", scheduled: "Scheduled", pending: "Pending review",
    rejected: "Rejected", revoked: "Revoked", expired: "Expired",
    needs_date_review: "Dates need review", not_requested: "Not requested" };
  const value = String(status).toLowerCase();
  return <span className={`status-pill ${value}`}><span />{labels[value] || value}</span>;
}

function EmptyState({ icon: Icon, title, text, action }) {
  return <div className="empty-state"><div className="empty-icon"><Icon size={22} /></div><strong>{title}</strong><p>{text}</p>{action}</div>;
}

function LoadingRows() {
  return <div className="loading-rows"><div /><div /><div /></div>;
}

function TableLoading({ columns }) {
  return <tr><td colSpan={columns}><div className="table-loading"><LoaderCircle className="spin" size={18} />Loading records…</div></td></tr>;
}

function App() {
  const [admin, setAdmin] = useState(null);
  const [checkingSession, setCheckingSession] = useState(true);
  const [authNotice, setAuthNotice] = useState("");

  // Restore and verify an existing session when the application opens.
  useEffect(() => {
    let active = true;

    async function restoreSession() {
      if (!api.hasSession()) {
        setCheckingSession(false);
        return;
      }

      try {
        const profile = await api.getCurrentAdmin();

        if (active) {
          api.startSessionTimer();
          setAdmin(profile);
        }
      } catch (error) {
        if (active) {
          setAdmin(null);

          if (api.hasSession()) {
            setAuthNotice(
              "Unable to verify your session. Check the API connection and sign in again."
            );
          } else {
            setAuthNotice("Your session has expired. Please sign in again.");
          }
        }
      } finally {
        if (active) {
          setCheckingSession(false);
        }
      }
    }

    restoreSession();

    return () => {
      active = false;
    };
  }, []);

  // Return to login if an authenticated API request receives HTTP 401.
  useEffect(() => {
    const handleSessionExpired = () => {
      setAdmin(null);
      setAuthNotice("Your session has expired. Please sign in again.");
    };

    window.addEventListener(
      "snwebshield:session-expired",
      handleSessionExpired
    );

    return () => {
      window.removeEventListener(
        "snwebshield:session-expired",
        handleSessionExpired
      );
    };
  }, []);

  // Re-check expiry after a background tab resumes as well as on the timer.
  useEffect(() => {
    const checkExpiry = () => { if (admin && !api.hasSession()) setAdmin(null); };
    window.addEventListener("focus", checkExpiry);
    document.addEventListener("visibilitychange", checkExpiry);
    return () => {
      window.removeEventListener("focus", checkExpiry);
      document.removeEventListener("visibilitychange", checkExpiry);
    };
  }, [admin]);

  // Authenticate the administrator against FastAPI.
  const handleLogin = async (credentials) => {
    const result = await api.login(credentials);
    const profile = result.admin || await api.getCurrentAdmin();

    setAdmin(profile);
    setAuthNotice("");
  };

  // Clear the browser session and return to login.
  const handleLogout = () => {
    api.logout();
    setAdmin(null);
    setAuthNotice("");
  };

  if (checkingSession) {
    return (
      <div className="auth-loading">
        <div className="auth-loading-mark">
          <ShieldCheck size={28} />
        </div>
        <LoaderCircle className="spin" size={20} />
        <p>Verifying administrator session...</p>
      </div>
    );
  }

  if (!admin) {
    return (
      <LoginPage
        onLogin={handleLogin}
        notice={authNotice}
      />
    );
  }

  return (
    <Dashboard
      admin={admin}
      onLogout={handleLogout}
    />
  );
}

export default App;
