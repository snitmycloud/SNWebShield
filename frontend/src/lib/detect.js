// Plain-language wording for scan results (spec rule 4: "Your database port is open to the internet", not "TCP/3306 open").
// Pure functions, unit-tested. Everything shown comes from the scanned server and is rendered as escaped text by React.

const DATABASES = {
  3306: "MySQL", 5432: "PostgreSQL", 1433: "Microsoft SQL Server", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
  1521: "Oracle database", 5984: "CouchDB", 11211: "Memcached", 9300: "Elasticsearch (cluster)",
};
const KNOWN = {
  21: ["File transfer (FTP)", "File transfer (FTP) is open to the internet. It is usually not encrypted."],
  22: ["Remote login (SSH)", "Remote login (SSH) is open to the internet."],
  23: ["Telnet", "Telnet, an unencrypted remote login, is open to the internet."],
  25: ["Email sending (SMTP)", "Your mail server (SMTP) is reachable from the internet."],
  110: ["Email (POP3)", "Email retrieval (POP3) is open to the internet."],
  143: ["Email (IMAP)", "Email retrieval (IMAP) is open to the internet."],
  139: ["Windows file sharing", "Windows file sharing is open to the internet."],
  445: ["Windows file sharing (SMB)", "Windows file sharing (SMB) is open to the internet."],
  2375: ["Docker remote control", "Docker's remote control port is open to the internet. Anyone who can reach it may be able to control your server."],
  2376: ["Docker remote control (encrypted)", "Docker's encrypted remote control port is open to the internet. Only the people who need it should be able to reach it."],
  2379: ["etcd settings store", "Your etcd store, where cluster settings and secrets are kept, is open to the internet."],
  5601: ["Kibana dashboard", "Your Kibana dashboard, a viewer for log and search data, is open to the internet."],
  10250: ["Kubernetes node control (kubelet)", "A Kubernetes node's control port (kubelet) is open to the internet."],
  15672: ["RabbitMQ admin page", "The admin page of your RabbitMQ message queue is open to the internet."],
  3389: ["Remote Desktop", "Remote Desktop is open to the internet."],
  5900: ["Remote screen (VNC)", "Remote screen sharing (VNC) is open to the internet."],
};

export function describePort(item) {
  const port = Number(item.port);
  const service = (item.service || "").toLowerCase();
  if (DATABASES[port] || ["mysql", "postgresql", "ms-sql-s", "mongod", "mongodb", "redis"].includes(service)) {
    const name = DATABASES[port] || (item.product || "database");
    return { label: `${name} database`, sentence: "Your database port is open to the internet.", group: "database" };
  }
  if (service === "https" || service === "http" || item.http) {
    const secure = service === "https" || item.http?.over_tls;
    return { label: secure ? "Website (HTTPS)" : "Website (HTTP)",
      sentence: `Your website is reachable${secure ? " securely" : ""} on port ${port}.`, group: "web" };
  }
  if (KNOWN[port]) return { label: KNOWN[port][0], sentence: KNOWN[port][1], group: "service" };
  if (["smtp", "pop3", "imap", "ftp", "ssh", "telnet"].includes(service)) {
    return { label: service.toUpperCase(), sentence: `A ${service.toUpperCase()} service is open to the internet on port ${port}.`, group: "service" };
  }
  const guess = item.service ? ` (probably ${item.service}, guessed from the port number)` : "";
  return { label: item.service ? item.service : "Unknown service", sentence: `Port ${port} is open${guess}.`, group: "other" };
}

export function softwareText(item) {
  if (item.product && item.version) return `${item.product} ${item.version}`;
  if (item.product) return `${item.product} (version not disclosed)`;
  return item.service_guess || !item.service ? "Not identified" : "Version not disclosed";
}

export const STEP_LABELS = {
  ports: "Open ports", versions: "Service versions", technologies: "Technologies",
  exposed: "Exposed files", dns: "Email and DNS records", subdomains: "Subdomain list",
};

// Every step that did not finish, in plain words. A step that failed or timed out is "could not check", never "clean".
export function stepProblems(result) {
  const steps = result?.steps || {};
  return Object.entries(STEP_LABELS)
    .filter(([key]) => steps[key] && ["could_not_check", "stopped"].includes(steps[key].state))
    .map(([key, label]) => ({ key, label, text: steps[key].state === "stopped" ? "Stopped before it finished" : "Could not check" }));
}

export function stepState(result, key) {
  return result?.steps?.[key]?.state || "missing";
}

// What a results section should say. A step that has no result is NEVER shown as "nothing found":
//   problem   - the step could not finish
//   unchecked - the step has not run (yet), or the scan stopped before it
//   data      - there is something to list
//   empty     - the step finished and found nothing
export function sectionNote(state, { running = false, hasData = false } = {}) {
  if (["could_not_check", "stopped", "skipped"].includes(state)) {
    return { kind: "problem", text: "Could not check this part. That is not the same as “nothing found”." };
  }
  if (state === "missing" && !hasData) {
    return { kind: "unchecked", text: running ? "Not checked yet." : "Not checked: the scan stopped before this part." };
  }
  return { kind: hasData ? "data" : "empty", text: "" };
}

const DNS_TEXT = {
  spf: { title: "SPF", what: "which servers may send email for your domain" },
  dmarc: { title: "DMARC", what: "what receivers do with email that fails checks" },
  dkim: { title: "DKIM", what: "digital signatures on your email" },
  caa: { title: "CAA", what: "which companies may issue certificates for your domain" },
  mx: { title: "Mail servers (MX)", what: "where your email is delivered" },
};

export function dnsText(row) {
  const info = DNS_TEXT[row.key] || { title: row.key.toUpperCase(), what: "" };
  const status = { present: "Found", missing: "Not found", could_not_check: "Could not check" }[row.status] || "Could not check";
  let detail = "";
  if (row.status === "present") {
    if (row.key === "spf") detail = { fail: "Strict (rejects others).", softfail: "Soft (marks others as suspicious).", neutral: "Neutral.", pass_all: "Allows anyone.", no_all: "No final rule." }[row.data?.policy] || "";
    if (row.key === "dmarc" && row.data?.policy) detail = `Policy: ${row.data.policy}.`;
    if (row.key === "dkim") detail = `Signing keys found for: ${(row.data?.selectors_found || []).join(", ")}.`;
  }
  if (row.status === "missing" && row.key === "dkim") detail = "None of the common selectors were found.";
  return { title: info.title, what: info.what, status, detail, tone: row.status === "present" ? "good" : row.status === "missing" ? "warn" : "muted" };
}

const EXPOSED = {
  "git-head": "A Git repository is publicly readable.",
  "env-file": "A configuration file (.env) that can contain passwords is publicly readable.",
  "zip-archive": "A backup archive can be downloaded by anyone.",
  "wp-config-backup": "A backup of your WordPress settings, including database details, can be read by anyone.",
  "phpinfo-page": "A page that reveals your server's PHP settings is public.",
  "apache-server-status": "A server status page is public.",
  "ds-store": "A macOS folder-listing file (.DS_Store) is public.",
  "login-form": "An administrator or login page is publicly reachable.",
  "index-of": "A folder's contents are listed publicly.",
};

export function exposedText(item) {
  return EXPOSED[item.signature] || "A file or page that should probably not be public was found.";
}

export function scanNowText(scanNow) {
  if (!scanNow) return "";
  if (scanNow.reason === "not_verified") return "Verify ownership to scan.";
  if (scanNow.reason === "scan_running") return "A scan is running.";
  const left = scanNow.remaining;
  if (left <= 0) return "No scans left today";
  return `${left} of ${scanNow.limit} scan${scanNow.limit === 1 ? "" : "s"} left today`;
}

// A scan limit or plan feature is a normal answer, not a failure: show its message, do not show an error page.
export function isFriendlyLimit(error) {
  return Boolean(error && (error.code === "scan_limit" || error.code === "plan_feature"));
}

export function isActiveScan(scan) {
  return Boolean(scan && ["queued", "running"].includes(scan.status));
}

export function resultBanner(scan) {
  if (!scan) return null;
  if (scan.status === "completed") return { tone: "info", title: "Detection finished", text: scan.message };
  if (scan.status === "incomplete") return { tone: "warn", title: "Incomplete results", text: scan.message };
  if (scan.status === "refused") return { tone: "bad", title: "Scan did not run", text: scan.message };
  return null;
}
