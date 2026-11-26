
const API_BASE_URL = (
  import.meta.env?.VITE_API_BASE_URL ||
  "http://127.0.0.1:8000/api/v1"
).replace(/\/$/, "");

const TOKEN_KEY = "snwebshield_access_token";
const EXPIRY_KEY = "snwebshield_access_token_expiry";
let expiryTimer;

function expireSession() {
  clearSession();
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event("snwebshield:session-expired"));
  }
}

function getAccessToken() {
  try {
    const token = sessionStorage.getItem(TOKEN_KEY);
    const expiry = Number(sessionStorage.getItem(EXPIRY_KEY));

    if (!token) return null;

    if (!Number.isFinite(expiry) || expiry <= Date.now()) {
      expireSession();
      return null;
    }

    return token;
  } catch {
    return null;
  }
}

function saveSession(data) {
  if (!data?.access_token) {
    throw new Error("Login response did not contain an access token.");
  }

  const expiresIn = Number(data.expires_in) || 1200;

  sessionStorage.setItem(TOKEN_KEY, data.access_token);
  sessionStorage.setItem(
    EXPIRY_KEY,
    String(Date.now() + expiresIn * 1000)
  );
  startSessionTimer();
}

function clearSession() {
  clearTimeout(expiryTimer);
  try {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(EXPIRY_KEY);
  } catch {
    // Session storage may be unavailable.
  }
}

function startSessionTimer() {
  clearTimeout(expiryTimer);
  if (getAccessToken()) {
    expiryTimer = setTimeout(expireSession, Math.max(
      0, Number(sessionStorage.getItem(EXPIRY_KEY)) - Date.now()
    ));
  }
}

// Turn an API error body into an Error with a plain message. Structured details such as
// {code: "plan_limit", message, ...} keep their fields on `error.code` / `error.detail`.
export function apiError(status, detail, retryAfter) {
  let message = Array.isArray(detail)
    ? detail.map((item) => item.msg || JSON.stringify(item)).join("; ")
    : typeof detail === "string"
      ? detail
      : detail && typeof detail.message === "string"
        ? detail.message
        : `Request failed with HTTP ${status}`;
  const wait = Number(retryAfter);
  if (status === 429 && Number.isFinite(wait) && wait > 0) {
    message += ` (retry in about ${Math.ceil(wait / 60)} min)`;
  }
  const error = new Error(message);
  error.status = status;
  if (detail && typeof detail === "object" && !Array.isArray(detail)) {
    error.code = detail.code;
    error.detail = detail;
  }
  return error;
}

async function request(path, options = {}) {
  const { auth = true, binary = false, ...fetchOptions } = options;
  const token = auth ? getAccessToken() : null;
  if (auth && !token) {
    expireSession();
    throw new Error("Your session has expired. Please sign in again.");
  }

  const headers = {
    Accept: "application/json",
    ...(fetchOptions.body ? { "Content-Type": "application/json" } : {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...fetchOptions.headers,
  };

  let response;

  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...fetchOptions,
      headers,
    });
  } catch {
    throw new Error(
      `Cannot reach the SNWebShield API at ${API_BASE_URL}. Check that the FastAPI server is running.`
    );
  }

  const raw = binary && response.ok ? "" : await response.text();
  let payload = null;

  if (raw) {
    try {
      payload = JSON.parse(raw);
    } catch {
      payload = { detail: raw };
    }
  }

  if (!response.ok) {
    if (response.status === 401 && auth && token === getAccessToken()) {
      expireSession();
    }

    throw apiError(response.status, payload?.detail, response.headers?.get?.("Retry-After"));
  }

  if (auth && token !== getAccessToken()) {
    throw new Error("Your session has changed. Please sign in again.");
  }
  return binary ? response.blob() : payload;
}

// Existing list APIs return pages of up to 100. Keep the current UI search and
// relationships complete while retaining the public paginated API contract.
async function allPages(path, filters = {}) {
  const rows = [];
  for (let offset = 0; ; offset += 100) {
    const params = new URLSearchParams({ ...filters, limit: "100", offset: String(offset) });
    const page = await request(`${path}?${params}`);
    rows.push(...page);
    if (page.length < 100) return rows;
  }
}

const jsonPost = (path, data) =>
  request(path, {
    method: "POST",
    body: JSON.stringify(data),
  });

export const api = {
  // Authentication
  login: async (credentials) => {
    const result = await request("/auth/login", {
      method: "POST",
      body: JSON.stringify(credentials),
      auth: false,
    });

    saveSession(result);
    return result;
  },

  getCurrentAdmin: () => request("/auth/me"),
  myPlan: () => request("/auth/me/plan"),
  signUp: (data) => request("/auth/signup", { method: "POST", body: JSON.stringify(data), auth: false }),
  verifyEmail: (token) => request("/auth/verify-email", { method: "POST", body: JSON.stringify({ token }), auth: false }),
  resendVerification: (email) => request("/auth/resend-verification", { method: "POST", body: JSON.stringify({ email }), auth: false }),
  forgotPassword: (email) => request("/auth/forgot-password", { method: "POST", body: JSON.stringify({ email }), auth: false }),
  resetPassword: (token, newPassword) => request("/auth/reset-password", {
    method: "POST", body: JSON.stringify({ token, new_password: newPassword }), auth: false,
  }),
  // A password change ends every other session; keep this one by saving the new token.
  changePassword: async (currentPassword, newPassword) => {
    const result = await jsonPost("/auth/change-password", { current_password: currentPassword, new_password: newPassword });
    saveSession(result);
    return result;
  },

  // Websites and ownership verification (self-service)
  myWebsites: () => request("/websites?limit=200"),
  allWebsites: () => request("/websites?limit=200&all_accounts=true"),
  website: (id) => request(`/websites/${encodeURIComponent(id)}`),
  addWebsite: (domain) => jsonPost("/websites", { domain }),
  verifyManually: (id, reason) => jsonPost(`/websites/${encodeURIComponent(id)}/verify-manual`, { reason }),
  verifyWebsite: (id, method) => jsonPost(`/websites/${encodeURIComponent(id)}/verify`, { method }),
  websiteScans: (id) => request(`/websites/${encodeURIComponent(id)}/scans?limit=10`),
  scanNow: (id, scanType = "standard") => jsonPost(`/websites/${encodeURIComponent(id)}/scan`, { scan_type: scanType }),
  scanDetail: (id, scanId) => request(`/websites/${encodeURIComponent(id)}/scans/${encodeURIComponent(scanId)}`),
  scanComparison: (id, scanId) => request(`/websites/${encodeURIComponent(id)}/scans/${encodeURIComponent(scanId)}/comparison`),
  acceptRisk: (id, fingerprint, reason, days) => jsonPost(`/websites/${encodeURIComponent(id)}/findings/${encodeURIComponent(fingerprint)}/accept`, { reason, days }),
  stopAcceptingRisk: (id, fingerprint) => request(`/websites/${encodeURIComponent(id)}/findings/${encodeURIComponent(fingerprint)}/accept`, { method: "DELETE" }),
  recheckFinding: (id, fingerprint) => jsonPost(`/websites/${encodeURIComponent(id)}/findings/${encodeURIComponent(fingerprint)}/recheck`, {}),
  removeWebsite: (id, confirmDomain) => jsonPost(`/websites/${encodeURIComponent(id)}/remove`, { confirm_domain: confirmDomain }),

  // Admin
  adminUsers: () => request("/admin/users?limit=500"),
  setUserPlan: (id, plan) => jsonPost(`/admin/users/${encodeURIComponent(id)}/plan`, { plan }),
  setUserActive: (id, active) => jsonPost(`/admin/users/${encodeURIComponent(id)}/${active ? "enable" : "disable"}`, {}),

  hasSession: () => Boolean(getAccessToken()),
  startSessionTimer,

  logout: () => clearSession(),

  // Sign out for real: clear the browser session at once, then ask the server to revoke the token
  // (best effort; a failed request must never keep the person signed in).
  signOut: async () => {
    const token = getAccessToken();
    clearSession();
    if (!token) return;
    try {
      await fetch(`${API_BASE_URL}/auth/logout`, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
    } catch {
      // The token still expires on its own.
    }
  },

  // Monitoring uses the shared execution engine; API requests only queue work.
  monitoringOverview: () => request("/monitoring/overview"),
  monitoringHistory: (id, collection, offset = 0) => request(`/websites/${id}/monitoring/${collection}?limit=50&offset=${offset}`),
  monitoringConfig: (id) => request(`/websites/${id}/monitoring`),
  monitoringAction: (id, action) => jsonPost(`/websites/${id}/monitoring/${action}`, {}),
  stopMonitoring: () => jsonPost("/monitoring/stop", {}),

  // Legacy assessments (staff, read-only; stop actions only).
  portWatch: id => request(`/port-watch/${encodeURIComponent(id)}`),
  disablePortWatch: (id, data) => jsonPost(`/port-watch/${encodeURIComponent(id)}/disable`, data),
  websiteLifecycle: id => request(`/websites/${encodeURIComponent(id)}/lifecycle`),
  orphanContainers: () => request("/assessments/orphan-containers"),
  assessmentWorkerStatus: () => request("/assessments/worker-status"),
  getAssessments: (websiteId = "", offset = 0) => request(`/assessments?limit=50&offset=${offset}${websiteId ? `&website_id=${websiteId}` : ""}`),
  downloadAssessmentReport: id => request(`/assessments/${id}/report/download`, { binary: true }),
  assessmentReviews: id => request(`/assessments/${id}/reviews`),
  reviewObservation: (id, check, data) => jsonPost(`/assessments/${id}/reviews/${encodeURIComponent(check)}`, data),
  observationReviewHistory: (id, check, offset = 0) => request(`/assessments/${id}/reviews/${encodeURIComponent(check)}/history?limit=50&offset=${offset}`),
  createReviewedReport: id => jsonPost(`/assessments/${id}/reviewed-reports`, {}),
  downloadReviewedReport: (id, exportId) => request(`/assessments/${id}/reviewed-reports/${exportId}/download`, { binary: true }),
  getAssessment: (id) => request(`/assessments/${id}`),
  assessmentHistory: (id, collection, offset = 0) => request(`/assessments/${id}/${collection}?limit=50&offset=${offset}`),
  cancelAssessment: (id, data) => jsonPost(`/assessments/${id}/cancel`, data),

  getFindings: (filters = {}, offset = 0) => {
    const params = new URLSearchParams({ limit: "50", offset: String(offset) });
    for (const [key, value] of Object.entries(filters)) if (value !== "" && value !== false && value != null) params.set(key, String(value));
    return request(`/findings?${params}`);
  },
  findingDetail: (id, check) => request(`/findings/${id}/${encodeURIComponent(check)}`),
  setFindingDeadline: (id, check, data) => jsonPost(`/findings/${id}/${encodeURIComponent(check)}/deadline`, data),
  findingDeadlineHistory: (id, check, offset = 0) => request(`/findings/${id}/${encodeURIComponent(check)}/deadline-history?limit=50&offset=${offset}`),

  // Module E: normalised, deduplicated vulnerabilities. Ingestion reads stored reports only.
  getVulnerabilities: (filters = {}, offset = 0) => {
    const params = new URLSearchParams({ limit: "50", offset: String(offset) });
    for (const [key, value] of Object.entries(filters)) if (value !== "" && value != null) params.set(key, String(value));
    return request(`/vulnerabilities?${params}`);
  },
  vulnerability: id => request(`/vulnerabilities/${encodeURIComponent(id)}`),
  vulnerabilityHistory: (id, collection, offset = 0) => request(`/vulnerabilities/${encodeURIComponent(id)}/${collection === "occurrences" ? "occurrences" : "events"}?limit=20&offset=${offset}`),
  ingestVulnerabilities: (assessmentId = null) => jsonPost("/vulnerabilities/ingest", assessmentId ? { assessment_id: assessmentId } : {}),
  commentVulnerability: (id, comment) => jsonPost(`/vulnerabilities/${encodeURIComponent(id)}/comments`, { comment }),
  decideVulnerability: (id, data) => jsonPost(`/vulnerabilities/${encodeURIComponent(id)}/validation`, data),

  // Module F: analyst workbench (analyst role required by the API)
  workbenchQueue: (filters = {}, offset = 0) => {
    const params = new URLSearchParams({ limit: "50", offset: String(offset) });
    for (const [key, value] of Object.entries(filters)) if (value !== "" && value != null) params.set(key, String(value));
    return request(`/workbench/queue?${params}`);
  },
  workbenchDetail: id => request(`/workbench/${encodeURIComponent(id)}`),
  workbenchAudit: id => request(`/workbench/${encodeURIComponent(id)}/audit?limit=100`),
  saveWorkbenchAssessment: (id, data) => jsonPost(`/workbench/${encodeURIComponent(id)}/assessment`, data),
  signoffWorkbench: (id, data) => jsonPost(`/workbench/${encodeURIComponent(id)}/signoff`, data),

  // Module G: VAPT reports (report role required by the API). PDFs are fetched with the bearer token.
  reportEligibility: assessmentId => request(`/reports/eligibility?assessment_id=${encodeURIComponent(assessmentId)}`),
  generateReport: assessmentId => jsonPost("/reports", { assessment_id: assessmentId }),
  reports: (filters = {}, offset = 0) => {
    const params = new URLSearchParams({ limit: "50", offset: String(offset) });
    for (const [key, value] of Object.entries(filters)) if (value) params.set(key, value);
    return request(`/reports?${params}`);
  },
  report: id => request(`/reports/${encodeURIComponent(id)}`),
  reportEvents: id => request(`/reports/${encodeURIComponent(id)}/events?limit=100`),
  approveReport: (id, data) => jsonPost(`/reports/${encodeURIComponent(id)}/approve`, data),
  rejectReport: (id, data) => jsonPost(`/reports/${encodeURIComponent(id)}/reject`, data),
  // Module H: remediation, retesting and closure. A retest is a normal authorised assessment request.
  remediationList: (filters = {}, offset = 0) => {
    const params = new URLSearchParams({ limit: "50", offset: String(offset) });
    for (const [key, value] of Object.entries(filters)) if (value) params.set(key, value);
    return request(`/remediation?${params}`);
  },
  remediation: id => request(`/remediation/${encodeURIComponent(id)}`),
  updateRemediation: (id, data) => jsonPost(`/remediation/${encodeURIComponent(id)}/update`, data),
  verifyFix: (id, data) => jsonPost(`/remediation/${encodeURIComponent(id)}/verify-fix`, data),
  reopenRemediation: (id, data) => jsonPost(`/remediation/${encodeURIComponent(id)}/reopen`, data),
  assessmentClosure: id => request(`/assessments/${encodeURIComponent(id)}/closure`),
  closeAssessment: (id, data) => jsonPost(`/assessments/${encodeURIComponent(id)}/close`, data),
  reopenClosure: (id, data) => jsonPost(`/assessments/${encodeURIComponent(id)}/reopen-closure`, data),
  downloadReportPdf: (id, official) =>
    request(`/reports/${encodeURIComponent(id)}/${official ? "pdf" : "preview"}`, { binary: true }),

  // Health
  health: () => request("/health", { auth: false }),

  // Legacy clients (staff, read-only)
  getClients: () => allPages("/clients"),
};

export { API_BASE_URL };
