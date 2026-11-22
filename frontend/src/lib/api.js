
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

    const detail = payload?.detail;

    const message = Array.isArray(detail)
      ? detail.map((item) => item.msg || JSON.stringify(item)).join("; ")
      : typeof detail === "string"
        ? detail
        : `Request failed with HTTP ${response.status}`;

    throw new Error(message);
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

  hasSession: () => Boolean(getAccessToken()),
  startSessionTimer,

  logout: () => clearSession(),

  // Monitoring uses the shared execution engine; API requests only queue work.
  monitoringOverview: () => request("/monitoring/overview"),
  monitoringHistory: (id, collection, offset = 0) => request(`/websites/${id}/monitoring/${collection}?limit=50&offset=${offset}`),
  monitoringConfig: (id) => request(`/websites/${id}/monitoring`),
  configureMonitoring: (id, data) => jsonPost(`/websites/${id}/monitoring/configure`, data),
  monitoringAction: (id, action) => jsonPost(`/websites/${id}/monitoring/${action}`, {}),
  stopMonitoring: () => jsonPost("/monitoring/stop", {}),

  // Health
  health: () => request("/health", { auth: false }),

  // Clients
  getClients: () => allPages("/clients"),

  createClient: (data) => jsonPost("/clients", data),

  // Websites
  getWebsites: () => allPages("/websites"),

  createWebsite: (data) => jsonPost("/websites", data),

  // Private evidence: authentication stays in the header, never in URLs.
  getEvidence: (id) => request(`/authorizations/${id}/evidence`),
  getEvidenceEvents: (id) => request(`/authorizations/${id}/evidence/events`),
  uploadEvidence: (id, file) => request(`/authorizations/${id}/evidence`, {
    method: "POST", body: file,
    headers: { "Content-Type": "application/octet-stream", "X-Evidence-Filename": encodeURIComponent(file.name) },
  }),
  openEvidence: (id, preview = false) => request(`/evidence/${id}/${preview ? "preview" : "download"}`, { binary: true }),
  reviewEvidence: (id, data) => jsonPost(`/authorizations/${id}/evidence/reviews`, data),
  evidenceAction: (id, action, data) => jsonPost(`/evidence/${id}/${action}`, data),

  // Authorizations
  getAuthorizations: (filters = {}) => {
    const params = {};

    if (filters.status && filters.status !== "all") {
      params.status = filters.status;
    }

    if (filters.websiteId) {
      params.website_id = String(filters.websiteId);
    }

    return allPages("/authorizations", params);
  },

  getAuthorizationSummary: () => request("/authorizations/summary"),
  getAuthorization: (id) => request(`/authorizations/${id}`),

  getAuthorizationEvents: (authorizationId) =>
    request(`/authorizations/${authorizationId}/events`),

  createAuthorization: (data) =>
    jsonPost("/authorizations", data),

  approveAuthorization: (authorizationId, data) =>
    jsonPost(`/authorizations/${authorizationId}/approve`, data),

  rejectAuthorization: (authorizationId, data) =>
    jsonPost(`/authorizations/${authorizationId}/reject`, data),

  revokeAuthorization: (authorizationId, data) =>
    jsonPost(`/authorizations/${authorizationId}/revoke`, data),
};

export { API_BASE_URL };
