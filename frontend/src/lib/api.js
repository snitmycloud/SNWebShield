
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
  website: (id) => request(`/websites/${encodeURIComponent(id)}`),
  addWebsite: (domain) => jsonPost("/websites", { domain }),
  verifyManually: (id, { ownerName, consent, reason }) => jsonPost(`/websites/${encodeURIComponent(id)}/verify-manual`, { owner_name: ownerName, consent_method: consent, reason }),
  websiteAudit: (id) => request(`/websites/${encodeURIComponent(id)}/audit`),
  verifyWebsite: (id, method) => jsonPost(`/websites/${encodeURIComponent(id)}/verify`, { method }),
  websiteScans: (id) => request(`/websites/${encodeURIComponent(id)}/scans?limit=10`),
  scanNow: (id, scanType = "standard") => jsonPost(`/websites/${encodeURIComponent(id)}/scan`, { scan_type: scanType }),
  scanDetail: (id, scanId) => request(`/websites/${encodeURIComponent(id)}/scans/${encodeURIComponent(scanId)}`),
  scanComparison: (id, scanId) => request(`/websites/${encodeURIComponent(id)}/scans/${encodeURIComponent(scanId)}/comparison`),
  acceptRisk: (id, fingerprint, reason, days) => jsonPost(`/websites/${encodeURIComponent(id)}/findings/${encodeURIComponent(fingerprint)}/accept`, { reason, days }),
  stopAcceptingRisk: (id, fingerprint) => jsonPost(`/websites/${encodeURIComponent(id)}/findings/${encodeURIComponent(fingerprint)}/unaccept`, {}),
  recheckFinding: (id, fingerprint) => jsonPost(`/websites/${encodeURIComponent(id)}/findings/${encodeURIComponent(fingerprint)}/recheck`, {}),
  websiteTrend: (id) => request(`/websites/${encodeURIComponent(id)}/trend`),
  alertPreferences: () => request("/alerts/preferences"),
  setAlertPreference: (type, enabled) => request(`/alerts/preferences/${encodeURIComponent(type)}`, { method: "PUT", body: JSON.stringify({ enabled }) }),
  sendTestAlert: () => jsonPost("/alerts/test", {}),
  adminWorkers: () => request("/admin/workers"),
  adminSiteCheck: () => request("/admin/site-check"),
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

  // Health
  health: () => request("/health", { auth: false }),
};

export { API_BASE_URL };
