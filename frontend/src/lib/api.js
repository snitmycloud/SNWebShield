
const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ||
  "http://127.0.0.1:8000/api/v1"
).replace(/\/$/, "");

const TOKEN_KEY = "snwebshield_access_token";
const EXPIRY_KEY = "snwebshield_access_token_expiry";

function getAccessToken() {
  try {
    const token = sessionStorage.getItem(TOKEN_KEY);
    const expiry = Number(sessionStorage.getItem(EXPIRY_KEY));

    if (!token) return null;

    if (expiry && Date.now() >= expiry) {
      clearSession();
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
}

function clearSession() {
  try {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(EXPIRY_KEY);
  } catch {
    // Session storage may be unavailable.
  }
}

async function request(path, options = {}) {
  const { auth = true, ...fetchOptions } = options;
  const token = auth ? getAccessToken() : null;

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

  const raw = await response.text();
  let payload = null;

  if (raw) {
    try {
      payload = JSON.parse(raw);
    } catch {
      payload = { detail: raw };
    }
  }

  if (!response.ok) {
    if (response.status === 401 && token && auth) {
      clearSession();

      if (typeof window !== "undefined") {
        window.dispatchEvent(
          new Event("snwebshield:session-expired")
        );
      }
    }

    const detail = payload?.detail;

    const message = Array.isArray(detail)
      ? detail.map((item) => item.msg || JSON.stringify(item)).join("; ")
      : typeof detail === "string"
        ? detail
        : `Request failed with HTTP ${response.status}`;

    throw new Error(message);
  }

  return payload;
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

  logout: () => clearSession(),

  // Health
  health: () => request("/health"),

  // Clients
  getClients: () => request("/clients?limit=100&offset=0"),

  createClient: (data) => jsonPost("/clients", data),

  // Websites
  getWebsites: () => request("/websites?limit=100&offset=0"),

  createWebsite: (data) => jsonPost("/websites", data),

  // Authorizations
  getAuthorizations: (filters = {}) => {
    const params = new URLSearchParams({
      limit: "100",
      offset: "0",
    });

    if (filters.status && filters.status !== "all") {
      params.set("status", filters.status);
    }

    if (filters.websiteId) {
      params.set("website_id", String(filters.websiteId));
    }

    return request(`/authorizations?${params.toString()}`);
  },

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
