// Light / dark theme. The choice is remembered in the browser (never required: if storage is blocked the theme simply follows the system).
export const THEMES = ["light", "dark"];
export const THEME_KEY = "snwebshield-theme";

export function resolveTheme(stored, systemPrefersDark) {
  return THEMES.includes(stored) ? stored : systemPrefersDark ? "dark" : "light";
}

export function otherTheme(theme) {
  return theme === "dark" ? "light" : "dark";
}

export function readStoredTheme(storage = typeof window !== "undefined" ? window.localStorage : null) {
  try { return storage?.getItem(THEME_KEY) || null; } catch { return null; }
}

export function storeTheme(theme, storage = typeof window !== "undefined" ? window.localStorage : null) {
  try { storage?.setItem(THEME_KEY, theme); return true; } catch { return false; }
}

export function systemPrefersDark(matchMedia = typeof window !== "undefined" ? window.matchMedia : null) {
  try { return Boolean(matchMedia?.("(prefers-color-scheme: dark)")?.matches); } catch { return false; }
}

export function applyTheme(theme, root = typeof document !== "undefined" ? document.documentElement : null) {
  if (root) { root.dataset.theme = theme; root.style.colorScheme = theme; }
}

export function initialTheme() {
  return resolveTheme(readStoredTheme(), systemPrefersDark());
}
