import React, { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";
import { applyTheme, initialTheme, otherTheme, storeTheme } from "./lib/theme.js";

// Light / dark switch. The first choice follows the system; after the person picks one it is remembered in the browser.
export function useTheme() {
  const [theme, setTheme] = useState(() => (typeof document !== "undefined" && document.documentElement.dataset.theme) || initialTheme());
  useEffect(() => { applyTheme(theme); }, [theme]);
  const choose = next => { setTheme(next); storeTheme(next); };
  return [theme, choose];
}

export default function ThemeToggle() {
  const [theme, choose] = useTheme();
  const next = otherTheme(theme);
  return <button type="button" className="icon-button" onClick={() => choose(next)} aria-label={`Switch to ${next} theme`} title={`Switch to ${next} theme`} data-testid="theme-toggle">
    {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}</button>;
}
