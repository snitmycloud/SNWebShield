import React from "react";

// The SNwebshield mark: a simple shield with a check. It uses the one accent colour (--accent) so it follows the theme.
export function ShieldMark({ size = 28, className = "" }) {
  return <svg className={`sw-logo-mark ${className}`} width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" focusable="false">
    <path d="M16 2.2 4.5 6.6v8.1c0 7.1 4.8 12.7 11.5 15.1 6.7-2.4 11.5-8 11.5-15.1V6.6L16 2.2Z" fill="var(--accent)" />
    <path d="m10.6 16.3 3.9 3.9 7-7.7" fill="none" stroke="var(--on-accent)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
  </svg>;
}

// Mark and name. `caption` is the small line under the name (the sidebar uses it; the login page does not).
export default function Logo({ size = 30, caption = "", stacked = false, className = "" }) {
  return <span className={`sw-logo${stacked ? " stacked" : ""} ${className}`} data-testid="logo">
    <ShieldMark size={size} />
    <span className="sw-logo-text"><span className="sw-logo-name">SNwebshield</span>{caption && <span className="sw-logo-caption">{caption}</span>}</span>
  </span>;
}
