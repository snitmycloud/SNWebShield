import React from "react";

// Every empty screen says what to do next; every loading screen is a skeleton of what is coming, not a spinner.
export function EmptyState({ icon: Icon, title, text, action }) {
  return <div className="empty-state" data-testid="empty-state">
    {Icon && <div className="empty-icon"><Icon size={22} /></div>}
    <strong>{title}</strong>{text && <p>{text}</p>}{action}
  </div>;
}

export function Skeleton({ rows = 3, className = "" }) {
  return <div className={`loading-rows ${className}`} role="status" aria-label="Loading"><span className="sr-only">Loading</span>
    {Array.from({ length: rows }, (_, i) => <div key={i} />)}</div>;
}
