// Display helpers for scanner reports. Report fields originate from untrusted target
// responses or remote runners, so only fixed vocabulary is turned into text here.
const REDIRECT_LABELS = {
  same_origin: "same origin",
  https_upgrade_same_host: "HTTPS upgrade on the same host",
  same_host_scheme_or_port_change: "same host, different scheme or port",
  different_host_not_followed: "different host",
  invalid_or_unsupported: "invalid or unsupported destination",
  missing: "no Location header",
  ambiguous: "multiple Location headers",
};

export function describeRedirect(transport) {
  const redirect = transport?.redirect;
  if (!redirect || redirect.is_redirect !== true) return null;
  const where = REDIRECT_LABELS[redirect.location] ?? "unclassified destination";
  return `Redirect not followed (${where}); the Location value is not stored.`;
}

export function describeTls(transport) {
  if (!transport || transport.tls_verified !== true) return "TLS: not used";
  const version = /^TLSv1\.[23]$/.test(transport.tls_version ?? "") ? transport.tls_version : "verified";
  return `TLS: ${version}`;
}

export function describeIsolation(execution) {
  if (!execution) return null;
  return execution.isolation_attested === true
    ? "Container isolation: verified by the runner before start"
    : "Container isolation: not attested by this runner version";
}

// Read-only VM inventory (R6). Text comes from fixed categories and counts, never from remote strings.
export function describeOrphanReport(report) {
  if (!report || !Array.isArray(report.sections)) return [];
  return report.sections.map(section => {
    const orphaned = (section.containers ?? []).filter(c => c.status === "orphaned").length;
    const recent = (section.containers ?? []).length - orphaned;
    const text = {
      disabled: "Not checked: this scanner is disabled, so the VM was not contacted.",
      unsupported: "The installed runner cannot list containers. Redeploy the runner to enable this report.",
      unavailable: "The VM could not be checked (" + String(section.error ?? "unavailable").replace(/[^a-z0-9_ ]/gi, "") + ").",
      ok: orphaned ? `${orphaned} leftover container${orphaned === 1 ? "" : "s"} found${recent ? `, ${recent} recent` : ""}. Review and remove manually.`
        : recent ? `No leftover containers; ${recent} recent (likely still running).` : "No leftover containers.",
    }[section.status] ?? "Status unavailable.";
    return { scanner: section.scanner, status: section.status, orphaned, text };
  });
}
