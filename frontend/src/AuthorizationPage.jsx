
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertCircle,
  ArrowUpRight,
  CheckCircle2,
  Clock3,
  FileCheck2,
  Globe2,
  History,
  LoaderCircle,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  UserRound,
  X,
} from "lucide-react";
import EvidencePanel from "./EvidencePanel.jsx";
import "./authorization.css";
import { api } from "./lib/api.js";

const METHODS = {
  passive_reconnaissance: "Passive reconnaissance",
  configuration_review: "Configuration review",
  automated_non_intrusive_scanning: "Automated non-intrusive scanning",
  manual_web_application_testing: "Manual web application testing",
  authenticated_testing: "Authenticated testing",
  api_security_testing: "API security testing",
};

function formatDate(value) {
  if (!value) return "Not provided";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return "Invalid date";

  return new Intl.DateTimeFormat("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  }).format(date);
}

function formatDateTime(value) {
  if (!value) return "Not available";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return "Invalid date";

  return new Intl.DateTimeFormat("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function prettyMethod(method) {
  return METHODS[method] || method.replaceAll("_", " ");
}

function StatusBadge({ status }) {
  const value = String(status || "pending").toLowerCase();

  return (
    <span className={`authz-status ${value}`}>
      <span />
      {{ active: "Currently valid", scheduled: "Scheduled", pending: "Pending review",
        needs_date_review: "Dates need review", expired: "Expired", rejected: "Rejected",
        revoked: "Revoked", approved: "Approved" }[value] || value}
    </span>
  );
}

function SummaryCard({ label, value, icon: Icon, tone }) {
  return (
    <div className="authz-stat-card">
      <div className={`authz-stat-icon ${tone}`}>
        <Icon size={19} />
      </div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function AuthorizationPage({ websites = [], clients = [], onNotice, onDecision, admin }) {
  const [evidenceReady, setEvidenceReady] = useState(false);
  const [summary, setSummary] = useState(null);
  const listRequest = useRef(0);
  const detailRequest = useRef(0);
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");

  const [selected, setSelected] = useState(null);
  const [events, setEvents] = useState([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditError, setAuditError] = useState("");

  const [actionType, setActionType] = useState("");
  const [reviewNote, setReviewNote] = useState("");
  const [evidenceReviewed, setEvidenceReviewed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState("");

  const loadAuthorizations = useCallback(async () => {
    const requestId = ++listRequest.current;
    setLoading(true);
    setError("");

    try {
      const [data, totals] = await Promise.all([api.getAuthorizations(), api.getAuthorizationSummary()]);
      if (requestId !== listRequest.current) return;
      setSummary(totals);
      setRecords(Array.isArray(data) ? data : []);
    } catch (err) {
      if (requestId !== listRequest.current) return;
      setSummary(null);
      setError(err.message || "Unable to load authorization records.");
    } finally {
      if (requestId === listRequest.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAuthorizations();
    const timer = window.setInterval(loadAuthorizations, 60000);
    return () => { window.clearInterval(timer); listRequest.current += 1; detailRequest.current += 1; };
  }, [loadAuthorizations]);

  const counts = {
    total: summary?.total ?? "—",
    pending: summary?.effective_counts?.pending ?? "—",
    approved: summary?.effective_counts?.active ?? "—",
    rejected: summary?.effective_counts?.rejected ?? "—",
  };

  const filteredRecords = useMemo(() => {
    const query = search.trim().toLowerCase();

    return records.filter((record) => {
      if (
        statusFilter !== "all" &&
        record.effective_status !== statusFilter
      ) {
        return false;
      }

      const website = websites.find(
        (item) => item.id === record.website_id
      );

      const client = clients.find(
        (item) => item.id === website?.client_id
      );

      const searchable = [
        record.authorization_reference,
        record.authorized_by,
        ...(record.authorized_domains || []),
        website?.name,
        website?.url,
        client?.company_name,
      ];

      return searchable.some((value) =>
        String(value || "").toLowerCase().includes(query)
      );
    });
  }, [records, search, statusFilter, websites, clients]);

  const getWebsite = (websiteId) =>
    websites.find((item) => item.id === websiteId);

  const getClient = (websiteId) => {
    const website = getWebsite(websiteId);

    return clients.find((item) => item.id === website?.client_id);
  };

  const loadAuditEvents = async (authorizationId) => {
    const requestId = ++detailRequest.current;
    setAuditLoading(true);
    setAuditError("");

    try {
      const [data, current] = await Promise.all([api.getAuthorizationEvents(authorizationId), api.getAuthorization(authorizationId)]);
      if (requestId !== detailRequest.current) return;
      setSelected(current);
      setEvents(Array.isArray(data) ? data : []);
    } catch (err) {
      if (requestId !== detailRequest.current) return;
      setAuditError(err.message || "Unable to load audit history.");
      setEvents([]);
    } finally {
      if (requestId === detailRequest.current) setAuditLoading(false);
    }
  };

  const openDetails = async (record) => {
    setEvidenceReady(false);
    setSelected(record);
    setEvents([]);
    setActionType("");
    setReviewNote("");
    setEvidenceReviewed(false);
    setActionError("");

    await loadAuditEvents(record.id);
  };

  const closeDetails = () => {
    if (submitting) return;

    detailRequest.current += 1;
    setSelected(null);
    setActionType("");
    setReviewNote("");
    setEvidenceReviewed(false);
    setActionError("");
    setEvents([]);
  };

  const beginAction = (type) => {
    setActionType(type);
    setReviewNote("");
    setEvidenceReviewed(false);
    setActionError("");
  };

  const handleAction = async (event) => {
    event.preventDefault();

    if (!selected || submitting) return;

    const note = reviewNote.trim();

    if (actionType === "approve") {
      if (!evidenceReviewed) {
        setActionError(
          "Confirm that you reviewed the written authorisation evidence."
        );
        return;
      }

      if (note.length < 20) {
        setActionError("The review note must contain at least 20 characters.");
        return;
      }
    } else if (note.length < 10) {
      setActionError("Please enter a reason of at least 10 characters.");
      return;
    }

    setSubmitting(true);
    setActionError("");

    try {
      let updated;

      if (actionType === "approve") {
        updated = await api.approveAuthorization(selected.id, {
          evidence_reviewed: true,
          review_note: note,
        });
      } else if (actionType === "reject") {
        updated = await api.rejectAuthorization(selected.id, {
          reason: note,
        });
      } else if (actionType === "revoke") {
        updated = await api.revokeAuthorization(selected.id, {
          reason: note,
        });
      } else {
        return;
      }

      setRecords((current) =>
        current.map((item) => item.id === updated.id ? updated : item)
      );

      setSelected(updated);
      setActionType("");
      setReviewNote("");
      setEvidenceReviewed(false);

      const actionLabel = {
        approve: "approved",
        reject: "rejected",
        revoke: "revoked",
      }[actionType];

      onNotice?.(
        `Authorization ${updated.authorization_reference} was ${actionLabel}.`
      );

      await loadAuditEvents(updated.id);
      await loadAuthorizations();
      await onDecision?.();
    } catch (err) {
      setActionError(err.message || "The authorization decision failed.");
      await loadAuditEvents(selected.id);
      await loadAuthorizations();
      await onDecision?.();
    } finally {
      setSubmitting(false);
    }
  };

  const pendingExpired = selected?.effective_status === "expired";
  const needsDateReview = selected?.effective_status === "needs_date_review";

  return (
    <div className="authz-page">
      <div className="authz-heading">
        <div>
          <div className="eyebrow">SECURITY GOVERNANCE</div>
          <h1>Authorization management</h1>
          <p>
            Review written permission, verify testing scope and record
            administrator decisions.
          </p>
        </div>

        <button
          type="button"
          className="secondary-button"
          onClick={loadAuthorizations}
          disabled={loading}
        >
          <RefreshCw size={15} className={loading ? "spin" : ""} />
          Refresh
        </button>
      </div>

      <div className="authz-safety-banner">
        <ShieldCheck size={19} />
        <div>
          <strong>Review before approval</strong>
          <span>
            Confirm the original written permission, exact domain scope,
            permitted methods and validity dates. Approval does not start
            a security scan.
          </span>
        </div>
      </div>

      <div className="authz-stat-grid">
        <SummaryCard
          label="Total records"
          value={counts.total}
          icon={FileCheck2}
          tone="blue"
        />
        <SummaryCard
          label="Pending review"
          value={counts.pending}
          icon={Clock3}
          tone="amber"
        />
        <SummaryCard
          label="Currently valid"
          value={counts.approved}
          icon={ShieldCheck}
          tone="green"
        />
        <SummaryCard
          label="Rejected"
          value={counts.rejected}
          icon={AlertCircle}
          tone="red"
        />
      </div>

      {error && (
        <div className="alert alert-error" role="alert">
          <ShieldAlert size={18} />
          <div>
            <strong>Could not load authorization records</strong>
            <span>{error}</span>
          </div>
          <button
            type="button"
            className="alert-action"
            onClick={loadAuthorizations}
          >
            Retry
          </button>
        </div>
      )}

      <p className="toolbar-count">Counts as of {formatDateTime(summary?.as_of)}. Recorded approval and current validity are separate.</p>

      <div className="authz-toolbar">
        <div className="search-box">
          <Search size={17} />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search reference, domain, client or contact"
          />
        </div>

        <select
          className="authz-filter"
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value)}
          aria-label="Filter authorization status"
        >
          <option value="all">All statuses</option>
          <option value="pending">Pending</option>
          <option value="active">Currently valid</option>
          <option value="scheduled">Scheduled</option>
          <option value="needs_date_review">Dates need review</option>
          <option value="rejected">Rejected</option>
          <option value="expired">Expired</option>
          <option value="revoked">Revoked</option>
        </select>

        <span className="toolbar-count">
          {filteredRecords.length} record(s)
        </span>
      </div>

      <section className="panel authz-table-panel">
        <div className="table-scroll">
          <table className="authz-table">
            <thead>
              <tr>
                <th>Authorization reference</th>
                <th>Website / Client</th>
                <th>Authorised domains</th>
                <th>Valid until</th>
                <th>Status</th>
                <th>Review</th>
              </tr>
            </thead>

            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="6">
                    <div className="table-loading">
                      <LoaderCircle className="spin" size={18} />
                      Loading authorization records...
                    </div>
                  </td>
                </tr>
              ) : filteredRecords.length ? (
                filteredRecords.map((record) => {
                  const website = getWebsite(record.website_id);
                  const client = getClient(record.website_id);

                  return (
                    <tr key={record.id}>
                      <td>
                        <div className="authz-reference">
                          <strong>{record.authorization_reference}</strong>
                          <small>Record #{record.id}</small>
                        </div>
                      </td>

                      <td>
                        <div className="authz-website">
                          <strong>
                            {website?.name || `Website #${record.website_id}`}
                          </strong>
                          <small>
                            {client?.company_name || "Client not found"}
                          </small>
                        </div>
                      </td>

                      <td>
                        <div className="authz-domain-list">
                          {(record.authorized_domains || [])
                            .slice(0, 2)
                            .map((domain) => (
                              <span key={domain}>{domain}</span>
                            ))}
                          {(record.authorized_domains || []).length > 2 && (
                            <small>
                              +{record.authorized_domains.length - 2} more
                            </small>
                          )}
                        </div>
                      </td>

                      <td>{record.timestamps_verified ? formatDate(record.valid_until) : "Dates need review"}</td>

                      <td>
                        <StatusBadge status={record.effective_status} />
                      </td>

                      <td>
                        <button
                          type="button"
                          className="authz-review-button"
                          onClick={() => openDetails(record)}
                        >
                          Review
                          <ArrowUpRight size={14} />
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="6">
                    <div className="authz-empty">
                      <div>
                        <FileCheck2 size={24} />
                      </div>
                      <strong>No authorization records found</strong>
                      <p>
                        There are no records matching this search or status.
                      </p>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="table-footnote">
          <ShieldCheck size={14} />
          Only an authenticated administrator can make authorization decisions.
        </div>
      </section>

      {selected && (
        <div
          className="modal-backdrop authz-backdrop"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) closeDetails();
          }}
        >
          <section
            className="modal-card authz-detail-card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="authz-detail-title"
          >
            <div className="modal-heading">
              <div>
                <div className="eyebrow">AUTHORIZATION REVIEW</div>
                <h2 id="authz-detail-title">
                  {selected.authorization_reference}
                </h2>
                <p>Record #{selected.id} · Website #{selected.website_id}</p>
              </div>

              <button
                type="button"
                className="icon-button"
                onClick={closeDetails}
                aria-label="Close authorization details"
                disabled={submitting}
              >
                <X size={19} />
              </button>
            </div>

            <div className="authz-detail-body">
              <div className="authz-detail-status">
                <StatusBadge status={selected.effective_status} />
                <span>
                  Recorded decision: {selected.status} · Submitted {formatDateTime(selected.created_at)}
                </span>
              </div>

              <EvidencePanel key={selected.id} authorization={selected} adminId={admin?.id} onReady={setEvidenceReady} />

              <div className="authz-info-grid">
                <div>
                  <span>Website</span>
                  <strong>
                    {getWebsite(selected.website_id)?.name ||
                      `Website #${selected.website_id}`}
                  </strong>
                </div>

                <div>
                  <span>Client</span>
                  <strong>
                    {getClient(selected.website_id)?.company_name ||
                      "Not found"}
                  </strong>
                </div>

                <div>
                  <span>Authorised by</span>
                  <strong>{selected.authorized_by}</strong>
                </div>

                <div>
                  <span>Linked website URL</span>
                  <strong>
                    {getWebsite(selected.website_id)?.url || "Not available"}
                  </strong>
                </div>

                <div>
                  <span>Valid from</span>
                  <strong>{selected.timestamps_verified ? formatDateTime(selected.valid_from) : `Unverified: ${selected.valid_from}`}</strong>
                </div>

                <div>
                  <span>Valid until</span>
                  <strong>{selected.timestamps_verified ? formatDateTime(selected.valid_until) : `Unverified: ${selected.valid_until}`}</strong>
                </div>
              </div>

              <div className="authz-detail-section">
                <h3><Globe2 size={16} /> Authorised domains</h3>
                <div className="authz-chip-list">
                  {(selected.authorized_domains || []).map((domain) => (
                    <span key={domain}>{domain}</span>
                  ))}
                </div>
              </div>

              <div className="authz-detail-section">
                <h3><ShieldCheck size={16} /> Permitted testing methods</h3>
                <div className="authz-method-list">
                  {(selected.permitted_methods || []).map((method) => (
                    <div key={method}>
                      <CheckCircle2 size={15} />
                      {prettyMethod(method)}
                    </div>
                  ))}
                </div>
              </div>

              {needsDateReview && (
                <div className="authz-expired-notice" role="status">
                  Legacy dates have no reliable timezone. Keep this record for history and
                  create a replacement through the API using dates from the original written permission.
                  No current validity is granted by this record.
                </div>
              )}

              {pendingExpired && (
                <div className="authz-expired-notice">
                  <AlertCircle size={16} />
                  This authorization validity period has expired.
                  The backend will not allow approval.
                </div>
              )}

              <div className="authz-detail-section">
                <h3><History size={16} /> Audit history</h3>

                {auditLoading ? (
                  <div className="authz-audit-loading">
                    <LoaderCircle className="spin" size={17} />
                    Loading audit events...
                  </div>
                ) : auditError ? (
                  <div className="authz-inline-error">{auditError}</div>
                ) : events.length ? (
                  <div className="authz-timeline">
                    {events.map((item) => (
                      <div className="authz-event" key={item.id}>
                        <div className={`authz-event-dot ${item.action}`} />
                        <div>
                          <div className="authz-event-title">
                            <strong>{item.action.toUpperCase()}</strong>
                            <span>{formatDateTime(item.created_at)}</span>
                          </div>
                          <p>{item.note}</p>
                          <small>
                            Admin #{item.admin_id} · {item.previous_status}
                            {" → "}
                            {item.new_status}
                            {item.evidence_reviewed && " · Evidence reviewed"}
                          </small>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="authz-no-events">
                    No administrator decisions have been recorded yet.
                  </div>
                )}
              </div>

              {!actionType && (
                <div className="authz-actions">
                  {selected.status === "pending" && (
                    <>
                      <button
                        type="button"
                        className="authz-reject-button"
                        onClick={() => beginAction("reject")}
                      >
                        Reject request
                      </button>

                      <button
                        type="button"
                        className="authz-approve-button"
                        disabled={!evidenceReady || pendingExpired || needsDateReview || auditLoading || Boolean(auditError)}
                        onClick={() => beginAction("approve")}
                      >
                        <CheckCircle2 size={16} />
                        Approve request
                      </button>
                    </>
                  )}

                  {selected.status === "approved" && (
                    <button
                      type="button"
                      className="authz-reject-button"
                      onClick={() => beginAction("revoke")}
                    >
                      Revoke approval
                    </button>
                  )}

                  {selected.status !== "pending" &&
                    selected.status !== "approved" && (
                      <span className="authz-readonly-note">
                        No further decision is available for this status.
                      </span>
                    )}
                </div>
              )}

              {actionType && (
                <form className="authz-action-form" onSubmit={handleAction}>
                  <div className="authz-action-heading">
                    <strong>
                      {actionType === "approve"
                        ? "Approve authorization"
                        : actionType === "reject"
                          ? "Reject authorization"
                          : "Revoke authorization"}
                    </strong>
                    <span>
                      {actionType === "approve"
                        ? "Record your review of the written permission."
                        : "Enter the reason for this decision."}
                    </span>
                  </div>

                  {actionType === "approve" && (
                    <label className="authz-evidence-check">
                      <input
                        type="checkbox"
                        checked={evidenceReviewed}
                        onChange={(event) =>
                          setEvidenceReviewed(event.target.checked)
                        }
                      />
                      <span>
                        I have reviewed the original written authorisation,
                        verified the authorised domains and checked the
                        permitted methods.
                      </span>
                    </label>
                  )}

                  <label className="authz-note-field">
                    <span>
                      {actionType === "approve"
                        ? "Review note (minimum 20 characters)"
                        : "Reason (minimum 10 characters)"}
                    </span>
                    <textarea
                      value={reviewNote}
                      onChange={(event) => setReviewNote(event.target.value)}
                      minLength={actionType === "approve" ? 20 : 10}
                      maxLength={2000}
                      rows={4}
                      placeholder={
                        actionType === "approve"
                          ? "Describe the evidence reviewed and how the permitted scope was verified..."
                          : "Explain the reason for this decision..."
                      }
                      required
                    />
                    <small>{reviewNote.trim().length} / 2000 characters</small>
                  </label>

                  {actionError && (
                    <div className="authz-inline-error">
                      <AlertCircle size={15} />
                      {actionError}
                    </div>
                  )}

                  <div className="authz-action-buttons">
                    <button
                      type="button"
                      className="secondary-button"
                      onClick={() => {
                        setActionType("");
                        setActionError("");
                      }}
                      disabled={submitting}
                    >
                      Cancel
                    </button>

                    <button
                      type="submit"
                      className={
                        actionType === "approve"
                          ? "authz-approve-button"
                          : "authz-reject-button"
                      }
                      disabled={
                        submitting ||
                        (actionType === "approve" &&
                          (!evidenceReviewed || reviewNote.trim().length < 20)) ||
                        (actionType !== "approve" &&
                          reviewNote.trim().length < 10)
                      }
                    >
                      {submitting ? (
                        <LoaderCircle className="spin" size={16} />
                      ) : null}
                      {submitting
                        ? "Saving decision..."
                        : actionType === "approve"
                          ? "Confirm approval"
                          : actionType === "reject"
                            ? "Confirm rejection"
                            : "Confirm revocation"}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

export default AuthorizationPage;
