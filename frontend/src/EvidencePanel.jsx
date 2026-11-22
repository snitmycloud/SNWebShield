import React, { useCallback, useEffect, useState } from "react";
import { api } from "./lib/api.js";

export default function EvidencePanel({ authorization, adminId, onReady }) {
  const [data, setData] = useState(null), [events, setEvents] = useState([]);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [comment, setComment] = useState(""), [decision, setDecision] = useState("accepted");
  const [inspected, setInspected] = useState(false), [reason, setReason] = useState("");
  const [preview, setPreview] = useState(null);
  const id = authorization.id;
  const load = useCallback(async () => {
    const [current, history] = await Promise.all([api.getEvidence(id), api.getEvidenceEvents(id)]);
    setData(current); setEvents(history);
  }, [id]);
  useEffect(() => {
    let active = true;
    Promise.all([api.getEvidence(id), api.getEvidenceEvents(id)]).then(([current, history]) => {
      if (active) { setData(current); setEvents(history); }
    }).catch(e => { if (active) setError(e.message); });
    return () => { active = false; onReady(false); };
  }, [id, onReady]);
  useEffect(() => {
    const latest = data?.reviews.find(r => r.revision === data.revision && r.reviewer_id === adminId);
    onReady(Boolean(latest?.decision === "accepted" && data.documents.some(d => d.state === "available")));
  }, [data, adminId, onReady]);
  useEffect(() => () => { if (preview) URL.revokeObjectURL(preview); }, [preview]);
  async function run(action) {
    setBusy(true); setError("");
    try { await action(); await load(); } catch (e) { setError(e.message); onReady(false); await load().catch(() => {}); }
    finally { setBusy(false); }
  }
  async function open(document, image = false) {
    const blob = await api.openEvidence(document.id, image);
    const url = URL.createObjectURL(blob);
    if (image) setPreview(url);
    else {
      const link = window.document.createElement("a"); link.href = url; link.download = document.filename;
      link.click(); setTimeout(() => URL.revokeObjectURL(url), 60000);
    }
  }
  return <section className="evidence-panel">
    <h3>Signed permission documents</h3>
    <p>Inspect every current document, then record your review. PDF files download for inspection; images support a safe preview.</p>
    {error && <p role="alert" className="form-error">{error}</p>}
    {authorization.status === "pending" && <label>Upload permission document (PDF, PNG or JPEG; default limit 10 MB)
      <input type="file" aria-label="Upload permission document" accept=".pdf,.png,.jpg,.jpeg" disabled={busy}
        onChange={e => { const file = e.target.files[0]; if (file) run(async () => {
          onReady(false); setInspected(false); await api.uploadEvidence(id, file);
        }); e.target.value = ""; }} />
    </label>}
    {busy && <p role="status">Processing evidence…</p>}
    {!data && <p>Loading evidence…</p>}
    {data && !data.documents.length && <p>No permission documents uploaded. Approval requires an accepted evidence review.</p>}
    {data?.documents.map(d => <article className="evidence-document" key={d.id}>
      <strong>{d.filename}</strong> — {d.state}
      <p>{d.size} bytes · Uploaded by admin #{d.uploader_id} · {new Date(d.uploaded_at).toLocaleString()}</p>
      <p>SHA-256: <code>{d.sha256}</code></p>
      <p>Retain until {new Date(d.retain_until).toLocaleString()} · Legal hold: {d.legal_hold ? "Yes" : "No"}</p>
      {d.state === "available" && <>
        <button type="button" disabled={busy} onClick={() => run(() => open(d))}>Download {d.filename}</button>
        {d.media_type !== "application/pdf" && <button type="button" disabled={busy} onClick={() => run(() => open(d, true))}>Preview {d.filename}</button>}
        {authorization.status !== "approved" && <button type="button" disabled={busy || reason.trim().length < 10}
          onClick={() => run(() => api.evidenceAction(d.id, "withdraw", { reason }))}>Withdraw {d.filename}</button>}
      </>}
      {!['purged', 'deletion_pending'].includes(d.state) && <button type="button" disabled={busy || reason.trim().length < 10}
        onClick={() => run(() => api.evidenceAction(d.id, "hold", { reason, legal_hold: !d.legal_hold }))}>{d.legal_hold ? "Release" : "Place"} legal hold on {d.filename}</button>}
      {['withdrawn', 'deletion_pending'].includes(d.state) && <button type="button" disabled={busy || reason.trim().length < 10 || d.legal_hold}
        onClick={() => run(() => api.evidenceAction(d.id, "purge", { reason }))}>Purge {d.filename} after retention</button>}
    </article>)}
    {preview && <div><img src={preview} alt="Permission document preview" style={{maxWidth:"100%"}} /><button type="button" onClick={() => setPreview(null)}>Close preview</button></div>}
    <label>Reason for withdrawal, hold changes or deletion (minimum 10 characters)
      <input value={reason} onChange={e => setReason(e.target.value)} maxLength={2000} />
    </label>
    {authorization.status === "pending" && <div className="evidence-review">
      <h4>Human evidence review — revision {data?.revision ?? "…"}</h4>
      <label>Evidence review decision <select value={decision} onChange={e => setDecision(e.target.value)}>
        <option value="accepted">Accept evidence</option><option value="rejected">Reject evidence</option>
      </select></label>
      <label>Evidence review comments<textarea value={comment} onChange={e => setComment(e.target.value)} maxLength={2000} /></label>
      <label><input type="checkbox" checked={inspected} onChange={e => setInspected(e.target.checked)} />I inspected all current documents and checked the signatory, domains, methods and dates.</label>
      <button type="button" disabled={busy || !data || !inspected || comment.trim().length < 20}
        onClick={() => run(() => api.reviewEvidence(id, { revision: data.revision, decision, inspected: true, comment }))}>Record evidence review</button>
    </div>}
    <h4>Evidence review history</h4>
    {data?.reviews.map(r => <p key={r.id}>{r.decision} · revision {r.revision} · admin #{r.reviewer_id} · {new Date(r.reviewed_at).toLocaleString()} — {r.comment}</p>)}
    <h4>Evidence audit history</h4>
    {events.map(e => <p key={e.id}>{e.action} · admin #{e.actor_id} · {new Date(e.occurred_at).toLocaleString()} — {e.comment}</p>)}
  </section>;
}
