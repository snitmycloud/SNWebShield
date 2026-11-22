from datetime import timedelta
from io import BytesIO
from pathlib import Path

import pytest
from pypdf import PdfWriter
from sqlalchemy import select

from app.core.config import settings
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.models.evidence import AuthorizationEvidence, EvidenceEvent
from app.services.evidence import stored_path
from evidence_helpers import attach_review, png
from test_auth import create_admin_and_login
from test_authorization_correctness import api, seed_record, APPROVAL


def upload(api, authorization_id, content=None, filename="permission.png"):
    return api.post(f"/api/v1/authorizations/{authorization_id}/evidence", content=png() if content is None else content,
                    headers={"X-Evidence-Filename": filename, "Content-Type": "application/octet-stream"})


def review(api, authorization_id, decision="accepted", revision=None):
    if revision is None: revision = api.get(f"/api/v1/authorizations/{authorization_id}/evidence").json()["revision"]
    return api.post(f"/api/v1/authorizations/{authorization_id}/evidence/reviews", json={
        "revision": revision, "decision": decision, "inspected": True,
        "comment": "Inspected the signed synthetic permission and exact domain scope.",
    })


def test_upload_metadata_download_preview_and_human_review(api):
    record_id, website_id = seed_record()
    assert api.post(f"/api/v1/authorizations/{record_id}/approve", json=APPROVAL).status_code == 409
    response = upload(api, record_id); assert response.status_code == 201, response.text
    document = response.json(); key = document["id"]
    assert document["website_id"] == website_id and document["uploader_id"] == api.admin_id
    assert len(document["sha256"]) == 64
    assert stored_path(key).name == key and "permission" not in str(stored_path(key))
    assert review(api, record_id).status_code == 409
    opened = api.get(f"/api/v1/evidence/{key}/preview")
    assert opened.status_code == 200 and opened.content.startswith(b"\x89PNG")
    assert opened.headers["cache-control"] == "no-store, private"
    assert api.get(f"/api/v1/evidence/{key}/download").content == png()
    assert review(api, record_id).status_code == 201
    approved = api.post(f"/api/v1/authorizations/{record_id}/approve", json=APPROVAL)
    assert approved.status_code == 200, approved.text
    assert api.get(f"/api/v1/authorizations/{record_id}/events").json()[0]["evidence_review_id"]
    assert upload(api, record_id).status_code == 409
    events = api.get(f"/api/v1/authorizations/{record_id}/evidence/events").json()
    assert {e["action"] for e in events} >= {"uploaded", "opened", "review_accepted"}


@pytest.mark.parametrize("filename,content", [
    ("x.pdf", b"%PDF-broken"), ("x.png", b"not an image"), ("x.html", b"<html>"),
    ("../x.png", b"anything"), ("C:%5Csecret.png", b"anything"), ("x.png", b""),
    ("x.jpg", png()), ("x.png%00.pdf", b"anything"),
])
def test_invalid_uploads_rejected_without_files(api, filename, content):
    record_id, _ = seed_record()
    root = Path(settings.evidence_root); before = set(root.glob("*"))
    assert upload(api, record_id, content, filename).status_code == 422
    assert set(root.glob("*")) == before


def test_size_limit_cleanup(api, monkeypatch):
    record_id, _ = seed_record(); monkeypatch.setattr(settings, "evidence_max_bytes", 1024)
    assert upload(api, record_id, b"x" * 1025).status_code == 413
    assert api.get(f"/api/v1/authorizations/{record_id}/evidence").json()["documents"] == []


def test_pdf_parser_rejects_active_content(api):
    record_id, _ = seed_record()
    writer = PdfWriter(); writer.add_blank_page(width=100, height=100)
    out = BytesIO(); writer.write(out)
    result = upload(api, record_id, out.getvalue(), "signed.pdf")
    assert result.status_code == 201, result.text
    key = result.json()["id"]
    assert api.get(f"/api/v1/evidence/{key}/preview").status_code == 422
    with pytest.warns(DeprecationWarning):
        writer.add_js("app.alert('synthetic')")
    out = BytesIO(); writer.write(out)
    assert upload(api, record_id, out.getvalue(), "active.pdf").status_code == 422


def test_upload_invalidates_accepted_review_and_old_revision(api):
    record_id, _ = seed_record(); attach_review(api, record_id)
    old_revision = api.get(f"/api/v1/authorizations/{record_id}/evidence").json()["revision"]
    new = upload(api, record_id); assert new.status_code == 201
    assert review(api, record_id, revision=old_revision).status_code == 409
    assert api.post(f"/api/v1/authorizations/{record_id}/approve", json=APPROVAL).status_code == 409
    api.get(f"/api/v1/evidence/{new.json()['id']}/download")
    assert review(api, record_id, decision="rejected").status_code == 201
    assert api.post(f"/api/v1/authorizations/{record_id}/approve", json=APPROVAL).status_code == 409


def test_review_is_bound_to_reviewer_and_unauthenticated_access_denied(api):
    record_id, _ = seed_record(); key = attach_review(api, record_id)
    old_headers = dict(api.headers)
    _, second_headers = create_admin_and_login(api)
    api.headers.update(second_headers)
    assert api.post(f"/api/v1/authorizations/{record_id}/approve", json=APPROVAL).status_code == 409
    api.headers.pop("Authorization")
    assert api.get(f"/api/v1/evidence/{key}/download").status_code == 401
    assert api.get(f"/api/v1/authorizations/{record_id}/evidence").status_code == 401
    assert upload(api, record_id).status_code == 401
    api.headers.update(old_headers)


def test_hash_tampering_blocks_approval(api):
    record_id, _ = seed_record(); key = attach_review(api, record_id)
    stored_path(key).write_bytes(b"tampered")
    assert api.get(f"/api/v1/evidence/{key}/download").status_code == 409
    assert api.post(f"/api/v1/authorizations/{record_id}/approve", json=APPROVAL).status_code == 409


def test_retention_hold_and_purge_preserve_history(api):
    record_id, _ = seed_record(); key = attach_review(api, record_id)
    reason = {"reason": "Synthetic document withdrawn under the retention policy."}
    assert api.post(f"/api/v1/evidence/{key}/withdraw", json=reason).status_code == 200
    assert api.get(f"/api/v1/evidence/{key}/download").status_code == 410
    assert api.post(f"/api/v1/evidence/{key}/purge", json=reason).status_code == 409
    with SessionLocal() as db:
        db.get(AuthorizationEvidence, key).retain_until = utc_now() - timedelta(days=1); db.commit()
    assert api.post(f"/api/v1/evidence/{key}/hold", json={**reason, "legal_hold": True}).status_code == 200
    assert api.post(f"/api/v1/evidence/{key}/purge", json=reason).status_code == 409
    api.post(f"/api/v1/evidence/{key}/hold", json={**reason, "legal_hold": False})
    assert api.post(f"/api/v1/evidence/{key}/purge", json=reason).status_code == 200
    assert not stored_path(key).exists()
    listing = api.get(f"/api/v1/authorizations/{record_id}/evidence").json()
    assert listing["documents"][0]["state"] == "purged" and listing["reviews"]


def test_cross_record_listing_and_duplicate_names(api):
    record_id, _ = seed_record(); other_id, _ = seed_record()
    first = upload(api, record_id).json(); second = upload(api, record_id).json()
    assert first["id"] != second["id"] and stored_path(first["id"]).exists()
    assert api.get(f"/api/v1/authorizations/{other_id}/evidence").json()["documents"] == []


def test_failed_commit_removes_uncommitted_file(api, monkeypatch):
    record_id, _ = seed_record()
    before = set(Path(settings.evidence_root).glob("*"))
    def fail(*args, **kwargs): raise RuntimeError("synthetic database outage")
    monkeypatch.setattr(SessionLocal.class_, "commit", fail)
    with pytest.raises(RuntimeError, match="synthetic database"):
        upload(api, record_id)
    assert set(Path(settings.evidence_root).glob("*")) == before


def test_changed_revision_between_review_check_and_approval_is_rejected(api, monkeypatch):
    from sqlalchemy import update
    from app.models.authorization import WebsiteAuthorization
    from app.services import evidence
    record_id, _ = seed_record(); attach_review(api, record_id)
    original = evidence.accepted_review
    def raced(db, record, admin_id):
        result = original(db, record, admin_id)
        with SessionLocal() as concurrent:
            concurrent.execute(update(WebsiteAuthorization).where(WebsiteAuthorization.id == record_id).values(
                evidence_revision=WebsiteAuthorization.evidence_revision + 1))
            concurrent.commit()
        return result
    monkeypatch.setattr(evidence, "accepted_review", raced)
    assert api.post(f"/api/v1/authorizations/{record_id}/approve", json=APPROVAL).status_code == 409
    assert api.get(f"/api/v1/authorizations/{record_id}").json()["status"] == "pending"


def test_purge_failure_can_be_retried_without_exposing_file(api, monkeypatch):
    record_id, _ = seed_record(); key = attach_review(api, record_id)
    reason = {"reason": "Synthetic retention expiry purge test."}
    api.post(f"/api/v1/evidence/{key}/withdraw", json=reason)
    with SessionLocal() as db:
        db.get(AuthorizationEvidence, key).retain_until = utc_now() - timedelta(days=1); db.commit()
    original = Path.unlink
    def fail(path, *args, **kwargs):
        if path.name == key: raise OSError("synthetic disk failure")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", fail)
    with pytest.raises(OSError): api.post(f"/api/v1/evidence/{key}/purge", json=reason)
    assert api.get(f"/api/v1/evidence/{key}/download").status_code == 410
    monkeypatch.setattr(Path, "unlink", original)
    assert api.post(f"/api/v1/evidence/{key}/purge", json=reason).status_code == 200


def test_cors_preflight_allows_binary_upload_header(api):
    response = api.options("/api/v1/authorizations/1/evidence", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type,x-evidence-filename",
    })
    assert response.status_code == 200
