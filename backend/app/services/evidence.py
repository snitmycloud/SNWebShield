"""Private evidence storage and review policy. No scanner execution."""
from datetime import timedelta
from hashlib import sha256
from io import BytesIO
import os
import stat
from pathlib import Path
from uuid import UUID, uuid4
import warnings

from fastapi import HTTPException
from PIL import Image
from pypdf import PdfReader
from pypdf.generic import DictionaryObject, ArrayObject, IndirectObject
from sqlalchemy import select, update
from sqlalchemy.exc import OperationalError

from app.core.config import settings
from app.core.time import as_utc, utc_now
from app.models.evidence import AuthorizationEvidence, EvidenceEvent, EvidenceReview
from app.models.authorization import WebsiteAuthorization


def storage_root():
    root = settings.evidence_root.expanduser().absolute()
    repository = Path(__file__).resolve().parents[3]
    if root.is_relative_to(repository) or root.is_symlink():
        raise HTTPException(503, "Evidence storage must be a private directory outside the repository")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.resolve() != root:
        raise HTTPException(503, "Evidence storage may not use symbolic links")
    return root


def stored_path(key):
    try:
        canonical = str(UUID(key))
    except ValueError:
        raise HTTPException(404, "Evidence not found")
    return storage_root() / canonical


def validate_file(path, filename):
    suffix = Path(filename).suffix.lower()
    with path.open("rb") as stream:
        signature = stream.read(8)
    try:
        if suffix == ".pdf" and signature.startswith(b"%PDF-"):
            reader = PdfReader(path, strict=True)
            if reader.is_encrypted or not 1 <= len(reader.pages) <= 100:
                raise ValueError("Encrypted or excessively long PDF")
            seen = set()
            budget = [20000]
            banned = {"/JavaScript", "/JS", "/Launch", "/OpenAction", "/AA", "/EmbeddedFiles", "/RichMedia", "/XFA", "/SubmitForm", "/ImportData"}
            def walk(obj):
                budget[0] -= 1
                if budget[0] < 0:
                    raise ValueError("PDF is too complex")
                if isinstance(obj, IndirectObject):
                    key = (obj.idnum, obj.generation)
                    if key in seen: return
                    seen.add(key)
                    return walk(obj.get_object())
                if isinstance(obj, DictionaryObject):
                    if banned.intersection(map(str, obj.keys())) or str(obj.get("/S")) in banned:
                        raise ValueError("PDF contains active or embedded content")
                    for value in obj.values(): walk(value)
                elif isinstance(obj, ArrayObject):
                    for value in obj: walk(value)
            walk(reader.trailer)
            for page in reader.pages:
                page.get_contents()  # Force page content parsing while bounded by upload size.
            return "application/pdf"
        expected = {".png": ("PNG", b"\x89PNG\r\n\x1a\n"), ".jpg": ("JPEG", b"\xff\xd8\xff"), ".jpeg": ("JPEG", b"\xff\xd8\xff")}
        kind, magic = expected[suffix]
        if not signature.startswith(magic): raise ValueError("Signature mismatch")
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(path) as img:
                if img.format != kind or img.width * img.height > 20_000_000 or getattr(img, "n_frames", 1) != 1:
                    raise ValueError("Unsupported image dimensions or frames")
                img.verify()
            with Image.open(path) as img: img.load()
        return "image/png" if kind == "PNG" else "image/jpeg"
    except Exception as exc:
        raise HTTPException(422, "Use a valid PDF, PNG or JPEG without encryption, active content or excessive complexity") from exc


def event(db, authorization_id, actor_id, action, evidence_id=None, comment=""):
    db.add(EvidenceEvent(id=str(uuid4()), authorization_id=authorization_id,
        evidence_id=evidence_id, actor_id=actor_id, occurred_at=utc_now(), action=action, comment=comment))


def lock_revision(db, record, *, increment=False, pending=True):
    where = [WebsiteAuthorization.id == record.id,
             WebsiteAuthorization.evidence_revision == record.evidence_revision]
    where.append(WebsiteAuthorization.status == ("pending" if pending else record.status))
    try:
        result = db.execute(update(WebsiteAuthorization).where(*where).values(
            evidence_revision=record.evidence_revision + (1 if increment else 0)
        ).execution_options(synchronize_session=False))
    except OperationalError as exc:
        db.rollback()
        if db.bind.dialect.name == "sqlite" and "locked" in str(exc).lower():
            raise HTTPException(409, "Evidence is being changed; refresh and retry") from exc
        raise
    if result.rowcount != 1:
        raise HTTPException(409, "Authorization or evidence changed. Refresh before continuing")


def available(db, authorization_id):
    return list(db.scalars(select(AuthorizationEvidence).where(
        AuthorizationEvidence.authorization_id == authorization_id,
        AuthorizationEvidence.state == "available").order_by(AuthorizationEvidence.uploaded_at)))


def verified_bytes(record):
    path = stored_path(record.id)
    if path.is_symlink() or not path.is_file():
        raise HTTPException(409, "Evidence file is missing or unavailable")
    with path.open("rb") as file:
        content = file.read(settings.evidence_max_bytes + 1)
    if len(content) != record.size or sha256(content).hexdigest() != record.sha256:
        raise HTTPException(409, "Evidence integrity check failed; approval is blocked")
    return content


def accepted_review(db, authorization, admin_id):
    review = db.scalar(select(EvidenceReview).where(
        EvidenceReview.authorization_id == authorization.id,
        EvidenceReview.revision == authorization.evidence_revision,
        EvidenceReview.reviewer_id == admin_id
    ).order_by(EvidenceReview.reviewed_at.desc(), EvidenceReview.id.desc()).limit(1))
    documents = available(db, authorization.id)
    if not review or review.decision != "accepted" or not documents or set(review.evidence_ids) != {d.id for d in documents}:
        raise HTTPException(409, "Inspect all current evidence and record an accepted human review before approval")
    for document in documents: verified_bytes(document)
    return review


def image_preview(content):
    with Image.open(BytesIO(content)) as image:
        image.thumbnail((1600, 1600))
        safe = Image.new("RGB", image.size, "white")
        safe.paste(image.convert("RGB"))
        out = BytesIO(); safe.save(out, format="PNG")
        return out.getvalue()


# --- Retention and secure deletion (risk R9) ---------------------------------------------------

OVERWRITE_METHOD = "overwrite-1pass-fsync-unlink"
_LIVE_STATES = ("available", "withdrawn", "deletion_pending")


def secure_erase(path):
    """Overwrite a stored document with random bytes, flush it to disk, then unlink it.

    The database row, with its SHA-256, is kept: the hash is the immutable audit proof that a document
    existed. Only regular files are touched; symbolic links are refused. Overwrite-in-place is
    best-effort on SSDs and journaling or copy-on-write filesystems, so keep the evidence volume
    encrypted (BitLocker) as the real protection.
    """
    if path.is_symlink():
        raise HTTPException(409, "Storage integrity error")
    try:
        mode = path.lstat()
    except FileNotFoundError:
        return "already_absent"
    if not stat.S_ISREG(mode.st_mode):
        raise HTTPException(409, "Storage integrity error")
    with path.open("r+b") as handle:
        remaining = mode.st_size
        while remaining > 0:
            chunk = min(remaining, 1024 * 1024)
            handle.write(os.urandom(chunk))
            remaining -= chunk
        handle.flush()
        os.fsync(handle.fileno())
    path.unlink()
    return OVERWRITE_METHOD


def purge_blockers(db, row, authorization, now=None):
    """Why this document cannot be purged right now (empty list = eligible once withdrawn)."""
    now = now or utc_now()
    blockers = []
    if row.legal_hold:
        blockers.append("legal_hold")
    if authorization is not None and authorization.status == "approved":
        blockers.append("authorization_approved")
    if as_utc(row.retain_until) > now:
        blockers.append("retention_period_running")
    if row.state == "available":
        blockers.append("not_withdrawn")
    return blockers


def retention_report(db, now=None):
    """Report-only sweep: documents past `retain_until`, with what still blocks their purge.

    Nothing is deleted automatically. A human withdraws and purges each document with a recorded reason.
    """
    now = now or utc_now()
    rows = db.scalars(select(AuthorizationEvidence).where(AuthorizationEvidence.state.in_(_LIVE_STATES))
                      .order_by(AuthorizationEvidence.retain_until))
    report = []
    for row in rows:
        if as_utc(row.retain_until) > now:
            continue
        authorization = db.get(WebsiteAuthorization, row.authorization_id)
        blockers = purge_blockers(db, row, authorization, now)
        report.append({"evidence_id": row.id, "authorization_id": row.authorization_id, "state": row.state,
                       "retain_until": as_utc(row.retain_until).isoformat(), "legal_hold": row.legal_hold,
                       "sha256": row.sha256, "blockers": [b for b in blockers if b != "retention_period_running"]})
    return report
