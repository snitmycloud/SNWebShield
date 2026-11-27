"""Shared helpers for the Phase 1 account, website and scan tests."""
from email import message_from_bytes
from email.policy import default as default_policy
from pathlib import Path
import re
from uuid import uuid4

from app.core.config import settings
from app.core.security import hash_password
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.models.admin import Admin

PASSWORD = "A-strong-test-password-123!"


def make_account(role="user", *, verified=True, active=True, plan="free", password=PASSWORD, email=None):
    email = email or f"{role}-{uuid4().hex[:10]}@example.com"
    with SessionLocal() as db:
        account = Admin(email=email, full_name=f"Test {role}", password_hash=hash_password(password), role=role,
                        is_active=active, plan=plan, email_verified_at=utc_now() if verified else None)
        db.add(account)
        db.commit()
        return account.id, email


def login(client, email, password=PASSWORD):
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def account_headers(client, role="user", **kwargs):
    account_id, email = make_account(role, **kwargs)
    return account_id, email, login(client, email, kwargs.get("password", PASSWORD))


def outbox_messages(to=None):
    folder = Path(settings.mail_outbox_dir)
    if not folder.exists():
        return []
    messages = []
    for path in sorted(folder.glob("*.eml")):
        message = message_from_bytes(path.read_bytes(), policy=default_policy)
        if to is None or message["To"] == to:
            messages.append(message)
    return messages


def latest_link_token(to, path):
    """The token from the newest email to `to` whose link points at /<path>."""
    for message in reversed(outbox_messages(to)):
        found = re.search(rf"/{path}\?token=([A-Za-z0-9_-]+)", message.get_body(preferencelist=("plain",)).get_content())
        if found:
            return found.group(1)
    raise AssertionError(f"No {path} email for {to}")
