"""Account emails (verification and password reset).

Real email: set SMTP_HOST, SMTP_PORT, SMTP_SECURITY (ssl or starttls), SMTP_SENDER and, if your provider needs
them, SMTP_USERNAME / SMTP_PASSWORD in backend/.env.

Development fallback: when SMTP_HOST or SMTP_SENDER is empty, each email is written as a .eml file into
MAIL_OUTBOX_DIR (default: ~/SNWebShield-Private/outbox, outside the repository). Open the file to click the link.
Nothing here ever prints or logs a message body, link or token.
"""
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
import os
import smtplib
import ssl
from uuid import uuid4

from app.core.config import settings

REPO_ROOT = Path(__file__).resolve().parents[3]


def smtp_configured() -> bool:
    return bool(settings.smtp_host and settings.smtp_sender)


def channel() -> str:
    return "smtp" if smtp_configured() else "outbox"


def outbox_dir() -> Path:
    path = Path(settings.mail_outbox_dir).expanduser().resolve()
    # Emails contain one-time links; never write them anywhere they could be committed.
    if path == REPO_ROOT or REPO_ROOT in path.parents:
        raise RuntimeError("MAIL_OUTBOX_DIR must be outside the repository")
    return path


def _message(to: str, subject: str, body: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = settings.smtp_sender or "SNWebShield <no-reply@snwebshield.local>"
    message["To"] = to
    message["Subject"] = subject
    message["Message-ID"] = f"<{uuid4()}@snwebshield.local>"
    message.set_content(body)
    return message


def send(to: str, subject: str, body: str) -> str:
    """Send one email. Returns the channel used. Raises on SMTP failure (the caller decides what to show)."""
    message = _message(to, subject, body)
    if smtp_configured():
        context = ssl.create_default_context()
        if settings.smtp_security == "ssl":
            smtp = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=15, context=context)
        else:
            smtp = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15)
        with smtp:
            if settings.smtp_security == "starttls":
                smtp.starttls(context=context)
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password.get_secret_value())
            smtp.send_message(message)
        return "smtp"
    folder = outbox_dir()
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    path = folder / f"{stamp}-{uuid4().hex[:8]}.eml"
    path.write_bytes(bytes(message))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return "outbox"
