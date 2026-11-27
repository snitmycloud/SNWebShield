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


ACCENT = "#0f766e"   # the one accent colour (the logo, buttons and links everywhere)
SHIELD_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" viewBox="0 0 32 32" style="vertical-align:middle">'
              '<path d="M16 2.2 4.5 6.6v8.1c0 7.1 4.8 12.7 11.5 15.1 6.7-2.4 11.5-8 11.5-15.1V6.6L16 2.2Z" fill="#ffffff"/>'
              '<path d="m10.6 16.3 3.9 3.9 7-7.7" fill="none" stroke="#0f766e" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>')


def render_html(subject: str, body: str) -> str:
    """The plain-text message as a simple branded HTML email: the SNwebshield shield and name on the accent colour, the text as
    paragraphs with its links clickable, and the "What to do" line as a call-out. Everything is escaped; the text stays the source of truth.
    (Some mail programs hide the inline shield; the name next to it is always there.)"""
    import html
    import re

    def linkify(text: str) -> str:
        def one(match):
            url = match.group(0)
            trail = ""
            while url and url[-1] in ".,;:)":
                trail, url = url[-1] + trail, url[:-1]
            return f'<a href="{url}" style="color:{ACCENT};word-break:break-all">{url}</a>{trail}'
        return re.sub(r"https?://[^\s<]+", one, text)

    parts = []
    for paragraph in re.split(r"\n\s*\n", body.strip()):
        safe = linkify(html.escape(paragraph)).replace("\n", "<br>")
        if paragraph.startswith("What to do:"):
            parts.append(f'<p style="margin:16px 0;padding:12px 14px;background:#e1f4f1;border-left:4px solid {ACCENT};border-radius:6px;color:#0a3f3b;font-size:15px"><strong>{safe}</strong></p>')
        else:
            parts.append(f'<p style="margin:0 0 14px;font-size:15px;line-height:1.55;color:#14213a">{safe}</p>')
    return (f'<!doctype html><html><body style="margin:0;background:#f3f6fa;font-family:Segoe UI,Arial,sans-serif">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f6fa"><tr><td align="center" style="padding:24px 12px">'
            f'<table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:10px;overflow:hidden;border:1px solid #dde4ee">'
            f'<tr><td style="background:{ACCENT};padding:16px 22px;color:#ffffff;font-size:20px;font-weight:700">{SHIELD_SVG} <span style="vertical-align:middle">SNwebshield</span></td></tr>'
            f'<tr><td style="padding:22px">{"".join(parts)}</td></tr>'
            f'<tr><td style="padding:14px 22px;background:#f7f9fc;color:#4d5b72;font-size:13px">SNwebshield &middot; monitors, detects, identifies and reports the security of your websites.</td></tr>'
            f'</table></td></tr></table></body></html>')


def _message(to: str, subject: str, body: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = settings.smtp_sender or "SNwebshield <no-reply@snwebshield.local>"
    message["To"] = to
    message["Subject"] = subject
    message["Message-ID"] = f"<{uuid4()}@snwebshield.local>"
    message.set_content(body)
    message.add_alternative(render_html(subject, body), subtype="html")
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
