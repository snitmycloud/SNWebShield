"""Authentication audit trail and login throttling (risks R1 and R2).

Events never contain a password, token or raw email address. Attempts are keyed by a SHA-256 of the
normalised email and by the TCP peer address (a forwarded-for header is never trusted, because a
client could forge it to dodge the limit).

Throttling counts recent `login_failure` events, so the limit is durable across restarts and shared by
every worker process. Three scopes apply, each over a sliding window:

* the same email from the same address: `login_max_failures`;
* the same email from anywhere: 4x that (blocks distributed guessing, but a victim is not locked out by
  one noisy address);
* the same address against any email: 4x that (blocks credential stuffing).

Failures before the account's last successful login are not counted. While throttled, even a correct
password is refused with 429 and no password hash is computed.
"""
from datetime import timedelta
from hashlib import sha256

from sqlalchemy import func, select

from app.core.config import settings
from app.core.time import as_utc, utc_now
from app.models.security import AuthEvent

MAX_IP_LENGTH = 64


def email_digest(email: str) -> str:
    return sha256(email.strip().lower().encode("utf-8")).hexdigest()


def client_ip(request) -> str:
    host = request.client.host if request.client else "unknown"
    return str(host)[:MAX_IP_LENGTH]


def record(db, event_type, email, ip, *, admin_id=None, reason="", detail=None):
    """Add an event to the session. The caller commits (so it can be committed before raising)."""
    row = AuthEvent(occurred_at=utc_now(), event_type=event_type, email_sha256=email_digest(email), admin_id=admin_id,
                    client_ip=ip[:MAX_IP_LENGTH], reason=reason[:40], detail=detail or {})
    db.add(row)
    return row


def retry_after_seconds(db, email, ip) -> int:
    """Seconds until a login attempt would be considered, or 0 when it may proceed."""
    now = utc_now()
    window = timedelta(minutes=settings.login_window_minutes)
    since = now - window
    digest = email_digest(email)
    last_success = db.scalar(select(func.max(AuthEvent.occurred_at)).where(
        AuthEvent.event_type == "login_success", AuthEvent.email_sha256 == digest))
    email_since = max(since, as_utc(last_success)) if last_success else since
    base = settings.login_max_failures
    scopes = (
        ((AuthEvent.email_sha256 == digest, AuthEvent.client_ip == ip), email_since, base),
        ((AuthEvent.email_sha256 == digest,), email_since, base * 4),
        ((AuthEvent.client_ip == ip,), since, base * 4),
    )
    wait = 0
    for conditions, start, limit in scopes:
        times = list(db.scalars(select(AuthEvent.occurred_at).where(
            AuthEvent.event_type == "login_failure", AuthEvent.occurred_at > start, *conditions)
            .order_by(AuthEvent.occurred_at)))
        if len(times) >= limit:
            # The lock lifts when enough old failures age out of the window to drop below the limit.
            releasing = as_utc(times[len(times) - limit])
            wait = max(wait, int((releasing + window - now).total_seconds()) + 1)
    return max(wait, 0)
