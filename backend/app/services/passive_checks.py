"""Extra passive observations derived from data the single authorised HEAD already returned.

These run in the backend only. They are deliberately NOT part of header_analyzer.analyze(), which is
also baked into the scanner image on the VM and must match byte for byte: changing it would break the
remote profile until the image is rebuilt and re-pinned. No new request, probe or tool is involved.
Every result is an unconfirmed observation; a human decides whether a real vulnerability exists.
"""
import ssl
from datetime import UTC, datetime

from app.core.time import as_utc, utc_now

EXPIRY_WARNING_DAYS = 30
EXPIRY_URGENT_DAYS = 7


def _observation(check, observed, severity, ref, explanation):
    return {"check": check, "observed": observed, "severity_suggestion": severity if observed is False else "informational",
            "requires_human_validation": True, "confirmed_vulnerability": False,
            "evidence_ref": ref, "explanation": explanation}


def _days_left(not_after, now):
    """Days until expiry. The broker stores OpenSSL's notAfter text ("Dec  1 12:00:00 2026 GMT"); ISO is also accepted."""
    if not isinstance(not_after, str) or len(not_after) > 64:
        return None
    try:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC)
    except (ValueError, OverflowError, OSError):
        try:
            expires = as_utc(datetime.fromisoformat(not_after.replace("Z", "+00:00")))
        except ValueError:
            return None
    return (expires - as_utc(now)).total_seconds() / 86400


def extra_observations(transport, facts, now=None):
    """Return observations for HTTPS use, certificate lifetime and cookie flags.

    `observed` follows the analyzer's convention: True means the good state, False means review needed,
    None means not applicable to this response (so no record is created).
    """
    now = now or utc_now()
    transport, facts = transport or {}, facts or {}
    https = transport.get("tls_verified") if type(transport.get("tls_verified")) is bool else facts.get("https")
    https = https if type(https) is bool else None

    days = _days_left(transport.get("certificate_not_after"), now) if https else None
    if days is None:
        expiry, severity = None, "low"
    else:
        expiry = days > EXPIRY_WARNING_DAYS
        severity = "medium" if days <= EXPIRY_URGENT_DAYS else "low"

    cookies = facts.get("cookies") if isinstance(facts.get("cookies"), dict) else {}
    count = cookies.get("count") if type(cookies.get("count")) is int else 0
    missing = [cookies.get(k) for k in ("secure_missing", "httponly_missing", "samesite_missing")]
    cookie_ok = None if count <= 0 or any(type(m) is not int for m in missing) else not any(missing)

    return [
        _observation("https_in_use", https, "medium", "request.scheme",
                     "The site was reached over plain HTTP. Confirm whether an HTTPS version and redirect exist."),
        _observation("certificate_expiry", expiry, severity, "tls.certificate.not_after",
                     "The TLS certificate is within 30 days of expiry (or already expired). Confirm the renewal process."),
        _observation("cookie_flags", cookie_ok, "low", "response.set-cookie.attributes",
                     "At least one cookie lacks Secure, HttpOnly or SameSite. Cookie names and values are never stored; "
                     "an analyst must judge whether the cookie is security-relevant."),
    ]


def merge(analysis, transport, facts, now=None):
    """Return a copy of a validated analysis with the applicable extra observations and limitations appended."""
    merged = dict(analysis)
    # Not-applicable results (no cookies, no certificate date) are left out so analysts are never asked
    # to review an observation that cannot apply to this response.
    applicable = [o for o in extra_observations(transport, facts, now) if o["observed"] is not None]
    merged["observations"] = list(analysis["observations"]) + applicable
    merged["limitations"] = list(analysis.get("limitations", [])) + ["cookie_names_and_values_never_retained"]
    return merged
