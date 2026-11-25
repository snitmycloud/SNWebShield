"""Extra TLS probes for the configuration checks. Each is ONE handshake to the pinned IP, nothing more:
no data is sent after the handshake, nothing is stored but the answer, and every outcome that is not a clear yes/no is
"could_not_check" (never "fine").

* protocol_supported(): does the server still accept TLS 1.0 / TLS 1.1?
* weak_cipher_accepted(): does it still accept a clearly weak cipher (RC4, 3DES, export or anonymous suites)?
* trust(): does a normal, verifying client accept the certificate (valid chain, matching name)?
"""
import asyncio
import re
import ssl

from app.services import netio

ACCEPTED, REFUSED, UNKNOWN = "accepted", "refused", "could_not_check"
LOCAL = "unsupported_here"   # this computer's own TLS library cannot make the test: a limit of ours, not an answer
VERSIONS = {"TLSv1": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1}
WEAK_CIPHERS = "RC4:3DES:DES:EXPORT:NULL:aNULL:eNULL:@SECLEVEL=0"
# Cipher names (as OpenSSL reports a negotiated cipher) that count as weak.
WEAK_NAME = re.compile(r"RC4|RC2|DES|DES-CBC|3DES|DES-CBC3|EXP|NULL|ADH|AECDH|MD5", re.I)
# Our own OpenSSL cannot offer this protocol or cipher at all: that is OUR limit, not an answer from the server.
LOCAL_LIMITS = ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "NO_CIPHER_MATCH", "NO_SHARED_CIPHER_LOCAL", "UNSUPPORTED_PROTOCOL_LOCAL")


def _probe_context(version=None, ciphers=None, maximum=None) -> ssl.SSLContext | None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        if version is not None:
            context.minimum_version = context.maximum_version = version
        else:
            context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        if maximum is not None:
            context.maximum_version = maximum
        context.set_ciphers(ciphers or "DEFAULT:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        return None
    return context


async def _handshake(ip, port, domain, context, timeout):
    """('accepted', ssl_object) | ('refused', None) | ('could_not_check', None)."""
    try:
        reader, writer = await netio.open_connection(ip, port, tls=True, server_name=domain, timeout=timeout, ssl_context=context)
    except ssl.SSLCertVerificationError:
        return ACCEPTED, None  # only possible with a verifying context; callers that verify use trust()
    except ssl.SSLError as error:
        reason = (getattr(error, "reason", "") or "").upper()
        return (LOCAL, None) if any(item in reason for item in LOCAL_LIMITS) else (REFUSED, None)
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        # Many servers (IIS, load balancers) refuse a protocol they have switched off by closing the connection. We only
        # probe ports that completed a normal TLS handshake moments earlier, so a reset now is a refusal.
        return REFUSED, None
    except (asyncio.TimeoutError, OSError):
        return UNKNOWN, None  # no answer at all tells us nothing
    info = writer.get_extra_info("ssl_object")
    await netio.close(writer)
    return ACCEPTED, info


async def protocol_supported(ip: str, port: int, domain: str, version_name: str, *, timeout: float = 2.0) -> str:
    context = _probe_context(VERSIONS[version_name])
    if context is None:
        return LOCAL
    state, _ = await _handshake(ip, port, domain, context, timeout)
    return state


async def weak_cipher_accepted(ip: str, port: int, domain: str, *, timeout: float = 2.0) -> str:
    """'accepted' (a weak cipher works), 'refused', 'unsupported_here' (our OpenSSL has no weak cipher to offer) or 'could_not_check'."""
    # Capped at TLS 1.2: TLS 1.3 ignores the cipher list, so it could never show a weak cipher.
    context = _probe_context(None, WEAK_CIPHERS, maximum=ssl.TLSVersion.TLSv1_2)
    if context is None:
        return LOCAL
    state, info = await _handshake(ip, port, domain, context, timeout)
    if state != ACCEPTED:
        return state
    cipher = info.cipher()[0] if info is not None and info.cipher() else ""
    return ACCEPTED if WEAK_NAME.search(cipher) else REFUSED


async def trust(ip: str, port: int, domain: str, *, timeout: float = 2.0) -> dict:
    """Does a verifying client accept this server's certificate? {'state': 'trusted'|'untrusted'|'could_not_check', 'reason'}"""
    context = ssl.create_default_context()
    try:
        reader, writer = await netio.open_connection(ip, port, tls=True, server_name=domain, timeout=timeout, ssl_context=context)
    except ssl.SSLCertVerificationError as error:
        return {"state": "untrusted", "reason": netio.clean_text(getattr(error, "verify_message", "") or "certificate not trusted", 120),
                "code": getattr(error, "verify_code", None)}
    except (ssl.SSLError, asyncio.TimeoutError, OSError):
        return {"state": "could_not_check", "reason": "handshake_failed"}
    await netio.close(writer)
    return {"state": "trusted", "reason": None, "code": 0}
