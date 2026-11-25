"""The ONE place where a scan opens a network connection to a target, plus text clean-up for untrusted data.

Keeping it in one place means (a) every connection goes to the single IP pinned for the scan, and (b) tests can
replace it, so no test ever reaches the internet.
"""
import asyncio
import re
import ssl

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]")


def clean_text(value, limit: int = 200) -> str:
    """Untrusted bytes or text -> short plain text: control and bidi characters removed, cut to `limit`."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    text = _CONTROL.sub("", str(value)).replace("\r\n", "\n").replace("\r", "\n")
    return text[:limit]


def tls_context() -> ssl.SSLContext:
    """A context for LOOKING at a server's TLS, not for trusting it: nothing sent over it is secret."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")  # we are inspecting, so old servers must still answer
    except ssl.SSLError:
        pass
    return context


async def open_connection(ip: str, port: int, *, tls: bool = False, server_name: str | None = None, timeout: float = 1.5):
    """Open a TCP (optionally TLS) connection to `ip`. SNI uses `server_name`. Raises on refusal or timeout."""
    kwargs = {}
    if tls:
        kwargs = {"ssl": tls_context(), "server_hostname": server_name or None, "ssl_handshake_timeout": timeout}
    return await asyncio.wait_for(asyncio.open_connection(ip, port, **kwargs), timeout)


async def close(writer) -> None:
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 0.5)
    except Exception:
        pass


async def read_some(reader, limit: int, timeout: float) -> bytes:
    """Read up to `limit` bytes, waiting at most `timeout` for the first data. Empty bytes if nothing arrives."""
    try:
        return await asyncio.wait_for(reader.read(limit), timeout)
    except (asyncio.TimeoutError, ConnectionError, ssl.SSLError, OSError):
        return b""


async def read_until_end(reader, limit: int, timeout: float) -> bytes:
    """Read until the server closes, at most `limit` bytes and `timeout` seconds in total."""
    data = bytearray()
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while len(data) < limit:
        left = end - loop.time()
        if left <= 0:
            break
        chunk = await read_some(reader, min(65536, limit - len(data)), left)
        if not chunk:
            break
        data += chunk
    return bytes(data)
