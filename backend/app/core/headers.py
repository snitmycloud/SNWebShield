"""Pure ASGI middleware that adds HTTP security headers to every API response.

It is not BaseHTTPMiddleware, so streamed uploads and downloads are untouched. Headers a route
already set (for example the evidence download CSP) are never overwritten. HSTS is sent only when the
request really arrived over TLS (`scope["scheme"] == "https"`); a forwarded-proto header is never trusted.
"""
from app.core.config import settings

_DOC_PATHS = ("/docs", "/redoc")  # Swagger UI loads its own scripts, so it gets no strict CSP.


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        https = scope.get("scheme") == "https"
        path = scope.get("path", "")

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                wanted = [
                    (b"x-frame-options", b"DENY"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
                    (b"cross-origin-resource-policy", b"same-site"),
                ]
                if not path.startswith(_DOC_PATHS):
                    wanted.append((b"content-security-policy",
                                   b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"))
                if path.startswith("/api/"):
                    wanted.append((b"cache-control", b"no-store"))
                if https and settings.hsts_max_age_seconds > 0:
                    wanted.append((b"strict-transport-security",
                                   f"max-age={settings.hsts_max_age_seconds}; includeSubDomains".encode()))
                headers.extend(item for item in wanted if item[0] not in present)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)
