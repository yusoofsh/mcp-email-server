"""HTTP boundary checks not delegated to the OAuth provider interface."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

import anyio
from starlette.responses import JSONResponse

from .auth import NO_STORE
from .config import Settings
from .store import StateFull, Store, digest


class Boundary:
    def __init__(self, app, settings: Settings, store: Store):
        self.app, self.settings, self.store = app, settings, store

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.lower(): v for k, v in scope["headers"]}
        host = headers.get(b"host", b"").decode("latin-1")
        path = scope.get("path", "")
        expected_host = urlsplit(self.settings.public_url).netloc
        error, status = None, 400
        if host != expected_host and not (
            path == "/healthz" and host.split(":")[0] in {"localhost", "127.0.0.1"}
        ):
            error = "invalid_host"
        origin = headers.get(b"origin")
        if origin is not None and origin.decode("latin-1") != self.settings.public_url:
            error, status = "invalid_origin", 403
        if len(scope.get("query_string", b"")) > 8192:
            error, status = "request_too_large", 413
        ip = scope.get("client", ("unknown", 0))[0]
        if path in {"/register", "/authorize", "/token", "/revoke", "/login"}:
            if not self.store.allow("http:global", 300, 60) or not self.store.allow(
                "http:" + digest(str(ip)), 120, 60
            ):
                error, status = "rate_limited", 429
        if path == "/register" and scope["method"] == "POST":
            if not self.store.allow("register:global", 10, 60):
                error, status = "rate_limited", 429
        if error:
            await JSONResponse({"error": error}, status_code=status, headers=NO_STORE)(scope, receive, send)
            return
        max_body = 16384 if path != "/mcp" else 2 * 1024 * 1024
        body = bytearray()
        try:
            with anyio.fail_after(15):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    body.extend(message.get("body", b""))
                    if len(body) > max_body:
                        await JSONResponse({"error": "request_too_large"}, status_code=413, headers=NO_STORE)(
                            scope, receive, send
                        )
                        return
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            await JSONResponse({"error": "request_timeout"}, status_code=408, headers=NO_STORE)(
                scope, receive, send
            )
            return
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        # Pinned SDK token handlers validate PKCE but don't bind a supplied token-request
        # resource. Enforce the exact advertised resource before the library handler runs.
        if path in {"/authorize", "/token", "/login"}:
            raw = scope.get("query_string", b"") if scope["method"] == "GET" else bytes(body)
            try:
                params = parse_qs(raw.decode("utf-8"), keep_blank_values=True, max_num_fields=32)
                if any(len(v) != 1 for v in params.values()):
                    raise ValueError("duplicate parameters")
            except (ValueError, UnicodeError):
                await JSONResponse({"error": "invalid_request"}, status_code=400, headers=NO_STORE)(
                    scope, replay, send
                )
                return
            if "resource" in params and params["resource"] != [self.settings.resource]:
                await JSONResponse({"error": "invalid_target"}, status_code=400, headers=NO_STORE)(
                    scope, replay, send
                )
                return
            if path == "/authorize" and (
                params.get("code_challenge_method") != ["S256"]
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.get("code_challenge", [""])[0])
            ):
                await JSONResponse(
                    {"error": "invalid_request", "error_description": "PKCE S256 required"},
                    status_code=400,
                    headers=NO_STORE,
                )(scope, replay, send)
                return

        async def secured_send(message):
            nonlocal rejected_oauth_redirect, rejected_body_sent
            if message["type"] == "http.response.start":
                if path == "/authorize" and 300 <= message["status"] < 400:
                    response_headers = {k.lower(): v for k, v in message.get("headers", [])}
                    location = response_headers.get(b"location", b"").decode("latin-1")
                    target = urlsplit(location)
                    expected_issuer = urlsplit(self.settings.public_url)
                    same_issuer = (
                        target.scheme == expected_issuer.scheme and target.netloc == expected_issuer.netloc
                    )
                    local_login = (
                        target.path == "/login"
                        and bool(target.query)
                        and not location.startswith("//")
                        and (not target.scheme and not target.netloc or same_issuer)
                    )
                    if not local_login:
                        # The SDK normally redirects OAuth errors to the callback. With
                        # open DCR that callback has not been trusted by the operator.
                        rejected_oauth_redirect = True
                        error_body = b'{"error":"invalid_request"}'
                        message = {
                            **message,
                            "status": 400,
                            "headers": [
                                (b"content-type", b"application/json"),
                                (b"content-length", str(len(error_body)).encode("ascii")),
                                (b"cache-control", b"no-store"),
                            ],
                        }
                if rejected_oauth_redirect:
                    message = {
                        **message,
                        "headers": [
                            (k, v)
                            for k, v in message.get("headers", [])
                            if k.lower() not in {b"content-length", b"content-type", b"location"}
                        ]
                        + [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(b'{"error":"invalid_request"}')).encode("ascii")),
                            (b"cache-control", b"no-store"),
                        ],
                    }
                response_headers = list(message.get("headers", []))
                response_headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"x-frame-options", b"DENY"),
                        (
                            b"content-security-policy",
                            b"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
                        ),
                    ]
                )
                message = {**message, "headers": response_headers}
            elif message["type"] == "http.response.body" and rejected_oauth_redirect:
                if rejected_body_sent:
                    return
                rejected_body_sent = True
                message = {
                    **message,
                    "body": b'{"error":"invalid_request"}',
                    "more_body": False,
                }
            await send(message)

        rejected_oauth_redirect = False
        rejected_body_sent = False
        try:
            await self.app(scope, replay, secured_send)
        except StateFull:
            await JSONResponse({"error": "temporarily_unavailable"}, status_code=503, headers=NO_STORE)(
                scope, replay, secured_send
            )
