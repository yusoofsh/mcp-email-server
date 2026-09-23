"""Local hashed-password login using FastMCP's OAuthProvider extension point.

FastMCP owns OAuth routing and PKCE verification. This module owns single-user
consent, grant persistence and opaque-token lifecycles. No password grant exists.
"""

from __future__ import annotations

import base64
import html
import re
import secrets
import time
from hmac import compare_digest
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import anyio
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastmcp.server.auth import AccessToken, OAuthProvider
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
)
from mcp.server.auth.routes import build_metadata
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from .config import Settings
from .store import Store, digest

SCOPE = "email:access"
COOKIE = "__Host-email-mcp-csrf"
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer"}


def redirect_to(uri: str, **params: str) -> str:
    parts = urlsplit(uri)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.extend(params.items())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


class PasswordOAuthProvider(OAuthProvider):
    def __init__(self, settings: Settings, store: Store):
        super().__init__(
            base_url=settings.public_url,
            required_scopes=[SCOPE],
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]
            ),
            revocation_options=RevocationOptions(enabled=True),
        )
        self.config = settings
        self.store = store
        self.hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)
        self.password_slots = anyio.CapacityLimiter(2)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = self.store.get("client", client_id)
        return OAuthClientInformationFull.model_validate(data) if data else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if client_info.token_endpoint_auth_method != "none" or client_info.client_secret:
            raise RegistrationError(
                "invalid_client_metadata", "Register as a public client using none and PKCE"
            )
        if not client_info.redirect_uris or len(client_info.redirect_uris) > 16:
            raise RegistrationError("invalid_redirect_uri", "One or more allowed callbacks are required")
        if any(str(uri) not in self.config.redirect_uris for uri in client_info.redirect_uris):
            raise RegistrationError("invalid_redirect_uri", "Callback is not in the operator allowlist")
        if (
            set(client_info.grant_types) - {"authorization_code", "refresh_token"}
            or "authorization_code" not in client_info.grant_types
        ):
            raise RegistrationError("invalid_client_metadata", "Unsupported grant type")
        if set(client_info.response_types) != {"code"}:
            raise RegistrationError("invalid_client_metadata", "Only code responses are supported")
        if set((client_info.scope or SCOPE).split()) != {SCOPE}:
            raise RegistrationError("invalid_client_metadata", "Only email:access is supported")
        # Registrations persist until an explicit operator reset; tokens have separate TTLs.
        self.store.put("client", client_info.client_id, client_info.model_dump(mode="json"), 253402300799)

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if str(params.redirect_uri) not in self.config.redirect_uris:
            raise AuthorizeError("access_denied", "Callback no longer allowed")
        if params.resource is not None and params.resource != self.config.resource:
            raise AuthorizeError("invalid_target", "Unknown resource")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.code_challenge):
            raise AuthorizeError("invalid_request", "PKCE S256 is required")
        if set(params.scopes or [SCOPE]) != {SCOPE}:
            raise AuthorizeError("invalid_scope", "Only email:access is supported")
        ticket = secrets.token_urlsafe(32)
        expires = time.time() + 300
        self.store.put(
            "pending",
            digest(ticket),
            {
                "client_id": client.client_id,
                "client_name": (client.client_name or "MCP client")[:200],
                "params": params.model_dump(mode="json"),
                "expires_at": expires,
            },
            expires,
        )
        return self.config.public_url + "/login?ticket=" + ticket

    def _page(self, ticket: str, pending: dict, csrf: str, error: str = "") -> HTMLResponse:
        esc = html.escape
        body = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Connect Email MCP</title>
<style>body{{font:16px system-ui;max-width:34rem;margin:8vh auto;padding:1.5rem;line-height:1.5}}
label{{display:block;margin-top:1rem}}input{{box-sizing:border-box;width:100%;padding:.7rem}}
button{{padding:.65rem 1rem;margin:1rem .5rem 0 0}}code{{overflow-wrap:anywhere}}.error{{color:#a00}}</style>
<h1>Connect your email</h1><p><strong>{esc(pending["client_name"])}</strong> requests access.</p>
<p>Callback: <code>{esc(pending["params"]["redirect_uri"])}</code></p>
<p>Permission: <code>{SCOPE}</code>. This can read and modify all configured mailboxes,
including sending mail and returning attachments, subject to your email policies.</p>
<p>Approve only the connection you just started. Your login password is not sent to the MCP client.</p>
<p class="error" role="alert">{esc(error)}</p>
<form method="post" action="/login"><input type="hidden" name="ticket" value="{esc(ticket)}">
<input type="hidden" name="csrf" value="{esc(csrf)}">
<label for="username">Username</label><input id="username" name="username" autocomplete="username" required maxlength="128">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="1024">
<button name="decision" value="approve">Sign in and authorize</button>
<button name="decision" value="deny" formnovalidate>Deny</button></form></html>"""
        return HTMLResponse(body, headers=NO_STORE)

    async def login_get(self, request: Request):
        ticket = request.query_params.get("ticket", "")
        pending = self.store.get("pending", digest(ticket))
        if not pending:
            return HTMLResponse(
                "Authorization expired. Start a new connection.", status_code=400, headers=NO_STORE
            )
        csrf, browser = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        pending.update(csrf_hash=digest(csrf), browser_hash=digest(browser))
        self.store.put("pending", digest(ticket), pending, pending["expires_at"])
        response = self._page(ticket, pending, csrf)
        response.set_cookie(
            COOKIE, browser, max_age=300, secure=True, httponly=True, samesite="strict", path="/"
        )
        return response

    async def login_post(self, request: Request):
        if request.headers.get("origin") != self.config.public_url:
            return JSONResponse({"error": "invalid_origin"}, status_code=403, headers=NO_STORE)
        form = await request.form()
        ticket, csrf = str(form.get("ticket", "")), str(form.get("csrf", ""))
        pending = self.store.get("pending", digest(ticket))
        if (
            not pending
            or not compare_digest(pending.get("csrf_hash", ""), digest(csrf))
            or not compare_digest(pending.get("browser_hash", ""), digest(request.cookies.get(COOKIE, "")))
        ):
            return JSONResponse({"error": "invalid_csrf"}, status_code=403, headers=NO_STORE)
        params = AuthorizationParams.model_validate(pending["params"])
        if str(params.redirect_uri) not in self.config.redirect_uris:
            return JSONResponse({"error": "invalid_redirect_uri"}, status_code=403, headers=NO_STORE)
        if form.get("decision") == "deny":
            self.store.pop("pending", digest(ticket))
            location = redirect_to(
                str(params.redirect_uri),
                error="access_denied",
                iss=self.config.public_url,
                **({"state": params.state} if params.state is not None else {}),
            )
            return RedirectResponse(location, status_code=303, headers=NO_STORE)
        if form.get("decision") != "approve":
            return JSONResponse({"error": "explicit_consent_required"}, status_code=400, headers=NO_STORE)
        username, password = str(form.get("username", "")), str(form.get("password", ""))
        # Basic is a login-only convenience, NEVER an alternative to bearer auth on /mcp.
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("basic "):
            try:
                username, password = base64.b64decode(authorization[6:], validate=True).decode().split(":", 1)
            except (ValueError, UnicodeError):
                username, password = "", ""
        ip = request.client.host if request.client else "unknown"
        if not self.store.allow("login:global", 30, 300) or not self.store.allow(
            "login:" + digest(ip), 5, 300
        ):
            return JSONResponse(
                {"error": "rate_limited"}, status_code=429, headers={**NO_STORE, "Retry-After": "300"}
            )
        if len(username) > 128 or len(password.encode()) > 1024:
            valid = False
        else:

            def check() -> bool:
                try:
                    result = self.hasher.verify(self.config.password_hash, password)
                except VerificationError:
                    result = False
                return result and compare_digest(username.encode(), self.config.username.encode())

            valid = await anyio.to_thread.run_sync(check, limiter=self.password_slots)
        if not valid:
            response = self._page(ticket, pending, csrf, "Invalid username or password.")
            response.status_code = 401
            return response
        if not self.store.pop("pending", digest(ticket)):
            return JSONResponse({"error": "authorization_already_used"}, status_code=400, headers=NO_STORE)
        code = secrets.token_urlsafe(32)
        grant = {
            "client_id": pending["client_id"],
            "scopes": params.scopes or [SCOPE],
            "expires_at": time.time() + 120,
            "code_challenge": params.code_challenge,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "resource": self.config.resource,
            "subject": self.config.username,
        }
        self.store.put("code", digest(code), grant, grant["expires_at"])
        location = redirect_to(
            str(params.redirect_uri),
            code=code,
            iss=self.config.public_url,
            **({"state": params.state} if params.state is not None else {}),
        )
        response = RedirectResponse(location, status_code=303, headers=NO_STORE)
        response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return response

    async def load_authorization_code(self, client, authorization_code):
        data = self.store.get("code", digest(authorization_code))
        if not data or data["client_id"] != client.client_id or data["resource"] != self.config.resource:
            return None
        return AuthorizationCode(code=authorization_code, **data)

    def _issue(self, client_id: str, scopes: list[str], family: str, family_expiry: int):
        access_token, refresh_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        common = {
            "client_id": client_id,
            "scopes": scopes,
            "resource": self.config.resource,
            "subject": self.config.username,
            "issuer": self.config.public_url,
            "family": family,
        }
        access = {**common, "expires_at": int(time.time()) + self.config.access_ttl}
        refresh = {**common, "expires_at": family_expiry, "used": False}
        result = OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=self.config.access_ttl,
            refresh_token=refresh_token,
            scope=" ".join(scopes),
        )
        return result, access, refresh

    async def exchange_authorization_code(self, client, authorization_code):
        if (
            authorization_code.client_id != client.client_id
            or authorization_code.resource != self.config.resource
        ):
            raise TokenError("invalid_grant", "Invalid authorization")
        result, access, refresh = self._issue(
            client.client_id,
            authorization_code.scopes,
            secrets.token_urlsafe(24),
            int(time.time()) + self.config.refresh_ttl,
        )
        if not self.store.exchange(
            "code",
            authorization_code.code,
            client.client_id,
            result.access_token,
            result.refresh_token,
            access,
            refresh,
        ):
            raise TokenError("invalid_grant", "Authorization expired or already used")
        return result

    async def load_refresh_token(self, client, refresh_token):
        data = self.store.get("refresh", digest(refresh_token))
        if not data or data["client_id"] != client.client_id:
            return None
        if data.get("used"):
            self.store.revoke(data["family"])
            return None
        if data["resource"] != self.config.resource or not self.store.family_active(data["family"]):
            return None
        return RefreshToken(
            token=refresh_token,
            **{k: data[k] for k in ("client_id", "scopes", "expires_at", "resource", "subject")},
        )

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        data = self.store.get("refresh", digest(refresh_token.token))
        if (
            not data
            or data["client_id"] != client.client_id
            or set(scopes) - set(data["scopes"])
            or data["resource"] != self.config.resource
        ):
            raise TokenError("invalid_grant", "Invalid refresh token")
        result, access, refresh = self._issue(client.client_id, scopes, data["family"], data["expires_at"])
        if not self.store.exchange(
            "refresh",
            refresh_token.token,
            client.client_id,
            result.access_token,
            result.refresh_token,
            access,
            refresh,
        ):
            raise TokenError("invalid_grant", "Refresh token expired, revoked, or replayed")
        return result

    async def load_access_token(self, token: str) -> AccessToken | None:
        if len(token) > 512:
            return None
        data = self.store.get("access", digest(token))
        if (
            not data
            or data["resource"] != self.config.resource
            or data["issuer"] != self.config.public_url
            or data["subject"] != self.config.username
            or not self.store.family_active(data["family"])
            or SCOPE not in data["scopes"]
        ):
            return None
        return AccessToken(
            token=token,
            client_id=data["client_id"],
            scopes=data["scopes"],
            expires_at=data["expires_at"],
            resource=data["resource"],
            subject=data["subject"],
            claims={"iss": data["issuer"], "sub": data["subject"]},
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        kind = "refresh" if isinstance(token, RefreshToken) else "access"
        data = self.store.get(kind, digest(token.token))
        if data:
            self.store.revoke(data["family"])

    async def revoke_public_client(self, request: Request):
        # SDK 2.2's revocation request model requires client_secret even for
        # public clients. Authenticate by client binding + possession of the
        # presented token; RFC 7009 deliberately hides invalid-token status.
        form = await request.form()
        client = await self.get_client(str(form.get("client_id", "")))
        if not client or client.token_endpoint_auth_method != "none":
            return JSONResponse({"error": "invalid_client"}, status_code=401, headers=NO_STORE)
        raw_token = str(form.get("token", ""))
        if not raw_token:
            return JSONResponse({"error": "invalid_request"}, status_code=400, headers=NO_STORE)
        for kind in ("refresh", "access"):
            record = self.store.get(kind, digest(raw_token))
            if record and record["client_id"] == client.client_id:
                self.store.revoke(record["family"])
        return JSONResponse({}, headers=NO_STORE)

    def get_routes(self, mcp_path=None):
        routes = super().get_routes(mcp_path)
        document = build_metadata(
            self.base_url,
            self.service_documentation_url,
            self.client_registration_options,
            self.revocation_options,
        ).model_dump(mode="json", exclude_none=True)
        document.update(
            issuer=self.config.public_url,
            token_endpoint_auth_methods_supported=["none"],
            authorization_response_iss_parameter_supported=True,
            code_challenge_methods_supported=["S256"],
        )

        async def metadata(request):
            return JSONResponse(document, headers=NO_STORE)

        replaced = []
        for route in routes:
            if route.path == "/.well-known/oauth-authorization-server":
                replaced.append(Route(route.path, metadata, methods=["GET", "OPTIONS"]))
            elif route.path == "/revoke":
                replaced.append(Route(route.path, self.revoke_public_client, methods=["POST"]))
            else:
                replaced.append(route)
        return replaced + [
            Route("/login", self.login_get, methods=["GET"]),
            Route("/login", self.login_post, methods=["POST"]),
        ]
