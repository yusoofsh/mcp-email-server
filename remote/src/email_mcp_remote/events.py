"""Authenticated, durable MCP Events webhook extension for the private email bridge."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import secrets
import socket
import ssl
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastmcp import Client
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.extensions import MethodBinding, ServerExtension
from fastmcp.server.middleware import Middleware
from jsonschema import ValidationError, validate
from mcp.shared.exceptions import MCPError
from mcp_types import RequestParams
from pydantic import ConfigDict

from .store import digest

EVENT = {
    "name": "email.received",
    "description": "New message arrived in a configured receive-capable email account. Metadata is checked every 60 seconds; event payloads contain references only.",
    "delivery": ["webhook"],
    "inputSchema": {
        "type": "object",
        "properties": {"account_name": {"type": "string", "minLength": 1, "maxLength": 256}},
        "required": ["account_name"],
        "additionalProperties": False,
    },
    "payloadSchema": {
        "type": "object",
        "properties": {"account_name": {"type": "string"}, "email_id": {"type": "string"}},
        "required": ["account_name", "email_id"],
        "additionalProperties": False,
    },
}


class Params(RequestParams):
    model_config = ConfigDict(extra="allow")


def fail(code: int, message: str, reason: str | None = None):
    raise MCPError(code, message, data={"reason": reason} if reason else None)


def signing_key(secret: str) -> bytes:
    try:
        if not isinstance(secret, str) or not secret.startswith("whsec_"):
            raise ValueError
        key = base64.b64decode(secret[6:], validate=True)
        if not 24 <= len(key) <= 64:
            raise ValueError
        return key
    except (ValueError, TypeError):
        fail(-32602, "Invalid webhook signing secret")


def callback_url(url: str) -> str:
    try:
        p = urlsplit(url)
        if (
            len(url) > 2048
            or any(c.isspace() or c == "\\" for c in url)
            or p.scheme != "https"
            or not p.hostname
            or p.username
            or p.password
            or p.fragment
            or p.port not in (None, 443)
        ):
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        fail(-32602, "Invalid HTTPS callback URL")
    return url


def signed_headers(subscription: dict, event_id: str, body: bytes) -> dict[str, str]:
    timestamp = str(int(time.time()))
    material = event_id.encode() + b"." + timestamp.encode() + b"." + body
    keys = [subscription["secret"]]
    if subscription.get("old_secret") and subscription.get("rotate_until", 0) > time.time():
        keys.append(subscription["old_secret"])
    signatures = [
        "v1," + base64.b64encode(hmac.digest(signing_key(key), material, "sha256")).decode() for key in keys
    ]
    return {
        "Content-Type": "application/json",
        "webhook-id": event_id,
        "webhook-timestamp": timestamp,
        "webhook-signature": " ".join(signatures),
        "X-MCP-Subscription-Id": subscription["id"],
    }


def safe_post(url: str, headers: dict, body: bytes) -> tuple[int, dict]:
    """Resolve on every connection, pin the public address, preserve hostname TLS, never redirect."""
    p = urlsplit(callback_url(url))
    addresses = socket.getaddrinfo(p.hostname, 443, type=socket.SOCK_STREAM)
    if not addresses or any(
        not ipaddress.ip_address(item[4][0]).is_global or ipaddress.ip_address(item[4][0]).is_multicast
        for item in addresses
    ):
        raise ValueError("Non-public callback destination")
    family, kind, protocol, _, address = addresses[0]
    raw = socket.socket(family, kind, protocol)
    raw.settimeout(10)
    conn = http.client.HTTPSConnection(p.hostname, 443, timeout=10, context=ssl.create_default_context())
    try:
        raw.connect(address)
        conn.sock = conn._context.wrap_socket(raw, server_hostname=p.hostname)
        conn.request("POST", (p.path or "/") + ("?" + p.query if p.query else ""), body=body, headers=headers)
        response = conn.getresponse()
        result = response.read(16385)
        if len(result) > 16384:
            raise ValueError("Callback response exceeds limit")
        try:
            parsed = json.loads(result) if result else {}
        except ValueError:
            parsed = {}
        return response.status, parsed
    finally:
        conn.close()
        raw.close()


class EmailEvents(ServerExtension):
    identifier = "id.yusoofsh/events"

    def __init__(self, auth, target, post=safe_post):
        self.auth, self.target, self.post = auth, target, post
        self.cipher = AESGCM(hashlib.sha256(("mcp-events:" + auth.config.password_hash).encode()).digest())
        self.lock = asyncio.Lock()

    def _put(self, kind: str, key: str, value: dict, expires: float):
        with self.auth.store.lock:
            count = self.auth.store.db.execute(
                "SELECT COUNT(*) FROM records WHERE kind=? AND expires>=?", (kind, time.time())
            ).fetchone()[0]
            if count >= (128 if kind == "event_subscription" else 1000) and not self.auth.store.get(
                kind, key
            ):
                fail(-32000, "Event state limit reached")
        nonce = secrets.token_bytes(12)
        encrypted = self.cipher.encrypt(
            nonce, json.dumps(value, separators=(",", ":")).encode(), key.encode()
        )
        self.auth.store.put(kind, key, {"sealed": base64.b64encode(nonce + encrypted).decode()}, expires)

    def _list(self, kind: str):
        with self.auth.store.lock:
            rows = self.auth.store.db.execute(
                "SELECT key,data FROM records WHERE kind=? AND expires>=? LIMIT 1001", (kind, time.time())
            ).fetchall()
        if len(rows) > 1000:
            fail(-32000, "Event state limit reached")
        values = []
        for key, raw in rows:
            sealed = base64.b64decode(json.loads(raw)["sealed"])
            values.append(json.loads(self.cipher.decrypt(sealed[:12], sealed[12:], key.encode())))
        return values

    def methods(self):
        return [
            MethodBinding(name, Params, self._handle, protocol_versions=frozenset({"2026-07-28"}))
            for name in ("events/list", "events/subscribe", "events/unsubscribe")
        ]

    async def _owner(self):
        access = get_access_token()
        if not access:
            fail(-32001, "Authenticated event owner required")
        record = self.auth.store.get("access", digest(access.token))
        if not record or not self.auth.store.family_active(record["family"]):
            fail(-32001, "Event owner access revoked")
        return record["family"]

    async def _account_exists(self, name: str):
        async with Client(self.target) as client:
            response = await client.call_tool("list_available_accounts", {})
            values = response.data
            if isinstance(values, dict):
                values = values.get("accounts", values.get("result", []))
            return isinstance(values, list) and any(
                a.get("account_name", a.get("name")) == name and a.get("can_receive") for a in values
            )

    async def _handle(self, ctx, params):
        owner = await self._owner()
        values = params.model_dump(by_alias=True, exclude_none=True)
        if ctx.method == "events/list":
            if values.get("cursor") is not None:
                fail(-32602, "Invalid event catalog cursor")
            return {"events": [EVENT]}
        try:
            if values.get("name") != EVENT["name"]:
                raise ValueError
            arguments = values.get("arguments", {})
            validate(arguments, EVENT["inputSchema"])
            delivery = values["delivery"]
            if delivery["mode"] != "webhook":
                raise ValueError
            url = callback_url(delivery["url"])
        except (KeyError, TypeError, ValueError, ValidationError):
            fail(-32602, "Invalid event subscription")
        ident = "sub_" + digest(
            json.dumps([owner, EVENT["name"], arguments, url], sort_keys=True, separators=(",", ":"))
        )
        async with self.lock:
            if ctx.method == "events/unsubscribe":
                self.auth.store.pop("event_subscription", ident)
                return {}
            secret = delivery.get("secret")
            signing_key(secret)
            ttl = values.get("ttlMs", 86400000)
            if ttl is None:
                ttl = 86400000
            if type(ttl) is not int or ttl <= 0 or values.get("cursor") is not None:
                fail(-32602, "Invalid lifetime or unsupported replay cursor")
            if not await self._account_exists(arguments["account_name"]):
                fail(-32001, "Email account is not available for receive events")
            now = time.time()
            old = next((s for s in self._list("event_subscription") if s["id"] == ident), None)
            subscription = {
                "id": ident,
                "owner": owner,
                "name": EVENT["name"],
                "arguments": arguments,
                "url": url,
                "secret": secret,
                "expires": now + min(ttl, 86400000) / 1000,
                "verified_until": now + 300,
                "generation": old["generation"] if old else secrets.token_hex(16),
                "start": old["start"] if old else datetime.fromtimestamp(now, timezone.utc).isoformat(),
            }
            if old and old["secret"] != secret:
                subscription.update(old_secret=old["secret"], rotate_until=now + 300)
            if not old or old["secret"] != secret or old["verified_until"] <= now:
                challenge = secrets.token_urlsafe(32)
                body = json.dumps(
                    {"type": "verification", "challenge": challenge}, separators=(",", ":")
                ).encode()
                try:
                    status, response = await asyncio.wait_for(
                        asyncio.to_thread(
                            self.post,
                            url,
                            signed_headers(subscription, "msg_verification_" + secrets.token_hex(16), body),
                            body,
                        ),
                        timeout=10,
                    )
                except (TimeoutError, OSError, ValueError):
                    fail(-32015, "Callback verification failed", "timeout_or_connection_failed")
                echoed = response.get("challenge") if isinstance(response, dict) else None
                if (
                    not 200 <= status < 300
                    or not isinstance(echoed, str)
                    or not hmac.compare_digest(challenge, echoed)
                ):
                    fail(-32015, "Callback verification failed", "challenge_failed")
            else:
                subscription["verified_until"] = old["verified_until"]
            self._put("event_subscription", ident, subscription, subscription["expires"])
            return {
                "id": ident,
                "refreshBefore": datetime.fromtimestamp(subscription["expires"], timezone.utc).isoformat(),
                "cursor": None,
                "truncated": False,
            }

    @asynccontextmanager
    async def lifespan(self):
        task = asyncio.create_task(self._loop())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def _loop(self):
        while True:
            try:
                await self.tick()
            except Exception:
                # Credentials, callback URLs, and email contents never enter logs.
                pass
            await asyncio.sleep(60)

    async def tick(self):
        async with self.lock:
            for subscription in self._list("event_subscription"):
                if not self.auth.store.family_active(subscription["owner"]):
                    self.auth.store.pop("event_subscription", subscription["id"])
                    continue
                if not await self._account_exists(subscription["arguments"]["account_name"]):
                    self.auth.store.pop("event_subscription", subscription["id"])
                    continue
                account = subscription["arguments"]["account_name"]
                cursor_key = "snapshot_" + subscription["id"] + subscription["generation"]
                prior = next((s for s in self._list("event_snapshot") if s["id"] == cursor_key), None)
                since = prior["since"] if prior else subscription["start"]
                observed = datetime.now(timezone.utc).isoformat()
                async with Client(self.target) as client:
                    result = await client.call_tool(
                        "list_emails_metadata",
                        {
                            "account_name": account,
                            "since": since,
                            "before": prior["before"] if prior and prior.get("page", 1) > 1 else observed,
                            "page_size": 100,
                            "page": prior.get("page", 1) if prior else 1,
                        },
                    )
                    data = result.data
                if not isinstance(data, dict) or not isinstance(data.get("emails"), list):
                    raise ValueError("Email event source returned an invalid result")
                seen = set(prior.get("seen", [])) if prior else set()
                for email in data["emails"]:
                    message = email["email_id"]
                    if message in seen:
                        continue
                    event_id = "evt_" + digest(account + "\0" + message)
                    event = {
                        "eventId": event_id,
                        "name": EVENT["name"],
                        "timestamp": observed,
                        "data": {"account_name": account, "email_id": message},
                        "cursor": None,
                    }
                    ident = digest(subscription["id"] + "\0" + subscription["generation"] + "\0" + event_id)
                    if self.auth.store.get("event_delivery", ident):
                        continue
                    self._put(
                        "event_delivery",
                        ident,
                        {
                            "id": ident,
                            "subscription": subscription["id"],
                            "generation": subscription["generation"],
                            "event": event,
                            "attempts": 0,
                            "due": time.time(),
                        },
                        subscription["expires"],
                    )
                self._put(
                    "event_snapshot",
                    cursor_key,
                    {
                        "id": cursor_key,
                        "since": since
                        if data.get("total", 0) > (prior.get("page", 1) if prior else 1) * 100
                        else (prior["before"] if prior and prior.get("page", 1) > 1 else observed),
                        "before": prior["before"] if prior and prior.get("page", 1) > 1 else observed,
                        "page": (prior.get("page", 1) if prior else 1) + 1
                        if data.get("total", 0) > (prior.get("page", 1) if prior else 1) * 100
                        else 1,
                        "seen": sorted({e["email_id"] for e in data["emails"]}),
                    },
                    subscription["expires"],
                )
            subscriptions = {s["id"]: s for s in self._list("event_subscription")}
            for delivery in self._list("event_delivery")[:20]:
                if delivery["due"] > time.time():
                    continue
                subscription = subscriptions.get(delivery["subscription"])
                if (
                    not subscription
                    or delivery["generation"] != subscription["generation"]
                    or not self.auth.store.family_active(subscription["owner"])
                ):
                    self.auth.store.pop("event_delivery", delivery["id"])
                    continue
                body = json.dumps(delivery["event"], separators=(",", ":")).encode()
                if len(body) > 262144:
                    self.auth.store.pop("event_delivery", delivery["id"])
                    continue
                try:
                    status, _ = await asyncio.wait_for(
                        asyncio.to_thread(
                            self.post,
                            subscription["url"],
                            signed_headers(subscription, delivery["event"]["eventId"], body),
                            body,
                        ),
                        10,
                    )
                except (TimeoutError, OSError, ValueError):
                    status = 0
                if status == 410:
                    self.auth.store.pop("event_subscription", subscription["id"])
                if (
                    200 <= status < 300
                    or status in (410, 413)
                    or (400 <= status < 500 and status != 429)
                    or delivery["attempts"] >= 7
                ):
                    self.auth.store.pop("event_delivery", delivery["id"])
                else:
                    delivery["due"] = time.time() + min(3600, 2 ** delivery["attempts"])
                    delivery["attempts"] += 1
                    self._put("event_delivery", delivery["id"], delivery, subscription["expires"])


def attach_email_events(mcp, auth, target):
    extension = EmailEvents(auth, target)
    mcp.add_extension(extension)

    class EventDiscovery(Middleware):
        async def on_discover(self, context, call_next):
            result = await call_next(context)
            values = (
                result.model_dump(by_alias=True, exclude_none=True)
                if hasattr(result, "model_dump")
                else dict(result)
            )
            values["capabilities"]["events"] = {}
            return values

    mcp.add_middleware(EventDiscovery())
    return extension
