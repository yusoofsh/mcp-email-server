"""Fail-closed, single-operator configuration."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from argon2 import Type, extract_parameters


def check_https_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or any(c.isspace() for c in value)
    ):
        raise ValueError("Expected an absolute HTTPS URL without credentials, query, or fragment")
    return value


def check_redirect_uri(value: str) -> str:
    """Accept safe OAuth web, loopback, and native-app redirect URI forms."""
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        parsed.port
    except (AttributeError, ValueError):
        raise ValueError("OAuth callback must be a valid absolute URI") from None
    if (
        not parsed.scheme
        or not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", parsed.scheme)
        or not hostname
        and parsed.scheme.lower() in {"https", "http"}
        or parsed.netloc
        and not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or "*" in value
        or any(c.isspace() or ord(c) < 32 for c in value)
        or "\\" in value
    ):
        raise ValueError("OAuth callback must be an exact absolute URI without credentials or fragments")

    scheme = parsed.scheme.lower()
    if scheme == "https":
        return value
    if scheme == "http":
        if parsed.port is None or parsed.port == 0:
            raise ValueError("Loopback OAuth callbacks must specify a nonzero port")
        try:
            loopback = ip_address(hostname).is_loopback
        except ValueError:
            loopback = hostname.lower() == "localhost"
        if not loopback:
            raise ValueError("HTTP OAuth callbacks are allowed only on the local loopback interface")
        return value

    # RFC 8252 private-use schemes identify a native app. Do not allow browser
    # execution, file access, or generic URL handlers as OAuth destinations.
    if scheme in {
        "about",
        "blob",
        "data",
        "file",
        "ftp",
        "javascript",
        "mailto",
        "tel",
        "vbscript",
        "view-source",
    }:
        raise ValueError("Unsupported OAuth callback scheme")
    if "." not in scheme or not (parsed.netloc or parsed.path.startswith("/")):
        raise ValueError("Native OAuth callback schemes must use a reverse-domain scheme and path")
    return value


@dataclass(frozen=True)
class Settings:
    public_url: str
    username: str
    password_hash: str = field(repr=False)
    redirect_uris: tuple[str, ...]
    state_path: Path
    engine_command: str = "/opt/email/bin/mcp-email-server"
    host: str = "0.0.0.0"
    port: int = 9557
    access_ttl: int = 900
    refresh_ttl: int = 2592000

    def __post_init__(self) -> None:
        check_https_url(self.public_url)
        if urlsplit(self.public_url).path or self.public_url.endswith("/"):
            raise ValueError("MCP_PUBLIC_URL must be an HTTPS origin without a path or trailing slash")
        if not self.username or len(self.username) > 128 or ":" in self.username:
            raise ValueError("Set a nonempty MCP_AUTH_USERNAME (maximum 128 characters, no colon)")
        if not self.redirect_uris or len(self.redirect_uris) > 16:
            raise ValueError(
                "Set MCP_AUTH_REDIRECT_URIS to exact callback URL(s), or * to allow dynamic clients"
            )
        if self.redirect_uris != ("*",):
            if "*" in self.redirect_uris:
                raise ValueError("Use * alone to allow dynamically registered OAuth clients")
            for uri in self.redirect_uris:
                check_redirect_uri(uri)
        try:
            params = extract_parameters(self.password_hash)
        except Exception as exc:
            raise ValueError("Set a valid Argon2id password hash") from exc
        if (
            params.type != Type.ID
            or params.version != 19
            or params.memory_cost < 19456
            or params.memory_cost > 262144
            or not 2 <= params.time_cost <= 10
            or not 1 <= params.parallelism <= 8
            or params.salt_len < 16
            or params.hash_len < 32
        ):
            raise ValueError("Password hash must use Argon2id v19 with bounded, strong parameters")
        if not 60 <= self.access_ttl <= 3600 or not 3600 <= self.refresh_ttl <= 2592000:
            raise ValueError("Invalid token lifetime")

    @property
    def resource(self) -> str:
        return self.public_url + "/mcp"

    @classmethod
    def from_env(cls) -> Settings:
        hash_file = os.environ.get("MCP_AUTH_PASSWORD_HASH_FILE")
        direct_hash = os.environ.get("MCP_AUTH_PASSWORD_HASH")
        if hash_file and direct_hash:
            raise ValueError("Configure the password hash via a file OR environment, not both")
        hashed = Path(hash_file).read_text().strip() if hash_file else (direct_hash or "")
        return cls(
            public_url=os.environ.get("MCP_PUBLIC_URL", ""),
            username=os.environ.get("MCP_AUTH_USERNAME", ""),
            password_hash=hashed,
            redirect_uris=tuple(
                x.strip() for x in os.environ.get("MCP_AUTH_REDIRECT_URIS", "").split(",") if x.strip()
            ),
            state_path=Path(os.environ.get("MCP_AUTH_STATE_PATH", "/data/auth/oauth.sqlite3")),
            engine_command=os.environ.get("MCP_EMAIL_COMMAND", "/opt/email/bin/mcp-email-server"),
            host=os.environ.get("MCP_HOST", "0.0.0.0"),
            port=int(os.environ.get("MCP_PORT", "9557")),
        )
