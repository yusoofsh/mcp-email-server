"""Fail-closed, single-operator configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
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
            raise ValueError("Set MCP_AUTH_REDIRECT_URIS to the exact client callback URL(s)")
        for uri in self.redirect_uris:
            check_https_url(uri)
            if "*" in uri or not urlsplit(uri).path:
                raise ValueError("OAuth callbacks must have exact HTTPS paths; wildcards are forbidden")
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
