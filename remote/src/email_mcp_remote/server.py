"""FastMCP v4 front end; SDK-v1 email engine runs over private stdio."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from pathlib import Path

import uvicorn
from argon2 import PasswordHasher
from fastmcp import Client
from fastmcp.client.transports import StdioTransport
from fastmcp.server import create_proxy
from starlette.responses import JSONResponse

from .auth import PasswordOAuthProvider
from .config import Settings
from .security import Boundary
from .store import Store, digest


def create_server(settings: Settings, target=None):
    store = Store(
        settings.state_path,
        digest(settings.public_url + "\0" + settings.username + "\0" + settings.password_hash),
    )
    auth = PasswordOAuthProvider(settings, store)
    if target is None:
        if not os.path.isabs(settings.engine_command) or not os.access(settings.engine_command, os.X_OK):
            raise ValueError("MCP_EMAIL_COMMAND must name an existing absolute executable")
        # Do not disclose the front-end password hash to the email subprocess.
        env = {k: v for k, v in os.environ.items() if not k.startswith("MCP_AUTH_") and k != "MCP_PUBLIC_URL"}
        target = Client(StdioTransport(settings.engine_command, ["stdio"], env=env), mode="legacy")
    mcp = create_proxy(target, name="Private Email MCP", version="0.1.0", auth=auth, mask_error_details=True)

    @mcp.custom_route("/healthz", methods=["GET"])
    async def health(request):
        # Liveness only: no mailbox login and no private configuration exposed.
        return JSONResponse({"status": "ok"})

    app = mcp.http_app(
        path="/mcp",
        stateless_http=True,
        json_response=True,
        allowed_hosts=[settings.public_url.split("//", 1)[1], "localhost:*", "127.0.0.1:*"],
        allowed_origins=[settings.public_url],
    )
    return mcp, Boundary(app, settings, store), auth


def main() -> None:
    parser = argparse.ArgumentParser(description="Private Email MCP with local hashed-password OAuth login")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve")
    sub.add_parser("smoke-engine", help="Verify private stdio tool discovery; does not read or send mail")
    hash_parser = sub.add_parser("hash-password", help="Generate Argon2id hash; never writes the password")
    hash_parser.add_argument("--stdin", action="store_true", help="Read password from stdin instead of a TTY")
    reset_parser = sub.add_parser(
        "reset-auth", help="Invalidate all clients and tokens; stop the service first"
    )
    reset_parser.add_argument("--confirm", required=True, choices=["RESET"])
    args = parser.parse_args()
    if args.command == "smoke-engine":

        async def smoke():
            command = os.environ.get("MCP_EMAIL_COMMAND", "/opt/email/bin/mcp-email-server")
            async with Client(
                StdioTransport(command, ["stdio"], env=dict(os.environ)), mode="legacy"
            ) as client:
                tools = await client.list_tools()
                names = {tool.name for tool in tools}
                required = {"send_email", "list_emails_metadata", "get_attachment_content"}
                if not required <= names:
                    raise RuntimeError("Email tool catalog incomplete")
                print(f"Private stdio email engine ready: {len(tools)} tools")

        asyncio.run(smoke())
        return
    if args.command == "hash-password":
        if args.stdin:
            password = sys.stdin.readline(1026).rstrip("\r\n")
        else:
            password = getpass.getpass("New MCP login password: ")
            if password != getpass.getpass("Repeat password: "):
                raise SystemExit("Passwords do not match")
        if len(password) < 16 or len(password.encode()) > 1024:
            raise SystemExit("Use a password of at least 16 characters and at most 1024 bytes")
        print(PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1).hash(password))
        return
    if args.command == "reset-auth":
        path = Path(os.environ.get("MCP_AUTH_STATE_PATH", "/data/auth/oauth.sqlite3"))
        store = Store(path, "explicit-operator-reset")
        with store.transaction():
            store.db.execute("DELETE FROM records")
            store.db.execute("DELETE FROM families")
        store.close()
        print("OAuth clients and grants invalidated. Restart and reconnect your clients.")
        return
    os.umask(0o077)
    try:
        settings = Settings.from_env()
        _, app, auth = create_server(settings)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Configuration error: {exc}") from None
    # Do not trust caller-controlled forwarded headers or log OAuth query strings.
    try:
        uvicorn.run(
            app,
            host=settings.host,
            port=settings.port,
            proxy_headers=False,
            access_log=False,
            log_level="warning",
            limit_concurrency=64,
        )
    finally:
        auth.store.close()


if __name__ == "__main__":
    main()
