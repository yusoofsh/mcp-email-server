"""Exercise the exact image with the canonical Compose service, without real mail.

Uses a random test-only Compose project and its own temporary credential/volume.
The HTTP client models HTTPS termination by supplying the configured Host/Origin.
No external callback is followed and no mailbox credentials are configured.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = "https://mail-ci.example"
CALLBACK = "https://client.example/callback"
SCOPE = "email:access"


def run(args: list[str], *, env: dict[str, str] | None = None, data: str | None = None) -> str:
    result = subprocess.run(args, env=env, input=data, capture_output=True, text=True, timeout=90)
    if result.returncode:
        # Do not include input or daemon logs, which could contain credentials.
        raise RuntimeError(f"Command failed: {args[0]} {args[1]} (exit {result.returncode})")
    return result.stdout.strip()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, port: int):
        self.base = f"http://127.0.0.1:{port}"
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))

    def request(self, path: str, *, method: str = "GET", form=None, payload=None, headers=None):
        parsed = urllib.parse.urlsplit(path)
        if parsed.netloc:
            if f"{parsed.scheme}://{parsed.netloc}" != PUBLIC:
                raise AssertionError("Refusing an external OAuth callback")
            path = urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))
        request_headers = {"Host": urllib.parse.urlsplit(PUBLIC).netloc, **(headers or {})}
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif payload is not None:
            data = json.dumps(payload).encode()
            request_headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=request_headers)
        try:
            response = self.opener.open(req, timeout=20)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            return response.status, response.headers, response.read().decode()

    def wait(self):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                if self.request("/healthz")[0] == 200:
                    return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.25)
        raise AssertionError("OAuth HTTP service did not become ready")


def connect_compose(compose: list[str], env: dict[str, str], *, restart: bool = False) -> Client:
    """Resolve the current endpoint; Docker can remap an ephemeral port on restart."""
    if restart:
        run(compose + ["restart", "email-mcp"], env=env)
    endpoint = run(compose + ["port", "email-mcp", "9557"], env=env)
    host, separator, port = endpoint.rpartition(":")
    if host != "127.0.0.1" or not separator or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise AssertionError("Compose must expose exactly one concrete IPv4 loopback port")
    client = Client(int(port))
    client.wait()
    return client


def verify(image: str, expected_version: str | None, source: str | None, report: Path | None):
    metadata = json.loads(run(["docker", "image", "inspect", image]))[0]
    assert metadata["Config"]["User"] == "10001:10001", "Image must default to non-root"
    assert metadata["Config"]["Cmd"] == ["serve"], "Image must default to OAuth HTTP"
    if source:
        assert metadata["Config"]["Labels"]["org.opencontainers.image.revision"] == source
    assert metadata["Architecture"] in {"amd64", "arm64"}
    failure = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", image, "serve"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert failure.returncode != 0 and "Configuration error" in failure.stderr
    project = "email-ci-" + secrets.token_hex(6)
    with tempfile.TemporaryDirectory(prefix=project) as temporary:
        password = secrets.token_urlsafe(36)
        hashed = run(["docker", "run", "--rm", "-i", image, "hash-password", "--stdin"], data=password + "\n")
        assert hashed.startswith("$argon2id$")
        hash_file = Path(temporary) / "password.hash"
        hash_file.write_text(hashed + "\n")
        # Directory is private; the container's non-root UID must read the bound secret.
        hash_file.chmod(0o444)
        empty_env = Path(temporary) / ".env"
        empty_env.write_text("")
        env = {
            **os.environ,
            "MCP_IMAGE": image,
            "MCP_BIND_PORT": "0",
            "MCP_PUBLIC_URL": PUBLIC,
            "MCP_AUTH_USERNAME": "test-operator",
            "MCP_AUTH_REDIRECT_URIS": "*",
            "MCP_PASSWORD_HASH_FILE": str(hash_file),
        }
        compose = [
            "docker",
            "compose",
            "--project-name",
            project,
            "--env-file",
            str(empty_env),
            "-f",
            str(ROOT / "deploy/compose.yaml"),
        ]
        try:
            config = json.loads(run(compose + ["config", "--format", "json"], env=env))
            service = config["services"]["email-mcp"]
            assert service["environment"]["MCP_HOST"] == "0.0.0.0"
            assert service["read_only"] is True and "ALL" in service["cap_drop"]
            assert all(port["host_ip"] == "127.0.0.1" for port in service["ports"])
            # Never re-pull a candidate: test the exact locally loaded image reference.
            run(compose + ["up", "-d", "--pull", "never"], env=env)
            client = connect_compose(compose, env)
            if expected_version:
                actual = run(
                    compose + ["exec", "-T", "email-mcp", "/opt/email/bin/mcp-email-server", "--version"],
                    env=env,
                )
                assert actual == expected_version
            run(
                compose + ["exec", "-T", "email-mcp", "/opt/remote/bin/email-mcp-remote", "smoke-engine"],
                env=env,
            )
            status, headers, _ = client.request("/mcp", method="POST", payload={})
            assert status == 401 and "resource_metadata" in headers["WWW-Authenticate"]
            basic = base64.b64encode(f"test-operator:{password}".encode()).decode()
            assert (
                client.request(
                    "/mcp", method="POST", payload={}, headers={"Authorization": "Basic " + basic}
                )[0]
                == 401
            )
            assert client.request("/healthz", headers={"Host": "attacker.example"})[0] == 400
            assert client.request("/healthz", headers={"Origin": "https://attacker.example"})[0] == 403
            status, _, body = client.request("/.well-known/oauth-authorization-server")
            assert status == 200 and json.loads(body)["code_challenge_methods_supported"] == ["S256"]
            status, _, body = client.request(
                "/register",
                method="POST",
                payload={
                    "redirect_uris": [CALLBACK],
                    "client_name": "Synthetic container test",
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "scope": SCOPE,
                },
            )
            assert status == 201
            client_id = json.loads(body)["client_id"]
            verifier = secrets.token_urlsafe(48)
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            )
            status, headers, _ = client.request(
                "/authorize?"
                + urllib.parse.urlencode(
                    {
                        "client_id": client_id,
                        "redirect_uri": CALLBACK,
                        "response_type": "code",
                        "scope": SCOPE,
                        "state": "container-test",
                        "code_challenge": challenge,
                        "code_challenge_method": "S256",
                        "resource": PUBLIC + "/mcp",
                    }
                )
            )
            assert status in {302, 303}
            status, headers, page = client.request(headers["Location"])
            assert status == 200
            csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
            ticket = re.search(r'name="ticket" value="([^"]+)"', page).group(1)
            cookie = SimpleCookie()
            cookie.load(headers["Set-Cookie"])
            login_headers = {
                "Origin": PUBLIC,
                "Cookie": "; ".join(f"{key}={value.value}" for key, value in cookie.items()),
            }
            form = {
                "ticket": ticket,
                "csrf": csrf,
                "username": "test-operator",
                "password": password,
                "decision": "approve",
            }
            assert (
                client.request(
                    "/login", method="POST", form={**form, "csrf": "invalid"}, headers=login_headers
                )[0]
                == 403
            )
            assert (
                client.request(
                    "/login", method="POST", form={**form, "password": "wrong"}, headers=login_headers
                )[0]
                == 401
            )
            status, headers, _ = client.request("/login", method="POST", form=form, headers=login_headers)
            assert status == 303
            callback = urllib.parse.urlsplit(headers["Location"])
            params = urllib.parse.parse_qs(callback.query)
            assert params["state"] == ["container-test"] and params["iss"] == [PUBLIC]
            grant = {
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": params["code"][0],
                "redirect_uri": CALLBACK,
                "code_verifier": verifier,
                "resource": PUBLIC + "/mcp",
            }
            assert (
                client.request(
                    "/token", method="POST", form={**grant, "resource": "https://attacker.example/mcp"}
                )[0]
                == 400
            )
            status, _, body = client.request("/token", method="POST", form=grant)
            assert status == 200
            pair = json.loads(body)
            assert client.request("/token", method="POST", form=grant)[0] in {400, 401}

            def rpc(method, parameters=None):
                status, _, body = client.request(
                    "/mcp",
                    method="POST",
                    payload={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": method,
                        "params": parameters or {},
                    },
                    headers={
                        "Authorization": "Bearer " + pair["access_token"],
                        "Accept": "application/json, text/event-stream",
                        "MCP-Protocol-Version": "2025-11-25",
                    },
                )
                assert status == 200
                result = json.loads(body)
                assert "error" not in result
                return result["result"]

            rpc(
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "container-smoke", "version": "1"},
                },
            )
            listed = rpc("tools/list")["tools"]
            expected = json.loads((ROOT / "tests/fixtures/mcp_catalog.json").read_text())["tools"]
            assert {tool["name"] for tool in listed} == {tool["name"] for tool in expected}
            client = connect_compose(compose, env, restart=True)
            rpc("tools/list")
            status, _, body = client.request(
                "/token",
                method="POST",
                form={
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                    "refresh_token": pair["refresh_token"],
                    "resource": PUBLIC + "/mcp",
                },
            )
            assert status == 200
            refreshed = json.loads(body)
            assert refreshed["refresh_token"] != pair["refresh_token"]
            pair = refreshed
            rpc("ping")
            assert (
                client.request(
                    "/revoke",
                    method="POST",
                    form={
                        "client_id": client_id,
                        "token": pair["refresh_token"],
                        "token_type_hint": "refresh_token",
                    },
                )[0]
                == 200
            )
            assert (
                client.request(
                    "/mcp",
                    method="POST",
                    payload={},
                    headers={"Authorization": "Bearer " + pair["access_token"]},
                )[0]
                == 401
            )
        finally:
            # Remove only the random synthetic project and its empty volume.
            run(compose + ["down", "--volumes", "--remove-orphans"], env=env)
    if report:
        assert source and "@sha256:" in image
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(
            json.dumps(
                {
                    "source": source,
                    "image": image,
                    "arch": metadata["Architecture"],
                    "verified": True,
                    "checks": "compose-oauth-http-restart-revocation",
                }
            )
            + "\n"
        )
    print(f"PASS: exact {metadata['Architecture']} image; Compose, OAuth, full tool catalog and persistence")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-version")
    parser.add_argument("--source-sha")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    verify(args.image, args.expected_version, args.source_sha, args.report)


if __name__ == "__main__":
    main()
