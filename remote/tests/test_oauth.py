from __future__ import annotations

import base64
import hashlib
import re
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import anyio
import pytest
from argon2 import PasswordHasher
from fastmcp import FastMCP
from mcp.types import BlobResourceContents, CallToolResult, EmbeddedResource
from starlette.testclient import TestClient

from email_mcp_remote.auth import SCOPE
from email_mcp_remote.config import Settings
from email_mcp_remote.server import create_server
from email_mcp_remote.store import Store, digest

BASE = "https://mail.test"
CALLBACK = "https://chatgpt.com/connector/oauth/test"
PASSWORD = "correct-test-password-not-a-secret"
VERIFIER = "v" * 64
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")


@pytest.fixture(scope="session")
def password_hash():
    return PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1).hash(PASSWORD)


@pytest.fixture
def settings(tmp_path, password_hash):
    return Settings(
        public_url=BASE,
        username="operator",
        password_hash=password_hash,
        redirect_uris=(CALLBACK,),
        state_path=tmp_path / "auth" / "oauth.sqlite3",
    )


@pytest.fixture
def backend():
    server = FastMCP("Test email engine")

    @server.tool(annotations={"readOnlyHint": True, "destructiveHint": False})
    def list_accounts() -> list[str]:
        return ["test-account"]

    @server.tool(annotations={"readOnlyHint": True})
    def get_attachment_content() -> CallToolResult:
        return CallToolResult(
            content=[
                EmbeddedResource(
                    type="resource",
                    resource=BlobResourceContents(
                        uri="email://attachment/test",
                        mimeType="application/octet-stream",
                        blob=base64.b64encode(b"attachment-bytes").decode(),
                    ),
                )
            ]
        )

    return server


@pytest.fixture
def app(settings, backend):
    mcp, asgi, auth = create_server(settings, target=backend)
    with TestClient(asgi, base_url=BASE, follow_redirects=False) as client:
        yield client, auth
    auth.store.close()


def register(client, callback=CALLBACK):
    response = client.post(
        "/register",
        json={
            "client_name": "Test client",
            "redirect_uris": [callback],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": SCOPE,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["client_id"]


def begin(client, client_id, callback=CALLBACK, **overrides):
    params = dict(
        client_id=client_id,
        response_type="code",
        redirect_uri=callback,
        scope=SCOPE,
        state="client-state",
        code_challenge=CHALLENGE,
        code_challenge_method="S256",
        resource=BASE + "/mcp",
    )
    params.update(overrides)
    return client.get("/authorize", params=params)


def form_for(client, client_id):
    response = begin(client, client_id)
    assert response.status_code in (302, 303), response.text
    page = client.get(response.headers["location"])
    assert page.status_code == 200, page.text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    ticket = parse_qs(urlsplit(response.headers["location"]).query)["ticket"][0]
    return {
        "ticket": ticket,
        "csrf": csrf,
        "decision": "approve",
        "username": "operator",
        "password": PASSWORD,
    }


def issue_code(client, client_id):
    data = form_for(client, client_id)
    response = client.post("/login", data=data, headers={"origin": BASE})
    assert response.status_code == 303, response.text
    params = parse_qs(urlsplit(response.headers["location"]).query)
    assert params["state"] == ["client-state"]
    assert params["iss"] == [BASE]
    return params["code"][0]


def redeem(client, client_id, code, **overrides):
    data = dict(
        grant_type="authorization_code",
        client_id=client_id,
        code=code,
        redirect_uri=CALLBACK,
        code_verifier=VERIFIER,
        resource=BASE + "/mcp",
    )
    data.update(overrides)
    return client.post("/token", data=data)


def token_pair(client):
    client_id = register(client)
    code = issue_code(client, client_id)
    result = redeem(client, client_id, code)
    assert result.status_code == 200, result.text
    return client_id, result.json()


def test_discovery_and_unauthenticated_mcp(app):
    client, _ = app
    metadata = client.get("/.well-known/oauth-authorization-server")
    assert metadata.status_code == 200
    assert metadata.json()["code_challenge_methods_supported"] == ["S256"]
    assert metadata.json()["token_endpoint_auth_methods_supported"] == ["none"]
    assert metadata.json()["authorization_response_iss_parameter_supported"] is True
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 401, response.text
    assert "resource_metadata" in response.headers["www-authenticate"]
    resource = client.get("/.well-known/oauth-protected-resource/mcp")
    assert resource.status_code == 200, resource.text
    assert resource.json()["resource"] == BASE + "/mcp"


def test_authorization_and_proxy_tools(app):
    client, _ = app
    _, tokens = token_pair(client)
    headers = {
        "authorization": "Bearer " + tokens["access_token"],
        "accept": "application/json, text/event-stream",
        "mcp-protocol-version": "2025-11-25",
    }
    response = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 200, response.text
    tools = {x["name"]: x for x in response.json()["result"]["tools"]}
    assert {"list_accounts", "get_attachment_content"} <= tools.keys()
    assert tools["list_accounts"]["annotations"]["readOnlyHint"] is True
    result = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "get_attachment_content", "arguments": {}},
        },
    )
    assert result.status_code == 200, result.text
    resource = result.json()["result"]["content"][0]["resource"]
    assert base64.b64decode(resource["blob"]) == b"attachment-bytes"


def test_basic_only_allowed_at_login(app):
    client, _ = app
    auth = "Basic " + base64.b64encode(("operator:" + PASSWORD).encode()).decode()
    assert client.post("/mcp", headers={"authorization": auth}, json={}).status_code == 401
    cid = register(client)
    form = form_for(client, cid)
    form.pop("username")
    form.pop("password")
    response = client.post("/login", data=form, headers={"origin": BASE, "authorization": auth})
    assert response.status_code == 303, response.text


def test_password_failure_and_csrf(app):
    client, _ = app
    form = form_for(client, register(client))
    assert client.post("/login", data={**form, "csrf": "forged"}, headers={"origin": BASE}).status_code == 403
    bad = client.post("/login", data={**form, "password": "wrong"}, headers={"origin": BASE})
    assert bad.status_code == 401
    assert "wrong" not in bad.text and PASSWORD not in bad.text
    assert client.post("/login", data=form, headers={"origin": BASE}).status_code == 303


def test_login_without_origin_still_requires_csrf(app):
    client, _ = app
    form = form_for(client, register(client))
    forged = client.post("/login", data={**form, "csrf": "forged"})
    assert forged.status_code == 403
    assert forged.json() == {"error": "invalid_csrf"}
    assert client.post("/login", data=form).status_code == 303


def test_login_rejects_foreign_origin(app):
    client, _ = app
    form = form_for(client, register(client))
    response = client.post("/login", data=form, headers={"origin": "https://evil.test"})
    assert response.status_code == 403
    assert response.json() == {"error": "invalid_origin"}


def test_login_page_allows_cross_origin_navigation_but_checks_host(app):
    client, _ = app
    location = begin(client, register(client)).headers["location"]
    page = client.get(location, headers={"origin": "https://client.test"})
    assert page.status_code == 200
    assert "Connect your email" in page.text

    another_location = begin(client, register(client)).headers["location"]
    rejected = client.get(
        another_location, headers={"host": "evil.test", "origin": "https://client.test"}
    )
    assert rejected.status_code == 400
    assert rejected.json() == {"error": "invalid_host"}


def test_consent_deny(app):
    client, _ = app
    form = form_for(client, register(client))
    response = client.post(
        "/login", data={**form, "decision": "deny", "password": ""}, headers={"origin": BASE}
    )
    assert response.status_code == 200
    assert "No access was granted" in response.text
    assert "location" not in response.headers


def test_browser_binding(app):
    client, _ = app
    form = form_for(client, register(client))
    client.cookies.clear()
    assert client.post("/login", data=form, headers={"origin": BASE}).status_code == 403


def test_login_rate_limit(app):
    client, _ = app
    form = form_for(client, register(client))
    for _ in range(5):
        assert (
            client.post("/login", data={**form, "password": "bad"}, headers={"origin": BASE}).status_code
            == 401
        )
    assert client.post("/login", data=form, headers={"origin": BASE}).status_code == 429


@pytest.mark.parametrize(
    "override",
    [
        {"resource": "https://attacker.test/mcp"},
        {"code_challenge_method": "plain"},
        {"code_challenge": "short"},
        {"redirect_uri": "https://attacker.test/callback"},
        {"scope": "admin"},
    ],
)
def test_reject_bad_authorization(app, override):
    client, _ = app
    result = begin(client, register(client), **override)
    assert result.status_code in (400, 403) or "error=" in result.headers.get("location", ""), result.text


def test_registration_callback_allowlist(app):
    client, _ = app
    result = client.post(
        "/register",
        json={"redirect_uris": ["https://evil.test/callback"], "token_endpoint_auth_method": "none"},
    )
    assert result.status_code == 400, result.text


def test_dynamic_registration_binds_https_and_loopback_callbacks(app):
    client, auth = app
    auth.config = replace(auth.config, redirect_uris=("*",))
    callback = "https://second-client.example/oauth/callback"
    client_id = register(client, callback)
    accepted = begin(
        client,
        client_id,
        callback=callback,
    )
    assert accepted.status_code == 302
    assert urlsplit(accepted.headers["location"]).path == "/login"

    local_callback = "http://127.0.0.1:51004/oauth/callback"
    local_client_id = register(client, local_callback)
    port_changed = begin(
        client,
        local_client_id,
        callback="http://127.0.0.1:61023/oauth/callback",
    )
    assert port_changed.status_code == 302
    assert urlsplit(port_changed.headers["location"]).path == "/login"

    unregistered = begin(
        client,
        local_client_id,
        callback="http://127.0.0.1:61023/attacker",
    )
    assert unregistered.status_code == 400
    assert "location" not in unregistered.headers


def test_dynamic_registration_accepts_reverse_domain_native_callback(app):
    client, auth = app
    auth.config = replace(auth.config, redirect_uris=("*",))
    callback = "com.example.desktop:/oauth/callback"
    client_id = register(client, callback)
    accepted = begin(client, client_id, callback=callback)
    assert accepted.status_code == 302
    assert urlsplit(accepted.headers["location"]).path == "/login"


def test_dynamic_registration_rejects_unsafe_callbacks(app):
    client, auth = app
    auth.config = replace(auth.config, redirect_uris=("*",))
    for callback in (
        "http://attacker.example/callback",
        "javascript:alert(1)",
        "file:///tmp/oauth",
        "vscode://callback",
        "https://client.example/callback#fragment",
        "https://user@client.example/callback",
        "https://client.example/*",
    ):
        result = client.post(
            "/register",
            json={
                "redirect_uris": [callback],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": SCOPE,
            },
        )
        assert result.status_code == 400, (callback, result.text)


def test_authorization_errors_never_redirect_to_untrusted_callbacks(app):
    client, auth = app
    auth.config = replace(auth.config, redirect_uris=("*",))
    client_id = register(client, "https://attacker.example/callback")
    response = begin(client, client_id, scope="unknown")
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert "location" not in response.headers


def test_pkce_code_replay_and_token_resource(app):
    client, _ = app
    cid = register(client)
    code = issue_code(client, cid)
    assert redeem(client, cid, code, resource="https://evil.test/mcp").status_code == 400
    assert redeem(client, cid, code, code_verifier="wrong").status_code in (400, 401)
    assert redeem(client, cid, code).status_code == 200
    assert redeem(client, cid, code).status_code in (400, 401)


def test_refresh_rotation_replay_revokes_family(app):
    client, auth = app
    cid, initial = token_pair(client)
    refreshed = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": cid,
            "refresh_token": initial["refresh_token"],
            "resource": BASE + "/mcp",
        },
    )
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["refresh_token"] != initial["refresh_token"]
    replay = client.post(
        "/token",
        data={"grant_type": "refresh_token", "client_id": cid, "refresh_token": initial["refresh_token"]},
    )
    assert replay.status_code in (400, 401)
    assert anyio.run(auth.load_access_token, refreshed.json()["access_token"]) is None


def test_refresh_scope_and_resource_escalation(app):
    client, _ = app
    cid, pair = token_pair(client)
    request = {"grant_type": "refresh_token", "client_id": cid, "refresh_token": pair["refresh_token"]}
    assert client.post("/token", data={**request, "scope": "admin"}).status_code in (400, 401)
    assert client.post("/token", data={**request, "resource": "https://evil.test/mcp"}).status_code == 400


def test_revoke_invalidates_access(app):
    client, auth = app
    cid, pair = token_pair(client)
    result = client.post(
        "/revoke", data={"client_id": cid, "token": pair["refresh_token"], "token_type_hint": "refresh_token"}
    )
    assert result.status_code == 200, result.text
    assert anyio.run(auth.load_access_token, pair["access_token"]) is None


def test_access_expiry_and_secrets_not_stored(app):
    client, auth = app
    _, pair = token_pair(client)
    data = auth.store.get("access", digest(pair["access_token"]))
    auth.store.put("access", digest(pair["access_token"]), data, time.time() - 1)
    assert anyio.run(auth.load_access_token, pair["access_token"]) is None
    for file in auth.store.path.parent.iterdir():
        contents = file.read_bytes()
        for value in (pair["access_token"], pair["refresh_token"], PASSWORD):
            assert value.encode() not in contents


def test_state_survives_restart_and_hash_change_revokes(app, settings, backend):
    client, auth = app
    _, pair = token_pair(client)
    _, _, again = create_server(settings, target=backend)
    assert anyio.run(again.load_access_token, pair["access_token"]) is not None
    again.store.close()
    new_hash = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1).hash("another-test-password")
    _, _, changed = create_server(replace(settings, password_hash=new_hash), target=backend)
    assert anyio.run(changed.load_access_token, pair["access_token"]) is None
    changed.store.close()


def test_request_boundary(app):
    client, _ = app
    assert client.get("/healthz", headers={"host": "evil.test"}).status_code == 400
    assert client.get("/healthz", headers={"origin": "https://evil.test"}).status_code == 403
    assert client.post("/register", content=b"x" * 17000).status_code == 413
    assert (
        client.post(
            "/token",
            content="resource=x&resource=y",
            headers={"content-type": "application/x-www-form-urlencoded"},
        ).status_code
        == 400
    )


@pytest.mark.parametrize(
    "change",
    [
        {"public_url": "http://mail.test"},
        {"public_url": "https://mail.test/prefix"},
        {"password_hash": "password"},
        {"redirect_uris": ()},
        {"redirect_uris": ("https://chatgpt.com/*",)},
        {"redirect_uris": ("*", CALLBACK)},
        {"redirect_uris": ("http://attacker.example/callback",)},
        {"redirect_uris": ("vscode://callback",)},
        {"username": ""},
    ],
)
def test_fail_closed_configuration(settings, change):
    with pytest.raises(ValueError):
        replace(settings, **change)


def test_open_dynamic_registration_configuration(settings):
    assert replace(settings, redirect_uris=("*",)).redirect_uris == ("*",)


def test_store_consumes_code_atomically(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    store = Store(tmp_path / "auth.sqlite3", "test-binding")
    store.put("code", digest("test-grant"), {"client_id": "c"}, time.time() + 60)

    def exchange(i):
        common = {"client_id": "c", "family": str(i), "expires_at": time.time() + 60}
        return store.exchange("code", "test-grant", "c", "a" + str(i), "r" + str(i), common, common)

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(exchange, range(8))) == 1
    store.close()
