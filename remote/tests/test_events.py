import base64
import json

import pytest
from fastmcp import FastMCP
from starlette.testclient import TestClient
from test_oauth import BASE, password_hash, settings, token_pair  # noqa: F401, F811

from email_mcp_remote.server import create_server
from email_mcp_remote.store import digest

KEY = "whsec_" + base64.b64encode(b"k" * 32).decode()
META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}


@pytest.fixture
def event_app(settings):  # noqa: F811
    backend = FastMCP("Event fixture")
    source, sent = [], []
    status = [204]

    @backend.tool()
    def list_available_accounts() -> list[dict]:
        return [{"account_name": "test", "can_receive": True}]

    @backend.tool()
    def list_emails_metadata(account_name: str, since: str, before: str, page: int, page_size: int) -> dict:
        return {"emails": source[(page - 1) * page_size : page * page_size], "total": len(source)}

    mcp, app, auth = create_server(settings, backend)
    events = next(x for x in mcp._extensions.values() if x.identifier == "id.yusoofsh/events")

    def post(url, headers, body):
        value = json.loads(body)
        sent.append((headers, value))
        return (
            (200, {"challenge": value["challenge"]})
            if value.get("type") == "verification"
            else (status[0], {})
        )

    events.post = post
    with TestClient(app, base_url=BASE, follow_redirects=False) as client:
        yield client, auth, events, source, sent, status
    auth.store.close()


def rpc(client, tokens, method, params=None):
    res = client.post(
        "/mcp",
        headers={
            "Authorization": "Bearer " + tokens["access_token"],
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2026-07-28",
            "MCP-Method": method,
        },
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": {"_meta": META, **(params or {})}},
    )
    assert res.status_code in (200, 400), res.text
    return res.json()


def params():
    return {
        "name": "email.received",
        "arguments": {"account_name": "test"},
        "delivery": {"mode": "webhook", "url": "https://callback.example.test/events", "secret": KEY},
    }


def test_wire_delivery_and_revocation(event_app):
    client, auth, events, source, sent, _ = event_app
    _, tokens = token_pair(client)
    assert "events" in rpc(client, tokens, "server/discover")["result"]["capabilities"]
    assert rpc(client, tokens, "events/list")["result"]["events"][0]["name"] == "email.received"
    first = rpc(client, tokens, "events/subscribe", params())["result"]
    assert rpc(client, tokens, "events/subscribe", params())["result"]["id"] == first["id"]
    assert len(sent) == 1
    source.append({"email_id": "message-1", "subject": "private"})
    client.portal.call(events.tick)
    assert sent[-1][1]["data"] == {"account_name": "test", "email_id": "message-1"}
    assert "private" not in json.dumps(sent)
    assert KEY.encode() not in auth.store.path.read_bytes()
    owner = auth.store.get("access", digest(tokens["access_token"]))["family"]
    auth.store.revoke(owner)
    client.portal.call(events.tick)
    assert events._list("event_subscription") == []


def test_bad_input_and_unsubscribe(event_app):
    client, _, events, _, _, _ = event_app
    _, tokens = token_pair(client)
    p = params()
    p["arguments"]["unknown"] = "x"
    assert rpc(client, tokens, "events/subscribe", p)["error"]["code"] == -32602
    p = params()
    p["delivery"]["secret"] = "whsec_YQ=="
    assert rpc(client, tokens, "events/subscribe", p)["error"]["code"] == -32602
    rpc(client, tokens, "events/subscribe", params())
    assert rpc(client, tokens, "events/unsubscribe", params())["result"]["resultType"] == "complete"
    assert rpc(client, tokens, "events/unsubscribe", params())["result"]["resultType"] == "complete"
    assert events._list("event_subscription") == []
