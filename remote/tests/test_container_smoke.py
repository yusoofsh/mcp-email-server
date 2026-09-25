"""Synthetic Compose restarts must not reuse an ephemeral published port."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import Mock, call

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify_container.py"
SPEC = importlib.util.spec_from_file_location("verify_container", SCRIPT)
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


def test_restart_rediscovers_ephemeral_port(monkeypatch):
    compose = ["docker", "compose", "--project-name", "synthetic-only"]
    env = {"MCP_BIND_PORT": "0"}
    run = Mock(side_effect=["127.0.0.1:41001", "", "127.0.0.1:42002"])
    first, second = Mock(), Mock()
    clients = Mock(side_effect=[first, second])
    monkeypatch.setattr(smoke, "run", run)
    monkeypatch.setattr(smoke, "Client", clients)
    assert smoke.connect_compose(compose, env) is first
    assert smoke.connect_compose(compose, env, restart=True) is second
    assert clients.call_args_list == [call(41001), call(42002)]
    assert run.call_args_list == [
        call(compose + ["port", "email-mcp", "9557"], env=env),
        call(compose + ["restart", "email-mcp"], env=env),
        call(compose + ["port", "email-mcp", "9557"], env=env),
    ]
    first.wait.assert_called_once_with()
    second.wait.assert_called_once_with()


@pytest.mark.parametrize(
    "endpoint",
    ["0.0.0.0:41001", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:bad", "127.0.0.1:1\n127.0.0.1:2", ""],
)
def test_invalid_listener_is_not_contacted(monkeypatch, endpoint):
    client = Mock()
    monkeypatch.setattr(smoke, "run", Mock(return_value=endpoint))
    monkeypatch.setattr(smoke, "Client", client)
    with pytest.raises(AssertionError, match="IPv4 loopback"):
        smoke.connect_compose(["docker", "compose"], {})
    client.assert_not_called()
