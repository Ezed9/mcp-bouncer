"""Proxy mode must expose only the wrapped server's tools, never Bouncer's own.

In 0.1.x the proxy listed bouncer_check_verdict / bouncer_audit_summary beside
the upstream tools and handled them before the engine, so the agent being
constrained could reach them outside the audit log. This runs the real proxy
over stdio against the demo helpdesk server and checks the surface it exposes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import anyio
import pytest
from bouncer_mcp.cli import rewrite_config
from mcp import ClientSession, MCPError, StdioServerParameters
from mcp.client import Client, ClientRequestContext
from mcp.client.stdio import stdio_client
from mcp.types import ElicitRequestParams, ElicitResult
from mcp.types.version import HANDSHAKE_PROTOCOL_VERSIONS

_HELPDESK = Path(__file__).resolve().parents[2] / "examples" / "demo" / "helpdesk_server.py"


def _proxy_params(tmp_path: Path) -> tuple[StdioServerParameters, Path]:
    data = tmp_path / "helpdesk"
    (data / "workspace").mkdir(parents=True)
    (data / "customers.json").write_text("[]")
    home = tmp_path / "home"
    home.mkdir()
    config_path = tmp_path / "mcp-config.json"
    upstream = {"command": sys.executable, "args": [str(_HELPDESK), str(data)]}
    config = rewrite_config(
        {"mcpServers": {"helpdesk": upstream}},
        "helpdesk",
        command="bouncer",
        args=["run", "--config", str(config_path), "--upstream-name", "helpdesk"],
    )
    config_path.write_text(json.dumps(config))
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m", "bouncer_mcp", "run",
            "--config", str(config_path), "--upstream-name", "helpdesk",
        ],
        env={"HOME": str(home)},
    )
    return params, home / ".bouncer" / "audit.jsonl"


async def test_proxy_exposes_only_upstream_tools_and_gates_bouncer_names(tmp_path: Path) -> None:
    params, audit = _proxy_params(tmp_path)
    with anyio.fail_after(30):
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            names = {tool.name for tool in listed.tools}
            forged = await session.call_tool(
                "bouncer_check_verdict", {"tool": "send_email", "args": {"to": "x@y.example"}}
            )
            summary = await session.call_tool("bouncer_audit_summary", {"limit": 5})
            with pytest.raises(MCPError):
                await session.list_resources()
            with pytest.raises(MCPError):
                await session.list_prompts()

    assert "send_email" in names
    assert not {n for n in names if n.startswith("bouncer_")}
    for result in (forged, summary):
        assert result.is_error
        assert "[bouncer blocked]" in result.content[0].text

    # A call to a name the proxy never pinned goes through the engine and is
    # logged as a gated deny/ask; it must never appear as an allowed call.
    lines = [json.loads(line) for line in audit.read_text().splitlines()] if audit.exists() else []
    bouncer_lines = [line for line in lines if line["tool"].startswith("bouncer_")]
    assert bouncer_lines
    assert all(line["verdict"] != "allow" for line in bouncer_lines)


async def test_default_v2_client_still_gets_elicitation(tmp_path: Path) -> None:
    # A 2.x `Client` probes `server/discover` first. A 2026-07-28 connection has
    # no server-to-client requests, so the proxy declines discover and the
    # client falls back to the handshake; ASK must still reach the human.
    params, _audit = _proxy_params(tmp_path)
    asked: list[str] = []

    async def approve(
        context: ClientRequestContext, params: ElicitRequestParams
    ) -> ElicitResult:
        asked.append(params.message)
        return ElicitResult(action="accept", content={})

    args = {"to": "new.partner@example.com", "subject": "hi", "body": "hello"}
    with anyio.fail_after(30):
        async with Client(stdio_client(params), elicitation_callback=approve) as client:
            era = client.protocol_version
            sent = await client.call_tool("send_email", args)
            invalid = await client.call_tool("send_email", {"to": "x@y.example"})

    assert era in HANDSHAKE_PROTOCOL_VERSIONS
    assert len(asked) == 1
    assert not sent.is_error
    assert "sent to new.partner@example.com" in sent.content[0].text
    # Schema-invalid arguments are refused before the engine, as under mcp 1.x.
    assert invalid.is_error
    assert invalid.content[0].text.startswith("Input validation error")
