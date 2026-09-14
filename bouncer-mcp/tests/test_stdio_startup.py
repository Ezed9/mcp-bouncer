"""The server must start and answer over real stdio, under whatever `mcp` resolves.

Every other test calls handlers in-process, which is how 0.1.1 shipped a proxy
that could not start: under mcp 2.x the low-level Server lost its decorators and
`bouncer serve` died before initialize, while all 97 unit tests passed.
"""

from __future__ import annotations

import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_BUILTIN_TOOLS = {
    "bouncer_check_verdict",
    "bouncer_verify_policy",
    "bouncer_get_active_policies",
    "bouncer_audit_summary",
}


async def test_bouncer_serve_starts_and_lists_its_tools_over_stdio() -> None:
    params = StdioServerParameters(command=sys.executable, args=["-m", "bouncer_mcp", "serve"])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        listed = await session.list_tools()

    assert {tool.name for tool in listed.tools} == _BUILTIN_TOOLS
