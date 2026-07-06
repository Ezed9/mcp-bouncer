# bouncer/src/bouncer/proxy.py
"""The async stdio MCP proxy shell.

`route_call` is the pure, SDK-free routing decision (fully unit-tested). The
`BouncerProxy` class wraps it in the MCP server/client glue: it connects to an
upstream stdio MCP server as a *client*, pins each tool's schema at startup,
re-exports the tools 1:1 on its own stdio *server*, and runs every incoming
tools/call through `route_call`.

All safety lives in the engine; this module only forwards, denies, or asks. No
LLM and no network/async in the decision path — the transport layer is the only
async part.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from pathlib import Path

import mcp.types as mcp_types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.stdio import stdio_server

from .approvals import ApprovalStore
from .audit import AuditLog
from .engine import ContractEngine
from .policy import PolicyResolver, builtin_pack_paths, load_policies
from .taint import TaintTracker
from .types import ToolCall, Verdict

# forward(call) -> upstream result text.
Forward = Callable[[ToolCall], str]
# elicit(message) -> did the human approve? None means the client cannot elicit,
# so ASK fails closed to DENY.
Elicit = Callable[[str], bool] | None
# Live-path elicit: async round-trip to the client; None => cannot elicit.
AsyncElicit = Callable[[str], Awaitable[bool]] | None

_DEFAULT_AUDIT_PATH = Path.home() / ".bouncer" / "audit.jsonl"


def route_call(
    engine: ContractEngine,
    call: ToolCall,
    forward: Forward,
    elicit: Elicit,
) -> tuple[str, Verdict]:
    """Route one tool call through the engine. A DENY never calls `forward`.

    ASK re-evaluates in a loop: each approval marks *one* destination trusted,
    then we ask the engine again. Only ALLOW forwards; a DENY surfacing on
    re-evaluation (a tainted element in a multi-recipient call) blocks the whole
    call. The loop is bounded by the number of distinct sink destinations and
    makes strict progress (one destination proven per iteration), so it cannot
    spin.
    """
    decision = engine.evaluate(call)

    if decision.verdict is Verdict.ALLOW:
        result = forward(call)
        engine.register_output(result)
        return result, Verdict.ALLOW

    if decision.verdict is Verdict.DENY:
        return f"[bouncer blocked] {decision.reason}", Verdict.DENY

    # ASK. Fail closed if the client cannot elicit.
    if elicit is None:
        return f"[bouncer blocked] {decision.reason}", Verdict.DENY

    # Bound the loop by the number of distinct sink destinations: every approval
    # proves one more, so at most that many ASK rounds can occur.
    max_rounds = _distinct_destination_count(call) + 1
    for _ in range(max_rounds):
        if decision.verdict is Verdict.ALLOW:
            result = forward(call)
            engine.register_output(result)
            return result, Verdict.ALLOW
        if decision.verdict is Verdict.DENY:
            return f"[bouncer blocked] {decision.reason}", Verdict.DENY
        # ASK: ask the human about this specific destination.
        approved = elicit(decision.reason)
        if not approved or decision.ask_key is None:
            return f"[bouncer blocked] {decision.reason}", Verdict.DENY
        engine.on_approved(decision.ask_key)
        decision = engine.evaluate(call)

    # Loop exhausted without resolving (defensive; shouldn't happen given the
    # strict-progress bound). Fail closed.
    return f"[bouncer blocked] {decision.reason}", Verdict.DENY


def _distinct_destination_count(call: ToolCall) -> int:
    total = 0
    for value in call.args.values():
        if isinstance(value, (list, tuple)):
            total += len(value)
        else:
            total += 1
    return max(total, 1)


def _result_text(result: mcp_types.CallToolResult) -> str:
    """Flatten an upstream CallToolResult's content into plain text for taint."""
    parts: list[str] = []
    for block in result.content:
        text = getattr(block, "text", None)
        if text is not None:
            parts.append(str(text))
    return "\n".join(parts)


class BouncerProxy:
    """Stdio MCP proxy that gates one upstream server behind the engine."""

    def __init__(self, engine: ContractEngine, session: ClientSession) -> None:
        self._engine = engine
        self._upstream = session

    @classmethod
    async def serve(
        cls,
        upstream_command: str,
        upstream_args: list[str] | None = None,
        server_name: str = "bouncer",
    ) -> None:
        """Connect the upstream, pin its schemas, build the engine, and serve.

        `upstream_command`/`upstream_args` are the launch command for the
        upstream stdio MCP server (the CLI in Task 12 supplies these from its
        config). We stay connected for the whole session.
        """
        params = StdioServerParameters(
            command=upstream_command,
            args=upstream_args or [],
        )
        async with AsyncExitStack() as stack:
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()

            listed = await session.list_tools()
            tools = list(listed.tools)
            schemas: dict[str, dict[str, object]] = {
                tool.name: dict(tool.inputSchema or {}) for tool in tools
            }

            engine = ContractEngine(
                resolver=PolicyResolver(overrides=load_policies(builtin_pack_paths())),
                taint=TaintTracker(),
                approvals=ApprovalStore(),
                audit=AuditLog(_DEFAULT_AUDIT_PATH),
                schemas=schemas,
            )
            proxy = cls(engine, session)
            await proxy._run_server(server_name, tools)

    async def _run_server(
        self, server_name: str, tools: list[mcp_types.Tool]
    ) -> None:
        server: Server = Server(server_name)

        @server.list_tools()
        async def _list_tools() -> list[mcp_types.Tool]:
            # Re-export the upstream tools 1:1.
            return tools

        @server.call_tool()
        async def _call_tool(
            name: str, arguments: dict[str, object]
        ) -> list[mcp_types.ContentBlock]:
            ctx = server.request_context
            call = ToolCall(tool=name, args=arguments)

            async def do_forward() -> str:
                result = await self._upstream.call_tool(name, arguments)
                return _result_text(result)

            elicit = self._make_elicit(ctx)
            text, verdict = await self._route_async(call, do_forward, elicit)
            if verdict is Verdict.DENY:
                # Raised so the SDK marks the tools/call result isError=True; the
                # model reads the deny reason as a tool error and never sees an
                # upstream result (the upstream was never called).
                raise _ToolDenied(text)
            return [mcp_types.TextContent(type="text", text=text)]

        options = server.create_initialization_options(
            notification_options=NotificationOptions()
        )
        async with stdio_server() as (read, write):
            await server.run(read, write, options)

    async def _route_async(
        self,
        call: ToolCall,
        forward: Callable[[], Awaitable[str]],
        elicit: AsyncElicit,
    ) -> tuple[str, Verdict]:
        """Async mirror of `route_call` for the live transport.

        Structurally identical to `route_call` — same order, same fail-closed
        rules, same distinct-destination bound — but it *awaits* the upstream
        `call_tool` and the elicitation round-trip, which the sync helper cannot.
        `route_call` remains the single, exhaustively-tested statement of the
        policy; this keeps line-for-line parity with it.
        """
        decision = self._engine.evaluate(call)

        if decision.verdict is Verdict.ALLOW:
            text = await forward()
            self._engine.register_output(text)
            return text, Verdict.ALLOW

        if decision.verdict is Verdict.DENY:
            return f"[bouncer blocked] {decision.reason}", Verdict.DENY

        if elicit is None:
            return f"[bouncer blocked] {decision.reason}", Verdict.DENY

        max_rounds = _distinct_destination_count(call) + 1
        for _ in range(max_rounds):
            if decision.verdict is Verdict.ALLOW:
                text = await forward()
                self._engine.register_output(text)
                return text, Verdict.ALLOW
            if decision.verdict is Verdict.DENY:
                return f"[bouncer blocked] {decision.reason}", Verdict.DENY
            approved = await elicit(decision.reason)
            if not approved or decision.ask_key is None:
                return f"[bouncer blocked] {decision.reason}", Verdict.DENY
            self._engine.on_approved(decision.ask_key)
            decision = self._engine.evaluate(call)

        return f"[bouncer blocked] {decision.reason}", Verdict.DENY

    def _make_elicit(self, ctx: object) -> AsyncElicit:
        """Return an async elicit callable, or None if the client can't elicit.

        Detects the client's elicitation capability; if absent, ASK fails closed.
        """
        session = getattr(ctx, "session", None)
        if session is None:
            return None
        supports = session.check_client_capability(
            mcp_types.ClientCapabilities(
                elicitation=mcp_types.ElicitationCapability()
            )
        )
        if not supports:
            return None

        async def _elicit(message: str) -> bool:  # pragma: no cover - live path
            result = await session.elicit(
                message=message,
                requestedSchema={"type": "object", "properties": {}},
            )
            return result.action == "accept"

        return _elicit


class _ToolDenied(Exception):
    """Raised so the SDK marks the tools/call result as an error for the model."""
