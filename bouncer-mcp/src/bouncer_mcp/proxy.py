# bouncer/src/bouncer/proxy.py
"""The async stdio MCP proxy shell.

`route_call` is the pure, SDK-free routing decision (fully unit-tested). The
`BouncerProxy` class wraps it in the MCP server/client glue: it connects to an
upstream stdio MCP server as a *client*, pins each tool's schema at startup,
re-exports the tools 1:1 on its own stdio *server* (and nothing else: no Bouncer
management tools, prompts or resources are exposed to the agent), and runs every
incoming tools/call through `route_call`.

All safety lives in the engine; this module only forwards, denies, or asks. No
LLM and no network/async in the decision path — the transport layer is the only
async part.

A client that cannot elicit gets a one-time approval code instead of a prompt
(`_without_elicitation`): the call is denied, the human runs `bouncer approve
<code>` in their own terminal, and a retry of a call to the same destination
passes once. Clients that can elicit never reach that path.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from pathlib import Path

import jsonschema
import mcp.types as mcp_types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server import NotificationOptions, Server, ServerRequestContext
from mcp.server.runner import serve_loop
from mcp.server.stdio import stdio_server

from bouncer.approvals import ApprovalStore
from bouncer.audit import AuditLog
from bouncer.engine import ContractEngine, destination_count
from bouncer.pending import TTL_SECONDS, PendingApprovals, show_code
from bouncer.policy import PolicyResolver, builtin_pack_paths, load_policies
from bouncer.taint import TaintTracker
from bouncer.types import Decision, ToolCall, Verdict

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
    pending: PendingApprovals | None = None,
    server: str = "",
) -> tuple[str, Verdict]:
    """Route one tool call through the engine. A DENY never calls `forward`.

    ASK re-evaluates in a loop: each approval marks *one* destination trusted,
    then we ask the engine again. Only ALLOW forwards; a DENY surfacing on
    re-evaluation (a tainted element in a multi-recipient call) blocks the whole
    call. The loop is bounded by the number of distinct sink destinations and
    makes strict progress (one destination proven per iteration), so it cannot
    spin.

    Without elicitation, ASK goes to `_without_elicitation`: with no `pending`
    store it is a DENY, as before; with one, a one-time approval code.
    """
    decision = engine.evaluate(call)

    if decision.verdict is Verdict.ALLOW:
        result = forward(call)
        engine.register_output(result)
        return result, Verdict.ALLOW

    if decision.verdict is Verdict.DENY:
        return f"[bouncer blocked] {decision.reason}", Verdict.DENY

    # ASK, and the client cannot elicit: deny, with a one-time code if possible.
    if elicit is None:
        blocked = _without_elicitation(engine, call, decision, pending, server)
        if blocked is not None:
            return blocked, Verdict.DENY
        result = forward(call)
        engine.register_output(result)
        return result, Verdict.ALLOW

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
        # A pinning ASK (ask_key is None) has no destination to vouch for, so a
        # human answer can't resolve it — deny without a pointless elicit round.
        if decision.ask_key is None:
            return f"[bouncer blocked] {decision.reason}", Verdict.DENY
        # ASK: ask the human about this specific destination.
        approved = elicit(decision.reason)
        if not approved:
            return f"[bouncer blocked] {decision.reason}", Verdict.DENY
        engine.on_approved(decision.ask_key)
        # count_budget=False: a re-eval within one client call must not re-spend.
        decision = engine.evaluate(call, count_budget=False)

    # Loop exhausted without resolving (defensive; shouldn't happen given the
    # strict-progress bound). Fail closed.
    return f"[bouncer blocked] {decision.reason}", Verdict.DENY


def _blocked(reason: str) -> str:
    return f"[bouncer blocked] {reason}"


def _without_elicitation(
    engine: ContractEngine,
    call: ToolCall,
    decision: Decision,
    pending: PendingApprovals | None,
    server: str,
) -> str | None:
    """Resolve an ASK for a client that cannot elicit. None means forward.

    Otherwise returns the blocked text. Every destination the engine asks
    about must have an approved one-time code for this exact (server, approval
    key); if any lacks one, codes are issued for all that lack one and the call
    is denied. Codes are used up only when the call is forwarded, so approving
    the second of two recipients doesn't waste the first.

    Fail-closed cases, all DENY with no code: no store; a pinning ASK
    (`ask_key` None); a DENY found on the way (a tainted recipient); too many
    pending codes; an approval that expired or was used between the check and
    the forward.
    """
    if pending is None or decision.ask_key is None:
        return _blocked(decision.reason)
    first_reason = decision.reason
    granted: set[str] = set()
    needed: list[tuple[str, str]] = []
    for _ in range(_distinct_destination_count(call) + 1):
        if decision.verdict is Verdict.ALLOW:
            break
        if decision.verdict is Verdict.DENY or decision.ask_key is None:
            return _blocked(decision.reason)
        if pending.is_approved(server, decision.ask_key):
            granted.add(decision.ask_key)
        else:
            needed.append((decision.ask_key, decision.reason))
        # A lookahead, not the real verdict: assume the missing approvals so
        # the next destination surfaces. preview() logs no audit line.
        decision = engine.preview(call, frozenset(granted | {k for k, _ in needed}))
    else:
        return _blocked(decision.reason)

    if needed:
        codes = pending.request(server, call.tool, needed)
        if codes is None:
            return _blocked(
                f"{first_reason}; too many approvals are pending "
                "(a human can run `bouncer pending` to review them)"
            )
        return _approval_needed(needed, codes)

    if not pending.consume(server, granted):
        return _blocked(f"{first_reason}; its one-time approval expired or was already used")
    # The real, audited decision with the approvals this call just used.
    final = engine.evaluate(call, count_budget=False, granted=frozenset(granted))
    if final.verdict is not Verdict.ALLOW:
        return _blocked(final.reason)
    return None


def _approval_needed(needed: list[tuple[str, str]], codes: list[str]) -> str:
    shown = [show_code(c) for c in codes]
    lines = [
        _blocked(needed[0][1]),
        "This MCP client can't ask the user to confirm, so this call needs a "
        "one-time approval from a human. In their own terminal, not through the "
        f"agent, they run: bouncer approve {' '.join(shown)}",
        f"Then retry the same call within {TTL_SECONDS // 60} minutes. "
        "The approval allows one call to this destination.",
    ]
    if len(needed) > 1:
        lines += [f"{code}: {reason}" for code, (_, reason) in zip(shown, needed, strict=True)]
    return "\n".join(lines)


def _distinct_destination_count(call: ToolCall) -> int:
    # Count the way the gate flattens (nested lists, dict values and keys), so
    # a nested recipient list cannot run the loop out after the human approved.
    return destination_count(call.args)


def _result_text(result: mcp_types.CallToolResult) -> str:
    """Flatten an upstream CallToolResult's content into plain text for taint.

    Text blocks, plus the text and uri of an embedded resource and the uri,
    name, title and description of a resource link: the model reads those too.
    """
    parts: list[str] = []
    for block in result.content:
        for obj in (block, getattr(block, "resource", None)):
            for field in ("text", "uri", "name", "title", "description"):
                value = getattr(obj, field, None)
                if value is not None:
                    parts.append(str(value))
    return "\n".join(parts)


def _denied_result(reason: str) -> mcp_types.CallToolResult:
    """A Bouncer DENY surfaced as an error tool-result — no upstream forward.

    `is_error=True` and no `structured_content`: the model reads the deny reason
    as a tool error, distinct from an upstream error. The low-level SDK relays a
    returned `CallToolResult` verbatim (it does not validate it against the
    tool's outputSchema), so an unstructured deny is safe even for tools that
    declare an outputSchema.
    """
    return _error_result(f"[bouncer blocked] {reason}")


def _error_result(text: str) -> mcp_types.CallToolResult:
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=text)],
        is_error=True,
    )


def _build_resolver(user_policy: Path | None = None) -> PolicyResolver:
    """Resolver over the builtin packs, with an optional user YAML on top.

    `load_policies` builds a single name->policy dict where later paths win, so
    listing the user YAML *after* the packs makes it the highest-priority
    override (a user contract beats a curated pack). No user policy => packs
    only, exactly as before.
    """
    paths = builtin_pack_paths()
    if user_policy is not None:
        paths = [*paths, user_policy]
    return PolicyResolver(overrides=load_policies(paths))


class BouncerProxy:
    """Stdio MCP proxy that gates one upstream server behind the engine."""

    def __init__(
        self,
        engine: ContractEngine,
        session: ClientSession,
        user_policy: Path | None = None,
        pending: PendingApprovals | None = None,
        server_name: str = "",
    ) -> None:
        self._engine = engine
        self._upstream = session
        self._user_policy = user_policy
        # Outside the MCP surface: a local 0600 file. Nothing here exposes it.
        self._pending = pending
        self._server_name = server_name

    @classmethod
    async def serve(
        cls,
        upstream_command: str,
        upstream_args: list[str] | None = None,
        server_name: str = "bouncer",
        user_policy: Path | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> None:
        """Connect the upstream, pin its schemas, build the engine, and serve.

        `upstream_command`/`upstream_args` are the launch command for the
        upstream stdio MCP server (the CLI in Task 12 supplies these from its
        config). We stay connected for the whole session.

        `env`/`cwd`, if given, are passed straight through to the upstream
        subprocess (recovered from the wrapped config's stashed original entry
        -- credentials for servers like github/gmail/slack live in `env`).
        `None` preserves the prior behaviour (inherit the parent's env, cwd).

        `user_policy`, if given, is a user contract YAML layered as the
        highest-priority override over the builtin packs (see
        `_build_resolver`). None keeps the prior behaviour: builtin packs only.
        """
        params = StdioServerParameters(
            command=upstream_command,
            args=upstream_args or [],
            env=env,
            cwd=cwd,
        )
        async with AsyncExitStack() as stack:
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()

            listed = await session.list_tools()
            tools = list(listed.tools)
            schemas: dict[str, dict[str, object]] = {
                tool.name: dict(tool.input_schema or {}) for tool in tools
            }

            engine = ContractEngine(
                resolver=_build_resolver(user_policy),
                taint=TaintTracker(),
                approvals=ApprovalStore(),
                audit=AuditLog(_DEFAULT_AUDIT_PATH),
                schemas=schemas,
            )
            proxy = cls(
                engine, session, user_policy=user_policy,
                pending=PendingApprovals(), server_name=server_name,
            )
            await proxy._run_server(server_name, tools)

    async def _run_server(
        self, server_name: str, tools: list[mcp_types.Tool]
    ) -> None:
        by_name = {tool.name: tool for tool in tools}

        # Proxy mode exposes ONLY the upstream tools. Bouncer's own management
        # surface (bouncer_check_verdict, bouncer_audit_summary, ...) lives in
        # `bouncer serve`; here it would be reachable by the very agent being
        # constrained, outside the engine and the audit log, and could forge
        # audit lines or read every wrapped server's logged arguments.
        async def _list_tools(
            ctx: ServerRequestContext, params: mcp_types.PaginatedRequestParams | None
        ) -> mcp_types.ListToolsResult:
            return mcp_types.ListToolsResult(tools=tools)

        async def _call_tool(
            ctx: ServerRequestContext, params: mcp_types.CallToolRequestParams
        ) -> mcp_types.CallToolResult:
            name = params.name
            arguments: dict[str, object] = dict(params.arguments or {})
            # The 2.x low-level Server neither validates input nor turns handler
            # exceptions into error results; the 1.x decorator did both, so we
            # keep doing them here.
            try:
                tool = by_name.get(name)
                if tool is not None:
                    try:
                        jsonschema.validate(instance=arguments, schema=tool.input_schema)
                    except jsonschema.ValidationError as exc:
                        return _error_result(f"Input validation error: {exc.message}")

                call = ToolCall(tool=name, args=arguments)

                async def do_forward() -> mcp_types.CallToolResult:
                    # Relay the FULL upstream result so its structured_content
                    # and content survive to the client. `register_output` still
                    # gets the flattened text for taint; that split happens in
                    # `_route_async`.
                    return await self._upstream.call_tool(name, arguments)

                elicit = self._make_elicit(ctx)
                result, _verdict = await self._route_async(call, do_forward, elicit)
                # DENY: an error result returned WITHOUT forwarding and WITHOUT
                # fabricated structured_content. ALLOW/ASK-approved: the
                # upstream CallToolResult, relayed verbatim.
                return result
            except Exception as exc:
                # An upstream error message is server-controlled text the model
                # will read, so it is untrusted output like any result.
                self._engine.register_output(str(exc))
                return _error_result(str(exc))

        server: Server = Server(
            server_name, on_list_tools=_list_tools, on_call_tool=_call_tool
        )
        options = server.create_initialization_options(
            notification_options=NotificationOptions()
        )
        # Handshake era only. `server.run` would also serve 2026-07-28, which
        # has no server-to-client requests, so ASK could never elicit there.
        # 2.x clients in mode="auto" fall back to the handshake on their own.
        async with stdio_server() as (read, write), server.lifespan(server) as state:
            await serve_loop(server, read, write, lifespan_state=state, init_options=options)

    async def _route_async(
        self,
        call: ToolCall,
        forward: Callable[[], Awaitable[mcp_types.CallToolResult]],
        elicit: AsyncElicit,
    ) -> tuple[mcp_types.CallToolResult, Verdict]:
        """Async mirror of `route_call` for the live transport.

        Structurally identical to `route_call` — same order, same fail-closed
        rules, same distinct-destination bound — but it *awaits* the upstream
        `call_tool` and the elicitation round-trip, which the sync helper cannot.
        `route_call` remains the single, exhaustively-tested statement of the
        policy; this keeps line-for-line parity with it.

        Unlike the pure helper (which relays flattened text), this returns the
        FULL upstream `CallToolResult` on ALLOW so `structured_content`,
        `content`, and `is_error` reach the client intact; taint still sees only
        the text.
        """
        decision = self._engine.evaluate(call)

        if decision.verdict is Verdict.ALLOW:
            return await self._forward_and_record(forward), Verdict.ALLOW

        if decision.verdict is Verdict.DENY:
            return _denied_result(decision.reason), Verdict.DENY

        if elicit is None:
            blocked = _without_elicitation(
                self._engine, call, decision, self._pending, self._server_name
            )
            if blocked is not None:
                return _error_result(blocked), Verdict.DENY
            return await self._forward_and_record(forward), Verdict.ALLOW

        max_rounds = _distinct_destination_count(call) + 1
        for _ in range(max_rounds):
            if decision.verdict is Verdict.ALLOW:
                return await self._forward_and_record(forward), Verdict.ALLOW
            if decision.verdict is Verdict.DENY:
                return _denied_result(decision.reason), Verdict.DENY
            if decision.ask_key is None:
                return _denied_result(decision.reason), Verdict.DENY
            approved = await elicit(decision.reason)
            if not approved:
                return _denied_result(decision.reason), Verdict.DENY
            self._engine.on_approved(decision.ask_key)
            decision = self._engine.evaluate(call, count_budget=False)

        return _denied_result(decision.reason), Verdict.DENY

    async def _forward_and_record(
        self, forward: Callable[[], Awaitable[mcp_types.CallToolResult]]
    ) -> mcp_types.CallToolResult:
        """Forward upstream, feed the output to taint, and relay the full result.

        Both text blocks AND structured_content are recorded as untrusted: modern
        servers return destinations (emails, urls) only via structured_content,
        so ignoring it would blind the taint tracker to those values.
        """
        result = await forward()
        self._engine.register_output(_result_text(result))
        if result.structured_content is not None:
            self._engine.register_output(json.dumps(result.structured_content, default=str))
        return result

    def _make_elicit(self, ctx: object) -> AsyncElicit:
        """Return an async elicit callable, or None if the client can't elicit.

        Detects the client's elicitation capability, and that the connection
        can carry a server-to-client request at all; if not, ASK fails closed.
        """
        session = getattr(ctx, "session", None)
        if session is None or not session.can_send_request:
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
                requested_schema={"type": "object", "properties": {}},
            )
            return result.action == "accept"

        return _elicit
