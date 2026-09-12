# bouncer-mcp/src/bouncer_mcp/server.py
"""Standalone Bouncer MCP server and native capability declarations.

Provides:
- Native MCP tools (Skills) for policy validation, hypothetical verdict evaluation,
  active policy inspection, and security audit summarization.
- Native MCP prompts for reviewing MCP server security and generating policies.
- Native MCP resources for accessing built-in contract packs and audit summaries.
- Standalone stdio MCP server runner.
"""

from __future__ import annotations

import json
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import mcp.types as mcp_types
import yaml
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.stdio import stdio_server

from bouncer.approvals import ApprovalStore
from bouncer.audit import AuditLog
from bouncer.engine import ContractEngine
from bouncer.policy import (
    PolicyError,
    PolicyResolver,
    _policy_from_dict,
    builtin_pack_paths,
    load_policies,
)
from bouncer.taint import TaintTracker
from bouncer.types import ToolCall

_DEFAULT_AUDIT_PATH = Path.home() / ".bouncer" / "audit.jsonl"


def get_builtin_tools() -> list[mcp_types.Tool]:
    """Return Bouncer's native MCP tools (Skills)."""
    return [
        mcp_types.Tool(
            name="bouncer_check_verdict",
            description=(
                "Evaluate a hypothetical tool call against Bouncer's deterministic "
                "security contracts and return the verdict (ALLOW, DENY, or ASK) "
                "with the underlying reason, without executing the tool."
            ),
            inputSchema={
                "type": "object",
                "required": ["tool"],
                "properties": {
                    "tool": {
                        "type": "string",
                        "description": (
                            "Name of the tool being called (e.g. 'send_email', 'write_file')."
                        ),
                    },
                    "args": {
                        "type": "object",
                        "description": "Arguments passed to the tool call.",
                    },
                    "untrusted_context": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "List of untrusted strings currently in context "
                            "(from prior tool outputs)."
                        ),
                    },
                    "user_policy_yaml": {
                        "type": "string",
                        "description": "Optional YAML policy with custom contract overrides.",
                    },
                },
            },
        ),
        mcp_types.Tool(
            name="bouncer_verify_policy",
            description=(
                "Validate a YAML policy string against Bouncer's schema and report "
                "syntax validity, contract rules count, and covered tools."
            ),
            inputSchema={
                "type": "object",
                "required": ["policy_yaml"],
                "properties": {
                    "policy_yaml": {
                        "type": "string",
                        "description": "YAML content defining tool policies.",
                    },
                },
            },
        ),
        mcp_types.Tool(
            name="bouncer_get_active_policies",
            description=(
                "Inspect all active contract packs (builtin rules for filesystem, "
                "email, http, bash, etc.) and user overrides loaded by Bouncer."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pack_name": {
                        "type": "string",
                        "description": (
                            "Optional name of a specific pack to inspect (e.g. 'filesystem')."
                        ),
                    },
                },
            },
        ),
        mcp_types.Tool(
            name="bouncer_audit_summary",
            description=(
                "Retrieve recent audit log entries from Bouncer showing allowed, "
                "denied, and asked tool calls with their timestamps and reasons."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of recent entries to return (default: 20).",
                        "default": 20,
                    },
                },
            },
        ),
    ]


def handle_builtin_tool_call(
    name: str,
    arguments: dict[str, Any],
    user_policy: Path | None = None,
) -> mcp_types.CallToolResult | None:
    """Handle an invocation of one of Bouncer's native tools."""
    if name == "bouncer_check_verdict":
        tool_name = str(arguments.get("tool", ""))
        raw_args = arguments.get("args") or {}
        call_args = dict(raw_args) if isinstance(raw_args, dict) else {}
        untrusted = arguments.get("untrusted_context") or []
        user_yaml = arguments.get("user_policy_yaml")

        paths = builtin_pack_paths()
        temp_dir_obj = None
        if isinstance(user_yaml, str) and user_yaml.strip():
            temp_dir_obj = tempfile.TemporaryDirectory()
            temp_p = Path(temp_dir_obj.name) / "policy.yaml"
            temp_p.write_text(user_yaml)
            paths = [*paths, temp_p]
        elif user_policy is not None:
            paths = [*paths, user_policy]

        try:
            resolver = PolicyResolver(overrides=load_policies(paths))
            taint = TaintTracker()
            if isinstance(untrusted, list):
                for item in untrusted:
                    taint.record_output(str(item))

            engine = ContractEngine(
                resolver=resolver,
                taint=taint,
                approvals=ApprovalStore(),
                audit=AuditLog(_DEFAULT_AUDIT_PATH),
                schemas={tool_name: {}},
            )
            decision = engine.evaluate(ToolCall(tool=tool_name, args=call_args))
            payload = {
                "tool": tool_name,
                "args": call_args,
                "verdict": decision.verdict.value,
                "reason": decision.reason,
                "ask_key": decision.ask_key,
            }
            return mcp_types.CallToolResult(
                content=[
                    mcp_types.TextContent(
                        type="text",
                        text=json.dumps(payload, indent=2),
                    )
                ]
            )
        finally:
            if temp_dir_obj is not None:
                temp_dir_obj.cleanup()

    if name == "bouncer_verify_policy":
        policy_yaml = str(arguments.get("policy_yaml", ""))
        try:
            data = yaml.safe_load(policy_yaml) or {}
            if not isinstance(data, dict):
                raise PolicyError(
                    "Top-level YAML must be a mapping of tool names to policies, "
                    f"got {type(data).__name__}"
                )
            tools_covered = []
            for t_name, raw in data.items():
                _policy_from_dict(t_name, raw if isinstance(raw, dict) else {})
                tools_covered.append(t_name)
            result = {
                "valid": True,
                "rules_count": len(tools_covered),
                "tools_covered": tools_covered,
            }
        except Exception as exc:
            result = {
                "valid": False,
                "error": str(exc),
            }
        return mcp_types.CallToolResult(
            content=[
                mcp_types.TextContent(
                    type="text",
                    text=json.dumps(result, indent=2),
                )
            ]
        )

    if name == "bouncer_get_active_policies":
        filter_pack = arguments.get("pack_name")
        packs_paths = builtin_pack_paths()
        results: dict[str, Any] = {}
        for path in sorted(packs_paths):
            pack_name = path.stem
            if filter_pack and str(filter_pack).lower() not in pack_name.lower():
                continue
            data = yaml.safe_load(path.read_text()) or {}
            results[pack_name] = data
        return mcp_types.CallToolResult(
            content=[
                mcp_types.TextContent(
                    type="text",
                    text=json.dumps(results, indent=2),
                )
            ]
        )

    if name == "bouncer_audit_summary":
        limit = int(arguments.get("limit", 20))
        entries = []
        if _DEFAULT_AUDIT_PATH.exists():
            try:
                for line in _DEFAULT_AUDIT_PATH.read_text().splitlines():
                    if line.strip():
                        entries.append(json.loads(line))
            except Exception:
                pass
        counts = Counter(e.get("verdict") for e in entries)
        summary = {
            "total_calls": len(entries),
            "verdict_counts": dict(counts),
            "recent_entries": entries[-limit:],
        }
        return mcp_types.CallToolResult(
            content=[
                mcp_types.TextContent(
                    type="text",
                    text=json.dumps(summary, indent=2),
                )
            ]
        )

    return None


def get_builtin_prompts() -> list[mcp_types.Prompt]:
    """Return Bouncer's native MCP prompts."""
    return [
        mcp_types.Prompt(
            name="review_mcp_security",
            description=(
                "Evaluate an MCP server's security contracts, identifying potential "
                "data exfiltration channels, high-risk sinks, and missing path constraints."
            ),
            arguments=[
                mcp_types.PromptArgument(
                    name="server_name",
                    description="Name of the MCP server to analyze.",
                    required=True,
                ),
                mcp_types.PromptArgument(
                    name="tool_definitions",
                    description="Optional JSON or description of the tools exposed by the server.",
                    required=False,
                ),
            ],
        ),
        mcp_types.Prompt(
            name="generate_bouncer_policy",
            description=(
                "Draft a declarative, deterministic YAML policy for Bouncer protecting "
                "against prompt injection and unauthorized destination exfiltration."
            ),
            arguments=[
                mcp_types.PromptArgument(
                    name="server_name",
                    description="Target MCP server name.",
                    required=True,
                ),
                mcp_types.PromptArgument(
                    name="risk_level",
                    description="Security posture: 'standard', 'strict', or 'paranoid'.",
                    required=False,
                ),
            ],
        ),
    ]


def handle_builtin_prompt(
    name: str, arguments: dict[str, str] | None
) -> mcp_types.GetPromptResult | None:
    """Handle an invocation of one of Bouncer's native prompts."""
    args = arguments or {}
    server_name = args.get("server_name", "unknown_server")

    if name == "review_mcp_security":
        tools_def = args.get("tool_definitions", "No tool definitions provided.")
        text = (
            f"Please conduct a comprehensive security review for MCP server '{server_name}'.\n\n"
            f"Server tools:\n{tools_def}\n\n"
            "Analyze:\n"
            "1. Exfiltrating tools: Which tools send data externally (network, email, webhook)?\n"
            "2. Sinks: Which parameters control destination (recipient, url, channel)?\n"
            "3. State mutation: Which tools write to disk; should path prefixes be confined?\n"
            "4. Call budgets: Which tools should have a hard ceiling on calls per session?"
        )
        return mcp_types.GetPromptResult(
            description=f"Security analysis for {server_name}",
            messages=[
                mcp_types.PromptMessage(
                    role="user",
                    content=mcp_types.TextContent(type="text", text=text),
                )
            ],
        )

    if name == "generate_bouncer_policy":
        risk_level = args.get("risk_level", "strict")
        text = (
            f"Generate a hardened Bouncer policy YAML for MCP server '{server_name}' "
            f"under a '{risk_level}' security posture.\n\n"
            "Guidelines:\n"
            "- Define `exfiltrating: true` and specify `sink_params` for external tools.\n"
            "- Provide explicit `trusted_destinations` (teammate domains, trusted endpoints).\n"
            "- Specify `write_params` and `allowed_path_prefixes` for disk-writing tools.\n"
            "- Define reasonable `max_calls` budgets."
        )
        return mcp_types.GetPromptResult(
            description=f"Policy generator for {server_name}",
            messages=[
                mcp_types.PromptMessage(
                    role="user",
                    content=mcp_types.TextContent(type="text", text=text),
                )
            ],
        )

    return None


def get_builtin_resources() -> list[mcp_types.Resource]:
    """Return Bouncer's native MCP resources."""
    return [
        mcp_types.Resource(
            uri="bouncer://policies/builtin",
            name="Bouncer Builtin Policies",
            description="Active curated security packs and deterministic contract schemas.",
            mimeType="application/json",
        ),
        mcp_types.Resource(
            uri="bouncer://audit/summary",
            name="Bouncer Audit Log Summary",
            description="Recent audit trail of deterministic verdicts (ALLOW/DENY/ASK).",
            mimeType="application/json",
        ),
    ]


def handle_builtin_resource(uri: str) -> mcp_types.ReadResourceResult | None:
    """Read one of Bouncer's native MCP resources."""
    if uri == "bouncer://policies/builtin":
        packs_paths = builtin_pack_paths()
        data: dict[str, Any] = {}
        for path in sorted(packs_paths):
            data[path.stem] = yaml.safe_load(path.read_text()) or {}
        return mcp_types.ReadResourceResult(
            contents=[
                mcp_types.TextResourceContents(
                    uri=uri,
                    mimeType="application/json",
                    text=json.dumps(data, indent=2),
                )
            ]
        )

    if uri == "bouncer://audit/summary":
        entries = []
        if _DEFAULT_AUDIT_PATH.exists():
            try:
                for line in _DEFAULT_AUDIT_PATH.read_text().splitlines():
                    if line.strip():
                        entries.append(json.loads(line))
            except Exception:
                pass
        counts = Counter(e.get("verdict") for e in entries)
        summary = {
            "total_calls": len(entries),
            "verdict_counts": dict(counts),
            "recent_entries": entries[-10:],
        }
        return mcp_types.ReadResourceResult(
            contents=[
                mcp_types.TextResourceContents(
                    uri=uri,
                    mimeType="application/json",
                    text=json.dumps(summary, indent=2),
                )
            ]
        )

    return None


def register_builtin_handlers(
    server: Server, user_policy: Path | None = None
) -> None:
    """Register Bouncer's native tools, prompts, and resources on an MCP server."""

    @server.list_tools()
    async def _list_tools() -> list[mcp_types.Tool]:
        return get_builtin_tools()

    @server.call_tool()
    async def _call_tool(
        name: str, arguments: dict[str, Any]
    ) -> mcp_types.CallToolResult:
        res = handle_builtin_tool_call(name, arguments, user_policy=user_policy)
        if res is not None:
            return res
        return mcp_types.CallToolResult(
            content=[
                mcp_types.TextContent(type="text", text=f"Unknown tool {name}")
            ],
            isError=True,
        )

    @server.list_prompts()
    async def _list_prompts() -> list[mcp_types.Prompt]:
        return get_builtin_prompts()

    @server.get_prompt()
    async def _get_prompt(
        name: str, arguments: dict[str, str] | None
    ) -> mcp_types.GetPromptResult:
        res = handle_builtin_prompt(name, arguments)
        if res is not None:
            return res
        raise ValueError(f"Unknown prompt {name}")

    @server.list_resources()
    async def _list_resources() -> list[mcp_types.Resource]:
        return get_builtin_resources()

    @server.read_resource()
    async def _read_resource(uri: str) -> mcp_types.ReadResourceResult:
        res = handle_builtin_resource(uri)
        if res is not None:
            return res
        raise ValueError(f"Unknown resource {uri}")


async def run_standalone_server(
    server_name: str = "bouncer",
    user_policy: Path | None = None,
) -> None:
    """Serve Bouncer's native MCP server over stdio."""
    server: Server = Server(server_name)
    register_builtin_handlers(server, user_policy=user_policy)

    options = server.create_initialization_options(
        notification_options=NotificationOptions()
    )
    async with stdio_server() as (read, write):
        await server.run(read, write, options)
