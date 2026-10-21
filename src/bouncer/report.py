"""Security review pack: a Markdown report built from what Bouncer already has.

The active policy (user YAML > packs > heuristics, resolved exactly as the
proxy does), a count-only summary of the audit log, and optional benchmark
numbers. Every claim in the static sections maps to a code path; argument
values from the audit log are never printed.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .policy import PolicyResolver
from .types import ToolPolicy


@dataclass
class AuditSummary:
    path: str
    found: bool = False
    total: int = 0
    undated: int = 0
    malformed: int = 0
    first_ts: str | None = None
    last_ts: str | None = None
    since: date | None = None
    until: date | None = None
    by_verdict: Counter[str] = field(default_factory=Counter)
    by_tool: dict[str, Counter[str]] = field(default_factory=dict)
    by_contract: Counter[str] = field(default_factory=Counter)


def load_tools(path: Path) -> list[tuple[str, dict[str, object]]]:
    """Read a `tools/list` result (`{"tools": [...]}`) or a bare list of tools."""
    data = json.loads(path.read_text())
    tools = data.get("tools", []) if isinstance(data, dict) else data
    out: list[tuple[str, dict[str, object]]] = []
    for tool in tools:
        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        out.append((str(tool["name"]), schema))
    return out


def summarize_audit(
    path: Path, since: date | None = None, until: date | None = None
) -> AuditSummary:
    summary = AuditSummary(path=str(path), since=since, until=until)
    if not path.exists():
        return summary
    summary.found = True
    filtering = since is not None or until is not None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            summary.malformed += 1
            continue
        if not isinstance(rec, dict):
            summary.malformed += 1
            continue
        ts = rec.get("ts")
        if isinstance(ts, str):
            day = date.fromisoformat(ts[:10])
            if (since and day < since) or (until and day > until):
                continue
            summary.first_ts = min(summary.first_ts or ts, ts)
            summary.last_ts = max(summary.last_ts or ts, ts)
        else:
            if filtering:
                continue
            summary.undated += 1
        verdict = str(rec.get("verdict", ""))
        summary.total += 1
        summary.by_verdict[verdict] += 1
        summary.by_tool.setdefault(str(rec.get("tool", "")), Counter())[verdict] += 1
        summary.by_contract[str(rec.get("contract", ""))] += 1
    return summary


def _md(text: str) -> str:
    return text.replace("|", "\\|")


def _codes(items: tuple[str, ...]) -> str:
    return ", ".join(f"`{_md(i)}`" for i in items)


def _controls(policy: ToolPolicy) -> list[str]:
    out: list[str] = []
    if policy.exfiltrating:
        sinks = _codes(policy.sink_params) if policy.sink_params else "all args (none declared)"
        allow = (
            f"allowlist: {_codes(policy.trusted_destinations)}"
            if policy.trusted_destinations
            else "no allowlist: each new destination needs human approval"
        )
        out.append(f"sink gate on {sinks} ({allow})")
    if policy.write_params:
        if policy.allowed_path_prefixes:
            out.append(
                f"path confinement on {_codes(policy.write_params)} to "
                f"{_codes(policy.allowed_path_prefixes)}"
            )
        else:
            out.append(f"write params {_codes(policy.write_params)}, **no path prefix set**")
    for arg, pattern in policy.arg_patterns:
        out.append(f"`{_md(arg)}` must match `/{_md(pattern)}/`")
    if policy.max_calls is not None:
        plural = "" if policy.max_calls == 1 else "s"
        out.append(f"at most {policy.max_calls} call{plural} per session")
    return out


def _resolve(
    pack_policies: dict[str, ToolPolicy],
    user_policies: dict[str, ToolPolicy],
    tools: list[tuple[str, dict[str, object]]] | None,
) -> list[tuple[str, str, ToolPolicy]]:
    if tools is None:
        return [(name, "user", p) for name, p in sorted(user_policies.items())]
    resolver = PolicyResolver(overrides={**pack_policies, **user_policies})
    rows: list[tuple[str, str, ToolPolicy]] = []
    for name, schema in tools:
        policy = resolver.policy_for(name, schema)
        if name in user_policies:
            source = "user policy"
        elif name in pack_policies:
            source = "builtin pack"
        else:
            source = "heuristic" if _controls(policy) else "none"
        rows.append((name, source, policy))
    return rows


def _rate(rate: object, n: int) -> str:
    if not isinstance(rate, (int, float)):
        return "not run"
    return f"{rate:.2f} ({round(rate * n)}/{n})"


_GUARANTEES = """\
**Enforced by code (deterministic, no LLM in the decision path):**

- Every MCP tool call on a wrapped server is evaluated in a fixed order: schema
  pinning, call budget, argument constraints, sink gate
  (`src/bouncer/engine.py`, `ContractEngine._decide`).
- A tool that was not in the server's tool list at startup is not forwarded
  (ask, which the proxy turns into deny).
- A `deny` is never forwarded to the upstream server, so a blocked call has no
  side effects (`bouncer_mcp/proxy.py`, `route_call`).
- An `ask` goes to the human through MCP elicitation for that one destination.
  If the client cannot elicit, or the human declines, the call is denied.
- For tools marked exfiltrating, a destination that appears in earlier
  untrusted tool output on the same server is denied; an unknown destination
  is asked; only allowlisted or human-approved destinations are allowed.
  An exfiltrating tool with no declared sink params has every argument
  checked.
- Path confinement collapses `.` and `..` before comparing, so `../` cannot
  escape an allowed prefix.
- A malformed policy file (wrong shape, invalid regex) is an error, not
  ignored.
- Every verdict is appended to a JSONL audit log.

**Not guaranteed:**

- Only MCP tool calls are governed. An agent with shell or HTTP access outside
  MCP can bypass Bouncer.
- It controls destinations, not content. Sensitive content sent to a trusted
  destination is allowed (no DLP).
- Path checks are lexical; symlinks are not resolved.
- Taint is tracked per wrapped server. Data read through one server and sent
  through another is asked, not denied.
- Schemas are pinned at startup only; a changed schema for an existing tool
  name is not detected mid-session.
- A destination argument that is not declared in `sink_params` (while another
  one is) is treated as content and not gated.
- It does not vet the upstream server's own behaviour, and it does not detect
  prompt injection; it limits what an injected agent can do.
- The audit log is a plain append-only file. It is not tamper-evident (no
  hashing or signing) and it records argument values, so treat it as
  sensitive.
"""

_OWASP = """\
| OWASP LLM Top 10 (2025) | Coverage | How |
|---|---|---|
| LLM01 Prompt Injection | Partial | Does not detect injection. Limits its impact: sends to destinations taken from untrusted tool output are denied, unknown destinations need a human. |
| LLM02 Sensitive Information Disclosure | Partial | Controls where data can be sent by MCP tools, not what is in it. |
| LLM03 Supply Chain | No | Does not vet MCP servers or models. |
| LLM04 Data and Model Poisoning | No | |
| LLM05 Improper Output Handling | Partial | Only where `arg_patterns` are configured: model-produced tool arguments must match a regex before the call runs. |
| LLM06 Excessive Agency | Yes | Path confinement, argument regexes, per-session call budgets, schema pinning, human approval for new destinations. |
| LLM07 System Prompt Leakage | No | |
| LLM08 Vector and Embedding Weaknesses | No | |
| LLM09 Misinformation | No | |
| LLM10 Unbounded Consumption | Partial | `max_calls` caps calls per tool per session; no token or cost limits. |
"""  # noqa: E501 (Markdown table rows cannot wrap)


def build_report(
    *,
    pack_policies: dict[str, ToolPolicy],
    user_policies: dict[str, ToolPolicy],
    user_policy_path: Path | None,
    tools: list[tuple[str, dict[str, object]]] | None,
    audit: AuditSummary | None,
    benchmark: dict[str, object] | None,
    server_name: str | None,
    version: str,
    generated_on: date,
) -> str:
    rows = _resolve(pack_policies, user_policies, tools)
    subject = f"`{server_name}`" if server_name else "this MCP server"
    lines: list[str] = [
        f"# MCP security review pack: {server_name or 'MCP server'}",
        "",
        f"Generated {generated_on.isoformat()} by Bouncer {version} "
        "(https://github.com/Ezed9/mcp-bouncer).",
        "",
        "## 1. Summary",
        "",
        f"Tool calls from the AI agent to {subject} pass through Bouncer, a local "
        "proxy that checks each call against deterministic rules before it reaches "
        "the server. Calls that break a rule are blocked and never reach the server; "
        "calls to a new destination need a human's approval; every decision is "
        "logged. This report lists the rules in force, what the log recorded, and "
        "what Bouncer does and does not guarantee.",
        "",
        "## 2. Tool inventory and controls",
        "",
    ]
    policy_src = f"`{user_policy_path.name}`" if user_policy_path else "none"
    lines += [
        f"User policy: {policy_src}. Policy for each tool comes from the user policy "
        "first, then Bouncer's builtin packs, then schema heuristics.",
        "",
    ]
    if tools is None:
        lines += [
            "No server tool list was given (`--tools`), so only tools named in the "
            "user policy are listed. Tools not listed here still get pinning, "
            "heuristics and audit at runtime.",
            "",
        ]
    if rows:
        lines += ["| Tool | Policy source | Controls |", "|---|---|---|"]
        for name, source, policy in rows:
            controls = _controls(policy) or ["pass-through (pinned at startup, audited)"]
            lines.append(f"| `{_md(name)}` | {source} | {'; '.join(controls)} |")
    else:
        lines.append("_No tools to list._")
    lines += [
        "",
        "Every listed tool is also pinned at startup: a tool name the server adds "
        "later is not forwarded.",
        "",
        "## 3. Findings for the reviewer",
        "",
    ]
    unconfined = [n for n, _, p in rows if p.write_params and not p.allowed_path_prefixes]
    no_allow = [n for n, _, p in rows if p.exfiltrating and not p.trusted_destinations]
    heuristic = [n for n, s, _ in rows if s == "heuristic"]
    bare = [n for n, _, p in rows if not _controls(p)]
    findings: list[str] = []
    if unconfined:
        findings.append(
            f"- **Writes not confined to a path:** {_codes(tuple(unconfined))}. "
            "Set `allowed_path_prefixes` for these."
        )
    if no_allow:
        findings.append(
            f"- **Sends with no allowlist:** {_codes(tuple(no_allow))}. Every new "
            "destination needs human approval (denied if the client cannot ask). "
            "Add known-good destinations to `trusted_destinations` to cut prompts."
        )
    if heuristic:
        findings.append(
            f"- **Covered only by heuristics:** {_codes(tuple(heuristic))}. Rules were "
            "derived from the tool's name and parameter names; an explicit policy is "
            "more reliable."
        )
    if bare:
        findings.append(
            f"- **No contract beyond pinning and audit:** {_codes(tuple(bare))}. "
            "Expected for read-only tools; review any that write, delete or send."
        )
    lines += findings or ["- No gaps found in the listed policy."]
    lines += ["", "## 4. Audit log summary", ""]
    lines += _audit_section(audit)
    if benchmark is not None:
        lines += ["", "## 5. Benchmark evidence", ""]
        lines += _benchmark_section(benchmark)
    n = 6 if benchmark is not None else 5
    lines += [
        "",
        f"## {n}. What Bouncer guarantees and does not guarantee",
        "",
        _GUARANTEES,
        f"## {n + 1}. OWASP LLM Top 10 mapping",
        "",
        _OWASP,
    ]
    return "\n".join(lines)


def _audit_section(audit: AuditSummary | None) -> list[str]:
    if audit is None or not audit.found:
        where = f" (`{Path(audit.path).name}`)" if audit else ""
        return [f"No audit log found{where}."]
    window = "all entries"
    if audit.since or audit.until:
        window = f"{audit.since or 'start'} to {audit.until or 'now'} (UTC)"
    out = [f"Log: `{Path(audit.path).name}`, window: {window}.", ""]
    if audit.first_ts:
        out.append(f"Dated entries span {audit.first_ts} to {audit.last_ts}.")
    if audit.undated:
        out.append(
            f"{audit.undated} entries have no timestamp (written before Bouncer "
            "recorded one) and are included only when no date window is set."
        )
    if audit.malformed:
        out.append(f"{audit.malformed} malformed lines were skipped.")
    v = audit.by_verdict
    out += [
        "",
        "| Verdict | Calls |",
        "|---|---|",
        f"| allow | {v['allow']} |",
        f"| ask | {v['ask']} |",
        f"| deny | {v['deny']} |",
        f"| **total** | **{audit.total}** |",
        "",
        "`ask` is an escalation, not an outcome: an approved ask is followed by an "
        "`allow` line for the same call; a declined one is blocked with no further "
        "line.",
        "",
        "| Tool | allow | ask | deny | total |",
        "|---|---|---|---|---|",
    ]
    for tool, c in sorted(audit.by_tool.items(), key=lambda kv: -sum(kv[1].values())):
        out.append(
            f"| `{_md(tool)}` | {c['allow']} | {c['ask']} | {c['deny']} | {sum(c.values())} |"
        )
    out += ["", "| Rule (contract) | Decisions |", "|---|---|"]
    for contract, count in audit.by_contract.most_common():
        out.append(f"| {_md(contract) or '(none)'} | {count} |")
    out += ["", "Argument values are deliberately left out of this report."]
    return out


def _benchmark_section(bench: dict[str, object]) -> list[str]:
    auth = bench.get("authoritative", {})
    auth = auth if isinstance(auth, dict) else {}
    asr = auth.get("attack_success_rate", {})
    util = auth.get("utility", {})
    detail = bench.get("engine_detail", {})
    detail = detail if isinstance(detail, dict) else {}
    n = int(auth.get("n_injection_cases", 0))
    user_tasks = bench.get("user_tasks", [])
    n_benign = len(user_tasks) if isinstance(user_tasks, list) else 0
    attack_sinks = detail.get("attack_sink_verdicts", {})
    benign_sinks = detail.get("benign_sink_verdicts", {})
    return [
        f"AgentDojo `workspace` suite, attack `{bench.get('attack')}`, agent model "
        f"`{bench.get('agent_model')}`, {n} injection cases, scored by AgentDojo's own "
        "security and utility checks.",
        "",
        "| Metric | Without Bouncer | With Bouncer |",
        "|---|---|---|",
        f"| Attack success rate (lower is better) | {_rate(asr.get('baseline'), n)} "
        f"| {_rate(asr.get('bouncer'), n)} |",
        f"| Task completion under attack | {_rate(util.get('under_attack_baseline'), n)} "
        f"| {_rate(util.get('under_attack_bouncer'), n)} |",
        f"| Task completion, no attack | not run | "
        f"{_rate(util.get('benign_bouncer'), n_benign)} |",
        "",
        f"Sink (send) calls with Bouncer: under attack {_counts(attack_sinks)}; "
        f"no attack {_counts(benign_sinks)}.",
        "",
        "Read with care: the sample is small, and Bouncer also blocked legitimate sends "
        "whose recipient came from tool output, which lowered task completion. Full "
        "method and caveats: `benchmark/RESULTS.md` in the Bouncer repository.",
    ]


def _counts(verdicts: object) -> str:
    if not isinstance(verdicts, dict):
        return "n/a"
    return ", ".join(f"{verdicts.get(k, 0)} {k}" for k in ("allow", "ask", "deny"))
