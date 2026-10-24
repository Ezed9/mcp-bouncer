# MCP security review pack: helpdesk (demo)

Generated 2026-10-22 by Bouncer 0.1.2 (https://github.com/Ezed9/mcp-bouncer).

## 1. Summary

Tool calls from the AI agent to `helpdesk (demo)` pass through Bouncer, a local proxy that checks each call against deterministic rules before it reaches the server. Calls that break a rule are blocked and never reach the server; calls to a new destination need a human's approval; every decision is logged. This report lists the rules in force, what the log recorded, and what Bouncer enforces and what it does not.

## 2. Tool inventory and controls

User policy: `policy.yaml`. Policy for each tool comes from the user policy first, then Bouncer's builtin packs, then schema heuristics.

| Tool | Policy source | Controls |
|---|---|---|
| `get_ticket` | none | pass-through (pinned at startup, audited) |
| `list_customers` | none | pass-through (pinned at startup, audited) |
| `send_email` | user policy | sink gate on `to` (allowlist: `support@acme.example`) |
| `write_file` | user policy | path confinement on `path` to `workspace` |
| `delete_customer` | user policy | at most 1 call per session |

Every listed tool is also pinned at startup: a tool name the server adds later is not forwarded.

## 3. Findings for the reviewer

- **No contract beyond pinning and audit:** `get_ticket`, `list_customers`. Expected for read-only tools; review any that write, delete or send.

## 4. Audit log summary

Log: `audit.jsonl`, window: all entries.

Dated entries span 2026-10-21T21:03:09+00:00 to 2026-10-21T21:03:24+00:00.

| Verdict | Calls |
|---|---|
| allow | 6 |
| ask | 1 |
| deny | 3 |
| **total** | **10** |

`ask` is an escalation, not an outcome: an approved ask is followed by an `allow` line for the same call; a declined one is blocked with no further line.

| Tool | allow | ask | deny | total |
|---|---|---|---|---|
| `send_email` | 2 | 1 | 1 | 4 |
| `get_ticket` | 2 | 0 | 0 | 2 |
| `delete_customer` | 1 | 0 | 1 | 2 |
| `list_customers` | 1 | 0 | 0 | 1 |
| `write_file` | 0 | 0 | 1 | 1 |

| Rule (contract) | Decisions |
|---|---|
| default | 6 |
| sink_gate | 2 |
| constraint | 1 |
| budget | 1 |

Argument values are deliberately left out of this report.

## 5. What Bouncer enforces and what it does not

**Enforced by code (deterministic, no LLM in the decision path):**

- Every MCP tool call on a wrapped server is evaluated in a fixed order: tool-name
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

**Not enforced:**

- Only MCP tool calls are governed. An agent with shell or HTTP access outside
  MCP can bypass Bouncer.
- It controls destinations, not content. Sensitive content sent to a trusted
  destination is allowed (no DLP).
- Path checks are lexical; symlinks are not resolved.
- Taint is tracked per wrapped server. Data read through one server and sent
  through another is asked, not denied.
- Only tool names are pinned at startup; a changed schema for an existing
  tool name is not detected.
- A destination argument that is not declared in `sink_params` (while another
  one is) is treated as content and not gated.
- It does not vet the upstream server's own behaviour, and it does not detect
  prompt injection; it limits what an injected agent can do.
- The audit log is a plain append-only file. It is not tamper-evident (no
  hashing or signing) and it records argument values, so treat it as
  sensitive.

## 6. OWASP LLM Top 10 mapping

| OWASP LLM Top 10 (2025) | Coverage | How |
|---|---|---|
| LLM01 Prompt Injection | Partial | Does not detect injection. Limits its impact: sends to destinations taken from untrusted tool output are denied, unknown destinations need a human. |
| LLM02 Sensitive Information Disclosure | Partial | Controls where data can be sent by MCP tools, not what is in it. |
| LLM03 Supply Chain | No | Does not vet MCP servers or models. |
| LLM04 Data and Model Poisoning | No | |
| LLM05 Improper Output Handling | Partial | Only where `arg_patterns` are configured: model-produced tool arguments must match a regex before the call runs. |
| LLM06 Excessive Agency | Yes | Path confinement, argument regexes, per-session call budgets, tool-name pinning, human approval for new destinations. |
| LLM07 System Prompt Leakage | No | |
| LLM08 Vector and Embedding Weaknesses | No | |
| LLM09 Misinformation | No | |
| LLM10 Unbounded Consumption | Partial | `max_calls` caps calls per tool per session; no token or cost limits. |

