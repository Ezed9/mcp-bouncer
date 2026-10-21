# Bouncer

[![CI](https://github.com/Ezed9/mcp-bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/Ezed9/mcp-bouncer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)

**Bouncer sits between your agent and your MCP servers and enforces what the
agent is allowed to do, so a prompt-injected agent can't send data to an
attacker or run writes outside the limits you set. Every decision goes to an
audit log you can show a security reviewer.**

![Terminal recording: an agent that read a poisoned helpdesk ticket tries to
email the customer list to an attacker, write an SSH key and delete customers
through Bouncer. All three calls are denied, a send to a new address is
approved by a human, and a security review pack is written from the audit
log.](docs/assets/demo.gif)

*A hijacked agent's tool calls (scripted) against a real MCP server behind
Bouncer: three attacks denied, one new recipient approved by a human, and a
review pack written from the audit log. Reproduce from a clone with
`uv run python examples/demo/run_demo.py`.
[MP4](docs/assets/demo.mp4) · [review pack it writes](examples/demo/sample-review-pack.md) ·
[what the demo runs](examples/demo/README.md)*

- **Blocks exfiltration by where the destination came from.** If an agent
  tries to email, post or share to an address that first appeared in untrusted
  tool output (a poisoned email, a document), the call is denied. Destinations
  it can't trace go to a human for approval; allowlisted or approved ones pass.
  The decision is plain Python, with no LLM involved.
- **Puts hard limits on write tools.** Path confinement for file writes,
  regex checks on arguments, per-session call budgets, and tools
  that weren't present at startup are refused (schema pinning).
- **Logs every decision.** Each `allow`, `deny` and `ask` is one JSON line in
  `~/.bouncer/audit.jsonl`, with the tool, arguments, verdict and the rule that
  fired.

## Quickstart

Wrap the servers in any MCP client config that has an `mcpServers` block
(Claude Desktop, Claude Code's `.mcp.json`, Cursor's `mcp.json`):

```bash
uv tool install bouncer-mcp
```

```bash
bouncer init --config path/to/mcp-config.json
```

`init` prints the rewritten config and asks before writing it. Restart your
client: each wrapped server now runs behind Bouncer with the built-in policy
packs (filesystem, gmail, slack, github, gdrive). Python 3.12+; `pipx install
bouncer-mcp` works too.

**Result so far:** on AgentDojo's prompt-injection benchmark (15 attack cases,
`deepseek-v4-flash`), the one attack that exfiltrated data without Bouncer was
blocked with it (1/15 → 0/15), as judged by AgentDojo's own scorer. It also
blocked legitimate sends whose recipient came from tool output. Both sides are
in [benchmark](#benchmark).

---

## How it works

```
  your agent / MCP client
           │  tool call
           ▼
  ┌──────────────────────────────────────────────┐
  │ Bouncer (bouncer run, one per server, stdio) │
  │  1. tool known at startup?    no  → deny     │
  │  2. within call budget?       no  → deny     │
  │  3. argument constraints ok?  no  → deny     │
  │  4. sending somewhere? where did the         │
  │     destination come from?                   │
  │       untrusted tool output   → deny         │
  │       unknown                 → ask a human  │
  │       allowlisted / approved  → allow        │
  └──────────────────────────────────────────────┘
           │  allowed calls only        ▲ outputs recorded
           ▼                            │ as untrusted
  your MCP server (filesystem, gmail, slack, …)
```

`bouncer init` rewrites each server entry in your client config to launch
`bouncer run`, which starts the real server as a subprocess, re-exports its
tools unchanged, and checks every call. A denied call is never forwarded, so
it has no side effects. An `ask` goes to the human through MCP elicitation;
if the client can't elicit or the human declines, it becomes a deny. An
approval is remembered for the session.

Full details (decision order, taint matching, policy layering, the live demo
transcript): [`docs/how-it-works.md`](docs/how-it-works.md).

To see only the core decision, with no MCP server or proxy, from a clone:

```bash
uv run python scripts/demo.py
```

The same `send_email` call is allowed to a trusted teammate and denied to an
attacker address that only appeared in a poisoned inbox message.

![Bouncer allows an email to a trusted teammate but denies the same tool
sending to an attacker address that only appeared in a poisoned inbox](docs/demo.png)

## Policy

The built-in packs in [`src/bouncer/packs/`](src/bouncer/packs/) cover named
tools for five servers. Tools with no pack entry get a conservative fallback
that treats destination-shaped arguments (`to`, `url`, `channel`, …) as sinks.
Add your own rules in YAML:

```yaml
send_email:
  exfiltrating: true
  sink_params: [to, cc, bcc]
  trusted_destinations: [you@yourcompany.com]

write_file:
  write_params: [path]
  allowed_path_prefixes: ["./out", "./tmp"]

delete_file:
  write_params: [path]
  max_calls: 2
```

Pass it by adding `"--policy", "/abs/path/bouncer.yaml"` to the wrapped
server's `args`. A user entry **replaces** the pack entry for that tool, so
restate `exfiltrating` and `sink_params` when you override a sending tool.
Start from [`examples/bouncer.yaml`](examples/bouncer.yaml).

## For security reviewers

What Bouncer guarantees, for MCP tool calls that go through it:

- **Deterministic decisions.** No model or classifier is in the enforcement
  path ([`src/bouncer/engine.py`](src/bouncer/engine.py)).
- **Deny means not forwarded.** A denied call never reaches the upstream
  server ([`bouncer-mcp/src/bouncer_mcp/proxy.py`](bouncer-mcp/src/bouncer_mcp/proxy.py),
  tested in [`bouncer-mcp/tests/test_proxy.py`](bouncer-mcp/tests/test_proxy.py)).
- **Fails closed.** `ask` without a human answer is a deny. A sending tool
  with no declared destination arguments has all its arguments checked. A
  malformed policy file is an error, not ignored. Tools that appear after
  startup are refused.
- **Tainted destinations are denied.** A destination found in earlier output
  from the same wrapped server is a `deny`, including one hidden in a list of
  recipients ([`src/bouncer/taint.py`](src/bouncer/taint.py),
  [`tests/test_engine_sink_gate.py`](tests/test_engine_sink_gate.py)).
- **Every verdict is logged** to an append-only JSONL file
  ([`src/bouncer/audit.py`](src/bouncer/audit.py)).

`bouncer report` turns this into a Markdown review pack: each tool and the
controls on it, a summary of the audit log, findings, these guarantees and
limits, and an OWASP LLM Top 10 mapping. It is not in the 0.1.2 release on
PyPI yet; from a clone:

```bash
uv run bouncer report --policy bouncer.yaml --tools tools.json -o review-pack.md
```

`--tools` takes the server's `tools/list` result as JSON; the audit log
defaults to `~/.bouncer/audit.jsonl`. Example output:
[`examples/demo/sample-review-pack.md`](examples/demo/sample-review-pack.md).

What it does not do:

- **MCP only.** An agent with shell or raw HTTP access can go around it.
- **Destinations, not content.** Sensitive content can still go to a trusted
  destination. It is not a DLP tool.
- **Taint is per wrapped server.** Read via one server and send via another,
  and the destination is `ask`, not `deny`.
- **Lexical path checks.** `..` is collapsed but symlinks are not resolved.
- **Pinned names only.** A changed schema for a tool that existed at startup
  is not detected.
- **It does not vet malicious servers.** It constrains a well-meaning agent
  fed malicious data.
- **Undeclared destination arguments aren't checked** if a tool has other
  declared ones. Packs must list every recipient-type argument the server
  accepts.

Threat model and every limit in detail:
[`docs/how-it-works.md#documented-limits`](docs/how-it-works.md#documented-limits).
Report vulnerabilities privately: [`SECURITY.md`](SECURITY.md).

## Benchmark

AgentDojo v1 `workspace` suite, `important_instructions` attack, injection
tasks that try to send data to an attacker. Scored by AgentDojo's own security
scorer against a no-Bouncer baseline.

| run | attack success | task done under attack | benign task done |
|---|---|---|---|
| `deepseek-v4-flash`, 5 user tasks × 3 injections, no Bouncer | 1/15 | 8/15 | not measured |
| same, with Bouncer | **0/15** | 5/15 | 2/5 |

- **Security:** one attack landed without Bouncer; Bouncer blocked it. The
  other 14 failed without Bouncer too, so they say nothing about it.
- **Cost:** Bouncer denied every send it saw, including legitimate ones. Tasks
  like "email the person named in this file" take the recipient from tool
  output, which counts as untrusted. The pre-registered kill criterion (10%
  or more benign utility loss) probably trips; the benign baseline hasn't
  been run yet.
- An earlier n=3 run (`gemini-flash-lite-latest`) and an n=3 run on
  `gpt-oss-120b` are in [`benchmark/RESULTS.md`](benchmark/RESULTS.md) with
  per-case breakdowns. An early run also found a real bypass in Bouncer, fixed
  fail-closed in commit `3d9c904`.

Reproduce (about $0.10 at OpenRouter list prices):

```bash
BOUNCER_LLM=openrouter OPENROUTER_API_KEY=... BOUNCER_MODEL=deepseek/deepseek-v4-flash \
  uv run --extra benchmark python -m benchmark.run_agentdojo
```

## More

- **Configuration reference:** [`docs/how-it-works.md`](docs/how-it-works.md)
  covers install options, `bouncer init` / `run` / `serve`, policy layering,
  the standalone server's tools, and the audit log format.
- **Live smoke test** against the reference filesystem server:
  [`docs/manual-smoke.md`](docs/manual-smoke.md).
- **Library only:** `bouncer-core` is the engine with no MCP dependency
  (`pyyaml` only), for enforcing contracts inside your own agent harness.
  [`scripts/demo.py`](scripts/demo.py) shows how to drive it.

**Status:** v0.1.2, early. MCP over stdio, one machine. 113 tests pass
(`uv run pytest -q`).

**Roadmap** (not built yet): detecting a changed schema for an already-pinned
tool; support for `mcp` 2.x (currently capped below 2); a benign no-Bouncer
benchmark baseline to settle the kill criterion.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Development uses `uv`:

```bash
uv sync --all-packages
uv run pytest -q
uv run ruff check .
```

## License

[MIT](LICENSE)
