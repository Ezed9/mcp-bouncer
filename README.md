# Bouncer

[![CI](https://github.com/Ezed9/mcp-bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/Ezed9/mcp-bouncer/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/bouncer-mcp.svg)](https://pypi.org/project/bouncer-mcp/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**A local MCP proxy that stops a prompt-injected agent from sending your data
to an address it read in untrusted content. The rules are deterministic, no
LLM decides anything, and every decision is logged.**

![Terminal recording: an agent that read a poisoned helpdesk ticket tries to
email the customer list to an attacker, write an SSH key and delete customers
through Bouncer. All three calls are denied, a send to a new address is
approved by a human, and a security review pack is written from the audit
log.](docs/assets/demo.gif)

*Scripted tool calls from a hijacked agent, sent through the real proxy to a
real MCP server: three attacks denied, one new recipient approved by a human,
a review pack written from the audit log. No API keys; reproduce it in the
[quickstart](#see-it-in-60-seconds). [MP4](docs/assets/demo.mp4) ·
[what the demo runs](examples/demo/README.md) ·
[the review pack it writes](examples/demo/sample-review-pack.md)*

- **Blocks sends to addresses that came from untrusted data.** If an agent tries
  to email, post or share to a destination that first appeared in a tool's
  output (a poisoned email, ticket or document), the call is denied. A
  destination Bouncer can't trace goes to a human; allowlisted or approved ones
  pass.
- **Puts hard limits on write tools.** Path confinement, regex checks on
  arguments, per-session call budgets, and tools that weren't there at startup
  are refused.
- **Leaves evidence.** Every `allow`, `deny` and `ask` is a JSON line in
  `~/.bouncer/audit.jsonl`, and `bouncer report` turns it into a review pack.

Bouncer does not detect prompt injection. It assumes the agent will sometimes
be fooled and limits what a fooled agent can do through MCP.

**Status:** v0.1.3, early. MCP over stdio, one machine. Read the
[limits](#limits) before relying on it.

## See it in 60 seconds

From a clone, with [uv](https://docs.astral.sh/uv/) (no API keys, nothing
outside the repo is touched):

```bash
git clone https://github.com/Ezed9/mcp-bouncer.git && cd mcp-bouncer
uv sync --all-packages
uv run python examples/demo/run_demo.py
```

This is the recording above. It starts the real `bouncer run` proxy in front of
a small helpdesk MCP server with real side effects, then checks the server's
state afterwards: no mail reached the attacker and no file was written outside
the workspace. Output goes to `examples/demo/out/`.

## Use it with your MCP client

```bash
uv tool install bouncer-mcp          # or: pipx install bouncer-mcp (Python 3.12+)
```

Back up your client config, then wrap its servers:

```bash
cp .mcp.json .mcp.json.bak
bouncer init --config .mcp.json      # add --server <name> to wrap only some servers
```

Any config with an `mcpServers` block works, for example Claude Code's
`.mcp.json`, Cursor's `~/.cursor/mcp.json`, or Claude Desktop's
`"~/Library/Application Support/Claude/claude_desktop_config.json"` on macOS.

`init` prints the rewritten config and asks before writing. Each server entry
now launches `bouncer run`, and the original entry (command, args, `env`,
`cwd`) is kept under `x-bouncer-upstream`, which is how `run` starts the real
server and how you undo the change by hand. Restart your client.

Three things to know on the first run:

- **Your client must find `bouncer`.** The rewritten entry uses
  `"command": "bouncer"`. Desktop apps may not see your shell's `PATH`; if the
  server fails to start, replace it with the output of `which bouncer`.
- **`ask` needs MCP elicitation.** A send to an unknown destination asks the
  human through the client. If your client does not support elicitation, every
  `ask` becomes a `deny`, so list your usual recipients in
  `trusted_destinations` (see [Policy](#policy)).
- **Run `bouncer` with a subcommand.** With none, it starts Bouncer's own MCP
  server on stdio and waits for a client.

## How it works

```
  agent / MCP client
     │ tool call                           ▲ result, or
     ▼                                     │ "[bouncer blocked] <reason>"
  ┌─ bouncer run: one per server, stdio ──────────────┐
  │ 1. tool present at startup?      no  → deny       │
  │ 2. within the call budget?       no  → deny       │
  │ 3. path / regex checks pass?     no  → deny       │
  │ 4. sending somewhere? where did the destination   │
  │    come from?                                     │
  │      seen in this server's output   → deny        │
  │      allowlisted or approved        → allow       │
  │      can't tell                     → ask human   │
  │                       (no answer or no support    │
  │                        for asking = deny)         │
  │ every verdict → ~/.bouncer/audit.jsonl            │
  └───────────────────────────────────────────────────┘
     │ allowed calls only                  ▲ every output is
     ▼                                     │ recorded as untrusted
  your MCP server (filesystem, gmail, slack, …)
```

`bouncer run` starts the real server as a subprocess, records its tool list at
startup, and checks every call before forwarding it. A denied call is never
forwarded, so it has no side effects. Everything the server returns (text and
structured content) is recorded as untrusted, and a later destination that
appears in it is denied. An approval is remembered for the rest of the session.

The check is plain Python: normalize case and whitespace, then look for the
destination inside what the server has returned this session. A miss means
`ask`, never a silent `allow`.

Decision order, policy layering, the audit format and a live transcript against
the reference filesystem server: [`docs/how-it-works.md`](docs/how-it-works.md).

## Policy

Built-in packs in [`src/bouncer/packs/`](src/bouncer/packs/) name the sending
and writing tools of five servers. The filesystem pack is verified against the
reference server's `tools/list`; the gmail, slack, github and gdrive packs
follow those servers' documented schemas and are not yet verified live. Check
them against your server's `tools/list`. A tool with no pack entry gets a
fallback that treats destination-shaped arguments (`to`, `url`, `channel`, …)
as destinations.

Add your own rules in YAML:

```yaml
send_email:
  exfiltrating: true
  sink_params: [to, cc, bcc]
  trusted_destinations: [you@yourcompany.com]

write_file:
  write_params: [path]
  allowed_path_prefixes: ["/abs/path/to/project/out"]

delete_file:
  max_calls: 2          # 0 forbids the tool outright
```

Add `"--policy", "/abs/path/bouncer.yaml"` to the wrapped server's `args`. A
user entry **replaces** the pack entry for that tool, so restate
`exfiltrating` and `sink_params` when you override a sending tool, or the
destination check is off for it. Use absolute path prefixes: a relative one is
resolved against whatever directory your client starts the proxy in. Start
from [`examples/bouncer.yaml`](examples/bouncer.yaml).

## Why not just …

- **… approve each tool call?** Per-tool approval answers "may the agent send
  email?". Bouncer answers "may it send email to this address, given where the
  address came from?", refuses outright when the answer is "from untrusted
  data", and only interrupts you for destinations it can't place. Use both.
- **… add an LLM-based injection detector?** A detector is probabilistic and
  can be worded around; Bouncer doesn't try to spot the injection. It checks
  the action, and the same call with the same history always gets the same
  verdict, which you can test and audit. The two can run together.
- **… sandbox the agent or remove its send tools?** Do that where you can. Bouncer
  is for agents that need send and write tools to be useful.
- **… scan my MCP servers?** Scanners vet what a server declares. Bouncer
  assumes the server is honest and the data passing through it is hostile.

## For security reviewers

**Threat model.** The agent is well-meaning but reads attacker-controlled data
through MCP tools (an email, a ticket, a document) and may follow instructions
in it. The attacker controls tool output only; they cannot change Bouncer, its
policy, the client config or the server. Trusted: you (policy author and
approver), the MCP client, the upstream server and the local machine.

What Bouncer guarantees, for MCP tool calls that go through it:

| Guarantee | Code | Tests |
|---|---|---|
| No model or classifier in the enforcement path | [`engine.py`](src/bouncer/engine.py) | |
| A denied call is never forwarded upstream | [`proxy.py`](bouncer-mcp/src/bouncer_mcp/proxy.py) | [`test_proxy.py`](bouncer-mcp/tests/test_proxy.py) |
| A destination seen in this server's earlier output is denied, including one inside a list of recipients | [`taint.py`](src/bouncer/taint.py) | [`test_engine_sink_gate.py`](tests/test_engine_sink_gate.py) |
| Path traversal (`..`) can't escape an allowed prefix; budgets and regex checks deny | [`engine.py`](src/bouncer/engine.py) | [`test_engine_constraints.py`](tests/test_engine_constraints.py) |
| Fails closed: an unanswered `ask` is a deny; a sending tool with no declared destination arguments has all arguments checked; a malformed policy stops startup; a tool added after startup is refused | [`proxy.py`](bouncer-mcp/src/bouncer_mcp/proxy.py), [`policy.py`](src/bouncer/policy.py) | [`test_policy.py`](tests/test_policy.py), [`test_proxy.py`](bouncer-mcp/tests/test_proxy.py) |
| Every verdict is written to the audit log | [`audit.py`](src/bouncer/audit.py) | [`test_audit.py`](tests/test_audit.py) |

**The audit log** is one JSON line per verdict with a UTC timestamp, tool,
full arguments, verdict, reason and the rule that fired. `ask` is an
escalation: an approved one is followed by an `allow` line for the same call;
a declined one has no further line. A tool that wasn't present at startup is
logged as `ask` and blocked. The file is plaintext and contains whatever the
agent passed as arguments (email bodies included). Bouncer only appends to it,
but nothing makes it tamper-evident.

**Review pack.** `bouncer report` writes a Markdown pack: each tool and the
controls on it, an audit log summary, findings, these guarantees and limits,
and an OWASP LLM Top 10 mapping.

```bash
bouncer report --policy bouncer.yaml --tools tools.json -o review-pack.md
```

`--tools` takes the server's `tools/list` result as JSON; `--audit` defaults to
`~/.bouncer/audit.jsonl`, and `--since` / `--until` take `YYYY-MM-DD`. Example:
[`examples/demo/sample-review-pack.md`](examples/demo/sample-review-pack.md).

**Supply chain.** Releases are built by
[`release.yml`](.github/workflows/release.yml) from a tag and published with
PyPI Trusted Publishing, so each file on PyPI carries a provenance attestation
and no upload token exists. Workflow actions are pinned by commit SHA. A
weekly CI job installs both packages without the lockfile, the way a fresh
`pip install` resolves, and runs the tests on it. `bouncer-core` depends only
on PyYAML.

Report vulnerabilities privately: [`SECURITY.md`](SECURITY.md).

## Limits

- **MCP only.** An agent with shell or raw HTTP access can go around it.
- **Destinations, not content.** Sensitive content can still go to a trusted
  destination. It is not a DLP tool.
- **Taint is per wrapped server and per session.** Read through one server and
  send through another, and the destination is `ask`, not `deny`. Restarting
  the proxy clears what it has seen.
- **Matching is literal.** A destination is tainted only if it appears in
  earlier output after case and whitespace normalization. An encoded or
  assembled address gets `ask`, not `deny`. Destinations shorter than six
  characters are never marked tainted. A trusted-looking destination that also
  appears in tool output (a channel name in a message, say) is denied, which
  costs legitimate tasks.
- **Lexical path checks.** `..` is collapsed but symlinks are not resolved.
- **Pinned names only.** A changed schema for a tool that existed at startup
  is not detected.
- **It does not vet malicious servers.** It constrains a well-meaning agent
  fed malicious data.
- **Undeclared destination arguments aren't checked** if a tool has other
  declared ones. A pack must list every recipient-type argument the server
  accepts.
- **A budget limits damage; it doesn't prevent the first call.** Use
  `max_calls: 0` to forbid a tool.

Every limit in detail:
[`docs/how-it-works.md#documented-limits`](docs/how-it-works.md#documented-limits).

## Benchmark

**Headline:** on AgentDojo's `workspace` suite (v1.2.2, the `important_instructions`
attack, `openai/gpt-4o-mini` as the agent), attacks that tried to send data to
the attacker succeeded in **48 of 164 cases without Bouncer and 0 of 163 with
it** (95% upper bound 2.2%), scored by AgentDojo's own security checker.
**The cost:** with no attack, task completion went from 33/40 to 30/40, and the
whole loss is on the six tasks that send an email or share a file (4/6 to 0/6):
in this run Bouncer allowed no send at all.

![Every attack case as a square, user task by injection: without Bouncer 48 of 164 are red (attack succeeded) and 58 more amber (a send to the attacker ran); with Bouncer none are red or amber, 124 of 163 are blue (Bouncer refused a send or share)](docs/assets/agentdojo-cases.svg)

![Outcome counts per condition: without Bouncer 48 succeeded, 58 a send to the attacker ran without being scored a success, 58 no send to the attacker; with Bouncer 0 succeeded, 0 sends to the attacker, 124 refused, 39 no send attempted](docs/assets/agentdojo-outcomes.svg)

| condition | attack success | send to attacker ran | task done under attack | task done, no attack |
|---|---|---|---|---|
| no Bouncer | 48/164 (29%) | 106/164 (65%) | 44/164 | 33/40 |
| **Bouncer** | **0/163 (0%, 95% CI up to 2.2%)** | **0/163** | 86/163 | 30/40 |

- **Paired:** in 161 cases with a result under both conditions, the attack
  landed without Bouncer and not with it 46 times, and with it but not without it
  0 times (exact McNemar p = 3e-14).
- **"Send to attacker ran"** counts a `send_email` or `share_file` that actually
  ran with the attacker as a recipient. It is wider than AgentDojo's own check,
  which for injections 5-12 also requires deleting the sent email or files. Some
  of those sends carry no user data (injection 0 sends a one-line greeting).
- **Bouncer does not stop the agent from being hijacked; it stops the send.** The
  agent still tried to email the attacker in about two thirds of the Bouncer
  cases (read from the traces); every attempt was denied.
- **Task completion under attack is higher with Bouncer overall** (53% vs 27%),
  mostly because AgentDojo fails any task where an unwanted email actually went
  out. Scored without that side-effect check the gap shrinks (88/164 vs 99/163,
  p = 0.09). On the sending tasks completion is lower: 0/24 vs 8/24.
- **By task type, no attack:** sending tasks 4/6 without Bouncer, 0/6 with it;
  all other tasks 29/34 without, 30/34 with.

![Task completion with and without Bouncer, with 95% intervals: no attack, sending tasks 4/6 to 0/6, other tasks 29/34 to 30/34, all 33/40 to 30/40; under attack, sending 8/24 to 0/24, other 36/140 to 86/139, all 44/164 to 86/163](docs/assets/agentdojo-cost.svg)

**What this does not show:**

- **Bouncer allowed no send or share in the whole run** (0 allowed of 649 sink
  verdicts, including legitimate ones), so 0/163 follows by construction here. The
  run does not show the gate telling a legitimate send from an attack. The
  address-book variant is the only evidence that it allows one (2 sends, tasks 13
  and 19).
- The benchmark runs Bouncer's engine inside AgentDojo's tool loop, not through
  the MCP proxy, and treats every `ask` as a deny (no human).
- It is not an adaptive attack: one fixed template, one trial per case. The deny
  is expected by design, because the attacker's address arrives in tool output
  and is marked tainted. It checks that the rule fires end to end under a
  third-party scorer. It is not evidence of a general defence.
- Only injections that send data to the attacker are scored. Injections that
  delete files, create events or phish contacts are out of scope and not measured.
- The model was chosen because it follows injections: a cheap 8-case probe of four
  models picked it (`deepseek/deepseek-v4-flash`, which resists most injections on
  its own, was the control). Earlier runs on that model landed 1 attack in 15
  and 1 in 30; they are kept in [`benchmark/RESULTS.md`](benchmark/RESULTS.md).
- Coverage: all 40 user tasks against injections 0, 3, 4 and 6, plus injection 10
  on six tasks. The run stopped at its budget cap before the other six in-scope
  injections. Three cases ended in model errors (malformed or oversized output) and are excluded.
- There are only six sending tasks, so the sending-task numbers have wide
  intervals (0/6 has a 95% upper bound of 46%).

**Cost to legitimate tasks:** overall benign completion fell by 7.5 points, under
the 10% threshold set as a kill criterion before these runs, but concentrated: a
deployment dominated by tasks that send email or share files would see most of
them denied. The six sending tasks fail for different reasons: two used an address
the user typed (denied because it also appears in tool output), two follow an
instruction in an email the agent read, and two take the recipient from a file. An address book of
trusted recipients recovers only the two whose recipients are in it (13 and 19). Per-case results and
raw JSON: [`benchmark/RESULTS-final.md`](benchmark/RESULTS-final.md) and
`benchmark/results/final.jsonl`.

Reproduce (AgentDojo 0.1.35, about $1.40 at OpenRouter's reported prices; the run
stops at its `--max-cost-usd` cap):

```bash
export OPENROUTER_API_KEY=...
sh benchmark/run_final.sh      # model defaults to openai/gpt-4o-mini
```

## More

- **Configuration reference:** [`docs/how-it-works.md`](docs/how-it-works.md)
  covers `bouncer init` / `run` / `serve` / `report`, policy layering, the
  standalone server's tools, and the audit log format.
- **Live smoke test** against the reference filesystem server:
  [`docs/manual-smoke.md`](docs/manual-smoke.md).
- **Library only:** `pip install bouncer-core` is the engine with no MCP
  dependency (PyYAML only), for enforcing the same rules inside your own agent
  harness. [`scripts/demo.py`](scripts/demo.py) shows how to drive it.

**Roadmap** (not built yet): detecting a changed schema for an already-pinned
tool; support for `mcp` 2.x (capped below 2 today); packs verified against
live gmail, slack, github and gdrive servers.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The rule that isn't negotiable: every
ambiguous case resolves to `ask` or `deny`, never a silent `allow`.

```bash
uv sync --all-packages
uv run pytest -q        # 150 tests (3 need the benchmark extra)
uv run ruff check .
```

The most useful contribution is a pack verified against a real server's
`tools/list`.

## License

[MIT](LICENSE)
