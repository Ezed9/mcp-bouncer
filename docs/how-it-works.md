# How Bouncer works

The full technical reference: decision order, the contracts, policy layering,
the standalone server's tools, the audit log, a live demo transcript, and the
documented limits. The [README](../README.md) is the short version.

## How it decides

Every tool call runs the same deterministic gauntlet — no model, no scoring.
The sink gate is the novel part: it is **deny-unless-trusted on the
_destination_**, keyed to where the value came from.

```mermaid
flowchart TD
    call[Tool call from agent] --> pin{Known / pinned tool?}
    pin -- no --> ask[["ASK a human"]]
    pin -- yes --> bud{Within call budget?}
    bud -- no --> deny[["DENY (never forwarded)"]]
    bud -- yes --> con{Arg constraints pass?}
    con -- no --> deny
    con -- yes --> sink{Exfiltrating tool?}
    sink -- no --> allow[["ALLOW → forward upstream"]]
    sink -- yes --> trust{Where did the destination come from?}
    trust -- "tainted (untrusted tool output)" --> deny
    trust -- "unproven" --> ask
    trust -- "trusted (pack allowlist or remembered approval)" --> allow
```

## The three verdicts

Every tool call resolves to exactly one of:

- **allow** — forwarded to the upstream server unchanged.
- **deny** — never forwarded. The client gets `[bouncer blocked] <reason>`.
- **ask** — the proxy asks the human via MCP
  [elicitation](https://modelcontextprotocol.io) for a one-time approval of
  *this specific destination*. If the client doesn't support elicitation, or
  the human declines, `ask` **fails closed to deny**. An approval is
  remembered for the rest of the session, so a benign read-then-reply flow
  only asks once per destination.

A `deny` verdict never calls into the upstream server — a blocked call has no
side effects (`bouncer-mcp/src/bouncer_mcp/proxy.py`'s `route_call` / `_route_async`;
enforced by `bouncer-mcp/tests/test_proxy.py`).

## What it enforces

Four deterministic contract types, checked in this order (`ContractEngine._decide`,
`src/bouncer/engine.py`):

1. **Schema pinning (rug-pull guard).** Every upstream tool is recorded at
   startup. A tool call for a name that was **not pinned at startup** (e.g. a
   tool the server added mid-session) is unknown — `ask`, which fails closed to
   `deny` since a pinning `ask` has no destination a human can vouch for.
   (Detecting a *changed* schema for an already-pinned name is a
   [documented limit](#documented-limits), not implemented in v1.)
2. **Call budgets.** `max_calls` per tool per session. **Budgets count
   attempts, not successes** — the counter increments on every call that
   reaches the budget check, including one later denied by a different
   contract. This is a deliberate fail-safe choice: an attempted destructive
   call is a real attempt, and it keeps a denied call from being retried for
   free. See the live-verified walkthrough in
   [`docs/manual-smoke.md`](manual-smoke.md) for exactly how this plays
   out (a constraint-denied write still consumes a budget slot).
3. **Per-argument constraints.** Path-prefix confinement (normalized,
   traversal-safe — `.`/`..` are collapsed before comparison, so
   `../../etc/passwd` can't escape an allowed prefix) and regex
   matching on named arguments.
4. **Sink gate — deny-unless-trusted (the headline contract).** For tools
   marked `exfiltrating`, every declared `sink_params` argument (recipient,
   channel, url, share-target, …) must resolve to a **provenance-trusted**
   destination: a pack/YAML allowlist entry, or a remembered human approval.
   An exfiltrating tool with *no* declared sink args treats every argument as
   a sink (fail-closed — a forgotten declaration can't leave a hole).
   - A destination that traces back to untrusted output of a tool **on the same
     wrapped server** (an email body, a document's contents, …) is **tainted** →
     `deny`. (Taint is per-server — see [documented limits](#documented-limits).)
   - A destination that is neither trusted nor traceably tainted is
     **unproven** → `ask`.
   - List-valued sinks (e.g. multiple `cc` recipients) are classified
     element-by-element, so one tainted address hidden in a list of otherwise
     fine ones still denies the whole call.
   - This is a value-level taint check (`src/bouncer/taint.py`):
     normalize case/whitespace, then substring-match against everything the
     session has seen returned from an upstream tool. It decides `deny` vs.
     `ask`, never `deny` vs. silent `allow` — a missed match degrades to a
     human check, not a leak.

## Layered policy

Policy for a tool is resolved in this order, first match wins
(`src/bouncer/policy.py`):

1. **User YAML** (`bouncer run --policy your.yaml`) — your own overrides,
   allowlists, budgets, path prefixes.
2. **Curated packs** (`src/bouncer/packs/*.yaml`) — small, named-tool
   policies for popular servers: filesystem, gmail, slack, github, gdrive.
3. **Schema heuristics** (`src/bouncer/heuristics.py`) — for any tool
   with no user or pack entry, a conservative fallback that flags
   destination-shaped params (`to`, `cc`, `url`, `channel`, …) as sinks and
   `delete`/`remove`-verb tools with a default call budget.

A malformed policy file (top-level YAML that isn't a tool-name mapping, or an
invalid regex in `arg_patterns`) **fails closed**: `load_policies` /
`_policy_from_dict` raise `PolicyError` rather than silently ignoring the
file.

> **A user entry *replaces* the pack entry for that tool — it does not merge.**
> If you override `send_email` to add a `trusted_destinations` allowlist, you
> must also restate `exfiltrating: true` and its `sink_params`, or you silently
> turn the sink gate **off** for that tool. Copy the tool's block from the pack
> (`src/bouncer/packs/*.yaml`) and add to it. See
> [`examples/bouncer.yaml`](../examples/bouncer.yaml).

## MCP Tools (Skills)

Bouncer exposes native MCP tools that allow AI agents and developers to inspect security postures, evaluate hypothetical tool calls, and validate policy contracts:

| Tool | Description | Key Arguments |
| :--- | :--- | :--- |
| `bouncer_check_verdict` | Evaluates a hypothetical tool call against deterministic contracts and returns the verdict (`allow`, `deny`, or `ask`) without executing it. | `tool` (string, required), `args` (object), `untrusted_context` (string[]), `user_policy_yaml` (string) |
| `bouncer_verify_policy` | Validates a declarative YAML contract policy against Bouncer's schema, reporting syntax validity and covered tool rules. | `policy_yaml` (string, required) |
| `bouncer_get_active_policies` | Lists active security packs (`filesystem`, `gmail`, `slack`, `github`, `gdrive`) and user policies currently enforced. | `pack_name` (string, optional) |
| `bouncer_audit_summary` | Returns a summary and recent log entries of security decisions from the local audit trail (`~/.bouncer/audit.jsonl`). | `limit` (integer, default 20) |

## MCP Prompts

Interactive prompt templates for security review and policy authoring:

- **`review_mcp_security`**: Guided evaluation of an MCP server's exposed tools to uncover dangerous data exfiltration sinks, unsanitized parameters, and excessive privileges.
- **`generate_bouncer_policy`**: Interactive assistant that generates a hardened, declarative `policy.yaml` tailored to your MCP servers and desired risk tolerance (`standard`, `strict`, `paranoid`).

## MCP Resources

Direct access to Bouncer's security state and configuration:

- **`bouncer://policies/builtin`** (`application/json`): Catalog of active built-in security packs and rule schemas for the filesystem, gmail, slack, github and gdrive packs.
- **`bouncer://audit/summary`** (`application/json`): Aggregated audit metrics and recent enforcement decisions from the local audit log.

## Install and use

### Installation

```bash
# The MCP proxy, CLI and standalone server
uv tool install bouncer-mcp        # or: pipx install bouncer-mcp / pip install bouncer-mcp

# Only the contract engine, for use as a library (depends on pyyaml alone)
pip install bouncer-core

# From source
git clone https://github.com/Ezed9/mcp-bouncer.git && cd mcp-bouncer
uv sync --all-packages
```

### 1. Standalone MCP Server Mode

You can run Bouncer directly as an MCP server in Claude Desktop, Cursor, or LobeHub to access its policy validation and security auditing tools:

```json
{
  "mcpServers": {
    "bouncer": {
      "command": "bouncer",
      "args": ["serve"]
    }
  }
}
```

### 2. Proxy Mode (Wrapping Existing MCP Servers)

```bash
# Point bouncer at your existing MCP client config (Claude Code, Cursor, ...)
# and wrap the servers you want gated:
bouncer init --config path/to/mcp-config.json

# bouncer init rewrites each server entry in place: the original launch
# command is stashed under an `x-bouncer-upstream` sentinel, and the entry is
# repointed at `bouncer run`. Re-running init is a no-op (idempotent) once a
# server is already wrapped. Nothing else in your config changes.
```

The wrapped entry looks like:

```json
"filesystem": {
  "command": "bouncer",
  "args": ["run", "--config", "/abs/path/mcp-config.json",
           "--upstream-name", "filesystem"],
  "x-bouncer-upstream": {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/abs/path"]
  }
}
```

Your MCP client now launches `bouncer run`, which relaunches the real
upstream server as a subprocess and gates every call between them. To layer
your own contracts on top of the packs, add `--policy`:

```bash
bouncer run --config mcp-config.json --upstream-name filesystem \
  --policy bouncer.yaml
```

See [`examples/bouncer.yaml`](../examples/bouncer.yaml) for a starter policy
(sink allowlist, path confinement, a call budget).

## Audit log

Every verdict — `allow`, `deny`, and `ask` — is appended as one JSON line to
`~/.bouncer/audit.jsonl` (`src/bouncer/audit.py`):

```json
{"tool": "write_file", "args": {"path": "/etc/x", "content": "nope"}, "verdict": "deny", "reason": "path='/etc/x' outside allowed prefixes ['./out']", "contract": "constraint"}
```

This is a real line captured during the manual smoke test — see
[`docs/manual-smoke.md`](manual-smoke.md) for the full run. When a human
approves an `ask`, the same client call re-evaluates and immediately writes its
`allow` line, so an approved send appears in the log as an `ask` line followed
by an `allow` line for the same call.

## Demo: allow, then deny, for real

This is real output, not a mockup. It's the exact transcript captured during
the live smoke test against the official
`@modelcontextprotocol/server-filesystem` reference server on 2026-07-06 (see
[`docs/manual-smoke.md`](manual-smoke.md) for the full run, environment,
and audit log).

To reproduce on your machine, create a work dir with an MCP config and a user
policy, wrap it, and drive it (the helper scripts under
[`scripts/`](../scripts/) are the exact ones used — point them at your paths):

```bash
uv sync --all-packages
mkdir -p smoke_work/out

# an MCP config that runs the reference filesystem server over your work dir:
cat > smoke_work/mcp-config.json <<'JSON'
{"mcpServers": {"filesystem": {"command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-filesystem", "<ABS>/smoke_work"]}}}
JSON

# a user policy: confine writes to ./out and cap write_file at 2 calls:
cat > smoke_work/user-policy.yaml <<'YAML'
write_file:
  write_params: [path]
  allowed_path_prefixes: ["<ABS>/smoke_work/out"]
  max_calls: 2
YAML

# replace <ABS> with the absolute path to the repository root, then:
uv run bouncer init --config smoke_work/mcp-config.json
uv run python scripts/smoke_driver_policy.py   # drives it as a scripted client
cat ~/.bouncer/audit.jsonl
```

The `smoke_work/` dir is intentionally **not** committed (its paths are
machine-specific); create it as above.

Real per-call output from that run, with a user policy
(`allowed_path_prefixes: [".../smoke_work/out"]`, `max_calls: 2` on
`write_file`) layered over the filesystem pack:

```
--- b write_file to /etc: write_file({'path': '/etc/bouncer_should_not_write.txt', 'content': 'nope'}) ---
ERROR/DENY: [bouncer blocked] path='/etc/bouncer_should_not_write.txt' outside allowed prefixes ['.../smoke_work/out']

--- c write #1 into out ---  OK: Successfully wrote to .../out/note1.txt
--- c write #2 into out ---  ERROR/DENY: [bouncer blocked] call budget 2 for 'write_file' exceeded
--- c write #3 into out ---  ERROR/DENY: [bouncer blocked] call budget 2 for 'write_file' exceeded
```

Confirmed live: only `note1.txt` exists on disk afterward — the two
budget-denied writes never reached the upstream server. The constraint denial
is Bouncer's own contract firing (`contract: constraint`), not the upstream
server's error.

The sink-gate (deny-unless-trusted) contract can't be demonstrated against
the filesystem server — it exposes no send/share tool — so it's demonstrated
by driving the `ContractEngine` directly against a real, recorded tainted
output (also in `docs/manual-smoke.md`, and covered by
`tests/test_engine_sink_gate.py`):

```
d1 send to trusted ok@corp.com:        ALLOW [default]
d2 send to tainted attacker@evil.com:  DENY  [sink_gate] destination to='attacker@evil.com' came from untrusted data
d3 send to unproven new@random.com:    ASK   [sink_gate] destination to='new@random.com' is not a vouched recipient
```

Want a recorded GIF/asciinema of this against Claude Code or Cursor? None
exists yet — record your own with the commands above rather than trust a
canned capture.

## Documented limits

**Where Bouncer is _not_ the authority.**

- **MCP-only scope.** Bouncer governs MCP tool calls. An agent with raw shell
  access can `curl` data out around the proxy entirely — pair Bouncer with
  your client's own permission system for non-MCP tools.
- **Content egress, not content DLP.** The sink gate protects *destination*
  integrity, not content confidentiality. Tainted content may still flow to a
  *trusted* destination (e.g. "email this doc to alice@corp.com" is allowed
  even if the doc's contents came from an untrusted source). If that's a
  concern for your use case, Bouncer is the wrong layer for it.
- **Doesn't vet malicious servers.** Bouncer constrains a benign agent that's
  been hijacked by malicious *data*. It does not vet upstream MCP server
  *behavior* — pair it with [`mcp-scan`](https://github.com/invariantlabs-ai/mcp-scan)
  or similar for that.
- **Doesn't make the agent's plan smart.** Contracts bound what the agent may
  do, not whether its plan is a good idea. A denied call is safe, not
  necessarily corrected.
- **Taint is per wrapped server.** Each `bouncer run` wraps one server with its
  own taint tracker, so a *cross-server* flow — read a poisoned file via one
  server, then send via another — surfaces as `ask` (unproven destination), not
  `deny`. Deny-unless-trusted still holds (nothing is silently allowed), but the
  hard `deny` only fires when the tainted data and the send go through the same
  wrapped server.
- **Path confinement is lexical.** Prefix checks collapse `.`/`..` but do not
  resolve symlinks, so a symlink placed inside an allowed prefix could point
  outside it. Don't rely on path confinement alone against an adversary who can
  create symlinks in the allowed directory.
- **No mid-session schema-change detection (v1).** Schemas are pinned once at
  startup; a server that changes an *already-pinned* tool's schema mid-session
  is not re-checked. Only names absent from the startup snapshot are treated as
  unknown.
- **Sink params must be complete for your server.** The gate inspects the
  `sink_params` you declare (plus a fail-closed sweep of *all* args when a
  tool's declared sinks are entirely absent from a call — the schema-mismatch
  guard). But if a tool exposes a destination-bearing argument you did **not**
  declare *alongside* one you did (e.g. you declare `to` and the server also
  accepts an undeclared `recipients`), the undeclared field is treated as
  content, not a destination, and a value placed there is not gated. Undeclared
  extra params can't be auto-classified as sink-vs-content without guessing, so
  enumerate every recipient/destination argument your actual server accepts in
  your pack. The curated packs aim to be complete for the servers they name;
  verify against your server's `tools/list`.

