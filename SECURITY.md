# Security Policy

Bouncer is a safety layer, so a vulnerability here is a way to defeat the
enforcement — most importantly, **any way to make an `exfiltrating` tool call
resolve to a silent `allow`** when it should have been `deny` or `ask`. Other
examples: bypassing the sink gate with an encoded/typed destination, escaping a
path prefix, evading the call budget, or a malformed policy that fails open.

## Reporting a vulnerability

Please report privately rather than opening a public issue:

- Use GitHub's **[Report a vulnerability](https://github.com/Ezed9/mcp-bouncer/security/advisories/new)**
  (Security → Advisories) on this repository, **or**
- open a minimal issue titled "security contact request" with no details and
  we'll arrange a private channel.

Include, if you can: a minimal reproduction (a tool call, the tainted output
that precedes it, and the policy in effect), the verdict you got, and the
verdict you expected. A failing test in the style of
`tests/test_engine_sink_gate.py` is the ideal report.

## Scope

In scope: the enforcement logic in `src/bouncer/` — the engine, sink gate,
taint tracker, policy loader, path confinement, budgets, and schema pinning.

Out of scope (documented limitations, not vulnerabilities — see the README):

- Non-MCP exfiltration paths (an agent with raw shell access can bypass an
  MCP proxy entirely).
- Content confidentiality — Bouncer gates *destinations*, not content, so
  tainted content flowing to a *trusted* destination is by design.
- Cross-server taint (each `bouncer run` wraps one server) surfacing as `ask`
  rather than `deny`.
- Symlink escapes from lexical path confinement.

If you're unsure whether something is in scope, report it privately and we'll
figure it out together.

## Expectations

This is an early-stage project maintained on a best-effort basis. We'll
acknowledge reports as quickly as we can and credit reporters who want it.
