# Changelog

All notable changes to `bouncer-core` and `bouncer-mcp` are recorded here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and both
packages use [Semantic Versioning](https://semver.org/) and are released together.

## [Unreleased]

## [0.1.3] - 2026-10-23

### Added
- `bouncer report` writes a Markdown security review pack from a policy, the
  server's tool list and the audit log: tool inventory and controls, findings,
  an audit summary, guarantees and limits, and an OWASP LLM Top 10 mapping.
- Audit log lines carry a UTC `ts` timestamp.
- `examples/demo/`: an end-to-end demo of a hijacked agent against a mock
  helpdesk MCP server behind the real proxy, ending in a review pack. `--pace`
  (or `BOUNCER_DEMO_PACE=1`) slows it down for recording.
- A recording of that demo (`docs/assets/demo.gif`, `demo.mp4`), made from
  `examples/demo/demo.tape` with VHS.
- `bouncer-core` ships a `py.typed` marker, so type checkers read its types
  instead of treating it as untyped.

### Security
- Proxy mode no longer lists Bouncer's own `bouncer_*` tools, prompts or resources
  to the agent. In 0.1.0 to 0.1.2 they were answered before the engine, outside the audit
  log, so a prompt-injected agent could call them (including
  `bouncer_check_verdict`, which wrote to the audit log, and
  `bouncer_audit_summary`). `bouncer serve`, the standalone server, is unchanged.

### Changed
- The AgentDojo driver (`benchmark/run_agentdojo.py`) covers all 40 user tasks,
  adds a benign pass without Bouncer, a cost cap, resumable per-case logs,
  confidence intervals and a generated report and chart; the attack text now
  addresses the agent neutrally. `benchmark/run_final.sh` reproduces the run.
- `bouncer-mcp` declares `pydantic>=2,<3`, which it now imports directly.
  mcp 1.x already required it, so installs resolve the same.
- The AgentDojo benchmark runs on open-weight models (such as Qwen), whose chat
  templates reject OpenAI's `developer` role.

### Documentation
- The README is rewritten around what Bouncer enforces, with the demo
  recording at the top and a section for security reviewers. The technical
  reference moved to `docs/how-it-works.md`.
- The AgentDojo section of the README now reports the final run: `gpt-4o-mini`,
  40 user tasks, 164 attack cases. The attacker's goal was reached in 48 cases
  without Bouncer and 0 of 163 with it, but Bouncer allowed no send at all in
  that run (so the 0 follows by construction), and the six tasks that send email
  or share files went from 4/6 to 0/6. Charts, per-case results and the raw
  rows are committed under `benchmark/` and `docs/assets/`. Earlier
  `deepseek-v4-flash` (15 and 30 cases) and `gpt-oss-120b` results stay in
  `benchmark/RESULTS.md` as history.

## [0.1.2] - 2026-09-14

### Fixed
- `bouncer-mcp` crashed on startup for every fresh install: `mcp>=1.10` resolved
  mcp 2.x, which removed the low-level server API the proxy uses. `mcp` is now
  capped below 2 until the 2.x migration.
- `__version__` reported `0.1.0` on the 0.1.1 release; it now reads the installed
  distribution's version.

### Added
- A test that starts the server over real stdio, and a CI job that installs both
  packages with no lockfile, on push and weekly.

## [0.1.1] - 2026-09-13

### Changed
- Split into `bouncer-core` (engine, `pyyaml` only) and `bouncer-mcp` (proxy,
  CLI, standalone server).
