# Changelog

All notable changes to `bouncer-core` and `bouncer-mcp` are recorded here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and both
packages use [Semantic Versioning](https://semver.org/) and are released together.

## [Unreleased]

## [0.1.6] - 2026-11-12

### Added
- `bouncer report` has an AIUC-1 section. For each AIUC-1 control Bouncer
  touches (D003.1-D003.5, B006.1-B006.3, B008.3) it says where the pack holds
  evidence, filled in from the actual policy and audit log, and what Bouncer
  does not cover. B001.1 is listed as not covered, because it needs a
  third-party evaluation. It is a pointer for a reviewer, not an assessment.
- `bouncer-mcp` also installs a `bouncer-mcp` command, the same as `bouncer`,
  so `uvx bouncer-mcp` works. Before, uvx found no executable with the
  package's name and stopped.
- `server.json` for the official MCP Registry, and the `mcp-name` line in the
  `bouncer-mcp` README that the registry checks to confirm who owns the PyPI
  package. The registry entry starts `bouncer serve`.

### Changed
- **Breaking for policies with mistakes in them:** a policy file with a
  misspelled key, a value of the wrong type or an empty tool entry is now an
  error at startup. Before, it was ignored, which turned the control off:
  `allowed_path_prefixes: /workspace` (a string, not a list) confined nothing,
  and `max_calls: "1"` set no budget. `max_calls` must be a whole number of 0
  or more.
- A tool entry that sets `sink_params` or `trusted_destinations` without
  `exfiltrating: true` is an error. A user entry replaces the pack entry, so an
  entry that only added an allowlist switched the destination check off for
  that tool, and a send to an address from untrusted output was allowed.
- `bouncer init` skips servers that have no `command` (remote `url` servers).
  It used to wrap them, and the wrapped entry could not start.
- Packaging: both packages carry classifiers, keywords and links to the
  repository, docs and changelog. `bouncer-mcp` now ships the MIT license
  file. The `bouncer-core` page on PyPI is a short page with working links
  (the repository README's images and relative links did not resolve
  there), and its source archive holds the package source only.

### Fixed
- An address that follows a JSON escape in tool output is now tainted. A
  server that returns JSON as text writes a newline as `\n`, and the
  whole-token match from 0.1.5 read `\nattacker@evil.com` as a longer token, so
  the send was asked instead of denied. Same for `\t` and `<`.
- The text of an upstream error, of an embedded resource and of a resource
  link is recorded as untrusted output. Before, only text blocks and
  structured content were.
- The fallback for tools with no pack entry gave a two-call budget to any tool
  with `rm` or `drop` anywhere in its name, such as `browser_fill_form`,
  `get_user_permissions` and `dropbox_list_files`. Those two verbs must now be
  a whole word of the name.
- `bouncer_check_verdict` (in `bouncer serve`) no longer writes its
  hypothetical verdicts to `~/.bouncer/audit.jsonl`, where `bouncer report`
  counted them. It also treats the argument names of the call as the tool's
  parameters, so a tool with no pack entry gets the same fallback the proxy
  applies.

### Security
- The audit log is created with mode 0600 and its directory with 0700, and a
  log created by an older version is tightened to 0600 on the next run. It
  records argument values and was readable by other local users.
- Each audit line is written with one `write` call, so lines from several
  proxies appending to the same file don't interleave.

### Documentation
- README: the feature list now covers the approval fallback for clients that
  can't elicit, and the review pack's OWASP and AIUC-1 mappings.
- README, `docs/how-it-works.md` and CONTRIBUTING now match the code: the
  roadmap no longer lists `mcp` 2.x support (it shipped in 0.1.5), and the
  test count, the setup command and the CI Python versions are corrected.

## [0.1.5] - 2026-11-07

### Added
- One-time approvals for MCP clients that can't elicit. Before, every `ask`
  from such a client was a deny with no way through. Now the deny carries a
  short code. A human runs `bouncer approve <code>` in their own terminal, and
  a retry of a call to the same destination passes once, within five minutes.
  `bouncer pending` lists open codes.
  - A code is bound to the wrapped server and the approval key (tool, argument,
    destination). The proxy looks approvals up by that key, never by a code
    the agent sends, so a code can't approve a different destination, tool or
    server.
  - A pending code expires five minutes after it was issued. An approved one
    must be used within five minutes and allows one call. It is not remembered
    for the session.
  - State is `~/.bouncer/pending.json`, 0600 in a 0700 directory, written
    atomically under a lock. The file is ignored if anyone other than the owner
    can read or write it, or if it is a symlink. No MCP tool can approve.
  - `bouncer approve` needs a terminal: stdin must be a TTY, and each code is
    confirmed after it shows the server, tool and destination. Each approval
    is written to the audit log as an `approve` line (contract `out_of_band`),
    and the review pack counts them.
  - Still denied, with no code: a tainted destination, a pinning `ask` (a tool
    not present at startup), and more than 20 pending codes.
  - Clients that elicit are unchanged.
  - Research and design: `docs/clients-and-approvals.md`.

### Changed
- `bouncer-mcp` runs on the MCP Python SDK 2.x (`mcp>=2,<3`), so it can be
  installed next to other packages that need mcp 2. It no longer installs with
  mcp 1.x; 0.1.4 is the last release for 1.x. What the proxy does is unchanged:
  tool names are pinned at startup, every call goes through the engine, ASK is
  asked through elicitation, results are relayed with `structuredContent`, and
  the `bouncer_*` tools are not exposed.
- The proxy speaks only the `initialize`-handshake protocol versions, not
  2026-07-28, which has no server-to-client requests and so no way to ask the
  user. mcp 2.x clients fall back to the handshake on their own. If a
  connection still can't carry the request, ASK is denied, as it is for a
  client without elicitation.
- `bouncer-mcp` depends on `jsonschema` directly (for input validation, which
  the 2.x low-level server no longer does) and no longer on `pydantic`.

### Fixed
- A destination is tainted only when it appears in earlier tool output as a whole
  token. Before, `ana@globex.example` was denied after `dana@globex.example` had
  appeared, because the match was a plain substring check; it now gets `ask`.
  A trailing "." or "-" doesn't stop a match, so an address at the end of a
  sentence is still denied. Reported in #2.
- A recipient written with a display name, like `Dana <dana@globex.example>`, is
  now gated on the address inside the brackets. Before, a trusted address in that
  form wasn't recognized as trusted (so it asked, or was denied if it had appeared
  in tool output), and a tainted address in that form got `ask` instead of `deny`.
  Approvals cover both forms. Reported on r/mcp.
- A recipient string holding several addresses (`"alice@corp.com, attacker@evil.com"`,
  or `;`-separated) is now split and each address gated, so a tainted one denies
  instead of getting `ask`. Parsing uses `email.utils.getaddresses` (strict), as
  suggested on r/mcp, and every address-shaped token in the raw value is checked
  too, so an address the parser reads as a comment or display name can't slip
  past a trusted one. URLs are not split.
- **Security:** a dict-valued sink had only its values checked, so a recipient
  map keyed by address, like `{"attacker@evil.com": []}`, was allowed. Dict keys
  are now checked unless they are a known field name (`email`, `name`,
  `emailAddress`, …).
- **Security:** a declared sink that was present but empty (`to: []`) stopped the
  fail-closed sweep of all arguments, so
  `{"to": [], "recipients": ["attacker@evil.com"]}` was allowed. An empty
  declared sink now counts as absent, and an exfiltrating call with no
  destination anywhere (`{}`, `{"to": []}`) gets `ask`.
- **Security:** the allowlist and approvals used Unicode lowercasing, which maps
  KELVIN SIGN (U+212A) to "k", so `\u212Aate@corp.com` matched an allowlisted
  `kate@corp.com`. They now lowercase ASCII letters only, so `JOSÉ@x.es` no
  longer matches an allowlisted `josé@x.es`.
- **Security:** with a persisted `ApprovalStore(path)` (library API; the CLI keeps
  approvals in memory), an agent-chosen argument name containing a newline could
  write a second, forged key into the file, which approved another destination
  after a reload. Approval keys are now a one-line JSON array. Keys persisted by
  0.1.4 or earlier no longer match, so those destinations are asked about again.
- Taint matching is wider (it can only turn `ask` into `deny`): full-width forms
  and zero-width characters are folded, percent-encoding and HTML entities in
  output are decoded, and an address inside a URL query or with a `+tag` is
  checked on its own.
- The address-token regex no longer backtracks quadratically. A destination made
  of a long run of address characters (about 160 KB) held the gate for minutes.
- In proxy mode, a recipient nested inside a list or a dict could make the
  approval loop run out of rounds and deny a call after the human had approved
  every destination. The round bound now counts destinations the way the gate
  does.
- `ask` and `deny` reasons show a non-ASCII destination in escaped form too,
  since a Cyrillic "а" looks like "a" in an approval prompt, and quote an
  argument name that isn't a plain identifier.
- README Limits and `docs/how-it-works.md` list what is still not caught:
  base64, quoted-printable, homoglyphs, punycode, `-` subaddressing, URL path
  case in approvals, a structured recipient's name being gated, and unpacked
  tools whose destination parameter has an unrecognized name.

## [0.1.4] - 2026-10-24

### Changed
- The review pack heading "What Bouncer guarantees and does not guarantee" is now
  "What Bouncer enforces and what it does not", and "Not guaranteed" is "Not
  enforced". The review pack, `docs/how-it-works.md` and `SECURITY.md` now say
  that only tool names are pinned at startup, not schemas; a changed schema for
  an existing tool was never detected.
- The standalone server's `bouncer_get_active_policies` description lists the
  packs that exist (filesystem, gmail, slack, github, gdrive).

### Documentation
- README: the share of Bouncer cases where the agent tried to email the attacker
  is now counted (107 of 163). The unverified "88/164 vs 99/163, p = 0.09"
  figure is removed.
- README: the demo caption now says what the demo shows (email and SSH write
  denied, first delete runs, second stopped by the budget). The deepseek control
  line now reads 1 attack in 15, and 0 in 8 in the probe, each linked to its
  results file.
- `SECURITY.md` scope now includes the `bouncer-mcp` proxy.
- `docs/how-it-works.md` no longer lists LobeHub as a supported client; it was
  never tested.

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
