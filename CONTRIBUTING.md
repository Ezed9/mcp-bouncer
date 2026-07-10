# Contributing to Bouncer

Thanks for helping build a deterministic safety layer for agent tool calls.
This is security-adjacent code — the bar is correctness and clarity over
cleverness. Small, well-tested PRs are far easier to accept than large ones.

## Development setup

Bouncer uses [uv](https://docs.astral.sh/uv/). From the repository root:

```bash
uv sync                # install the project + dev tools (pytest, ruff)
uv run pytest -q       # run the full test suite
uv run ruff check .    # lint
```

The benchmark harness is an optional extra (it pulls in AgentDojo):

```bash
uv run --extra benchmark python -m benchmark.run_agentdojo   # needs GEMINI_API_KEY
uv run python -m benchmark.run_agentdojo                     # no key: scorer test only
```

CI runs exactly `ruff check .` and `pytest -q` on Python 3.12 and 3.13. Get
both green locally before opening a PR.

## The one rule that isn't negotiable: fail closed

Bouncer is only useful if it never *silently* allows something it couldn't
reason about. Every ambiguous case must resolve to `ask` or `deny`, never a
silent `allow`. Concretely:

- A tool marked `exfiltrating` with no usable `sink_params` treats **every**
  argument as a destination.
- An unknown/unpinned tool → `ask`, not `allow`.
- A malformed policy file → `PolicyError` at load time (the proxy refuses to
  start), not a best-effort partial parse.
- A `deny` **must not** forward the call upstream. This invariant is load-
  bearing; tests assert it, and any change near the decision path must keep it.

If your change adds a new decision branch, add a test that proves the
fail-closed direction, not just the happy path. See `tests/test_engine_sink_gate.py`
for the style (red test first, then the engine change).

## What makes a good PR

- **Tests with it.** New behavior needs a test; a bug fix needs a regression
  test that fails before your change and passes after.
- **No LLM in the decision path.** The engine is deterministic by design.
  Heuristics, packs, and taint rules are welcome; a model call inside
  `ContractEngine.evaluate` is not.
- **Type hints on every function signature** (params and return).
- **Match the surrounding style.** Comment density, naming, and idiom should
  read like the file you're editing. No docstrings on obvious functions.
- **Keep the diff scoped.** Don't refactor surrounding code as part of a fix.

## Adding or fixing a server pack

Packs live in `src/bouncer/packs/*.yaml` and map a server's tools to policies.
The most valuable contributions here are packs verified against a **real**
server's `tools/list`:

- Enumerate **every** destination-bearing argument as a `sink_param` — a
  missed one is a silent exfiltration gap (see the sink-completeness note in
  the README's limitations).
- Prefer verified tool/param names over documented-but-unchecked ones; note in
  a comment how you verified (e.g. "verified live 2026-07-06").
- Add or update a test in `tests/test_packs.py`.

## Reporting security issues

Please do **not** open a public issue for a vulnerability in the enforcement
logic (e.g. a way to make an exfiltrating call resolve to `allow`). See
[SECURITY.md](SECURITY.md) for private disclosure.

## Commit messages

Conventional-commit style (`fix(engine): ...`, `feat(packs): ...`,
`docs: ...`). Explain the *why* in the body when it isn't obvious from the diff.
