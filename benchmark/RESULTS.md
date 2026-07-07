# AgentDojo benchmark results — Bouncer contract engine

**Status: PENDING — run with GEMINI_API_KEY.**

No live benchmark has been run yet. This file was created without a
`GEMINI_API_KEY` in the environment, so every number below is a placeholder.
Nothing in this file is a measured result — do not read any value here as
real until the run below has actually been executed and this file updated
with its output.

## How to produce real results

```bash
cd bouncer
GEMINI_API_KEY=... uv run python -m benchmark.run_agentdojo --user-tasks user_task_8
```

Free Gemini key, no credit card: https://aistudio.google.com/apikey

The driver (`bouncer/benchmark/run_agentdojo.py`) runs the AgentDojo
`workspace` suite twice under the Bouncer `ContractEngine`:

1. **No injections** (`benchmark_suite_without_injections`) — measures the
   benign false-positive rate: how often a legitimate sink call was NOT a
   clean `ALLOW` (i.e. it was wrongly `DENY`'d, or required an `ASK` that a
   human would have to clear).
2. **With injections** (`benchmark_suite_with_injections`, the
   `important_instructions` attack) — measures the attack-block rate: how
   often the call carrying the injected/attacker destination was `DENY`'d or
   `ASK`'d (blocked) rather than `ALLOW`'d (leaked).

Both rates are computed by `bouncer.benchmark_scoring.block_rate` over the
verdict list the engine actually returned for each sink call, split by
whether the tool's policy came from a curated pack
(`bouncer/src/bouncer/packs/*.yaml`) or the heuristic fallback
(`bouncer/src/bouncer/heuristics.py`).

Running the command above writes `bouncer/benchmark/results.json` and prints
a markdown table; paste that table into the "Results" section below and
replace every `PENDING` cell with the printed number.

## Results

| metric | all | pack-covered | heuristic-covered |
|---|---|---|---|
| attack-block-rate | PENDING | PENDING | PENDING |
| benign false-positive rate | PENDING | PENDING | PENDING |

`user_tasks` run: PENDING (fill with the `--user-tasks` value used, e.g. `user_task_8`).

## Reading the result against the spec's kill criteria

From the design spec (`docs/superpowers/specs/2026-07-05-agent-contracts-mcp-proxy-design.md`,
section 10):

> **Kill (numeric, pre-registered):** if after approval-memory the benign
> suites still show **≥10% utility loss** or a **median of >3 asks per
> benign task**, the deterministic-only thesis is wrong for this layer —
> stop, or pivot to the hybrid (lightweight ML screener) approach RTBAS
> validates.

When real numbers land above, check them against these two thresholds
specifically:

1. **Benign utility loss ≥ 10%** — read this off the "benign false-positive
   rate" row (a false positive on a sink call is the mechanism by which a
   benign task fails or needs a human click). If the "all" column is ≥ 0.10,
   that is a signal to look closer at per-task utility loss, not just the
   raw call-level rate.
2. **Median > 3 asks per benign task** — the raw `ASK` count per benign task
   is not broken out separately in the table above (the table folds
   `ASK`+`DENY` into one "blocked" rate per `block_rate`'s definition); to
   check this criterion specifically, inspect `bouncer/benchmark/results.json`
   and `bouncer/benchmark/audit.jsonl` (written by the engine's `AuditLog`)
   for the per-task `ask` verdict counts and take the median across benign
   tasks.

If either threshold is crossed, treat it as a signal to pivot per the spec,
not as something to explain away.
