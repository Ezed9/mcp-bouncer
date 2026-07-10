# AgentDojo benchmark results — Bouncer contract engine

**Status: METHODOLOGY FINALIZED — awaiting the current harness's run.**

An earlier run of a *previous* version of this harness is described at the
bottom ("History") — it is retained for honesty because it caught a real bug,
but its headline number was measured the wrong way (see "Why the metric
changed") and is **not** the number to cite. Re-run the command below to
populate the results table; do not treat the History numbers as current.

## What is measured

The headline is **AgentDojo's own security scorer**, not a Bouncer-internal
count. For each `(user_task, injection_task)` pair, AgentDojo checks whether
the injection *actually accomplished its goal* — e.g. whether the attacker's
address actually received the exfiltrated data. This is destination-aware and
per-injection-case, so it cannot be inflated by agent retries or satisfied by
collateral-blocking the user's own task.

Reported under two conditions:

| condition | what it shows |
|---|---|
| **baseline** (no Bouncer) | the attacks actually work on this model — attack success should be **> 0**, otherwise a low Bouncer number would prove nothing |
| **with Bouncer** | attack success with every tool call gated — should drop toward **0** |

Alongside attack success we report **utility** (AgentDojo's user-task scorer)
for the benign run and both attack runs, so any collateral damage from
Bouncer's blocks is visible as a utility drop rather than hidden.

Injection tasks used: `injection_task_0`, `injection_task_3`,
`injection_task_4` — all instruct the agent to send data to the attacker
address `mark.black-2134@gmail.com`; task 4 is the "exfiltrate a Facebook 2FA
security code" case.

## Results

_Run the command in "Reproduce" and paste the printed table here. Every cell
below is a placeholder until then._

| condition | attack success rate | user-task utility |
|---|---|---|
| no Bouncer (baseline) | PENDING | PENDING |
| with Bouncer | PENDING | PENDING |

Benign utility (no injection, with Bouncer): PENDING
Number of injection cases (n): PENDING
Engine detail (with-Bouncer attack run), sink-call verdicts: PENDING

## Kill criteria (pre-registered in the design spec, section 10)

> if after approval-memory the benign suites still show **≥10% utility loss**
> or a **median of >3 asks per benign task**, the deterministic-only thesis
> is wrong for this layer — stop, or pivot to a hybrid approach.

Check the measured **benign utility** against the ≥10% loss threshold and the
benign sink-call `ask` count against the >3-per-task threshold once the run
completes. Treat a crossed threshold as a signal to pivot, not to explain away.

## Reproduce

```bash
cd bouncer
GEMINI_API_KEY=... uv run --extra benchmark python -m benchmark.run_agentdojo
```

Free Gemini key, no credit card: https://aistudio.google.com/apikey. The
driver waits out free-tier per-minute 429s, aborts with options on a
daily-quota 429, and on a model 404 prints the models your key can call.
Flags: `--user-tasks`, `--injection-tasks` (comma lists), `--no-baseline`.

## Why the metric changed

The first harness reported `block_rate` = fraction of Bouncer sink-call
verdicts that were not ALLOW. Two independent Opus code reviews found this
overstated defense: (1) it never checked that the blocked call was the one
carrying the injection, so Bouncer denying the *legitimate* send (tainted
because the poisoned inbox was read) also scored as an "attack block"; and
(2) blocked calls are retried by the agent, and each retry was counted again,
inflating the denominator. AgentDojo's security scorer has neither problem, so
it is now the headline. Bouncer's own verdict counts are kept as supplementary
"what the engine did" detail only.

## History (retained for honesty, not for citation)

- **First complete run, pre-fix:** attack-block 0.00 — Bouncer *allowed* the
  exfiltration (a Facebook code emailed to the attacker). Root cause: the
  gmail pack declared `sink_params: [to, cc, bcc]`, but the suite's
  `send_email` uses `recipients`; declared-but-absent sink params silently
  skipped the gate. Fixed fail-closed in commit `3d9c904` (if an exfiltrating
  tool's declared sinks are all absent, every arg is treated as a sink) with
  regression tests. **This is the benchmark doing its job — surfacing a real
  bypass in the engine.**
- **Second run, post-fix, old metric:** 1.00 sink-call block rate / 0.00
  benign false positives. Correct direction, but measured by the flawed
  block-rate metric above — superseded by the AgentDojo-scored results table.
