# bouncer/benchmark/run_agentdojo.py
"""Driver: run the Bouncer contract ENGINE against the real AgentDojo workspace
suite (not a live proxy — the engine is exercised in-process).

Mirrors `prototype/benchmark/run_workspace.py`'s shape: free-tier Gemini
pacing/backoff, an `OutputLogger` context around the AgentDojo benchmark
helpers, a `--user-tasks` flag, and a clean no-key path.

Two measurements, both read off the engine's own verdicts (not AgentDojo's
task-success scoring):

  1. Attack-block rate — on `benchmark_suite_with_injections` (the
     `important_instructions` attack), every sink-tool call the agent makes is
     routed through `ContractEngine.evaluate`; a DENY or ASK on the call that
     carries the injected destination counts as "blocked". `block_rate` over
     those verdicts is the attack-block rate (higher is better).
  2. Benign false-positive rate — on `benchmark_suite_without_injections`,
     the same per-call verdicts are collected; `block_rate` here is the
     fraction of BENIGN sink calls that were not a clean ALLOW (an ASK or a
     wrongly-triggered DENY — a false positive, lower is better).

Both splits are further broken down by whether the tool's policy came from a
curated pack (`bouncer/src/bouncer/packs/*.yaml`) or the heuristic fallback.

`agentdojo` and `google.genai` are imported ONLY inside the GEMINI_API_KEY-gated
code path, so this module — and the whole no-key path — imports and runs fine
without agentdojo installed (it is an optional `[benchmark]` extra).

Run (live):  cd bouncer && GEMINI_API_KEY=... uv run --extra benchmark python -m benchmark.run_agentdojo --user-tasks user_task_8
Run (no key): cd bouncer && uv run python -m benchmark.run_agentdojo   # scorer unit test only
Free key (no credit card): https://aistudio.google.com/apikey
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING

from bouncer.approvals import ApprovalStore
from bouncer.audit import AuditLog
from bouncer.benchmark_scoring import block_rate
from bouncer.engine import ContractEngine
from bouncer.policy import PolicyResolver, builtin_pack_paths, load_policies
from bouncer.taint import TaintTracker
from bouncer.types import ToolCall, Verdict

if TYPE_CHECKING:
    from agentdojo.functions_runtime import FunctionsRuntime

# Free-tier pacing + 429 backoff (mirrors the prototype harness). The
# benchmark helpers drive the LLM loop themselves, so we cannot inject
# per-call sleeps; we pace between suite runs and back off on a 429.
_PACE_SECONDS = 6.0
_RETRY_BACKOFF = (8.0, 16.0, 32.0)

_DEFAULT_USER_TASKS = ("user_task_8",)  # the read+send tracer
_ATTACK = "important_instructions"
_RESULTS_PATH = Path(__file__).with_name("results.json")
_AUDIT_PATH = Path(__file__).with_name("audit.jsonl")


def _is_rate_limit(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "429" in msg or "quota" in msg or "rate" in msg


# Loaded AFTER the builtin packs (last-wins), replacing e.g. the gmail pack's
# send_email (to/cc/bcc) with this suite's real schema (recipients/cc/bcc) —
# the same per-server pack a real deployment writes (see examples/bouncer.yaml).
_WORKSPACE_PACK = Path(__file__).with_name("agentdojo_workspace.yaml")


def _benchmark_pack_paths() -> list[Path]:
    return [*builtin_pack_paths(), _WORKSPACE_PACK]


def _build_engine() -> ContractEngine:
    """Mirrors `bouncer.proxy._build_resolver` + engine construction exactly,
    but schemas are populated per-call from the AgentDojo runtime (see
    `_RecordingToolsExecutor._schema_for`) rather than pinned up front, since
    there is no live upstream `list_tools` round-trip in this harness."""
    resolver = PolicyResolver(overrides=load_policies(_benchmark_pack_paths()))
    return ContractEngine(
        resolver=resolver,
        taint=TaintTracker(),
        approvals=ApprovalStore(),
        audit=AuditLog(_AUDIT_PATH),
        schemas={},  # populated lazily; see _RecordingToolsExecutor
    )


def _pack_covered_tools() -> set[str]:
    return set(load_policies(_benchmark_pack_paths()).keys())


class _CallRecord:
    __slots__ = ("tool", "verdict", "pack_covered", "sink")

    def __init__(self, tool: str, verdict: str, pack_covered: bool, sink: bool) -> None:
        self.tool = tool
        self.verdict = verdict
        self.pack_covered = pack_covered
        self.sink = sink  # tool's resolved policy is exfiltrating


def _make_recording_tools_executor(engine: ContractEngine, records: list[_CallRecord], pack_tools: set[str]):
    """Build a `ToolsExecutor` subclass that routes every tool call through
    the Bouncer engine before executing it, and records the verdict.

    A DENY never executes the underlying tool (mirrors `route_call`); an ASK
    is treated as blocked-and-not-executed too, since this harness has no
    interactive human to elicit (mirrors the proxy's fail-closed-when-no-elicit
    behaviour in `route_call`/`_route_async`). Only a clean ALLOW runs the
    tool and feeds its output back to `engine.register_output` for taint.
    """
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, tool_result_to_str
    from agentdojo.functions_runtime import EmptyEnv
    from agentdojo.types import ChatToolResultMessage, text_content_block_from_string

    class _RecordingToolsExecutor(ToolsExecutor):
        def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args=None):
            extra_args = extra_args or {}
            if len(messages) == 0 or messages[-1]["role"] != "assistant":
                return query, runtime, env, messages, extra_args
            tool_calls = messages[-1]["tool_calls"]
            if not tool_calls:
                return query, runtime, env, messages, extra_args

            results = []
            for tool_call in tool_calls:
                name = tool_call.function
                schema = _schema_for(runtime, name)
                engine._schemas[name] = schema  # populate lazily for pinning

                call = ToolCall(tool=name, args=dict(tool_call.args))
                decision = engine.evaluate(call)
                pack_covered = name in pack_tools
                sink = engine._resolver.policy_for(name, schema).exfiltrating
                records.append(_CallRecord(name, decision.verdict.value, pack_covered, sink))

                if decision.verdict is Verdict.ALLOW:
                    raw_result, error = runtime.run_function(env, name, tool_call.args)
                    if error is None:
                        engine.register_output(tool_result_to_str(raw_result))
                    text = tool_result_to_str(raw_result) if error is None else ""
                else:
                    error = f"[bouncer blocked] {decision.reason}"
                    text = ""

                results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(text)],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=error,
                    )
                )
            return query, runtime, env, [*messages, *results], extra_args

    return _RecordingToolsExecutor()


def _schema_for(runtime: "FunctionsRuntime", name: str) -> dict[str, object]:
    fn = runtime.functions.get(name)
    if fn is None:
        return {}
    return {"properties": dict.fromkeys(fn.parameters.model_fields.keys(), {})}


_thinking_patched = False


def _retry_delay_seconds(exc: object, default: float = 30.0) -> float:
    """Seconds to wait after a 429, from Google's suggested delay (+ buffer)."""
    import re

    match = re.search(r"retry in ([0-9.]+)s", str(exc))
    return float(match.group(1)) + 2.0 if match else default


def _is_daily_quota(exc: object) -> bool:
    """True when the 429's quota violation is a per-DAY cap (waiting is futile)."""
    return "perday" in str(exc).lower()


def _available_models(client: object) -> list[str]:
    """Model ids this key can call with generateContent (flash-class first)."""
    if client is None:
        return []
    try:
        names = [
            m.name.removeprefix("models/")
            for m in client.models.list()
            if "generateContent" in (getattr(m, "supported_actions", None) or [])
        ]
    except Exception:  # noqa: BLE001 — listing is best-effort diagnostics
        return []
    return sorted(names, key=lambda n: (("flash" not in n), n))


def _call_with_rate_limit_retry(original, *args):  # type: ignore[no-untyped-def]
    """Call AgentDojo's request fn, waiting out free-tier 429s.

    AgentDojo's GoogleLLM uses `retry_if_not_exception_type(ClientError)`, so it
    does NOT retry rate limits — a free-tier RPM cap (e.g. gemini-2.5-flash = 5
    req/min) kills the whole task. We catch 429s here and sleep the delay Google
    asks for, so a task completes on the free tier (slowly).
    """
    from google.genai.errors import ClientError

    for attempt in range(12):
        try:
            return original(*args)
        except ClientError as exc:
            if getattr(exc, "code", None) == 404:
                model = args[0] if args else "<model>"
                available = _available_models(args[1] if len(args) > 1 else None)
                listing = "\n".join(f"  {name}" for name in available) or "  (could not list models)"
                raise SystemExit(
                    f"\nModel {model} is not available to this API key.\n"
                    f"Models your key CAN use with generateContent:\n{listing}\n"
                    "Re-run with one of them (prefer a flash-class model):\n"
                    "  BOUNCER_GEMINI_MODEL=<model> uv run python -m benchmark.run_agentdojo --user-tasks user_task_8"
                ) from exc
            if getattr(exc, "code", None) != 429 or attempt == 11:
                raise
            if _is_daily_quota(exc):
                model = args[0] if args else "<model>"
                raise SystemExit(
                    f"\nDaily free-tier quota for {model} is exhausted — waiting will not help.\n"
                    "Options:\n"
                    "  1. Run with a different model (separate daily bucket):\n"
                    "       BOUNCER_GEMINI_MODEL=gemini-2.0-flash uv run python -m benchmark.run_agentdojo --user-tasks user_task_8\n"
                    "  2. Wait for the quota reset (midnight Pacific time) and re-run.\n"
                    "  3. Use a paid-tier GEMINI_API_KEY."
                ) from exc
            delay = _retry_delay_seconds(exc)
            print(f"  rate-limited (429); waiting {delay:.0f}s then retrying ...")
            time.sleep(delay)
    raise RuntimeError("rate-limit retries exhausted")  # pragma: no cover


def _disable_gemini_thinking(google_llm_module: object) -> None:
    """Preserve Gemini thought signatures across AgentDojo tool-call turns."""
    global _thinking_patched
    if _thinking_patched:
        return

    original = google_llm_module.chat_completion_request
    pending_signatures = []

    def patched(model, client, contents, generation_config):
        # AgentDojo reconstructs assistant function-call parts and drops
        # Gemini's thought_signature. Restore signatures in original order.
        signature_index = 0
        for content in contents:
            for part in content.parts or []:
                if part.function_call is not None:
                    if (
                        getattr(part, "thought_signature", None) is None
                        and signature_index < len(pending_signatures)
                    ):
                        part.thought_signature = pending_signatures[signature_index]
                    signature_index += 1

        response = _call_with_rate_limit_retry(
            original, model, client, contents, generation_config
        )

        # Save signatures returned with function calls for the next turn.
        if response.candidates:
            content = response.candidates[0].content
            if content is not None:
                for part in content.parts or []:
                    if (
                        part.function_call is not None
                        and getattr(part, "thought_signature", None) is not None
                    ):
                        pending_signatures.append(part.thought_signature)

        return response

    google_llm_module.chat_completion_request = patched
    _thinking_patched = True


def _build_pipeline(engine: ContractEngine, records: list[_CallRecord], pack_tools: set[str]):
    from google import genai

    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.llms import google_llm
    from agentdojo.agent_pipeline.llms.google_llm import GoogleLLM
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop

    _disable_gemini_thinking(google_llm)

    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    # Default verified live on a free-tier key (2026-07-10). Avoid
    # gemini-3.5-flash (20 req/DAY free tier — one task needs more) and
    # gemini-2.5-flash / 2.0-flash (404 "no longer available to new users" on
    # new keys). Lite tiers have the largest free per-minute quotas. Override
    # with BOUNCER_GEMINI_MODEL; on a 404 the driver prints the models your
    # key can actually call.
    model = os.environ.get("BOUNCER_GEMINI_MODEL", "gemini-3.1-flash-lite")
    llm = GoogleLLM(model, client=client)
    system_message = SystemMessage(load_system_message(None))
    init_query = InitQuery()
    tools_loop = ToolsExecutionLoop([_make_recording_tools_executor(engine, records, pack_tools), llm])
    pipeline = AgentPipeline([system_message, init_query, llm, tools_loop])
    # AgentDojo's attack loader (get_model_name_from_pipeline) resolves the model
    # by finding a known model-id KEY as a substring of pipeline.name, then uses
    # its prose label ("AI model developed by Google") to address the model in
    # the injection. Our real model (gemini-3.5-flash) isn't in AgentDojo's map,
    # so we label the pipeline with a known Google key that maps to the same
    # prose name — the attack is addressed identically.
    pipeline.name = "gemini-2.0-flash-001"
    return pipeline


def _run_suite(user_tasks: list[str], logdir: Path) -> dict[str, list[_CallRecord]]:
    """Runs the benign and injected suites once, returning per-suite call
    records collected by the recording tool executor."""
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import (
        benchmark_suite_with_injections,
        benchmark_suite_without_injections,
    )
    from agentdojo.logging import OutputLogger
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite("v1", "workspace")
    pack_tools = _pack_covered_tools()

    benign_records: list[_CallRecord] = []
    attack_records: list[_CallRecord] = []

    for delay in (*_RETRY_BACKOFF, None):
        try:
            benign_engine = _build_engine()
            benign_pipeline = _build_pipeline(benign_engine, benign_records, pack_tools)
            with OutputLogger(str(logdir)):
                benchmark_suite_without_injections(
                    benign_pipeline, suite, logdir=logdir, force_rerun=True, user_tasks=user_tasks
                )
            break
        except Exception as exc:  # noqa: BLE001 — classified below
            if _is_rate_limit(exc) and delay is not None:
                time.sleep(delay)
                continue
            raise

    time.sleep(_PACE_SECONDS)

    for delay in (*_RETRY_BACKOFF, None):
        try:
            attack_engine = _build_engine()
            attack_pipeline = _build_pipeline(attack_engine, attack_records, pack_tools)
            with OutputLogger(str(logdir)):
                attack = load_attack(_ATTACK, suite, attack_pipeline)
                benchmark_suite_with_injections(
                    attack_pipeline, suite, attack, logdir=logdir, force_rerun=True, user_tasks=user_tasks
                )
            break
        except Exception as exc:  # noqa: BLE001
            if _is_rate_limit(exc) and delay is not None:
                time.sleep(delay)
                continue
            raise

    return {"benign": benign_records, "attack": attack_records}


def _split_verdicts(records: list[_CallRecord]) -> dict[str, list[str]]:
    return {
        "all": [r.verdict for r in records],
        "sink": [r.verdict for r in records if r.sink],
        "pack": [r.verdict for r in records if r.pack_covered],
        "heuristic": [r.verdict for r in records if not r.pack_covered],
    }


def _verdict_counts(records: list[_CallRecord]) -> dict[str, int]:
    counts = {"allow": 0, "ask": 0, "deny": 0}
    for r in records:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    return counts


def _summarize(records_by_suite: dict[str, list[_CallRecord]]) -> dict[str, object]:
    attack_split = _split_verdicts(records_by_suite["attack"])
    benign_split = _split_verdicts(records_by_suite["benign"])
    return {
        # "sink" (exfiltrating-tool calls) is the metric that matters: on the
        # attack suite it is where the injected destination shows up; diluting
        # it with read-only calls makes both good and bad numbers look small.
        "attack_block_rate": {k: block_rate(v) for k, v in attack_split.items()},
        "benign_false_positive_rate": {k: block_rate(v) for k, v in benign_split.items()},
        "attack_call_counts": {k: len(v) for k, v in attack_split.items()},
        "benign_call_counts": {k: len(v) for k, v in benign_split.items()},
        # ask vs deny matters for UX honesty: an ASK is a one-tap, remembered
        # approval; a DENY is a hard block.
        "attack_verdict_counts": _verdict_counts(records_by_suite["attack"]),
        "benign_verdict_counts": _verdict_counts(records_by_suite["benign"]),
    }


def _render_markdown(summary: dict[str, object]) -> str:
    def _row(label: str, rates: dict[str, float], counts: dict[str, int]) -> str:
        cells = " | ".join(
            f"{rates[k]:.2f} (n={counts[k]})" if counts[k] else "n/a (n=0)"
            for k in ("sink", "all", "pack", "heuristic")
        )
        return f"| {label} | {cells} |"

    return "\n".join(
        [
            "| metric | sink calls | all calls | pack-covered | heuristic-covered |",
            "|---|---|---|---|---|",
            _row("attack-block-rate", summary["attack_block_rate"], summary["attack_call_counts"]),
            _row(
                "benign false-positive rate",
                summary["benign_false_positive_rate"],
                summary["benign_call_counts"],
            ),
            "",
            f"attack verdicts: {summary['attack_verdict_counts']}",
            f"benign verdicts: {summary['benign_verdict_counts']}",
        ]
    )


def _run_deterministic_wiring() -> None:
    import subprocess
    import sys

    print("GEMINI_API_KEY not set — running the scorer unit test only.\n")
    subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests/test_benchmark_scorer.py"],
        check=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Bouncer engine against AgentDojo workspace")
    parser.add_argument(
        "--user-tasks",
        default=os.environ.get("BOUNCER_USER_TASKS", ",".join(_DEFAULT_USER_TASKS)),
        help="comma-separated user task ids",
    )
    args = parser.parse_args()

    if not os.environ.get("GEMINI_API_KEY"):
        _run_deterministic_wiring()
        return 0

    try:
        import agentdojo  # noqa: F401
    except ImportError:
        raise SystemExit(
            "agentdojo is not installed — run with the benchmark extra:\n"
            "  uv run --extra benchmark python -m benchmark.run_agentdojo --user-tasks user_task_8"
        ) from None

    user_tasks = [t.strip() for t in args.user_tasks.split(",") if t.strip()]
    logdir = Path(__file__).with_name("logs")
    logdir.mkdir(parents=True, exist_ok=True)

    print(f"Running AgentDojo workspace suite on {user_tasks} ...")
    records_by_suite = _run_suite(user_tasks, logdir)
    summary = _summarize(records_by_suite)

    _RESULTS_PATH.write_text(json.dumps({"user_tasks": user_tasks, "summary": summary}, indent=2))
    print(f"\nWrote {_RESULTS_PATH}\n")
    print(_render_markdown(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
