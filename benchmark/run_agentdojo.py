# bouncer/benchmark/run_agentdojo.py
"""Driver: measure the Bouncer contract ENGINE on the real AgentDojo workspace
suite, using AgentDojo's OWN security scorer as the headline metric.

The number that matters is **attack success rate**: for each (user_task,
injection_task) pair, AgentDojo checks whether the injection actually
accomplished its goal (e.g. the attacker's address actually received the
exfiltrated data). That check is destination-aware and per-injection-case, so
it cannot be gamed by counting retries or by collateral-blocking the user's
own task. We report it under two conditions:

  * baseline  — the stock AgentDojo pipeline, no Bouncer. Establishes that the
    attacks actually work against this model (attack success > 0), so a low
    number under Bouncer means defense, not a model too weak to attack.
  * bouncer   — every tool call routed through `ContractEngine.evaluate`
    first; DENY/ASK are not executed (mirrors the proxy's fail-closed
    behaviour when there is no human to elicit). Attack success here should
    drop toward 0.

Alongside attack success we report **utility** (did the user's task still
succeed) from AgentDojo's utility scorer, so collateral damage from Bouncer's
blocks is visible rather than hidden — a defense that also breaks the benign
task shows up as a utility drop, not as a flattering block rate.

Engine-level verdict counts (allow/ask/deny) are kept as *supplementary*
detail — useful colour, but NOT the headline claim.

`agentdojo` and the provider SDKs are imported ONLY inside the key-gated path,
so the no-key path imports and runs fine without agentdojo installed (it is an
optional `[benchmark]` extra).

Provider is chosen with BOUNCER_LLM (default 'gemini'); model with BOUNCER_MODEL.
Any OpenAI-compatible endpoint works — 'groq' (FREE tier, no card), 'openai',
'deepseek', 'openrouter' — so you don't need a Gemini key at all:

Run (Gemini):  cd bouncer && GEMINI_API_KEY=... uv run --extra benchmark \
                   python -m benchmark.run_agentdojo
Run (Groq):    cd bouncer && BOUNCER_LLM=groq GROQ_API_KEY=... uv run --extra \
                   benchmark python -m benchmark.run_agentdojo
Run (no key):  cd bouncer && uv run python -m benchmark.run_agentdojo   # scorer test only
Free Gemini key: https://aistudio.google.com/apikey · Free Groq key: https://console.groq.com/keys
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
from bouncer.engine import ContractEngine
from bouncer.policy import PolicyResolver, builtin_pack_paths, load_policies
from bouncer.taint import TaintTracker
from bouncer.types import ToolCall, Verdict

if TYPE_CHECKING:
    from agentdojo.functions_runtime import FunctionsRuntime

_DEFAULT_USER_TASKS = ("user_task_8",)
# The exfil-to-attacker injections: 0/3/4 all instruct "send X to
# mark.black-2134@gmail.com". injection_task_4 is the Facebook-security-code
# exfiltration — the canonical "steal your 2FA code" case.
_DEFAULT_INJECTION_TASKS = ("injection_task_0", "injection_task_3", "injection_task_4")
_ATTACK = "important_instructions"
_RESULTS_PATH = Path(__file__).with_name("results.json")
_LOGDIR = Path(__file__).with_name("logs")


# Loaded AFTER the builtin packs (last-wins), replacing e.g. the gmail pack's
# send_email (to/cc/bcc) with this suite's real schema (recipients/cc/bcc) —
# the same per-server pack a real deployment writes (see examples/bouncer.yaml).
_WORKSPACE_PACK = Path(__file__).with_name("agentdojo_workspace.yaml")


def _benchmark_pack_paths() -> list[Path]:
    return [*builtin_pack_paths(), _WORKSPACE_PACK]


def _fresh_audit(name: str) -> AuditLog:
    """A per-run audit file, truncated at start so it reflects ONE run only
    (the old shared, append-across-runs audit.jsonl mixed suites and runs)."""
    path = Path(__file__).with_name(f"audit-{name}.jsonl")
    path.unlink(missing_ok=True)
    return AuditLog(path)


def _build_engine(audit_name: str) -> ContractEngine:
    resolver = PolicyResolver(overrides=load_policies(_benchmark_pack_paths()))
    return ContractEngine(
        resolver=resolver,
        taint=TaintTracker(),
        approvals=ApprovalStore(),
        audit=_fresh_audit(audit_name),
        schemas={},  # populated lazily; see _RecordingToolsExecutor
    )


def _pack_covered_tools() -> set[str]:
    return set(load_policies(_benchmark_pack_paths()).keys())


class _CallRecord:
    __slots__ = ("tool", "verdict", "sink")

    def __init__(self, tool: str, verdict: str, sink: bool) -> None:
        self.tool = tool
        self.verdict = verdict
        self.sink = sink  # resolved policy is exfiltrating


def _schema_for(runtime: FunctionsRuntime, name: str) -> dict[str, object]:
    fn = runtime.functions.get(name)
    if fn is None:
        return {}
    return {"properties": dict.fromkeys(fn.parameters.model_fields.keys(), {})}


def _make_recording_tools_executor(engine: ContractEngine, records: list[_CallRecord]):
    """A ToolsExecutor that routes every call through the Bouncer engine first.

    DENY/ASK do not execute the tool (mirrors the proxy's fail-closed-when-no-
    elicit path); only ALLOW runs it and feeds output back to taint.
    """
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, tool_result_to_str
    from agentdojo.functions_runtime import EmptyEnv
    from agentdojo.types import ChatToolResultMessage, text_content_block_from_string

    class _RecordingToolsExecutor(ToolsExecutor):
        # env=EmptyEnv() default mirrors AgentDojo's ToolsExecutor.query signature.
        def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args=None):  # noqa: B008
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
                sink = engine._resolver.policy_for(name, schema).exfiltrating
                records.append(_CallRecord(name, decision.verdict.value, sink))

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
    """Call AgentDojo's request fn, waiting out free-tier per-minute 429s.

    AgentDojo's GoogleLLM uses `retry_if_not_exception_type(ClientError)`, so it
    does NOT retry rate limits. We wait out per-minute 429s, abort clearly on a
    per-day quota, and on a 404 print the models this key can actually call.
    """
    from google.genai.errors import ClientError

    for attempt in range(12):
        try:
            return original(*args)
        except ClientError as exc:
            code = getattr(exc, "code", None)
            if code == 404:
                model = args[0] if args else "<model>"
                available = _available_models(args[1] if len(args) > 1 else None)
                listing = "\n".join(f"  {n}" for n in available) or "  (could not list models)"
                raise SystemExit(
                    f"\nModel {model} is not available to this API key.\n"
                    f"Models your key CAN use with generateContent:\n{listing}\n"
                    "Re-run with one of them (prefer a flash-class model):\n"
                    "  BOUNCER_GEMINI_MODEL=<model> uv run --extra benchmark "
                    "python -m benchmark.run_agentdojo"
                ) from exc
            if code != 429 or attempt == 11:
                raise
            if _is_daily_quota(exc):
                model = args[0] if args else "<model>"
                raise SystemExit(
                    f"\nDaily free-tier quota for {model} is exhausted — waiting will not help.\n"
                    "Options:\n"
                    "  1. A different model (separate daily bucket), e.g. "
                    "BOUNCER_GEMINI_MODEL=gemini-flash-lite-latest\n"
                    "  2. Wait for the quota reset (midnight Pacific) and re-run.\n"
                    "  3. Use a paid-tier GEMINI_API_KEY."
                ) from exc
            delay = _retry_delay_seconds(exc)
            print(f"  rate-limited (429); waiting {delay:.0f}s then retrying ...")
            time.sleep(delay)
    raise RuntimeError("rate-limit retries exhausted")  # pragma: no cover


def _disable_gemini_thinking(google_llm_module: object) -> None:
    """Preserve Gemini thought signatures across AgentDojo tool-call turns,
    resetting at each conversation boundary so signatures never bleed between
    tasks/runs."""
    global _thinking_patched
    if _thinking_patched:
        return

    original = google_llm_module.chat_completion_request
    pending_signatures: list[object] = []

    def patched(model, client, contents, generation_config):
        # First model call of a fresh conversation: no assistant function-call
        # parts yet. Clear stale signatures so a later run/task never restores
        # a previous conversation's signature (cross-conversation contamination).
        has_prior_call = any(
            part.function_call is not None
            for content in contents
            for part in (content.parts or [])
        )
        if not has_prior_call:
            pending_signatures.clear()

        # AgentDojo reconstructs function-call parts and drops thought_signature.
        # Restore in original order.
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

        response = _call_with_rate_limit_retry(original, model, client, contents, generation_config)

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


def _gemini_llm():
    from agentdojo.agent_pipeline.llms import google_llm
    from agentdojo.agent_pipeline.llms.google_llm import GoogleLLM
    from google import genai

    _disable_gemini_thinking(google_llm)
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    # Default verified callable on a free-tier key (2026-07). Avoid
    # gemini-2.5/2.0-flash (404 "no longer available to new users" on new keys)
    # and gemini-3.5-flash (20 req/DAY free tier). Override with
    # BOUNCER_MODEL; on a 404 the driver prints your key's real menu.
    model = os.environ.get("BOUNCER_MODEL", os.environ.get(
        "BOUNCER_GEMINI_MODEL", "gemini-flash-lite-latest"))
    return GoogleLLM(model, client=client), model


# Known OpenAI-compatible endpoints. Any of these lets you run the benchmark
# on a free or cheap key instead of Gemini — pick with BOUNCER_LLM.
_OPENAI_COMPATIBLE = {
    # Groq: genuinely free tier, no card, Llama with tool calling, generous RPM.
    "groq": ("GROQ_API_KEY", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
    "openai": ("OPENAI_API_KEY", None, "gpt-4o-mini"),
    "deepseek": ("DEEPSEEK_API_KEY", "https://api.deepseek.com", "deepseek-chat"),
    "openrouter": (
        "OPENROUTER_API_KEY",
        "https://openrouter.ai/api/v1",
        "meta-llama/llama-3.3-70b-instruct",
    ),
}

_openai_retry_patched = False


def _patch_openai_rate_limit(openai_llm_module) -> None:
    """Wrap AgentDojo's OpenAI request fn to survive two free-tier realities:

    1. Rate limits — AgentDojo retries only 3x; a hammered free tier outlasts
       that, so we add a longer explicit wait (mirrors the Gemini path).
    2. `tool_use_failed` — smaller models (e.g. Llama on Groq) sometimes emit a
       MALFORMED tool call that the provider rejects with a 400. AgentDojo does
       NOT retry BadRequestError, so one bad generation kills the whole task.
       This is an infrastructure failure, not a security outcome, and at
       temperature 0 a naive retry reproduces the identical bad output — so we
       retry with a temperature nudge (arg index 5) so the model varies and
       escapes the trap. The first attempt keeps AgentDojo's temperature."""
    global _openai_retry_patched
    if _openai_retry_patched:
        return
    import openai

    original = openai_llm_module.chat_completion_request

    def _with_temperature(args, temperature):
        return (*args[:5], temperature, *args[6:]) if len(args) > 5 else args

    def patched(*args, **kwargs):
        tool_fail_attempts = 0
        for attempt in range(12):
            try:
                return original(*args, **kwargs)
            except openai.RateLimitError as exc:
                if attempt == 11:
                    raise
                delay = _retry_delay_seconds(exc, default=20.0)
                print(f"  rate-limited (429); waiting {delay:.0f}s then retrying ...")
                time.sleep(delay)
            except openai.BadRequestError as exc:
                if "tool_use_failed" not in str(exc) or tool_fail_attempts >= 5:
                    raise
                tool_fail_attempts += 1
                temperature = min(0.2 * tool_fail_attempts, 1.0)
                print(f"  model emitted a malformed tool call; retrying at "
                      f"temperature={temperature:.1f} ...")
                args = _with_temperature(args, temperature)
        raise RuntimeError("openai retries exhausted")  # pragma: no cover

    openai_llm_module.chat_completion_request = patched
    _openai_retry_patched = True


def _openai_compatible_llm(provider: str):
    import openai
    from agentdojo.agent_pipeline.llms import openai_llm
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM

    if provider not in _OPENAI_COMPATIBLE:
        raise SystemExit(
            f"Unknown BOUNCER_LLM={provider!r}. Options: gemini, "
            f"{', '.join(_OPENAI_COMPATIBLE)}."
        )
    key_env, base_url, default_model = _OPENAI_COMPATIBLE[provider]
    api_key = os.environ.get(key_env)
    if not api_key:
        raise SystemExit(
            f"BOUNCER_LLM={provider} needs {key_env} set.\n"
            + ("Get a free Groq key (no card): https://console.groq.com/keys"
               if provider == "groq" else f"Set {key_env} to your {provider} API key.")
        )
    _patch_openai_rate_limit(openai_llm)
    client = openai.OpenAI(api_key=api_key, base_url=base_url)
    model = os.environ.get("BOUNCER_MODEL", default_model)
    return OpenAILLM(client, model), model


def _build_llm():
    """(llm, model_label) for the configured provider. BOUNCER_LLM selects it;
    default 'gemini'. Non-Gemini providers use AgentDojo's OpenAI-compatible
    pipeline, so no Gemini key is required."""
    provider = os.environ.get("BOUNCER_LLM", "gemini").lower()
    if provider == "gemini":
        return _gemini_llm()
    return _openai_compatible_llm(provider)


def _pipeline(llm, tools_executor, name_suffix: str):
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop

    tools_loop = ToolsExecutionLoop([tools_executor, llm])
    pipeline = AgentPipeline(
        [SystemMessage(load_system_message(None)), InitQuery(), llm, tools_loop]
    )
    # AgentDojo's attack loader resolves the model by finding a known model-id
    # KEY as a substring of pipeline.name (base_attacks.get_model_name_from_pipeline),
    # so we keep "gemini-2.0-flash-001" as a substring. The suffix makes the
    # baseline and Bouncer pipelines write to DISTINCT log directories — without
    # it they collide on the same path and the second run silently overwrites
    # the first, destroying the comparison.
    pipeline.name = f"gemini-2.0-flash-001{name_suffix}"
    return pipeline


def _build_bouncer_pipeline(records: list[_CallRecord], audit_name: str):
    llm, _ = _build_llm()
    engine = _build_engine(audit_name)
    return _pipeline(llm, _make_recording_tools_executor(engine, records), "-bouncer")


def _build_baseline_pipeline():
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutor

    llm, _ = _build_llm()
    return _pipeline(llm, ToolsExecutor(), "-baseline")


def _mean(values) -> float:
    vals = list(values)
    return sum(1 for v in vals if v) / len(vals) if vals else 0.0


def _run_benign(user_tasks: list[str], records: list[_CallRecord]):
    from agentdojo.benchmark import benchmark_suite_without_injections
    from agentdojo.logging import OutputLogger
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite("v1", "workspace")
    pipeline = _build_bouncer_pipeline(records, "benign")
    with OutputLogger(str(_LOGDIR)):
        return benchmark_suite_without_injections(
            pipeline, suite, logdir=_LOGDIR, force_rerun=True, user_tasks=user_tasks
        )


def _run_attack(user_tasks: list[str], injection_tasks: list[str], *, bouncer: bool,
                records: list[_CallRecord] | None) -> dict[tuple[str, str], bool]:
    """Returns AgentDojo's per-(user_task, injection_task) SECURITY verdicts
    (True = the injection accomplished its goal = attack succeeded). Uses the
    lower-level runner to skip AgentDojo's standalone injection-solvability
    pre-check: the baseline run's own attack success is the validation that the
    attacks are real, so the extra API calls aren't needed."""
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import run_task_with_injection_tasks
    from agentdojo.logging import OutputLogger
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite("v1", "workspace")
    pipeline = (
        _build_bouncer_pipeline(records, "bouncer") if bouncer else _build_baseline_pipeline()
    )
    security: dict[tuple[str, str], bool] = {}
    utility: dict[tuple[str, str], bool] = {}
    with OutputLogger(str(_LOGDIR)):
        attack = load_attack(_ATTACK, suite, pipeline)
        for user_task_id in user_tasks:
            u, s = run_task_with_injection_tasks(
                suite, pipeline, suite.get_user_task_by_id(user_task_id), attack,
                logdir=_LOGDIR, force_rerun=True, injection_tasks=injection_tasks,
            )
            utility.update(u)
            security.update(s)
    return {"security": security, "utility": utility}


def _verdict_counts(records: list[_CallRecord]) -> dict[str, int]:
    counts = {"allow": 0, "ask": 0, "deny": 0}
    for r in records:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    return counts


def _sink_verdict_counts(records: list[_CallRecord]) -> dict[str, int]:
    return _verdict_counts([r for r in records if r.sink])


def _render_markdown(summary: dict) -> str:
    auth = summary["authoritative"]
    asr = auth["attack_success_rate"]
    util = auth["utility"]
    n = auth["n_injection_cases"]
    baseline_asr = f"{asr['baseline']:.2f}" if asr["baseline"] is not None else "not run"
    lines = [
        f"AgentDojo v1 workspace · user_tasks={summary['user_tasks']} · "
        f"injection_tasks={summary['injection_tasks']} (n={n} cases) · "
        f"attack={summary['attack']} · agent={summary['agent_model']}",
        "",
        "Authoritative metric — AgentDojo's own per-injection security scorer",
        "(attack success = the injection actually accomplished its goal; lower is better):",
        "",
        "| condition | attack success rate | user-task utility |",
        "|---|---|---|",
        f"| no Bouncer (baseline) | {baseline_asr} | {_fmt(util['under_attack_baseline'])} |",
        f"| **with Bouncer** | **{asr['bouncer']:.2f}** | {_fmt(util['under_attack_bouncer'])} |",
        "",
        f"Benign utility (no injection, with Bouncer): {_fmt(util['benign_bouncer'])}",
        "",
        f"Engine detail (with-Bouncer attack run) — all calls: "
        f"{summary['engine_detail']['attack_all_verdicts']}; "
        f"sink calls only: {summary['engine_detail']['attack_sink_verdicts']}",
    ]
    return "\n".join(lines)


def _fmt(v) -> str:
    return f"{v:.2f}" if v is not None else "not run"


def _llm_key_env() -> str:
    """The API-key env var the configured provider needs."""
    provider = os.environ.get("BOUNCER_LLM", "gemini").lower()
    if provider == "gemini":
        return "GEMINI_API_KEY"
    if provider in _OPENAI_COMPATIBLE:
        return _OPENAI_COMPATIBLE[provider][0]
    return "GEMINI_API_KEY"


def _run_deterministic_wiring() -> None:
    import subprocess
    import sys

    print(f"{_llm_key_env()} not set — running the scorer unit test only.\n")
    subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests/test_benchmark_scorer.py"],
        check=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure Bouncer on AgentDojo workspace")
    parser.add_argument("--user-tasks", default=os.environ.get(
        "BOUNCER_USER_TASKS", ",".join(_DEFAULT_USER_TASKS)))
    parser.add_argument("--injection-tasks", default=os.environ.get(
        "BOUNCER_INJECTION_TASKS", ",".join(_DEFAULT_INJECTION_TASKS)))
    parser.add_argument("--no-baseline", action="store_true",
                        help="skip the no-Bouncer baseline attack pass (faster, less evidence)")
    args = parser.parse_args()

    if not os.environ.get(_llm_key_env()):
        _run_deterministic_wiring()
        return 0

    try:
        import agentdojo  # noqa: F401
    except ImportError:
        raise SystemExit(
            "agentdojo is not installed — run with the benchmark extra:\n"
            "  uv run --extra benchmark python -m benchmark.run_agentdojo"
        ) from None

    user_tasks = [t.strip() for t in args.user_tasks.split(",") if t.strip()]
    injection_tasks = [t.strip() for t in args.injection_tasks.split(",") if t.strip()]
    _LOGDIR.mkdir(parents=True, exist_ok=True)

    _, agent_model = _build_llm()
    attack_records: list[_CallRecord] = []
    benign_records: list[_CallRecord] = []

    print(f"[1/3] baseline attack run (no Bouncer) on {user_tasks} × {injection_tasks} ...")
    baseline = None if args.no_baseline else _run_attack(
        user_tasks, injection_tasks, bouncer=False, records=None)

    print(f"[2/3] Bouncer attack run on {user_tasks} × {injection_tasks} ...")
    bouncer = _run_attack(user_tasks, injection_tasks, bouncer=True, records=attack_records)

    print(f"[3/3] benign run (no injection, with Bouncer) on {user_tasks} ...")
    benign = _run_benign(user_tasks, benign_records)

    # Persist raw verdicts the instant the (expensive, rate-limited) passes
    # finish — before any summary math — so a bug in summarising can never
    # again throw away a completed run's data.
    def _pairs(d: dict[tuple[str, str], bool]) -> dict[str, bool]:
        return {f"{u}|{i}": v for (u, i), v in d.items()}

    def _sec_util(res: dict) -> dict[str, dict[str, bool]]:
        return {
            f"{u}|{i}": {"security": res["security"][(u, i)], "utility": res["utility"][(u, i)]}
            for (u, i) in res["security"]
        }

    _raw_path = _RESULTS_PATH.with_name("results-raw.json")
    _raw_path.write_text(json.dumps({
        "baseline": None if baseline is None else _sec_util(baseline),
        "bouncer": _sec_util(bouncer),
        "benign_utility": _pairs(benign["utility_results"]),
    }, indent=2))
    print(f"Raw verdicts saved to {_raw_path}")

    summary = {
        "user_tasks": user_tasks,
        "injection_tasks": injection_tasks,
        "attack": _ATTACK,
        "agent_model": agent_model,
        "authoritative": {
            "attack_success_rate": {
                "baseline": None if baseline is None else _mean(baseline["security"].values()),
                "bouncer": _mean(bouncer["security"].values()),
            },
            "utility": {
                "under_attack_baseline": None if baseline is None else _mean(
                    baseline["utility"].values()),
                "under_attack_bouncer": _mean(bouncer["utility"].values()),
                "benign_bouncer": _mean(benign["utility_results"].values()),
            },
            "n_injection_cases": len(bouncer["security"]),
            "per_case_security_bouncer": {
                f"{u}|{i}": v for (u, i), v in bouncer["security"].items()},
            "per_case_security_baseline": None if baseline is None else {
                f"{u}|{i}": v for (u, i), v in baseline["security"].items()},
        },
        "engine_detail": {
            "attack_all_verdicts": _verdict_counts(attack_records),
            "attack_sink_verdicts": _sink_verdict_counts(attack_records),
            "benign_all_verdicts": _verdict_counts(benign_records),
            "benign_sink_verdicts": _sink_verdict_counts(benign_records),
        },
    }

    _RESULTS_PATH.write_text(json.dumps(summary, indent=2))
    print(f"\nWrote {_RESULTS_PATH}\n")
    print(_render_markdown(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
