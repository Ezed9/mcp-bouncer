import json
from datetime import date
from pathlib import Path

from bouncer.policy import builtin_pack_paths, load_policies
from bouncer.report import build_report, load_tools, summarize_audit
from bouncer.types import ToolPolicy

_TOOLS = [
    ("send_email", {"properties": {"to": {}, "body": {}}}),
    ("write_file", {"properties": {"path": {}, "content": {}}}),
    ("post_webhook", {"properties": {"url": {}, "payload": {}}}),
    ("list_things", {"properties": {"query": {}}}),
]


def _report(**overrides: object) -> str:
    kwargs: dict[str, object] = {
        "pack_policies": load_policies(builtin_pack_paths()),
        "user_policies": {},
        "user_policy_path": None,
        "tools": _TOOLS,
        "audit": None,
        "benchmark": None,
        "server_name": "acme",
        "version": "0.0.0",
        "generated_on": date(2026, 10, 21),
    }
    kwargs.update(overrides)
    return build_report(**kwargs)  # type: ignore[arg-type]


def _row(report: str, tool: str) -> str:
    return next(line for line in report.splitlines() if line.startswith(f"| `{tool}` |"))


def test_tool_source_follows_user_then_pack_then_heuristic() -> None:
    user = {"write_file": ToolPolicy(
        name="write_file", write_params=("path",), allowed_path_prefixes=("./out",))}
    report = _report(user_policies=user)
    assert "| user policy |" in _row(report, "write_file")
    assert "path confinement on `path` to `./out`" in _row(report, "write_file")
    assert "| builtin pack |" in _row(report, "send_email")
    assert "| heuristic |" in _row(report, "post_webhook")
    assert "sink gate on `url`" in _row(report, "post_webhook")
    assert "pass-through" in _row(report, "list_things")


def test_findings_flag_unconfined_writes_and_sends_without_allowlist() -> None:
    report = _report()
    findings = report.split("## 3.")[1].split("## 4.")[0]
    assert "Writes not confined to a path:** `write_file`" in findings
    assert "Sends with no allowlist:** `send_email`, `post_webhook`" in findings
    assert "Covered only by heuristics:** `post_webhook`" in findings
    assert "No contract beyond pinning and audit:** `list_things`" in findings


def test_without_tools_lists_user_policy_tools_only() -> None:
    user = {"send_email": ToolPolicy(
        name="send_email", exfiltrating=True, sink_params=("to",),
        trusted_destinations=("a@corp.com",))}
    report = _report(tools=None, user_policies=user)
    assert "allowlist: `a@corp.com`" in _row(report, "send_email")
    assert "| `write_file` |" not in report


def test_regex_pipe_is_escaped_in_table() -> None:
    user = {"post_webhook": ToolPolicy(name="post_webhook", arg_patterns=(("url", "a|b"),))}
    assert "`/a\\|b/`" in _row(_report(user_policies=user), "post_webhook")


def _write_audit(path: Path) -> None:
    lines = [
        {"ts": "2026-10-01T10:00:00+00:00", "tool": "send_email",
         "args": {"to": "secret-recipient@evil.com"}, "verdict": "deny",
         "reason": "", "contract": "sink_gate"},
        {"ts": "2026-10-05T10:00:00+00:00", "tool": "send_email", "args": {},
         "verdict": "ask", "reason": "", "contract": "sink_gate"},
        {"ts": "2026-10-05T10:00:01+00:00", "tool": "send_email", "args": {},
         "verdict": "allow", "reason": "", "contract": "default"},
        {"tool": "write_file", "args": {}, "verdict": "allow", "reason": "",
         "contract": "default"},
    ]
    path.write_text("\n".join(json.dumps(r) for r in lines) + "\nnot json\n")


def test_audit_summary_counts_undated_and_malformed(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_audit(path)
    s = summarize_audit(path)
    assert s.total == 4
    assert s.undated == 1
    assert s.malformed == 1
    assert s.by_verdict == {"deny": 1, "ask": 1, "allow": 2}
    assert s.by_tool["send_email"] == {"deny": 1, "ask": 1, "allow": 1}
    assert s.by_contract["sink_gate"] == 2
    assert s.first_ts == "2026-10-01T10:00:00+00:00"


def test_audit_date_window_drops_undated_and_out_of_range(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_audit(path)
    s = summarize_audit(path, since=date(2026, 10, 2), until=date(2026, 10, 5))
    assert s.total == 2
    assert s.undated == 0
    assert s.by_verdict == {"ask": 1, "allow": 1}


def test_missing_audit_log_is_reported(tmp_path: Path) -> None:
    report = _report(audit=summarize_audit(tmp_path / "nope.jsonl"))
    assert "No audit log found" in report


def test_report_never_prints_audit_args(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_audit(path)
    report = _report(audit=summarize_audit(path))
    assert "| deny | 1 |" in report
    assert "secret-recipient" not in report


def test_benchmark_section_uses_numbers_from_json() -> None:
    bench = {
        "user_tasks": ["u0", "u1"], "attack": "important_instructions",
        "agent_model": "m",
        "authoritative": {
            "attack_success_rate": {"baseline": 0.25, "bouncer": 0.0},
            "utility": {"under_attack_baseline": 0.5, "under_attack_bouncer": 0.75,
                        "benign_bouncer": 0.5},
            "n_injection_cases": 4,
        },
        "engine_detail": {"attack_sink_verdicts": {"allow": 0, "ask": 0, "deny": 3}},
    }
    report = _report(benchmark=bench)
    assert "| Attack success rate (lower is better) | 0.25 (1/4) | 0.00 (0/4) |" in report
    assert "| Task completion, no attack | not run | 0.50 (1/2) |" in report
    assert "under attack 0 allow, 0 ask, 3 deny" in report
    assert "## 6. What Bouncer enforces" in report


def test_benchmark_section_absent_when_not_given() -> None:
    report = _report()
    assert "Benchmark evidence" not in report
    assert "## 5. What Bouncer enforces" in report


def test_load_tools_accepts_tools_list_result_and_bare_list(tmp_path: Path) -> None:
    tool = {"name": "send_email", "inputSchema": {"properties": {"to": {}}}}
    wrapped = tmp_path / "a.json"
    wrapped.write_text(json.dumps({"tools": [tool]}))
    bare = tmp_path / "b.json"
    bare.write_text(json.dumps([tool]))
    expected = [("send_email", {"properties": {"to": {}}})]
    assert load_tools(wrapped) == expected
    assert load_tools(bare) == expected
