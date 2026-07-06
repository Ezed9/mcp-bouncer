# bouncer/tests/test_engine_constraints.py
from pathlib import Path

from bouncer.approvals import ApprovalStore
from bouncer.audit import AuditLog
from bouncer.engine import ContractEngine
from bouncer.policy import PolicyResolver
from bouncer.taint import TaintTracker
from bouncer.types import ToolCall, ToolPolicy, Verdict


def _engine(tmp_path: Path, overrides: dict[str, ToolPolicy],
            schemas: dict[str, dict]) -> ContractEngine:
    return ContractEngine(
        resolver=PolicyResolver(overrides=overrides),
        taint=TaintTracker(),
        approvals=ApprovalStore(),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        schemas=schemas,
    )


def test_unknown_tool_asks(tmp_path: Path) -> None:
    eng = _engine(tmp_path, {}, schemas={})  # nothing pinned
    d = eng.evaluate(ToolCall(tool="mystery", args={}))
    assert d.verdict == Verdict.ASK
    assert d.contract == "pinning"


def test_write_outside_prefix_is_denied(tmp_path: Path) -> None:
    pol = ToolPolicy(name="write_file", write_params=("path",),
                     allowed_path_prefixes=("./out",))
    eng = _engine(tmp_path, {"write_file": pol}, schemas={"write_file": {}})
    d = eng.evaluate(ToolCall(tool="write_file", args={"path": "/etc/passwd"}))
    assert d.verdict == Verdict.DENY
    assert d.contract == "constraint"


def test_write_inside_prefix_allowed(tmp_path: Path) -> None:
    pol = ToolPolicy(name="write_file", write_params=("path",),
                     allowed_path_prefixes=("./out",))
    eng = _engine(tmp_path, {"write_file": pol}, schemas={"write_file": {}})
    d = eng.evaluate(ToolCall(tool="write_file", args={"path": "./out/report.md"}))
    assert d.verdict == Verdict.ALLOW


def test_path_traversal_is_denied(tmp_path: Path) -> None:
    pol = ToolPolicy(name="write_file", write_params=("path",),
                     allowed_path_prefixes=("./out",))
    eng = _engine(tmp_path, {"write_file": pol}, schemas={"write_file": {}})
    traversal = eng.evaluate(
        ToolCall(tool="write_file", args={"path": "./out/../../etc/passwd"})
    )
    assert traversal.verdict == Verdict.DENY
    assert traversal.contract == "constraint"
    inside = eng.evaluate(ToolCall(tool="write_file", args={"path": "./out/notes.txt"}))
    assert inside.verdict == Verdict.ALLOW
    collision = eng.evaluate(ToolCall(tool="write_file", args={"path": "./outside/x"}))
    assert collision.verdict == Verdict.DENY
    assert collision.contract == "constraint"


def test_budget_denies_after_limit(tmp_path: Path) -> None:
    pol = ToolPolicy(name="delete_file", max_calls=2)
    eng = _engine(tmp_path, {"delete_file": pol}, schemas={"delete_file": {}})
    assert eng.evaluate(ToolCall("delete_file", {"path": "a"})).verdict == Verdict.ALLOW
    assert eng.evaluate(ToolCall("delete_file", {"path": "b"})).verdict == Verdict.ALLOW
    third = eng.evaluate(ToolCall("delete_file", {"path": "c"}))
    assert third.verdict == Verdict.DENY
    assert third.contract == "budget"


def test_arg_pattern_mismatch_denied(tmp_path: Path) -> None:
    pol = ToolPolicy(name="set_mode", arg_patterns=(("mode", r"read|write"),))
    eng = _engine(tmp_path, {"set_mode": pol}, schemas={"set_mode": {}})
    assert eng.evaluate(ToolCall("set_mode", {"mode": "delete"})).verdict == Verdict.DENY
    assert eng.evaluate(ToolCall("set_mode", {"mode": "read"})).verdict == Verdict.ALLOW


def test_every_call_is_audited(tmp_path: Path) -> None:
    eng = _engine(tmp_path, {}, schemas={"read_file": {}})
    eng.evaluate(ToolCall("read_file", {"path": "a"}))
    assert (tmp_path / "audit.jsonl").read_text().strip() != ""
