# bouncer/tests/test_types.py
from bouncer.types import (
    AuditEntry,
    Decision,
    ToolCall,
    ToolPolicy,
    TrustLevel,
    Verdict,
)


def test_verdict_values() -> None:
    assert Verdict.ALLOW == "allow"
    assert Verdict.DENY == "deny"
    assert Verdict.ASK == "ask"


def test_trustlevel_values() -> None:
    assert {t.value for t in TrustLevel} == {"trusted", "tainted", "unproven"}


def test_toolpolicy_defaults_non_exfiltrating() -> None:
    p = ToolPolicy(name="read_file")
    assert p.exfiltrating is False
    assert p.sink_params == ()
    assert p.max_calls is None


def test_decision_and_toolcall_and_audit_construct() -> None:
    call = ToolCall(tool="send_email", args={"to": "x@y.com"})
    d = Decision(verdict=Verdict.DENY, reason="tainted", contract="sink_gate", ask_key=None)
    e = AuditEntry(tool=call.tool, args=call.args, verdict=d.verdict.value,
                   reason=d.reason, contract=d.contract)
    assert e.verdict == "deny"
    assert call.args["to"] == "x@y.com"
