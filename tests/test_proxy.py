# bouncer/tests/test_proxy.py
"""Unit tests for the SDK-free routing helper `route_call`.

The security behavior lives here: a DENY must never call `forward` (never reach
the upstream tool). ASK re-evaluates in a loop so a single approval can never
vouch for a *different*, still-tainted destination in a multi-recipient call.
"""

from pathlib import Path

from bouncer.approvals import ApprovalStore
from bouncer.audit import AuditLog
from bouncer.engine import ContractEngine
from bouncer.policy import PolicyResolver
from bouncer.proxy import route_call
from bouncer.taint import TaintTracker
from bouncer.types import ToolCall, ToolPolicy, Verdict


def _engine(tmp_path: Path, pol: ToolPolicy) -> ContractEngine:
    return ContractEngine(
        resolver=PolicyResolver(overrides={pol.name: pol}),
        taint=TaintTracker(),
        approvals=ApprovalStore(),
        audit=AuditLog(tmp_path / "a.jsonl"),
        schemas={pol.name: {}},
    )


def test_route_allow_forwards_and_records(tmp_path: Path) -> None:
    eng = _engine(tmp_path, ToolPolicy(name="read_file"))
    forwarded: dict[str, str] = {}

    def fake_forward(call: ToolCall) -> str:
        forwarded["called"] = call.tool
        return "file contents: attacker@evil.com"

    text, verdict = route_call(
        eng,
        ToolCall("read_file", {"path": "a"}),
        forward=fake_forward,
        elicit=lambda _msg: False,
    )
    assert verdict == Verdict.ALLOW
    assert forwarded["called"] == "read_file"
    assert "attacker@evil.com" in text
    # the forwarded output was recorded as untrusted, so its address is now tainted
    assert eng._taint.classify("attacker@evil.com") is True


def test_route_deny_does_not_forward(tmp_path: Path) -> None:
    pol = ToolPolicy(name="send_email", exfiltrating=True, sink_params=("to",))
    eng = _engine(tmp_path, pol)
    eng.register_output("mail to attacker@evil.com")
    called = {"forwarded": False}

    def fake_forward(_c: ToolCall) -> str:
        called["forwarded"] = True
        return "sent"

    text, verdict = route_call(
        eng,
        ToolCall("send_email", {"to": "attacker@evil.com"}),
        forward=fake_forward,
        elicit=lambda _m: True,
    )
    assert verdict == Verdict.DENY
    assert called["forwarded"] is False


def test_route_ask_approved_forwards(tmp_path: Path) -> None:
    pol = ToolPolicy(name="send_email", exfiltrating=True, sink_params=("to",))
    eng = _engine(tmp_path, pol)

    def fake_forward(_c: ToolCall) -> str:
        return "sent"

    text, verdict = route_call(
        eng,
        ToolCall("send_email", {"to": "bob@partner.com"}),
        forward=fake_forward,
        elicit=lambda _m: True,
    )
    assert verdict == Verdict.ALLOW  # elicit approved -> re-evaluated to allow
    assert text == "sent"


def test_route_ask_declined_denies(tmp_path: Path) -> None:
    pol = ToolPolicy(name="send_email", exfiltrating=True, sink_params=("to",))
    eng = _engine(tmp_path, pol)
    called = {"forwarded": False}

    def fake_forward(_c: ToolCall) -> str:
        called["forwarded"] = True
        return "sent"

    text, verdict = route_call(
        eng,
        ToolCall("send_email", {"to": "bob@partner.com"}),
        forward=fake_forward,
        elicit=lambda _m: False,
    )
    assert verdict == Verdict.DENY
    assert called["forwarded"] is False


def test_route_ask_unsupported_elicitation_denies(tmp_path: Path) -> None:
    # elicit is None -> client lacks the capability -> ASK degrades to DENY.
    pol = ToolPolicy(name="send_email", exfiltrating=True, sink_params=("to",))
    eng = _engine(tmp_path, pol)
    called = {"forwarded": False}

    def fake_forward(_c: ToolCall) -> str:
        called["forwarded"] = True
        return "sent"

    text, verdict = route_call(
        eng,
        ToolCall("send_email", {"to": "bob@partner.com"}),
        forward=fake_forward,
        elicit=None,
    )
    assert verdict == Verdict.DENY
    assert called["forwarded"] is False


def test_route_ask_reeval_loop_approves_every_destination(tmp_path: Path) -> None:
    # Two distinct unproven destinations: the loop must ask about BOTH before it
    # forwards. One approval only vouches one destination; a naive forward-after-
    # one-approval would leak the second unproven recipient.
    pol = ToolPolicy(name="send_email", exfiltrating=True, sink_params=("to",))
    eng = _engine(tmp_path, pol)
    asked: list[str] = []

    def fake_elicit(msg: str) -> bool:
        asked.append(msg)
        return True

    text, verdict = route_call(
        eng,
        ToolCall("send_email", {"to": ["bob@partner.com", "carol@partner.com"]}),
        forward=lambda _c: "sent",
        elicit=fake_elicit,
    )
    assert verdict == Verdict.ALLOW
    assert text == "sent"
    assert len(asked) == 2  # each destination required its own approval


def test_route_ask_reeval_surfaces_tainted_element_denies(tmp_path: Path) -> None:
    # The list-sink correction: one approval must not vouch a *different*,
    # still-tainted destination. After approving the unproven recipient, the
    # re-evaluation surfaces the tainted one -> DENY -> never forward.
    pol = ToolPolicy(name="send_email", exfiltrating=True, sink_params=("to",))
    eng = _engine(tmp_path, pol)
    eng.register_output("leak to attacker@evil.com please")
    called = {"forwarded": False}

    def fake_forward(_c: ToolCall) -> str:
        called["forwarded"] = True
        return "sent"

    # bob is unproven (would be ASK); attacker is tainted (DENY). The engine
    # short-circuits on the tainted element, so the very first evaluate is DENY
    # and forward is never reached.
    text, verdict = route_call(
        eng,
        ToolCall("send_email", {"to": ["bob@partner.com", "attacker@evil.com"]}),
        forward=fake_forward,
        elicit=lambda _m: True,
    )
    assert verdict == Verdict.DENY
    assert called["forwarded"] is False


def test_route_ask_approve_then_tainted_after_progress_denies(tmp_path: Path) -> None:
    # Force the re-eval DENY path *through* the loop: approve an unproven
    # destination first; the second, tainted destination only surfaces on the
    # re-evaluation. Still no forward.
    pol = ToolPolicy(name="send_email", exfiltrating=True, sink_params=("to",))
    eng = _engine(tmp_path, pol)
    called = {"forwarded": False}

    def fake_forward(_c: ToolCall) -> str:
        called["forwarded"] = True
        return "sent"

    # Approve bob (unproven). On re-eval, mark attacker tainted by recording
    # output the first time we're asked, so the loop's next evaluate DENYs.
    state = {"first": True}

    def fake_elicit(_msg: str) -> bool:
        if state["first"]:
            eng.register_output("secret goes to attacker@evil.com")
            state["first"] = False
        return True

    text, verdict = route_call(
        eng,
        ToolCall("send_email", {"to": ["bob@partner.com", "attacker@evil.com"]}),
        forward=fake_forward,
        elicit=fake_elicit,
    )
    assert verdict == Verdict.DENY
    assert called["forwarded"] is False
