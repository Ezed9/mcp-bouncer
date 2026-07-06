# bouncer/tests/test_policy.py
from pathlib import Path

import pytest

from bouncer.policy import PolicyError, PolicyResolver, _policy_from_dict, load_policies


def _schema(*props: str) -> dict[str, object]:
    return {"type": "object", "properties": {p: {"type": "string"} for p in props}}


def test_load_policies_reads_yaml(tmp_path: Path) -> None:
    f = tmp_path / "pack.yaml"
    f.write_text(
        "send_email:\n"
        "  exfiltrating: true\n"
        "  sink_params: [to, cc]\n"
        "  trusted_destinations: [alice@corp.com]\n"
    )
    policies = load_policies([f])
    p = policies["send_email"]
    assert p.exfiltrating is True
    assert p.sink_params == ("to", "cc")
    assert p.trusted_destinations == ("alice@corp.com",)


def test_override_wins_over_heuristic() -> None:
    override = load_policies([])  # empty
    override["send_email"] = __import__(
        "bouncer.types", fromlist=["ToolPolicy"]
    ).ToolPolicy(name="send_email", exfiltrating=True, sink_params=("to",))
    r = PolicyResolver(overrides=override)
    p = r.policy_for("send_email", _schema("to", "recipient"))
    assert p.sink_params == ("to",)  # from override, not heuristic's (to, recipient)


def test_unknown_tool_falls_back_to_heuristic() -> None:
    r = PolicyResolver(overrides={})
    p = r.policy_for("share_file", _schema("email"))
    assert p.exfiltrating is True
    assert "email" in p.sink_params


def test_heuristics_disabled_returns_bare_policy() -> None:
    r = PolicyResolver(overrides={}, use_heuristics=False)
    p = r.policy_for("send_email", _schema("to"))
    assert p.exfiltrating is False


def test_malformed_top_level_yaml_raises_policy_error(tmp_path: Path) -> None:
    f = tmp_path / "bad.yaml"
    f.write_text("- a\n- b\n")
    with pytest.raises(PolicyError) as exc_info:
        load_policies([f])
    assert str(f) in str(exc_info.value)


def test_bool_max_calls_is_rejected() -> None:
    p = _policy_from_dict("send_email", {"max_calls": True})
    assert p.max_calls is None
