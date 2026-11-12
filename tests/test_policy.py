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


def test_malformed_arg_pattern_raises_policy_error(tmp_path: Path) -> None:
    f = tmp_path / "bad_pattern.yaml"
    f.write_text(
        "set_mode:\n"
        "  arg_patterns:\n"
        "    mode: \"[\"\n"
    )
    with pytest.raises(PolicyError) as exc_info:
        load_policies([f])
    assert "set_mode" in str(exc_info.value)
    assert "[" in str(exc_info.value)


def test_bool_max_calls_is_rejected() -> None:
    with pytest.raises(PolicyError):
        _policy_from_dict("send_email", {"max_calls": True})


@pytest.mark.parametrize("raw", [
    {"write_params": ["path"], "allowed_path_prefixes": "/workspace"},  # not a list
    {"max_calls": "1"},
    {"max_calls": -1},
    {"exfiltrating": "yes please"},
    {"exfiltrating": True, "trusted_destination": ["a@b.com"]},  # misspelled key
    {"arg_patterns": ["mode"]},
    None,  # `tool:` with nothing under it
])
def test_mistyped_policy_is_an_error_not_ignored(raw: object) -> None:
    with pytest.raises(PolicyError):
        _policy_from_dict("some_tool", raw)


@pytest.mark.parametrize("raw", [
    {"trusted_destinations": ["me@corp.com"]},
    {"sink_params": ["to"]},
    {"exfiltrating": False, "sink_params": ["to"]},
])
def test_sink_settings_without_exfiltrating_are_an_error(raw: dict[str, object]) -> None:
    # Loading these would replace the pack entry and turn the sink gate off.
    with pytest.raises(PolicyError, match="exfiltrating"):
        _policy_from_dict("send_email", raw)


def test_empty_and_zero_values_still_load() -> None:
    assert _policy_from_dict("t", {}).max_calls is None
    assert _policy_from_dict("t", {"max_calls": 0}).max_calls == 0
    assert _policy_from_dict("t", {"allowed_path_prefixes": []}).allowed_path_prefixes == ()
