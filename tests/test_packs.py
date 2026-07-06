# bouncer/tests/test_packs.py
from bouncer.policy import PolicyResolver, builtin_pack_paths, load_policies


def test_builtin_packs_exist_and_load() -> None:
    paths = builtin_pack_paths()
    assert paths, "no builtin packs found"
    policies = load_policies(paths)
    assert "send_email" in policies or "gmail_send_email" in policies


def test_gmail_send_is_exfiltrating_with_recipient_sinks() -> None:
    policies = load_policies(builtin_pack_paths())
    # find the send tool whatever its exact name
    send = next(p for name, p in policies.items() if "send" in name and p.exfiltrating)
    assert any(s in send.sink_params for s in ("to", "recipients", "recipient"))


def test_resolver_uses_packs_over_heuristics() -> None:
    r = PolicyResolver(overrides=load_policies(builtin_pack_paths()))
    p = r.policy_for("send_email", {"properties": {"to": {}, "body": {}}})
    assert p.exfiltrating is True


def test_filesystem_pack_matches_live_tool_surface() -> None:
    # Names verified live against @modelcontextprotocol/server-filesystem
    # (2026-07-06): the reference server exposes no delete tool.
    policies = load_policies(builtin_pack_paths())
    assert "delete_file" not in policies
    for tool in ("write_file", "edit_file", "create_directory", "move_file"):
        assert tool in policies, f"filesystem pack missing {tool}"
    assert policies["move_file"].write_params == ("source", "destination")
