# bouncer/tests/test_cli.py
"""Unit tests for the pure CLI helpers: `rewrite_config` and
`_upstream_from_config`.

Both are pure (no file I/O, no proxy launch) so they're exhaustively unit
tested here; `main`'s I/O plumbing is exercised only implicitly (it's a thin
wrapper around these).
"""

import pytest

from bouncer.cli import _upstream_from_config, rewrite_config


def test_rewrite_wraps_server_and_preserves_original() -> None:
    cfg = {"mcpServers": {"filesystem": {"command": "npx",
           "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]}}}
    out = rewrite_config(cfg, "filesystem", command="bouncer",
                         args=["run", "--upstream-name", "filesystem"])
    fs = out["mcpServers"]["filesystem"]
    assert fs["command"] == "bouncer"
    assert fs["args"][:1] == ["run"]
    # original command must be preserved somewhere Bouncer can relaunch it
    assert "npx" in str(out)


def test_rewrite_is_idempotent() -> None:
    cfg = {"mcpServers": {"fs": {"command": "npx", "args": ["x"]}}}
    once = rewrite_config(cfg, "fs", command="bouncer", args=["run"])
    twice = rewrite_config(once, "fs", command="bouncer", args=["run"])
    assert once == twice


def test_rewrite_stashes_original_under_sentinel() -> None:
    cfg = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "server-fs", "/data"]}}}
    out = rewrite_config(cfg, "fs", command="bouncer", args=["run"])
    fs = out["mcpServers"]["fs"]
    assert fs["x-bouncer-upstream"] == {"command": "npx", "args": ["-y", "server-fs", "/data"]}


def test_rewrite_leaves_non_matching_servers_alone() -> None:
    cfg = {
        "mcpServers": {
            "fs": {"command": "npx", "args": ["x"]},
            "other": {"command": "python", "args": ["-m", "other"]},
        }
    }
    out = rewrite_config(cfg, "fs", command="bouncer", args=["run"])
    assert out["mcpServers"]["other"] == {"command": "python", "args": ["-m", "other"]}


def test_rewrite_handles_missing_mcp_servers() -> None:
    cfg: dict[str, object] = {}
    out = rewrite_config(cfg, "fs", command="bouncer", args=["run"])
    assert out == {}


def test_rewrite_handles_unknown_server_name() -> None:
    cfg = {"mcpServers": {"fs": {"command": "npx", "args": ["x"]}}}
    out = rewrite_config(cfg, "does-not-exist", command="bouncer", args=["run"])
    assert out == cfg


def test_upstream_from_config_extracts_original_command() -> None:
    cfg = {
        "mcpServers": {
            "fs": {
                "command": "bouncer",
                "args": ["run", "--upstream-name", "fs"],
                "x-bouncer-upstream": {"command": "npx", "args": ["-y", "server-fs", "/data"]},
            }
        }
    }
    command, args = _upstream_from_config(cfg, "fs")
    assert command == "npx"
    assert args == ["-y", "server-fs", "/data"]


def test_upstream_from_config_raises_when_not_wrapped() -> None:
    cfg = {"mcpServers": {"fs": {"command": "npx", "args": ["x"]}}}
    with pytest.raises(ValueError):
        _upstream_from_config(cfg, "fs")


def test_upstream_from_config_raises_when_server_missing() -> None:
    cfg = {"mcpServers": {"fs": {"command": "npx", "args": ["x"]}}}
    with pytest.raises(ValueError):
        _upstream_from_config(cfg, "does-not-exist")
