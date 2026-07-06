# bouncer/tests/test_cli.py
"""Unit tests for the pure CLI helpers: `rewrite_config` and
`_upstream_from_config`.

Both are pure (no file I/O, no proxy launch) so they're exhaustively unit
tested here; `main`'s I/O plumbing is exercised only implicitly (it's a thin
wrapper around these).
"""

import json

import pytest

from bouncer.cli import _upstream_from_config, main, rewrite_config


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


def test_init_emits_runnable_args(tmp_path, monkeypatch) -> None:
    """`bouncer init`'s wrapped entry must be spawnable by a real MCP client:
    its args must parse cleanly through the SAME argparse parser `main` uses
    for `run`, carrying both `--config` (self-sufficient, absolute path) and
    `--upstream-name` (matching the wrapped server).
    """
    cfg_path = tmp_path / "client_config.json"
    cfg = {"mcpServers": {"filesystem": {"command": "npx",
           "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]}}}
    cfg_path.write_text(json.dumps(cfg))

    monkeypatch.setattr("builtins.input", lambda _: "y")
    rc = main(["init", "--config", str(cfg_path)])
    assert rc == 0

    written = json.loads(cfg_path.read_text())
    entry = written["mcpServers"]["filesystem"]
    assert entry["command"] == "bouncer"

    resolved = str(cfg_path.resolve())
    assert entry["args"] == [
        "run", "--config", resolved, "--upstream-name", "filesystem",
    ]

    # The wrapped args must parse through the REAL `main`/`run` argparse
    # setup without error -- that's the actual init->run contract a spawned
    # MCP client depends on. Stub `_cmd_run` so no live proxy is launched;
    # this still exercises the real parser in `main`, only skipping the I/O
    # body of `_cmd_run`.
    seen: dict[str, object] = {}

    def fake_cmd_run(config_path, server_name, user_policy=None):
        seen["config_path"] = config_path
        seen["server_name"] = server_name
        seen["user_policy"] = user_policy
        return 0

    monkeypatch.setattr("bouncer.cli._cmd_run", fake_cmd_run)
    run_rc = main(entry["args"])
    assert run_rc == 0
    assert str(seen["config_path"]) == resolved
    assert seen["server_name"] == "filesystem"
