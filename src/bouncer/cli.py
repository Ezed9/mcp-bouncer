# bouncer/src/bouncer/cli.py
"""CLI: `bouncer init` (wrap servers in a client config) and `bouncer run`.

`rewrite_config` is pure and idempotent -- it stashes the original launch
command under an `x-bouncer-upstream` sentinel and points the server entry at
`bouncer run`. Re-running is a no-op because the sentinel is detected.

`_upstream_from_config` is the pure inverse: given a config and a server name,
it recovers the original `{command, args}` from the sentinel so `run` can
relaunch the real upstream. main() holds no decision logic; it is I/O +
argument plumbing only.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

import anyio

_SENTINEL = "x-bouncer-upstream"


def rewrite_config(
    config: dict[str, object],
    server_name: str,
    command: str,
    args: list[str],
) -> dict[str, object]:
    out = copy.deepcopy(config)
    servers = out.get("mcpServers")
    if not isinstance(servers, dict) or server_name not in servers:
        return out
    entry = servers[server_name]
    if not isinstance(entry, dict) or _SENTINEL in entry:
        return out  # already wrapped -> idempotent no-op
    original = {"command": entry.get("command"), "args": entry.get("args", [])}
    servers[server_name] = {
        "command": command,
        "args": args,
        _SENTINEL: original,
    }
    return out


def _upstream_from_config(
    config: dict[str, object], server_name: str
) -> tuple[str, list[str]]:
    """Recover the original upstream `(command, args)` from the sentinel.

    Raises `ValueError` if the server is missing or was never wrapped by
    `rewrite_config` -- `run` has nothing to relaunch in that case.
    """
    servers = config.get("mcpServers")
    if not isinstance(servers, dict) or server_name not in servers:
        raise ValueError(f"no server named {server_name!r} in config")
    entry = servers[server_name]
    if not isinstance(entry, dict) or _SENTINEL not in entry:
        raise ValueError(
            f"server {server_name!r} has no {_SENTINEL!r} sentinel; "
            "run `bouncer init` first to wrap it"
        )
    original = entry[_SENTINEL]
    command = original.get("command")
    args = original.get("args", [])
    if not isinstance(command, str):
        raise ValueError(f"server {server_name!r} sentinel is missing a command")
    return command, list(args)


def _cmd_init(config_path: Path, server_names: list[str]) -> int:
    config = json.loads(config_path.read_text())
    resolved_config_path = config_path.resolve()
    updated = config
    for name in server_names or list(config.get("mcpServers", {})):
        updated = rewrite_config(
            updated, name, command="bouncer",
            args=["run", "--config", str(resolved_config_path),
                  "--upstream-name", name],
        )
    if updated == config:
        print("No changes (already wrapped or no matching servers).")
        return 0
    print(json.dumps(updated, indent=2))
    if input("Write this config? [y/N] ").strip().lower() != "y":
        print("Aborted.")
        return 1
    config_path.write_text(json.dumps(updated, indent=2))
    print(f"Wrote {config_path}")
    return 0


def _cmd_run(
    config_path: Path, server_name: str, user_policy: Path | None = None
) -> int:
    config = json.loads(config_path.read_text())
    command, args = _upstream_from_config(config, server_name)

    from .proxy import BouncerProxy  # deferred: avoids importing MCP for `init`

    anyio.run(BouncerProxy.serve, command, args, server_name, user_policy)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bouncer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    init = sub.add_parser("init", help="wrap MCP servers in a client config")
    init.add_argument("--config", type=Path, required=True)
    init.add_argument("--server", action="append", default=[],
                      help="server name to wrap (repeatable; default: all)")

    run = sub.add_parser("run", help="run the proxy for one upstream server")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--upstream-name", required=True)
    run.add_argument(
        "--policy", "--user-policy", dest="policy", type=Path, default=None,
        help="optional user contract YAML, layered over the builtin packs",
    )

    ns = parser.parse_args(argv)
    if ns.cmd == "init":
        return _cmd_init(ns.config, ns.server)
    if ns.cmd == "run":
        return _cmd_run(ns.config, ns.upstream_name, ns.policy)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
