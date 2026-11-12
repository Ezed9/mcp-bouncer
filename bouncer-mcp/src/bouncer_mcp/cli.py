# bouncer/src/bouncer/cli.py
"""CLI: `bouncer init` (wrap servers in a client config), `bouncer run`, `bouncer report`,
and `bouncer approve` / `bouncer pending` (one-time approvals for clients that cannot elicit).

`rewrite_config` is pure and idempotent -- it stashes the ENTIRE original
server entry (command, args, and anything else on it -- `env`, `cwd`, ...)
under an `x-bouncer-upstream` sentinel and points the server entry at
`bouncer run`. Re-running is a no-op because the sentinel is detected.

`_upstream_from_config` is the pure inverse: given a config and a server name,
it recovers the original `(command, args, env, cwd)` from the sentinel so
`run` can relaunch the real upstream with its credentials/env intact. main()
holds no decision logic; it is I/O + argument plumbing only.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from datetime import date
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
    if not isinstance(entry.get("command"), str):
        return out  # a remote (url) server: no stdio command for `run` to start
    # Stash the WHOLE original entry -- not just {command, args} -- so `env`,
    # `cwd`, and any other keys (credentials for github/gmail/slack upstreams)
    # survive the wrap and can be recovered by `_upstream_from_config`.
    original = entry
    servers[server_name] = {
        "command": command,
        "args": args,
        _SENTINEL: original,
    }
    return out


def _upstream_from_config(
    config: dict[str, object], server_name: str
) -> tuple[str, list[str], dict[str, str] | None, str | None]:
    """Recover the original upstream `(command, args, env, cwd)` from the sentinel.

    `env`/`cwd` are `None` when the original entry didn't set them (backward
    compatible with configs wrapped before this existed).

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
    env = original.get("env")
    cwd = original.get("cwd")
    if not isinstance(command, str):
        raise ValueError(f"server {server_name!r} sentinel is missing a command")
    return (
        command,
        list(args),
        dict(env) if isinstance(env, dict) else None,
        cwd if isinstance(cwd, str) else None,
    )


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
    command, args, env, cwd = _upstream_from_config(config, server_name)

    from .proxy import BouncerProxy  # deferred: avoids importing MCP for `init`

    anyio.run(BouncerProxy.serve, command, args, server_name, user_policy, env, cwd)
    return 0


def _cmd_serve(user_policy: Path | None = None) -> int:
    from .server import run_standalone_server  # deferred: avoids importing MCP for `init`

    anyio.run(run_standalone_server, "bouncer", user_policy)
    return 0


def _cmd_pending() -> int:
    import time

    from bouncer.pending import PendingApprovals, show_code

    entries = PendingApprovals().active()
    if not entries:
        print("No pending approvals.")
        return 0
    now = time.time()
    for e in entries:
        state = "approved, waiting for the retry" if e.approved else "pending"
        left = max(int(e.expires - now), 0)
        print(f"{show_code(e.code)}  {e.server or '-'}  {e.tool}  {state}, "
              f"expires in {left // 60}m{left % 60:02d}s")
        print(f"         {e.reason}")
    return 0


def _cmd_approve(codes: list[str]) -> int:
    """Approve one-time codes, after showing what each one allows.

    Interactive only: stdin must be a terminal and every code is confirmed by
    hand. There is no --yes flag, so an agent with a non-interactive shell
    can't approve its own call by piping an answer in. (An agent with full
    shell access can go around Bouncer anyway; see the README's Limits.)
    """
    import getpass

    from bouncer.audit import AuditLog
    from bouncer.pending import TTL_SECONDS, PendingApprovals, normalize_code, show_code
    from bouncer.types import AuditEntry

    if not sys.stdin.isatty():
        print("bouncer approve must be run by a human in a terminal "
              "(stdin is not a TTY).", file=sys.stderr)
        return 2
    store = PendingApprovals()
    audit = AuditLog(Path.home() / ".bouncer" / "audit.jsonl")
    status = 0
    for raw in codes:
        entry = store.get(raw)
        if entry is None or entry.approved:
            print(f"{show_code(normalize_code(raw))}: unknown, expired or already "
                  "approved. `bouncer pending` lists open codes.", file=sys.stderr)
            status = 1
            continue
        print(f"{show_code(entry.code)} on server {entry.server or '-'!r}, "
              f"tool {entry.tool!r}:")
        print(f"  {entry.reason}")
        print("  Approving allows ONE retry of a call to this destination, "
              f"within {TTL_SECONDS // 60} minutes.")
        if input("Approve? [y/N] ").strip().lower() != "y":
            print("Not approved.")
            status = 1
            continue
        approved = store.approve(entry.code)
        if approved is None:
            print(f"{show_code(entry.code)} expired while waiting.", file=sys.stderr)
            status = 1
            continue
        audit.write(AuditEntry(
            tool=approved.tool,
            args={"code": approved.code, "server": approved.server,
                  "approval_key": approved.key},
            verdict="approve",
            reason=f"approved out of band by {getpass.getuser()}: {approved.reason}",
            contract="out_of_band",
        ))
        print(f"Approved. Retry the call within {TTL_SECONDS // 60} minutes.")
    return status


def _cmd_report(ns: argparse.Namespace) -> int:
    from bouncer import __version__
    from bouncer.policy import builtin_pack_paths, load_policies
    from bouncer.report import build_report, load_tools, summarize_audit

    report = build_report(
        pack_policies=load_policies(builtin_pack_paths()),
        user_policies=load_policies([ns.policy]) if ns.policy else {},
        user_policy_path=ns.policy,
        tools=load_tools(ns.tools) if ns.tools else None,
        audit=summarize_audit(ns.audit, ns.since, ns.until),
        benchmark=json.loads(ns.benchmark.read_text()) if ns.benchmark else None,
        server_name=ns.server_name,
        version=__version__,
        generated_on=date.today(),
    )
    if ns.output is None:
        print(report)
    else:
        ns.output.write_text(report + "\n")
        print(f"Wrote {ns.output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bouncer",
        description="Bouncer: deterministic contract enforcement and security tools for MCP.",
    )
    sub = parser.add_subparsers(dest="cmd")

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

    serve = sub.add_parser("serve", help="run the standalone Bouncer MCP server over stdio")
    serve.add_argument(
        "--policy", "--user-policy", dest="policy", type=Path, default=None,
        help="optional user contract YAML, layered over the builtin packs",
    )

    approve = sub.add_parser(
        "approve", help="approve a one-time code from a client that cannot elicit")
    approve.add_argument("codes", nargs="+", metavar="CODE")
    sub.add_parser("pending", help="list open one-time approval codes")

    report = sub.add_parser("report", help="write a Markdown security review pack")
    report.add_argument("--policy", type=Path, default=None, help="user contract YAML")
    report.add_argument("--tools", type=Path, default=None,
                        help="the server's tools/list result as JSON")
    report.add_argument("--audit", type=Path, default=Path.home() / ".bouncer" / "audit.jsonl")
    report.add_argument("--since", type=date.fromisoformat, default=None, help="YYYY-MM-DD")
    report.add_argument("--until", type=date.fromisoformat, default=None, help="YYYY-MM-DD")
    report.add_argument("--benchmark", type=Path, default=None,
                        help="a benchmark results JSON (e.g. benchmark/results-*.json)")
    report.add_argument("--server-name", default=None)
    report.add_argument("-o", "--output", type=Path, default=None,
                        help="output file (default: stdout)")

    ns = parser.parse_args(argv)
    if ns.cmd == "init":
        return _cmd_init(ns.config, ns.server)
    if ns.cmd == "report":
        return _cmd_report(ns)
    if ns.cmd == "approve":
        return _cmd_approve(ns.codes)
    if ns.cmd == "pending":
        return _cmd_pending()
    if ns.cmd == "run":
        return _cmd_run(ns.config, ns.upstream_name, ns.policy)
    if ns.cmd == "serve" or ns.cmd is None:
        policy = getattr(ns, "policy", None)
        return _cmd_serve(policy)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
