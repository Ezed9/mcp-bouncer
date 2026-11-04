"""End to end over real stdio: a client with no elicitation, the real proxy, the
demo helpdesk server, and the `bouncer approve` / `bouncer pending` CLI.
"""

from __future__ import annotations

import io
import json
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from bouncer_mcp.cli import main as bouncer_cli
from bouncer_mcp.cli import rewrite_config
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_DEMO = Path(__file__).resolve().parents[2] / "examples" / "demo"
_CODE = re.compile(r"bouncer approve ([A-Z0-9]{3}-[A-Z0-9]{3})")


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def _setup(tmp_path: Path) -> tuple[Path, Path, StdioServerParameters]:
    data = tmp_path / "helpdesk"
    (data / "workspace").mkdir(parents=True)
    (data / "customers.json").write_text("[]")
    home = tmp_path / "home"
    home.mkdir()
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps(rewrite_config(
        {"mcpServers": {"helpdesk": {
            "command": sys.executable,
            "args": [str(_DEMO / "helpdesk_server.py"), str(data)]}}},
        "helpdesk", command="bouncer", args=[],
    )))
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "bouncer_mcp", "run", "--config", str(config),
              "--upstream-name", "helpdesk", "--policy", str(_DEMO / "policy.yaml")],
        env={"HOME": str(home)},
    )
    return data, home, params


def _text(result: object) -> str:
    return " ".join(getattr(b, "text", "") for b in getattr(result, "content", []))


async def test_no_elicitation_client_approves_out_of_band_and_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data, home, params = _setup(tmp_path)
    monkeypatch.setenv("HOME", str(home))
    args = {"to": "new.partner@example.com", "subject": "Intro", "body": "Hello"}

    # No elicitation_callback: the client does not declare the capability.
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        first = await session.call_tool("send_email", args)
        assert first.is_error
        match = _CODE.search(_text(first))
        assert match, _text(first)
        code = match.group(1)
        assert not (data / "outbox.jsonl").exists()

        pending = home / ".bouncer" / "pending.json"
        assert stat.S_IMODE(pending.stat().st_mode) == 0o600

        # The agent piping an answer into the CLI (no TTY) cannot approve.
        piped = subprocess.run(
            [sys.executable, "-m", "bouncer_mcp", "approve", code],
            input="y\n", capture_output=True, text=True,
            env={"HOME": str(home), "PATH": ""}, timeout=30,
        )
        assert piped.returncode == 2 and "TTY" in piped.stderr
        assert (await session.call_tool("send_email", args)).is_error

        assert bouncer_cli(["pending"]) == 0
        assert code in capsys.readouterr().out

        # The human, in a terminal, sees the destination and approves.
        monkeypatch.setattr(sys, "stdin", _Tty("y\n"))
        assert bouncer_cli(["approve", code.lower()]) == 0
        shown = capsys.readouterr().out
        assert "new.partner@example.com" in shown and "Approved" in shown

        second = await session.call_tool("send_email", args)
        assert not second.is_error, _text(second)
        assert "new.partner@example.com" in (data / "outbox.jsonl").read_text()

        # One call only. This server's reply ("sent to new.partner@...") put the
        # address in tool output, so it is now tainted: a plain deny, no code.
        # (An eliciting client's approval lasts the session and outranks taint;
        # a one-time approval does not.)
        third = await session.call_tool("send_email", args)
        assert third.is_error and "came from untrusted data" in _text(third)
        assert not _CODE.search(_text(third))
        assert len((data / "outbox.jsonl").read_text().splitlines()) == 1
        # A different new recipient gets its own code; the used one is gone.
        other = await session.call_tool("send_email", {**args, "to": "kim@example.org"})
        other_code = _CODE.search(_text(other))
        assert other.is_error and other_code and other_code.group(1) != code

    audit = [json.loads(line)
             for line in (home / ".bouncer" / "audit.jsonl").read_text().splitlines()]
    approvals = [r for r in audit if r["verdict"] == "approve"]
    assert len(approvals) == 1 and approvals[0]["contract"] == "out_of_band"
    assert approvals[0]["args"]["server"] == "helpdesk"


def test_approve_declined_or_unknown_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    from bouncer.approvals import approval_key
    from bouncer.pending import PendingApprovals

    store = PendingApprovals()
    [code] = store.request("helpdesk", "send_email",
                           [(approval_key("send_email", "to", "x@y.com"), "x?")]) or []
    monkeypatch.setattr(sys, "stdin", _Tty("n\n"))
    assert bouncer_cli(["approve", code]) == 1
    assert store.active()[0].approved is False

    monkeypatch.setattr(sys, "stdin", _Tty(""))
    assert bouncer_cli(["approve", "ZZZ-ZZZ"]) == 1
    assert "unknown, expired" in capsys.readouterr().err
