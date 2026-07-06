# bouncer/scripts/smoke_driver.py
"""Throwaway scripted MCP client for the live smoke test (Task 13).

Launches `bouncer run` (the async proxy) as a stdio MCP *server* wrapping the
reference filesystem server, then acts as a client: lists tools and calls them,
printing the real verdicts. This is a legitimate stand-in for Claude Code and
produces REAL, captured results.

Not part of the shipped package; lives under scripts/ purely as smoke evidence.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = Path(__file__).resolve().parent.parent  # bouncer/
BOUNCER = HERE / ".venv" / "bin" / "bouncer"
CONFIG = HERE / "smoke_work" / "mcp-config.json"


def _text(result: object) -> str:
    parts: list[str] = []
    for block in getattr(result, "content", []) or []:
        t = getattr(block, "text", None)
        if t is not None:
            parts.append(str(t))
    is_err = getattr(result, "isError", False)
    prefix = "ERROR/DENY: " if is_err else "OK: "
    return prefix + " | ".join(parts)


async def main() -> None:
    params = StdioServerParameters(
        command=str(BOUNCER),
        args=["run", "--config", str(CONFIG), "--upstream-name", "filesystem"],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            listed = await session.list_tools()
            print("=== tools/list (real names from live server) ===")
            for t in listed.tools:
                print(f"  - {t.name}")
            print()

            async def call(label: str, name: str, args: dict[str, object]) -> None:
                print(f"--- {label}: {name}({args}) ---")
                try:
                    res = await session.call_tool(name, args)
                    print(_text(res))
                except Exception as exc:  # noqa: BLE001 - smoke driver
                    print(f"EXCEPTION: {type(exc).__name__}: {exc}")
                print()

            base = str(HERE / "smoke_work")

            # (a) read then write into ./out -> expect ALLOW (see note on pack prefixes)
            await call("a1 read_file", "read_file",
                       {"path": f"{base}/mcp-config.json"})
            await call("a2 write_file into out", "write_file",
                       {"path": f"{base}/out/hello.txt", "content": "hello from smoke"})

            # (b) write outside allowed prefix -> expect DENY (constraint)
            await call("b write_file to /etc", "write_file",
                       {"path": "/etc/bouncer_should_not_write.txt", "content": "nope"})

            # (c) delete tool 3x with max_calls=2 -> third DENY (budget)
            for i in (1, 2, 3):
                await call(f"c delete #{i}", "delete_file",
                           {"path": f"{base}/out/hello.txt"})


if __name__ == "__main__":
    asyncio.run(main())
    sys.exit(0)
