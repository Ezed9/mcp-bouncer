"""Live smoke driver exercising a USER POLICY through the proxy (Task 13 re-verify).

Launches `bouncer run --policy smoke_work/user-policy.yaml` (the async proxy)
wrapping the reference filesystem server, then acts as a client. Proves the two
fixes end-to-end: (1) an ALLOWED write into ./out succeeds with real
structuredContent relay, and (2) the user policy enforces THROUGH the proxy —
write outside the allowed prefix is DENIED by Bouncer's own contract, and the
write budget (max_calls=2) DENIES the 3rd allowed-prefix write.

Throwaway; lives under scripts/ purely as smoke evidence.
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
POLICY = HERE / "smoke_work" / "user-policy.yaml"


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
        args=[
            "run", "--config", str(CONFIG),
            "--upstream-name", "filesystem",
            "--policy", str(POLICY),
        ],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            async def call(label: str, name: str, args: dict[str, object]) -> None:
                print(f"--- {label}: {name}({args}) ---")
                try:
                    res = await session.call_tool(name, args)
                    print(_text(res))
                except Exception as exc:  # noqa: BLE001 - smoke driver
                    print(f"EXCEPTION: {type(exc).__name__}: {exc}")
                print()

            base = str(HERE / "smoke_work")

            # constraint: write outside allowed prefix -> Bouncer DENY (constraint)
            await call("b write_file to /etc", "write_file",
                       {"path": "/etc/bouncer_should_not_write.txt", "content": "nope"})

            # budget: 3 writes into ./out with max_calls=2 -> 3rd DENY (budget)
            for i in (1, 2, 3):
                await call(f"c write #{i} into out", "write_file",
                           {"path": f"{base}/out/note{i}.txt", "content": "ok"})


if __name__ == "__main__":
    asyncio.run(main())
    sys.exit(0)
