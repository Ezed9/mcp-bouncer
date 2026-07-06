# Throwaway: dump the live filesystem server's tool schemas (outputSchema check).
from __future__ import annotations

import asyncio
import json

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE = "/Users/nishit/Desktop/Projects/Fable/bouncer/smoke_work"


async def main() -> None:
    params = StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", BASE],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            for t in listed.tools:
                if t.name in ("read_file", "write_file"):
                    print(f"### {t.name}")
                    print("outputSchema:", json.dumps(t.outputSchema))
                    print()


if __name__ == "__main__":
    asyncio.run(main())
