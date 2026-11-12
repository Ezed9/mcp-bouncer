# bouncer-core

The enforcement engine of [Bouncer](https://github.com/Ezed9/mcp-bouncer). It
checks an agent's tool calls against a policy and returns `allow`, `deny` or
`ask`. The rules are plain Python, no LLM decides anything, and the only
dependency is PyYAML. It speaks no MCP.

Most people want [`bouncer-mcp`](https://pypi.org/project/bouncer-mcp/), the
local stdio MCP proxy built on this engine. Install `bouncer-core` on its own
if you want the same rules inside your own agent harness.

```bash
pip install bouncer-core    # Python 3.12+
```

What the engine checks on each call, in this order:

1. The tool was there when the session started.
2. The tool is within its call budget.
3. Path prefixes and argument patterns pass.
4. For a tool that sends or shares: a destination that appeared in earlier
   tool output is denied, an allowlisted or approved one is allowed, and
   anything else is `ask`.

Every verdict is appended to a JSON-lines audit log.

It gates destinations, not content, and only the calls you pass to it. Read
the [limits](https://github.com/Ezed9/mcp-bouncer#limits) before relying on it.

- How to drive it: [`scripts/demo.py`](https://github.com/Ezed9/mcp-bouncer/blob/main/scripts/demo.py)
- Decision order, policy format and the audit log: [`docs/how-it-works.md`](https://github.com/Ezed9/mcp-bouncer/blob/main/docs/how-it-works.md)
- Benchmark and its cost to legitimate tasks: [README](https://github.com/Ezed9/mcp-bouncer#benchmark)
- [Changelog](https://github.com/Ezed9/mcp-bouncer/blob/main/CHANGELOG.md)
