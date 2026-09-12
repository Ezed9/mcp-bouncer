# bouncer-mcp

The local **stdio MCP proxy** half of [bouncer](https://github.com/Ezed9/mcp-bouncer).
It sits between your MCP client and your existing tool servers, re-exports every
tool 1:1, and enforces [`bouncer-core`](https://pypi.org/project/bouncer-core/)'s
contracts on each call.

```bash
uv tool install bouncer-mcp
bouncer init
```

The enforcement engine — provenance and taint rules, per-argument constraints,
call budgets — is `bouncer-core`, which depends only on `pyyaml` and speaks no
MCP at all. Install that one directly if you are enforcing contracts inside your
own harness rather than proxying an MCP server.

**There is no LLM in the enforcement path.** Every decision is plain Python over
a recorded schema, a policy, and a taint log.

Full documentation, the threat model, and the benchmark results are in the
[repository README](https://github.com/Ezed9/mcp-bouncer#readme).
