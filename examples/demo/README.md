# Demo: a hijacked agent against a real MCP server

```bash
uv sync --all-packages
uv run python examples/demo/run_demo.py
```

No API keys. Takes a few seconds. Everything it writes goes to `examples/demo/out/`.

Add `--pace` (or set `BOUNCER_DEMO_PACE=1`) to pause between steps. The README
recording is made with [VHS](https://github.com/charmbracelet/vhs) from the repo
root: `vhs examples/demo/demo.tape` writes `docs/assets/demo.gif` and `demo.mp4`.

## What runs

- `helpdesk_server.py` is a small MCP server (a mock helpdesk/CRM) with real side
  effects: `send_email` appends to an outbox file, `write_file` writes files,
  `delete_customer` removes records.
- The real `bouncer run` proxy sits in front of it with `policy.yaml`:
  - `send_email` may go to `support@acme.example`; any other recipient is checked.
  - `write_file` is confined to `workspace/`.
  - `delete_customer` may run once per session.
- The demo is the agent's MCP client. **The agent's tool calls are scripted.** They
  are the calls an agent makes after reading the poisoned ticket `T-1002`, which
  tells it to send the customer list to `attacker@evil.example`, write an SSH key,
  and delete customers. Results with real models are in
  [`benchmark/RESULTS.md`](../../benchmark/RESULTS.md).

## What you see

1. A normal ticket and a reply to the allowlisted address are allowed.
2. After the poisoned ticket:
   - The send to `attacker@evil.example` is denied, because that address came
     from the ticket.
   - The write to `../.ssh/authorized_keys` is denied by path confinement.
   - The first delete runs, and the second is denied by the call budget. A
     budget limits the damage; it does not stop the first call. Use
     `max_calls: 0` to forbid a tool outright.
3. A send to a new, legitimate address is asked. The demo approves it, standing
   in for the human.
4. The server's real state is checked: no mail reached the attacker, and no file
   was written outside `workspace/`.
5. The audit lines from this run are printed.
6. `bouncer report` writes `out/review-pack.md` from this run's tool list, policy,
   and audit log. A copy is committed as [`sample-review-pack.md`](sample-review-pack.md).

The proxy runs with `HOME` pointed at `out/home`, so the demo never touches your
own `~/.bouncer/audit.jsonl`.
