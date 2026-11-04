# Clients, elicitation and approvals

Bouncer's `ask` verdict needs a human. With a client that supports MCP
elicitation, the proxy asks the human through the client. Before this change,
a client without elicitation turned every `ask` into a `deny`, with no way
through. This page covers the research behind the fix (as of 2026-11-04) and
the design that was built. Every claim links its source. "Unconfirmed" marks
claims taken from a third party or inferred from code, not documented by the
vendor.

**What you need to know:**

- Several widely used clients can't elicit. Claude Desktop, Cline, Continue,
  Windsurf and Zed don't, and nor does the OpenAI Agents SDK as shipped.
  ([matrix](#1-which-clients-can-elicit))
- Commercial gateways have landed on one pattern for these clients: return a
  tool error with an approval ID, have a human approve somewhere else, and let
  the identical retry through once. ([gateways](#2-how-gateways-approve-when-the-client-cant-ask))
- No released MCP spec defines an "approval required" result. The 2026-07-28
  spec replaces server-to-client requests with retry-based multi round-trip
  requests (MRTR). ([spec](#3-spec-work))
- Bouncer now does the same as those gateways, locally: a short code, a
  `bouncer approve` command run by a human in their own terminal, and one retry
  within five minutes. ([design](#4-the-design-bouncer-uses))

## 1. Which clients can elicit

Elicitation lets a server ask the user something in the middle of a request
(`elicitation/create`). A client opts in by declaring the `elicitation`
capability, which in 2025-11-25 has a `form` mode and a `url` mode
([2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation),
[2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation)).

| Client | Elicitation | Since | What happens without it | Sources |
|---|---|---|---|---|
| Claude Desktop (chat) | No (unconfirmed: no vendor statement found) | n/a | A third-party test guide reports `-32601 Method not found`. A feature request was auto-closed as "not planned". | [request](https://github.com/anthropics/claude-code/issues/41347), [third-party guide](https://glama.ai/mcp/servers/@portel-dev/ncp/blob/15e66a895070b491d2839485dc6a759e72812009/tests/ELICITATION-TESTING-GUIDE.md) |
| Claude Code | Yes, form and URL | 2.1.76, per the clients-page PR (no primary changelog read). The docs say `{form, url}` on legacy connections from 2.1.287. | claude.ai connectors get form only. A hook can auto-decline. | [docs](https://code.claude.com/docs/en/mcp#elicitation-modes-claude-code-declares), [PR #2398](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2398), [hooks](https://code.claude.com/docs/en/hooks) |
| Cursor | Yes, form. URL mode unknown | 1.5 (2025-08-21) | Users report the prompt not showing and the agent hanging until timeout (3.10, Windows) | [changelog](https://cursor.com/changelog/1-5), [docs](https://cursor.com/docs/context/mcp), [forum](https://forum.cursor.com/t/mcp-elicitation-create-hangs-agent-on-windows-in-cursor-3-10-20-but-works-on-macos/165391) |
| VS Code (GitHub Copilot) | Yes, form and URL | 1.102 (form), 1.107 (URL) | n/a | [1.102](https://code.visualstudio.com/updates/v1_102), [1.107](https://code.visualstudio.com/updates/v1_107) |
| Windsurf (Cascade) | No evidence of support | n/a | Unknown | [feature request](https://windsurf.canny.io/feature-requests/p/please-add-elicitation-support-to-windsurf-cascade-so-that-mcp-tools-can-fully-l), [docs](https://docs.devin.ai/desktop/cascade/mcp) |
| Zed | No. The docs list tools and prompts only. | n/a | Declares no capability. From its source (untested), an unhandled inbound request is dropped with no reply, so the server waits for its own timeout. | [docs](https://zed.dev/docs/ai/mcp), [types.rs](https://github.com/zed-industries/zed/blob/main/crates/context_server/src/types.rs#L467-L474), [client.rs](https://github.com/zed-industries/zed/blob/main/crates/context_server/src/client.rs#L294-L302) |
| Cline | No. Declares `capabilities: {}`. | n/a | The server SDK refuses to send | [McpHub.ts](https://github.com/cline/cline/blob/c450589/apps/vscode/src/services/mcp/McpHub.ts#L466-L474) |
| Continue | No. Declares `capabilities: {}`. | n/a | The server SDK refuses to send | [MCPConnection.ts](https://github.com/continuedev/continue/blob/main/core/context/mcp/MCPConnection.ts#L88-L96) |
| Goose | Yes | 1.17.0 (dated "18 Dec", year inferred as 2025) | n/a | [release](https://github.com/block/goose/releases/tag/v1.17.0), [mcp_client.rs](https://github.com/block/goose/blob/main/crates/goose/src/agents/mcp_client.rs#L376-L451) |
| OpenAI Agents SDK (Python) | No. It passes no `elicitation_callback`. | n/a | Python SDK default: capability absent, `-32600` if asked anyway | [server.py](https://github.com/openai/openai-agents-python/blob/main/src/agents/mcp/server.py#L1366-L1371) |
| ChatGPT (developer mode / apps) | No source found. The old clients page doesn't list it. | n/a | Unknown | [MCP docs](https://developers.openai.com/api/docs/mcp/), [old clients page](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/87993a68/docs/clients.mdx) |
| LangChain MCP adapters | Opt in, via an `on_elicitation` callback | 0.2.0 (2025-12-09) | Python SDK default. The repo now points to `langchain.mcp`, which maps elicitation to LangGraph interrupts. | [changelog](https://changelog.langchain.com/announcements/ann_SYfYlerJSVuhY), [PyPI](https://pypi.org/pypi/langchain-mcp-adapters/json), [migration](https://docs.langchain.com/oss/python/migrate/langchain-mcp-adapters) |
| MCP Inspector | Yes, form and URL. Answers MRTR rounds on 2026-07-28. | Form: PR #535 (2025-07-24). URL: PR #1423 (2026-06-04). | n/a | [#535](https://github.com/modelcontextprotocol/inspector/pull/535), [#1423](https://github.com/modelcontextprotocol/inspector/pull/1423), [protocol eras](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/protocol-eras.md) |

What "without it" means at the SDK level:

- **Python SDK client.** It declares `elicitation` only when you pass an
  `elicitation_callback` (2.x too: `mcp/client/session.py` in the 2.x wheel
  this repo locks). If a request arrives anyway, the default handler
  answers `-32600` "Elicitation not supported"
  ([session.py](https://github.com/modelcontextprotocol/python-sdk/blob/v1.x/src/mcp/client/session.py#L85-L91)).
- **TypeScript SDK server.** `elicitInput()` throws locally ("Client does not
  support form elicitation.") before anything is sent
  ([server/index.ts](https://github.com/modelcontextprotocol/typescript-sdk/blob/3b73021/src/server/index.ts#L285-L288)). A TypeScript client with no handler replies `-32601` ([protocol.ts](https://github.com/modelcontextprotocol/typescript-sdk/blob/3b73021/src/shared/protocol.ts#L722-L726)).
- **Bouncer's proxy.** It checks the declared capability before it asks
  ([`proxy.py` `_make_elicit`](../bouncer-mcp/src/bouncer_mcp/proxy.py)), so on
  these clients `ask` goes straight to the one-time code path below.

The official client feature matrix that used to be at
`modelcontextprotocol.io/clients` has been removed. Its last version listed
elicitation for Claude Code, Cursor, VS Code GitHub Copilot, goose, Codex and
GitHub Copilot CLI ([last version](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/87993a68/docs/clients.mdx), [removal](https://github.com/modelcontextprotocol/modelcontextprotocol/commit/2075a21d)). Its entries were self-reported.

Relevant to the fallback, which returns an error result:

- **Claude Code** passes the text of an `isError: true` result to the model as
  the tool's error message
  ([docs](https://code.claude.com/docs/en/mcp)).
- **The OpenAI Agents SDK** gives error content to the model as normal tool
  output ([util.py](https://github.com/openai/openai-agents-python/blob/main/src/agents/mcp/util.py#L790-L797)).
- **LangChain's adapters** return it as a `ToolMessage` with `status="error"`
  ([repo](https://github.com/langchain-ai/langchain-mcp-adapters)).

So in all three the model can relay the code to the human.

## 2. How gateways approve when the client can't ask

Mechanisms only. Categories:

1. Deny only.
2. Elicit through the client.
3. Hold the call open while a human answers somewhere else.
4. Return an error, approve somewhere else, then the agent retries.
5. Async task, polled by the client.

| Product | Mechanism | What the approval is bound to | Expiry | Source |
|---|---|---|---|---|
| Runlayer | 4 for unattended clients: an error result with `code: approval_required`, `request_id`, `url` and `expires_at`. The approver uses a Slack DM, a web inbox or the API. | Session, client and arguments. The identical call passes once. | Pending 24 h. An approval is used within 1 h. A denial blocks identical retries for 15 min. | [docs](https://docs.runlayer.com/platform-policies) |
| DigitalOcean Action Gateway | 2, falling back to 4: an `approval_id` plus a `decide` endpoint. The client must "invoke the same tool with the same arguments". | Team, session, tool version and arguments. Used once. | On expiry, call again to get a new request. | [docs](https://docs.digitalocean.com/products/managed-agents/action-gateway/how-to/configure-server-side-approval/) |
| MintMCP (now Mintive) | 4: an error result telling the agent to show the user a link, then "the retry consumes it". | Exact arguments. Single use. | 30 s to 24 h, default 1 h. An expired request can't be approved. | [docs](https://www.mintive.com/docs/tool-approval) |
| TrueFoundry | 4: a success-shaped result with `_meta.approval_status: "pending"` and the tool not run. Approved via Slack, email, Teams or webhook. | Requester, server and tool, once or for a time window. Argument binding is not stated. | Not documented. | [docs](https://www.truefoundry.com/docs/ai-gateway/mcp/mcp-tool-approval) |
| Permit.io MCP Gateway | 3: the call is paused and approvers are alerted. | The approver sees the arguments. | 5 min default. A timeout is a rejection. | [docs](https://docs.permit.io/permit-mcp-gateway/human-in-the-loop) |
| Gravitee | 3: the agent "perceives a slow tool call" while a human decides in an inbox. | Rule conditions on the arguments. | 900 s default. Fallback (deny or allow) is set per rule. | [docs](https://documentation.gravitee.io/gravitee-gamma/agent-management/govern/require-human-approval-for-mcp-tool-calls.md) |
| Cloudflare Agents SDK | 2 (`elicitInput`, URL mode included). Also durable workflow gates (`waitForApproval`), which are 3/5. | Code Mode keys approval on the execution ID. | Workflow timeout, for example "7 days". | [human-in-the-loop](https://developers.cloudflare.com/agents/concepts/agentic-patterns/human-in-the-loop/) |
| Cloudflare MCP portals | 1: the critical risk tier disables the tool. The post says they could not rely on "elicitation prompts". | n/a | n/a | [blog](https://blog.cloudflare.com/mcp-portal-writeguard-private-beta/) |
| Docker MCP Gateway | Interceptor hooks (`before:exec`, `docker` or `http`). A hook's response can replace the call. No built-in approval. | n/a | Not documented | [interceptors](https://github.com/docker/mcp-gateway/tree/main/examples/interceptors) |
| ToolHive vMCP | 2: a workflow `elicitation` step. "Clients that don't support this method will abort the workflow." | n/a | `timeout` per step | [docs](https://docs.stacklok.com/toolhive/guides-vmcp/composite-tools) |
| Spring AI Playground | 2: with no elicitation capability, "the call cannot be approved". | Arguments are shown. | 180 s, then refused | [docs](https://spring-ai-community.github.io/spring-ai-playground/hitl-architecture/) |
| Operant AI | 1: per its product page, an inline block plus an alert. No approval flow is documented. | n/a | n/a | [page](https://www.operant.ai/platform/agent-protector) |
| agentgateway, Pomerium, Lasso, Invariant Gateway, Obot, Microsoft MCP Gateway | 1: policy allow or deny. No approval feature found. | n/a | n/a | [agentgateway](https://agentgateway.dev/docs/standalone/latest/documentation/configuration/security/mcp-authz/), [Pomerium](https://www.pomerium.com/docs/capabilities/mcp/limit-mcp-tools), [Lasso](https://github.com/lasso-security/mcp-gateway), [Invariant](https://github.com/invariantlabs-ai/invariant-gateway), [Obot](https://docs.obot.ai/functionality/filters/), [Microsoft](https://github.com/microsoft/mcp-gateway) |
| mcp-guardian, MCP-Defender, Peta Desk | 3 (unconfirmed): a local desktop app approves or denies live calls. | Not documented | Not documented | [mcp-guardian](https://github.com/eqtylab/mcp-guardian), [MCP-Defender](https://github.com/MCP-Defender/MCP-Defender), [Peta](https://github.com/dunialabs/peta-desk) |
| IBM ContextForge | Proposal only: a plugin that holds the call and asks via Slack or elicitation. Commenters suggest a single-use approval bound to a digest of the call. | (proposed) | n/a | [issue #5437](https://github.com/IBM/mcp-context-forge/issues/5437) |

Outside MCP, agent frameworks pause and resume instead of erroring and retrying:

- **OpenAI Agents SDK:** `needs_approval` produces interruptions, and the run is resumed from serialized `RunState`
  ([docs](https://openai.github.io/openai-agents-python/human_in_the_loop/)).
- **LangGraph:** `interrupt()`, resumed with `Command(resume=...)`
  ([docs](https://docs.langchain.com/oss/python/langgraph/interrupts)).
- **Vercel AI SDK:** a tool approval request and response
  ([docs](https://ai-sdk.dev/docs/ai-sdk-core/tools-and-tool-calling)).
- **Claude Code hooks** can `defer` a tool call in `-p` mode, and the session is resumed later
  ([docs](https://code.claude.com/docs/en/hooks)).

A proxy can't use any of these, because it doesn't own the agent loop.

**The takeaway.** The pattern in pattern 4 (error, approve elsewhere, retry passes
once) is what Runlayer, DigitalOcean and MintMCP ship for clients that can't
prompt. All three bind the approval to the call's arguments and make it single
use. None of them uses a terminal command; they use Slack, a web inbox or an
API. No MCP product using `sudo`-style one-time codes was found.

## 3. Spec work

- **2025-11-25: URL-mode elicitation**
  ([spec](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation),
  [SEP-1036](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/1036)).
  - The client declares `elicitation: { form: {}, url: {} }`.
  - A server can fail a request with `URLElicitationRequiredError` (code
    `-32042`), listing URL-mode elicitations. The documented flow ends with the
    client optionally retrying `tools/call`.
  - The client must show the full URL and get consent. The server must check
    that the person who opens the URL is the user the elicitation was made for.
  - This still requires the client to support URL mode.
- **2025-11-25: Tasks (experimental)**
  ([spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks),
  [SEP-1686](https://modelcontextprotocol.io/seps/1686-tasks.md)).
  - A `tools/call` can return a task that the client polls with `tasks/get`.
  - A task in `input_required` still gets its input through elicitation.
- **2026-07-28: the current revision**
  ([versioning](https://modelcontextprotocol.io/specification/versioning),
  [changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)).
  - Servers "MUST send server-to-client requests … using the MRTR pattern"
    ([MRTR](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr)).
    A `tools/call` returns `resultType: "input_required"` with `inputRequests`
    and an opaque `requestState`, and the client retries with `inputResponses`.
  - `requestState` must be integrity-protected when it affects authorization.
    The spec recommends binding it to the principal, a TTL and a digest of the
    request, and enforcing single use on the server.
  - `-32042` is marked "2025-11-25 only"
    ([schema](https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.ts)).
  - Tasks moved to an extension, `io.modelcontextprotocol/tasks`, which names
    "approval gates" as a use
    ([overview](https://modelcontextprotocol.io/extensions/tasks/overview.md)).
  - Bouncer's proxy doesn't offer 2026-07-28 yet. It serves the
    handshake-era versions only, so elicitation stays a server-to-client
    request ([CHANGELOG](../CHANGELOG.md)).
- **No standard "approval required" result.**
  - [SEP-2848 "Asynchronous Approval for Tool Calls"](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2848)
    is an unsponsored draft, flagged as inactive.
  - From a summary of the draft (unconfirmed): a "requestable denial" returns a
    task handle while approval happens out of band, with a server-side record
    that binds a digest of the arguments and allows at most one execution.
  - [Issue #2920](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2920)
    proposes a state-only `InputRequiredResult` as the standard "still waiting"
    answer.
- **Annotations are hints.** `destructiveHint` etc. "MUST" be treated as
  untrusted unless they come from trusted servers, and the tools page says
  there "SHOULD always be a human in the loop with the ability to deny tool
  invocations"
  ([tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools.md)).
- **Python SDK.** 2.x targets 2026-07-28 including MRTR. As of 2.3.0 it still ships `UrlElicitationRequiredError`
  and `elicit_url`, but not the tasks extension
  ([releases](https://github.com/modelcontextprotocol/python-sdk/releases)).

## 4. The design Bouncer uses

**Flow, for a client without elicitation:**

1. The agent calls `send_email(to="bob@partner.com", …)`. The engine says
   `ask`. The call is **not forwarded**.
2. The proxy records a pending approval and returns a tool error:
   ```text
   [bouncer blocked] destination to='bob@partner.com' is not a vouched recipient
   This MCP client can't ask the user to confirm, so this call needs a one-time
   approval from a human. In their own terminal, not through the agent, they
   run: bouncer approve K7Q-F2M
   Then retry the same call within 5 minutes. The approval allows one call to
   this destination.
   ```
3. The human runs `bouncer approve K7Q-F2M` (or `bouncer pending` to see open
   codes). The CLI shows the server, tool and destination from the local file,
   not from what the agent said, and asks for `y`.
4. The agent retries. The proxy finds an approved entry for this exact (server,
   approval key), uses it up, re-runs the engine with that key granted for this
   one evaluation, and forwards.

**Properties, and where each is tested:**

| Property | How | Test |
|---|---|---|
| Bound to the approval key | An entry stores `(server, approval_key(tool, param, destination))`. The proxy looks approvals up by that key, never by a code, and the agent never sends a code. | `test_code_never_approves_a_different_destination` (other destination, other param, other server) |
| Single use | `consume()` removes the entries under the lock, all or nothing. A one-time approval is not added to the session's approval memory. | `test_happy_path_…`, `test_reused_code_does_not_pass_twice`, `test_consume_is_all_or_nothing` |
| TTL | A pending code expires 5 min after it was issued. Approving it gives the retry 5 min from approval. | `test_expired_approval_denies`, `test_expired_code_cannot_be_approved`, `test_approved_code_expires_before_retry` |
| Taint still wins | The first evaluation of every attempt runs without grants. A destination that showed up in tool output after the code was issued is denied. | `test_destination_tainted_after_the_code_was_issued_denies` |
| No code where an answer can't help | A pinning `ask` (`ask_key` None), a tainted recipient anywhere in the call, or more than 20 pending codes: deny, no code. | `test_pinning_ask_still_denies_without_a_code`, `test_tainted_destination_gets_no_code`, `test_pending_codes_are_capped` |
| State outside MCP | `~/.bouncer/pending.json`, created 0600 in a 0700 directory, replaced atomically under `flock`. A file group or others can access, a symlink, or a file owned by another user reads as empty. Proxy mode lists only the upstream's tools, and no approve tool exists. | `test_file_is_private_and_dir_is_0700`, `test_group_writable_file_is_ignored`, `test_symlinked_file_is_ignored`, `test_proxy_surface.py` |
| Human only | `bouncer approve` refuses without a TTY on stdin and confirms each code. There is no `--yes`. | `test_no_elicitation_client_approves_out_of_band_and_retries` (an agent piping `y` gets exit 2) |
| Eliciting clients unchanged | `_without_elicitation` runs only when `_make_elicit` returned None. | `test_eliciting_client_is_unchanged`, the existing `test_proxy.py`, the demo |
| Evidence | The blocked attempt logs `ask` and no `allow` (the lookahead uses `preview()`, which writes no audit line). `bouncer approve` logs an `approve` line (contract `out_of_band`, OS user, code, server, key), and the review pack counts it. | `test_audit_never_logs_allow_for_a_blocked_attempt`, `test_out_of_band_approvals_get_their_own_row` |

A call with several new recipients gets one code per recipient in the same
error, and `bouncer approve A B` takes several codes. Approvals are used up
only when the call is forwarded, so approving one of two recipients wastes
nothing.

**Why this shape:**

- **It is the pattern the market uses.** It matches Runlayer, DigitalOcean and
  MintMCP (§2) on error, approve elsewhere, retry once, and expiry. It needs
  nothing from the client beyond showing a tool error to the model. Claude
  Code, the OpenAI Agents SDK and LangChain's adapters are documented to do
  that (§1). For the other clients that is expected but wasn't checked.
- **It is local.** Bouncer is one process per server on one machine, with no
  server or accounts. A terminal command is the approval channel that already
  exists. A Slack or web inbox would mean a service to run and to authenticate.
- **It is fail-closed by construction.** The default is still deny: no file,
  bad mode, expired, used, I/O error (caught as an error result) all deny. The
  engine decides exactly as before; the only new input is a set of keys that
  count as approved for one evaluation.
- **The code isn't a secret, and doesn't need to be.** The agent sees it.
  What stops an agent is that only the human's terminal can approve, and that
  the approval is checked against the call's own key. Six characters from a
  31-letter alphabet, valid for five minutes, keep codes from colliding; they
  aren't meant to resist guessing.

**Not covered, or chosen differently from the gateways:**

- **The approval is bound to the destination, not the whole call.** The brief
  asked for the existing approval key. Runlayer, DigitalOcean and MintMCP bind
  to the exact arguments, and MRTR recommends a digest of the request. The
  retry's subject and body can differ from the blocked call's. That matches
  what Bouncer gates (destinations, not content) and what an elicitation
  approval covers today. It also tolerates an agent rewording the body on the
  retry. Adding an argument digest to the entry is a small change if the
  owner wants exact-call binding. `bouncer approve` would then need to show
  the arguments, or the binding means little.
- **An agent with a shell can get around it.** Like the rest of Bouncer, it
  governs MCP only. The TTY check stops an agent piping `y` in, but not one that
  allocates a pty. Deny `bouncer approve` in the agent's shell permissions.
- **Budgets.** The blocked attempt and the retry each use a slot of the tool's
  call budget, as any denied call does.
- **An echoed address.** If the server's reply repeats the recipient, the
  address is in tool output and later sends to it are denied with no code. An
  elicitation approval lasts the session and outranks taint; a one-time
  approval doesn't.
- **Windows.** There is no `flock` and no mode check there. Writes are still
  atomic. Untested.

**Possible upgrades, by client:**

- **2025-11-25 clients that declare `elicitation.url`:** return `-32042` with a
  URL to a local approval page in place of the code.
- **2026-07-28 clients:** return an `InputRequiredResult` with a URL-mode
  elicitation and a sealed `requestState`, once the proxy speaks that version.

Both would reuse the same store and binding. The code path stays for clients
that support neither.
