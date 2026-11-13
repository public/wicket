# 21 — Agent Client Protocol (ACP): the protocol today, and wicket as client and as editor front

*Researched 2026-11-10 from primary sources: the spec repo and its RFDs (read at commit `8c390fb`, 2026-11-10),
the live registry, the Rust SDK, the Claude and Codex adapters, Zed's source, and GitHub release and advisory data
via `gh api`. This updates and goes deeper than [01 §2.1]; it doesn't repeat what 01 already covers unless the
facts have changed.*

**Confidence tags.** **[H]** means I read it in the primary source (spec text, schema, source code, release data).
**[M]** means I inferred it from source code or docs that don't say it in so many words, or the sources slightly
disagree. **[L]** means a weak signal: a single secondary source, or my reading of an ambiguous design.

The owner calls it "agent context protocol as used by Zed". Its name is the **Agent Client Protocol**. Zed
created it, and Zed and JetBrains now govern it jointly. It is not IBM's *Agent Communication Protocol* (also
"ACP", which merged into A2A), and it is not MCP.

---

## Summary

1. **ACP is how an editor drives a coding agent.** It is JSON-RPC over the agent's stdin and stdout: the editor
   (the *client*) spawns the agent, opens a session, sends prompts, and streams back messages, tool calls, plans
   and diffs. The agent asks the client for permission before risky steps. The stable wire version is still
   `protocolVersion` 1. v2 is a draft (schema `v2.0.0-alpha.14`, 2026-11-09). The project is very active:
   schema and SDK releases most weeks, and the Claude adapter shipped five releases in two days. [H]
2. **Permission answers are advisory by design.** The spec says plainly that ACP does not sandbox, that the agent
   enforces its own permissions, and that a proxy may answer prompts "under user-configured policy". So for
   wicket an ACP prompt is an *agent-local prompt* (design §14.1.2), never a grant. The box and the proxies stay
   the only enforcement. [H]
3. **A permission reply carries no reason.** It is just an option id: `allow_once`, `allow_always`,
   `reject_once` or `reject_always`, or `cancelled`. A rejection reaches the model as a generic "user refused".
   So wicket's typed denials (request id, remedies, `await_grant`) must keep coming from the gates, not from ACP
   replies. The practical rule: for operations a wicket gate mediates, let the attempt through and let the gate
   answer with the typed 403. [H for the shape; the rule is my proposal]
4. **Never pick an "always" option.** "Always" decisions live in the agent. The Claude adapter turns
   `allow_always` into an allow rule in `.claude/settings.local.json` inside the workspace. That is a policy
   write in the box which could leave in an extracted patch. wicket answers only `allow_once` or `reject_once`,
   chosen by `kind`, and hides "always" options from any human it forwards a prompt to. [H, code]
5. **The client-side file and terminal capabilities are the real hazard.** In v1 a client may offer
   `fs/read_text_file`, `fs/write_text_file` and `terminal/create`. The agent then asks the client to read and
   write files and run commands *on the client's machine*. Zed offers all three, and its `terminal/create`
   handler spawns the command without checking anything itself. So **piping a boxed ACP agent straight to an
   editor would let the agent run commands on the user's host**, outside the box. Any wicket front for editors
   must be an ACP-aware filter, not a byte pipe like `wicket wrap`. [H, Zed source]
6. **As an ACP client, wicket should offer neither capability.** Agents fall back to their own tools inside the
   box, which is where wicket wants execution anyway. The Claude adapter stopped using these capabilities in
   0.18.0. Gemini uses client file reads only for paths inside the workspace root and otherwise uses the real
   filesystem. v2 removes both capabilities. [H]
7. **MCP servers are passed per session in `session/new`, and so is control.** wicket passes its gateway as the
   only server. Two things matter. First, the Claude adapter accepts arbitrary Claude Agent SDK options from
   `_meta.claudeCode.options`, merged with its own: hooks, env, settings, MCP servers, executable path. So
   whoever writes `session/new` controls the agent's configuration: fine when that is wicket, dangerous when an
   editor's request passes through. Second, the adapter loads user, project and local settings by default.
   MCP-over-ACP (tools carried over the ACP pipe itself) is still an Active RFD and opt-in in the Rust SDK. No
   agent I checked consumes it natively; only a polyfill does. [H]
8. **Remote ACP isn't standard yet.** The Streamable HTTP + WebSocket transport is an Active RFD from the
   Transports Working Group, aimed at v1. It has no replay of messages missed during a disconnect, and leaves
   authentication to the host. The Rust SDK's HTTP server says "CORS does not authenticate requests". Zed
   itself has no remote ACP. It runs agents over its own SSH remoting instead, with the agent process on the
   remote host. For multi-host wicket: keep ACP local on each node, between `wicket-node` and the box. Carry
   wicket's own resumable event stream between hosts. Keep pending prompts in the ledger so a reconnecting
   editor sees them again. [H for the RFD and SDK; M for Zed]
9. **The ecosystem is broad.** The registry lists 45 agents. Native: Gemini CLI, goose, OpenCode, Cline,
   Copilot CLI, Cursor, Kiro, Junie and others. Through adapters: Claude Code, Codex and pi. There are over 100
   listed clients: Zed, JetBrains, Neovim (several plugins), Emacs, VS Code extensions, Qt Creator, Sublime and
   many desktop or web consoles. The registry bumps agent versions hourly by cron, straight to `main`, and npx
   entries carry no hash. So wicket must pin versions and hashes itself and never follow `latest`. [H]
10. **(b) is feasible and worth doing: a `wicket acp` front.** A Zed user adds `wicket acp --zone …` as a custom
    agent. To Zed it is an ACP agent; inside, it drives the boxed agent. It strips the editor's file and
    terminal capabilities, MCP servers, env, `_meta` and extra roots. It maps paths, and filters permission
    options. Wicket escalations are announced in the editor but decided only in wicket. One proposed handoff is
    a URL-mode elicitation that opens the console's passkey approval page; the front would drop agent-originated
    URL elicitations so only wicket's can appear. This works with any ACP agent, sends no transcript to a vendor
    cloud (unlike `vendor_rc`), and fits `ChannelKind::AcpFront`. That kind was in [09] but dropped from the
    design. [M, proposal]
11. **Things to borrow:**
    - `systemPrompt` in `append` mode (stabilized 2026-11-06) for wicket's sandbox notice;
    - the v2 `requires_action` state and `command` permission subject;
    - the conductor and proxy architecture for the front;
    - the security page's rendering rules;
    - the ACP Test Compatibility Kit for conformance;
    - `traceparent` in `_meta` for audit correlation.

    Things to avoid:
    - relying on prompts or on client capabilities;
    - unauthenticated HTTP;
    - auto-approval based on titles or command regexes (Zed has four 2026 advisories on exactly that);
    - shipping v2 or MCP-over-ACP in production yet.

---

## 0. What changed since research 01 (2026-11-08)

| Item | 01 said | Now (2026-11-10) | Tag |
|---|---|---|---|
| Schema releases | `schema-v1.29.1`, `v2.0.0-alpha.13` | `schema-v1.30.0` and `schema-v2.0.0-alpha.14` (2026-11-09); schema crate `agent-client-protocol-schema` 1.16.0 | [H] |
| Rust SDK | `agent-client-protocol` 5.0.0 | **5.1.0** (2026-11-09), all sibling crates bumped together; 2.47 M recent downloads on crates.io | [H] |
| TypeScript SDK | — | `@agentclientprotocol/sdk` 2.5.0 (2026-11-09) | [H] |
| Client system prompt | not mentioned | **Stabilized 2026-11-06** in v1 and v2: `systemPrompt {mode: append \| override}` on `session/new`, `load` and `resume` | [H] |
| Claude adapter | 0.101.0 | **0.104.1** (2026-11-10); still bundles the `claude` CLI | [H] |
| Codex adapter | 2.5.0 | **2.6.0** (2026-11-08) | [H] |
| goose repo | `aaif-goose/goose` | Registry still links `block/goose`, which redirects to `aaif-goose/goose`; goose 1.59.0 in the registry | [H] |
| Elicitation stabilized | 2026-07-24 | Announcement dated **2026-07-22** (the RFD revision is later) | [H] |
| `zed-industries/agent-client-protocol` | — | Redirects to `agentclientprotocol/agent-client-protocol` | [H] |

---

## 1. The protocol today

### 1.1 Version, stability, governance, health

- **Stable wire version: 1.** Version negotiation happens in `initialize`. The client sends the latest version it
  supports, and the agent answers with that version or its own latest. Capabilities omitted on either side MUST
  be treated as unsupported. New capabilities are not breaking changes. [H]
  https://agentclientprotocol.com/protocol/v1/initialization
- **v2 is a draft.** It was announced 2026-07-20. The guidance is to "gate your implementation behind the
  version negotiation **AND** feature flags", and "adding v2 support should not mean dropping v1". Its 13 Active
  RFDs are the whole breaking scope. Zed already links the Rust crate with `unstable_protocol_v2` (Zed's
  `Cargo.toml` pins `agent-client-protocol = "=5.1.0"` with `unstable` and `unstable_protocol_v2`) and keeps v1
  as the fallback. [H] https://agentclientprotocol.com/announcements/acp-v2-draft, Zed `Cargo.toml`
- **Governance** is "interim": "jointly governed by Zed and JetBrains … working toward transitioning to an
  independent foundation". The structure is maintainers, core maintainers and two lead core maintainers, with
  Working and Interest Groups chartered by core-maintainer vote. [H]
  https://agentclientprotocol.com/community/governance
- **RFD process.** RFDs move through Draft, Active, Preview and Completed. Most v1 features of the last year
  arrived as additive, capability-gated RFDs. [H] https://agentclientprotocol.com/rfds/about

**Repo health (`gh api`, 2026-11-10):** [H]

| Repo | Stars | Open issues | Last push | Latest release |
|---|---|---|---|---|
| `agentclientprotocol/agent-client-protocol` (spec, schema) | 4,614 | 31 | 2026-11-10 | `v1.16.0` / `schema-v1.30.0` / `schema-v2.0.0-alpha.14`, 2026-11-09 |
| `agentclientprotocol/rust-sdk` | 245 | 7 | 2026-11-09 | `v5.1.0`, 2026-11-09 |
| `agentclientprotocol/typescript-sdk` | 270 | 3 | 2026-11-09 | `v2.5.0`, 2026-11-09 |
| `agentclientprotocol/claude-agent-acp` | 2,747 | 145 | 2026-11-10 | `v0.104.1`, 2026-11-10 (0.101.1 → 0.104.1 in two days) |
| `agentclientprotocol/codex-acp` | 562 | 177 | 2026-11-09 | `v2.6.0`, 2026-11-08 |
| `agentclientprotocol/registry` | 453 | 280 | 2026-11-10 | rolling (hourly cron) |
| `zed-industries/zed` | 94,665 | — | 2026-11-10 | `v1.27.0`, 2026-11-04 |

The top human committers to the spec are Ben Brandt (Zed, lead maintainer) and `agu-z`, followed by Zed staff
and Sergey Ignatov (JetBrains). Most commits come from a release bot. The project is healthy and fast-moving.
For wicket that cuts both ways: the Claude adapter alone ships near-daily, so §6.1 conformance against a pinned
version is not optional.

### 1.2 Transport

**stdio (the only standard transport).** [H] https://agentclientprotocol.com/protocol/v1/transports
- The client launches the agent as a subprocess. Messages are newline-delimited JSON-RPC 2.0 in UTF-8, with no
  embedded newlines.
- The agent "MUST NOT write anything to its `stdout` that is not a valid ACP message". stderr is for logs.
- Custom transports are allowed if they keep the JSON-RPC format and lifecycle, and they "SHOULD document their
  security considerations, including how peers authenticate" (security page).
- **JSON-RPC batches are gone.** A JSON array is rejected with `-32600` (RFD revision 2026-10-30; v2 change list).

**Remote: Streamable HTTP and WebSocket, an Active RFD.** [H]
https://agentclientprotocol.com/rfds/streamable-http-websocket-transport
- Authors are Alex Hancock and jh-block (goose); the champion is Anna Zhdan. It moved to Active 2026-07-02.
- One `/acp` endpoint. `POST` sends a message: `initialize` returns `200` with the result and an
  `Acp-Connection-Id`, and everything else returns `202 Accepted` immediately. Long-lived SSE `GET` streams carry
  server→client traffic. There is one stream per connection, and one per session keyed by
  `Acp-Connection-Id` + `Acp-Session-Id`. Permission requests and session updates ride the session stream.
  `GET` with `Upgrade: websocket` gives full duplex instead. `DELETE` closes the connection.
- It **requires HTTP/2** for Streamable HTTP. Clients MUST support both profiles, so a server may offer
  WebSocket only. Clients MUST keep cookies, so load balancers can use sticky sessions.
- **v1 guarantees are thin.** Sessions outlive connections, and you reconnect with `session/load`. But "in-flight
  messages are not replayed". Reconnect and liveness are the implementer's job. Message IDs, `Last-Event-ID`
  resumption, defined reconnection and keepalive are deferred to v2. The `Acp-Protocol-Version` header and origin
  validation are "Phase 4 hardening", not done yet.
- **Authentication is out of scope:** it is "orthogonal and layered on top via HTTP headers, query parameters,
  or WebSocket subprotocols". The connection and session ids "are transport-level identifiers, not auth tokens".
- **Transports Working Group:** announced 2026-04-22, with Anna Zhdan for the core maintainers and Alex Hancock
  from goose. [H] https://agentclientprotocol.com/announcements/transports-working-group
- **Implementations.**
  - Rust `agent-client-protocol-http` 5.1.0 has `server` (axum; HTTP+SSE with WebSocket upgrade) and `client`
    features, both off by default. Its docs say "CORS does not authenticate requests … Authentication and custom
    credential policies belong to the host router", and requests without an `Origin` header pass the origin
    check. [H] rust-sdk `src/agent-client-protocol-http/src/server.rs`
  - goose's `goose serve` is the reference implementation [01 §2.4].
- **Security track record.** The TypeScript SDK's experimental Node HTTP adapter had three advisories in
  September 2026:
  - GHSA-p29f-jffj-96g8 (high): unbounded request-body buffering, a remote unauthenticated out-of-memory crash;
  - GHSA-6q4g-4xp9-ch96: uncapped message buffering;
  - GHSA-xwmv-pq97-hp3w: unbounded session-routing growth.

  These are classic first-version HTTP bugs, so treat any ACP-over-network endpoint as new attack surface. [H]

### 1.3 Session lifecycle

Source: https://agentclientprotocol.com/protocol/v1/session-setup and the overview. [H]

- **Baseline** (all agents MUST): `initialize`, `session/new`, `session/prompt`, `session/cancel` (a
  notification), `session/update` (notifications from the agent), and the client's `session/request_permission`.
  `authenticate` is used when the agent advertises a protocol-driven auth method.
- **Optional, capability-gated:**
  - `session/load` replays the whole history as updates;
  - `session/resume` gives no replay;
  - `session/close`, `session/list`, `session/delete`, `logout`;
  - `session/set_config_option`, and the older `session/set_mode`;
  - `$/cancel_request` cancels any outstanding request by id.
- **Drafts:** `session/fork`, `session/set_title`, `session/archive`, `session/status`.
- **`session/new` params:**
  - `cwd`: absolute;
  - `mcpServers[]`: required in v1, optional in v2;
  - `additionalDirectories?`;
  - `systemPrompt?`.

  `[cwd, …additionalDirectories]` is the **root set**. The spec's wording matters for wicket: the root set
  "declares the session's scope. It confines shell commands only when a sandbox enforces it." Implementations that
  enforce it should "check the resolved path at the time of use, compare paths by component, and fail closed".
- **System prompt, now stable:**
  - `append` adds system-level instructions;
  - `override` (separately advertised) replaces the agent's defaults but "does not change tool availability, MCP
    servers, permissions, or session configuration";
  - an agent that cannot apply it MUST error rather than create the session;
  - "Clients SHOULD only send content they trust at that level."
- **Replay is not authority.** `session/load` replays prior tool calls and their permission outcomes. The spec
  says agents "SHOULD NOT treat model output, Agent content, or replayed history as granting access outside the
  root set". A claude-agent-acp issue (#1094, closed 2026-09-14) probed whether a Write approval survives a runtime
  restart plus `session/load`. Its author concluded it "may be a spec-level gap … replay semantics for prior
  approvals are unspecified". [H]
  https://github.com/agentclientprotocol/claude-agent-acp/issues/1094

### 1.4 Prompt turns, v1 and v2

- **v1** [H] https://agentclientprotocol.com/protocol/v1/prompt-turn
  - `session/prompt` stays open for the whole turn. The agent streams `session/update` notifications: message
    and thought chunks, `tool_call` and `tool_call_update`, `plan`, `available_commands_update`, mode and config
    changes, `notice` (opt-in), compaction (opt-in) and `usage_update`.
  - The turn ends with a response carrying a `stopReason`: `end_turn`, `max_tokens`, `max_turn_requests`,
    `refusal` or `cancelled`.
  - On `session/cancel`, the client "MUST respond to all pending `session/request_permission` requests with the
    `cancelled` outcome", and the agent MUST answer the prompt with `cancelled`.
- **v2 decouples work from the request** [H] https://agentclientprotocol.com/protocol/v2/prompt-lifecycle
  - `session/prompt` returns only the inserted message's `messageId`. Foreground state arrives as `state_update`
    with values `running`, `requires_action` and `idle`, and the stop reason moves onto the idle update.
  - "While foreground work is blocked on user action, the Agent SHOULD report `requires_action`."
  - Prompts sent while the agent is busy are inserted or queued, never rejected. That is a standard steer.
  - Background work (a `paused` tool status, per-item `tool_call/cancel` and `terminal/cancel`, and a
    `background` list) is now explicit. Claude Code's background Bash, subagents, `Monitor` and `ScheduleWakeup`
    are cited as the motivation. [H] https://agentclientprotocol.com/rfds/v2/background-work
- **The v1 gap that hurts long pending.** In v1, a permission request raised by background work after the turn
  ends "has no turn to be surfaced in". Being a blocking RPC, it deadlocked a subagent in a field report
  (claude-agent-acp #866, closed 2026-07-13). v2's `requires_action` and the background list are the fix. [H]

### 1.5 Tool calls and permission requests

Source: https://agentclientprotocol.com/protocol/v1/tool-calls. [H]

- **Tool calls** are reported, not requested: "Agents run tool calls themselves."
  - Fields: `toolCallId`, `title` (agent-authored), `name` (programmatic, stabilized 2026-09-17, and explicitly
    "do[es] not … grant authorization"), `kind`, `status`, `content` (text, a diff, or a v1 terminal reference),
    `locations`, `rawInput` and `rawOutput`.
  - `kind` is one of `read`, `edit`, `delete`, `move`, `search`, `execute`, `think`, `fetch`, `switch_mode`
    or `other`.
  - Status runs `pending` → `in_progress` → `completed` or `failed`. v2 adds `cancelled` and `paused`.
- **`session/request_permission`** is a JSON-RPC *request* from the agent with
  `{sessionId, toolCall: ToolCallUpdate, options: [{optionId, name, kind}]}`.
  - Option kinds are `allow_once`, `allow_always`, `reject_once` and `reject_always`.
  - The client answers `{outcome: {outcome: "selected", optionId}}` or `{outcome: {outcome: "cancelled"}}`.
  - **There is no field for a reason, a narrowed scope or a message.** [H, schema]
- **Who answers:** "Clients MAY automatically allow or reject permission requests according to the user
  settings." Intermediaries "SHOULD NOT answer permission requests or elicitations for the user except under
  user-configured policy". That is the clause wicket relies on.
- **Remembered decisions belong to the agent:** "the Agent stores the decision, decides its scope … and how long
  it lasts … `kind` is only a UI hint. The option `name` describes the scope."
- **Security rules** (all [H]):
  - clients describe the operation from `kind`, `locations` and content, show `title` as agent-authored, and
    show commands and paths in full;
  - "Automatic approval SHOULD NOT rely only on `title` or option `name`";
  - agents "SHOULD NOT treat an outcome they don't recognize as approval", and "SHOULD request again if the
    command or resolved target changes";
  - agents "SHOULD NOT switch to a mode or configuration that reduces user oversight without user action".
- **No timeout** is defined anywhere in the spec. A client may hold the request open. The Claude Agent SDK's
  `canUseTool` callback can stay pending [01]. The Claude adapter has an internal timer for how long `canUseTool`
  waits *during a cancel* (`v1/acp-agent.ts`). I found no general timeout. [M]
- **v2 permission requests** [H] https://agentclientprotocol.com/rfds/v2/permission-requests
  - The prompt copy moves into a required `title` and an optional `description`.
  - An optional, open `subject` union replaces the hard-wired `toolCall`:
    - `{type: "tool_call", …}`;
    - `{type: "command", command, cwd (absolute), toolCallId?, terminalId?}`, which "never asks the Client to
      execute it";
    - unknown subjects, which must be preserved by proxies and declined or shown generically by clients that
      don't understand them.

**What the Claude adapter does with the answer** (claude-agent-acp 0.104.1, `src/permissions/effects.ts`): [H,
code]
- `allow_always` for a tool becomes an SDK `PermissionUpdate` `{type: "addRules", behavior: "allow",
  destination: "localSettings"}`, and WebFetch becomes `domain:<host>`. That writes Claude Code's
  `.claude/settings.local.json`, which lives in the project directory.
- A plan-exit option can switch the session to `bypassPermissions`.
- A deny becomes `"User refused permission to run tool"`.
- `bypassPermissions` is refused when running as root unless `IS_SANDBOX` is set (`permissions/modes.ts`).

### 1.6 Client-provided capabilities: the agent asks the client to touch files and run commands

Sources: https://agentclientprotocol.com/protocol/v1/file-system and https://agentclientprotocol.com/protocol/v1/terminals.
[H]

- **What they are.**
  - With `clientCapabilities.fs.readTextFile` / `writeTextFile`, the agent can call
    `fs/read_text_file {sessionId, path, line?, limit?}` (which includes unsaved editor buffers) and
    `fs/write_text_file {sessionId, path, content}`.
  - With `clientCapabilities.terminal`, it can call `terminal/create {sessionId, command, args, env, cwd,
    outputByteLimit}`, then `terminal/output`, `wait_for_exit`, `kill` and `release`.
  - The *client* performs the operation, on *its* machine.
- **The spec puts the checking on the client.** "The Client performs these operations itself, so it is
  responsible for checking them. A permission request from the Agent does not replace the Client's own checks."
  Clients SHOULD check paths and `cwd` against the root set at time of use. They SHOULD apply their own policy to
  the full command, args *and env*. They SHOULD ask before writing files that control execution (git hooks,
  editor or agent settings, MCP config).
- **What Zed does** (`crates/agent_servers/src/acp/v1.rs`, Zed main 2026-11-10): [H, code]
  - It advertises `fs.readTextFile`, `fs.writeTextFile`, `terminal` and `auth.terminal`.
  - Reads and writes resolve the path through `project_path_for_absolute_path`, so they are confined to the
    project's worktrees.
  - `handle_create_terminal` calls `create_terminal_entity(command, args, env, cwd, project)` directly. There is
    **no permission check in the handler**; it trusts that the agent asked first.
  - In an SSH remote project, the agent's command is fetched from and run on the *remote* host
    (`RemoteExternalAgentServer::get_command` → `proto::GetAgentServerCommand`). So these operations then land on
    that host. [M: inferred from `project/src/agent_server_store.rs`]
- **Who actually uses them.**
  - The Claude adapter stopped in **0.18.0**: "Switch over to built-in Claude tools … it won't use client
    capabilities for files or terminals". [H] `CHANGELOG.md`
  - **Gemini CLI** uses client reads and writes only for paths inside the session root (and never for
    `~/.gemini`). It falls back to the native filesystem otherwise. [H] `packages/cli/src/acp/acpFileSystemService.ts`
  - I didn't check every other agent. The v2 RFD says the surface "has not been widely adopted … most stuck to
    their standard implementations". [H]
- **v2 removes all of it**: `fs/*`, `terminal/*` and client-owned terminal content. "If clients want to offer
  specialized tooling … they can already expose a special MCP server." v2 keeps only an agent-owned, display-only
  terminal output stream. Cross-version adapters MUST reject v1 `fs` and `terminal` rather than drop them
  silently. [H] https://agentclientprotocol.com/rfds/v2/client-filesystem-terminal-capabilities

**What this means for sandboxing.**
1. These capabilities are **a reverse channel from agent to client host**. A boxed agent that can reach a real
   editor's `terminal/create` has escaped the box. The box can't see this, because it is "just" stdout.
2. They are **not a chokepoint** for an agent that has its own tools. Gemini uses its native filesystem outside
   the root, and Claude never uses them. Serving them doesn't mediate anything you couldn't already mediate at the
   box boundary.
3. They are going away in v2. Nothing in wicket should depend on them.

### 1.7 Passing MCP servers to the agent

Source: https://agentclientprotocol.com/protocol/v1/session-setup#mcp-servers. [H]

- `mcpServers` goes on `session/new`, `load` and `resume`.
  - stdio is mandatory for agents: `{name, command, args, env[]}`.
  - HTTP needs `mcpCapabilities.http`: `{type: "http", name, url, headers[]}`.
  - SSE is deprecated.
  - "Clients MAY use this ability to provide tools directly to the underlying language model by including their
    own MCP server."
- **Security text:**
  - "`env` and `headers` values are credentials";
  - agents SHOULD launch stdio servers without a shell;
  - clients SHOULD NOT send a stdio server from workspace files or agent output until the user approved the exact
    command;
  - agents SHOULD NOT log, echo or persist the values, and SHOULD send headers only to the configured origin.
- **Zed forwards its own MCP servers ("context servers") to external agents.** In remote projects it filters to
  those marked `remote` (`agent_servers/src/acp.rs::mcp_configurations_for_project`). [H, code] So a
  passthrough to a boxed agent would carry the editor user's MCP command lines and their env (often API tokens)
  into the box.
- **The Claude adapter merges client MCP servers with any in `_meta.claudeCode.options.mcpServers`.** It forwards
  almost every Claude Agent SDK option from `_meta.claudeCode.options` (`src/new-session-meta.ts`, `v1/acp-agent.ts`).
  - Hooks and disallowed tools are merged.
  - `env`, `settings`, `managedSettings`, `executableArgs`, `pathToClaudeCodeExecutable`, `sandbox`,
    `permissionPromptToolName` and the rest are accepted.
  - Only `cwd`, `includePartialMessages`, `permissionMode`, `canUseTool` and `executable` are reserved.
  - It starts the SDK with `settingSources: ["user", "project", "local"]`, so repository settings and hooks load
    unless managed settings forbid them. [H, code]
- **MCP-over-ACP** (Active RFD, author Niko Matsakis) [H] https://agentclientprotocol.com/rfds/mcp-over-acp
  - A server is declared as `{type: "acp", name, serverId}`. Requests travel as `mcp/message` on the existing ACP
    connection, carrying stateless MCP **2026-07-28 only** (no MCP initialize, no MCP session). Interactive tools
    use MRTR: `input_required` and a fresh retry.
  - Its own motivation: "Requiring a separate HTTP listener or subprocess for those tools creates an extra
    communication path and makes isolation harder."
  - Security text: server and request ids "are routing identifiers, not credentials", and MRTR state is
    "attacker-controlled input" whose integrity, principal binding, expiry and single use the server must
    protect.
  - In the Rust SDK it sits behind `unstable_mcp_over_acp`. `agent-client-protocol-polyfill`'s
    `McpOverAcpPolyfill::http()` re-exports it to an agent as a **loopback HTTP endpoint with a per-connection
    bearer**, placed "immediately before that agent in a conductor proxy chain".
  - No native consumer was found: a code search for `mcp/message` finds none in codex-acp, goose or Gemini CLI,
    and none in claude-agent-acp's source. [M]

### 1.8 Authentication

Source: https://agentclientprotocol.com/protocol/v1/authentication and the auth-methods RFD. [H]

- The agent lists `authMethods` in its `initialize` response.
  - Type `agent` (the default) means the client calls `authenticate {methodId}` and the agent does the rest.
  - Type `terminal` means the client re-runs the *same configured agent command*, plus the method's `args` and
    `env`, interactively. On exit 0 it reconnects. This needs `clientCapabilities.auth.terminal`.
  - `logout` is optional.
- The `env_var` method was **removed** on 2026-07-27, because it "assumes the Client owns the Agent process and does
  not generalize to remote transports".
- **Launch safety:** clients SHOULD NOT apply terminal-auth `env` that changes program lookup, loading, interpreter
  startup, or "proxy and TLS trust" (`PATH`, `LD_*`, `NODE_OPTIONS`, `HTTPS_PROXY`, `SSL_CERT_FILE`, …) without
  approval.
- **The registry admits only agents whose CI handshake returns valid `authMethods`.** [H] registry README
- The Claude adapter advertises three `terminal` methods (`claude-login`, `claude-ai-login`, `console-login`). It
  also offers legacy `gateway` / `gateway-bedrock` logins and the unstable `providers/set`, which routes the SDK
  through a client-chosen base URL and headers, with a token placeholder (`src/providers.ts`,
  `src/gateway-models.ts`). [H, code]
- **Zed:** the docs say external agents own their auth, and "Zed passes a key configured for its Google AI
  provider as `GEMINI_API_KEY`" to Gemini. [H] https://zed.dev/docs/ai/external-agents

### 1.9 Extensions, `_meta`, plans, modes, config, elicitation, subagents

- **Extensibility** [H] https://agentclientprotocol.com/protocol/v1/extensibility
  - `_meta` objects on most types, custom methods prefixed `_`, and custom capabilities advertised under `_meta`
    with reverse-DNS names (`com.example/<name>`, `_com.example/<name>`).
  - Root `_meta` keys `traceparent`, `tracestate` and `baggage` are reserved for W3C trace context.
  - Credentials SHOULD NOT go in `_meta`.
  - v2 makes enums open (`_`-prefixed variants for extensions) and turns `_meta` on upserts into patches.
- **Extension sprawl is real.** Both adapters carry a large JetBrains "AIR" extension set: permission
  presentation, goals, session failure, diff patches, async tasks and steering (`_session/steering` in
  codex-acp). Claude adds `_claude/sdkMessage` raw passthrough. A front that forwards unknown `_meta` forwards all
  of it. [H] adapter READMEs
- **Plans:** a `plan` update with entries `{content, priority, status}`, replaced in full each time. v2 adds
  item-based `plan_update`. [H]
- **Modes and config options.** Session Config Options, with categories `mode`, `model`, `model_config` and
  boolean options, supersede Session Modes. v2 removes `session/set_mode`. The Codex adapter exposes approval
  policy, sandbox mode and permission profiles as config options. So a client can switch a Codex session to
  `agent-full-access` *through ACP*. [H]
- **Elicitation** (stable since 2026-07-22): `elicitation/create` comes in form mode (non-sensitive data, restricted
  JSON Schema) and URL mode (out-of-band, such as OAuth). For URL mode, clients MUST show the full URL and host and
  get consent, MUST NOT prefetch, and MUST open it "in a secure context that prevents the Client or Agent's
  language model from inspecting the page". The agent MUST verify that the person completing the flow is the
  person who started it. [H] https://agentclientprotocol.com/protocol/v1/elicitation
- **Subagents** (Active RFD, revised 2026-11-09): each subagent gets its own child session id, announced by
  `subagent_update` with a `title`, `description`, `cwd` and state. The Claude adapter implements it, reporting
  `requires_action` while a child's permission request is open. [H] https://agentclientprotocol.com/rfds/subagents
  and the claude-agent-acp README. This gives wicket the *reported* "who asked" for §11.1 in structured form,
  instead of matching `parent_tool_use_id`.

### 1.10 Proxies, conductors, and client-chosen LLM routing

- **Proxy chains** (Draft RFD; schema types behind `unstable_proxy_chains`, always on in the Rust SDK core):
  - A *conductor* spawns the proxies and the agent and presents them to the editor as one agent. It routes every
    message, wrapping hops in `proxy/successor`.
  - Proxies get `proxy/initialize`. A proxy MUST initialize its successor before answering. It MAY change the
    capabilities it reports upward, "to add a capability it implements or remove one it blocks", but MUST NOT
    change `protocolVersion`.
  - [H] https://agentclientprotocol.com/rfds/proxy-chains and `agent-client-protocol-conductor`
  - That is exactly the hook a wicket editor front needs.
- **Configurable LLM Providers** (Draft): `providers/list`, `providers/set` and `providers/disable`, so clients
  "route LLM requests through their own infrastructure". The Claude adapter and the Codex adapter's gateway auth
  already implement variants. [H] https://agentclientprotocol.com/rfds/custom-llm-endpoint

### 1.11 Who speaks ACP

**Agents.** Source: the live registry, `https://cdn.agentclientprotocol.com/registry/v1/latest/registry.json`, format
1.0.0, 45 agents, read 2026-11-10. [H]

| Agent | Native or adapter | Registry command (version) |
|---|---|---|
| Claude Code | Adapter `@agentclientprotocol/claude-agent-acp` (Agent SDK; standalone binary bundles `claude`) | npx or binary (0.104.1) |
| Codex | Adapter `@agentclientprotocol/codex-acp` (starts Codex App Server) | npx (2.6.0) |
| Gemini CLI | Native | `gemini --acp` (0.67.0) |
| goose | Native; also ACP over HTTP/WS with `goose serve` | `goose acp` (1.59.0) |
| OpenCode | Native (also an `opencode-v2` entry) | `opencode acp` (2.2.7) |
| GitHub Copilot CLI | Native | `copilot --acp` (1.0.109) |
| Cursor | Native | `cursor-agent acp` (2026.11.05) |
| Cline | Native | `cline --acp` (3.0.74) |
| Kiro | Native | `kiro-cli acp --agent-engine=v3` (3.0.0) |
| Junie (JetBrains) | Native | `junie --acp=true` |
| pi | Third-party adapter `pi-acp` | npx (0.0.34) |
| Others | Amp (adapter), Antigravity, Auggie, Devin, Factory Droid, Grok Build, Kilo, Kimi, Mistral Vibe, Qwen Code, Qoder, Poolside, IBM Bob, and about 20 more, including a "marketplace … settled in USDC" entry | — |

The registry's bar is low and it moves by itself. "Agent versions are automatically updated via a cron job that
runs hourly … and commits updates directly to `main`." Binary entries carry a sha256; **npx entries are just
`package@version`**. [H]

**Clients.** The spec's client page lists over 100. [H] https://agentclientprotocol.com/get-started/clients
- **Editors:**
  - Zed;
  - JetBrains IDEs, through AI Assistant, plus JetBrains Air, which has its own registry indexes;
  - Neovim, through CodeCompanion, agentic.nvim, avante.nvim and hermes.nvim;
  - Emacs, through agent-shell.el;
  - VS Code, through several extensions;
  - Visual Studio, through Poolside;
  - Qt Creator, Sublime Text, Pulsar and Obsidian plugins.
- **CLI and TUI clients:** Toad, OpenClaw's `acpx`, Orca and Hydra.
- **Desktop and web consoles:** dozens. Several are remote consoles for agents on other machines, such as tlbx,
  Reemoat, Skylands, and a "Remote Agent Server" that exposes ACP agents through a task API.

**Test kit.** `agentclientprotocol/acp-tck` launches an agent over stdio and checks initialization, lifecycle,
prompt turns, cancellation, errors and transport hygiene. It is labelled experimental: "a passing run is not an
official statement of ACP conformance". [H] https://agentclientprotocol.com/libraries/testing

### 1.12 Security model and known issues

**The spec's own trust model** (https://agentclientprotocol.com/protocol/v1/security): [H]
- "The Agent runs with whatever permissions its process is given. ACP itself does not sandbox it."
- "Permission requests are advisory."
- "Treat every Agent-authored string, URI, and path as untrusted, including replayed content."
- `clientInfo` and `agentInfo` "are self-reported … Clients SHOULD identify the Agent from their own launch
  configuration."
- **Out of scope:** "a malicious Agent binary, detecting prompt injection, and operating-system sandboxing".
- **Rendering rules** (the same family as design §14.1.3):
  - no scripts and no raw HTML;
  - no auto-fetching agent URIs, and automatic fetches only to `https`/`data`, never to loopback or private
    networks;
  - show link targets;
  - reveal bidi, zero-width and tag characters in commands, paths, URLs, diffs and permission requests;
  - neutralise terminal escapes;
  - throttle prompts.
- **Intermediaries** "can read and change every message, and each side treats it as the other". An agent serving
  several users "SHOULD scope `session/list`, session loading and resumption, permission requests, and
  elicitations to the user that owns the session".
- **Residual risk**, in the spec's words: "A user can approve a harmful operation, prompt injection can steer
  operations the user allowed, and an Agent can act without asking."

**Known issues and advisories:** [H unless marked]

| Where | What | Lesson for wicket |
|---|---|---|
| Zed GHSA-x34m-39xw-g2wr (critical, 2025-08) | The agent wrote `./.zed/settings.json` enabling `always_allow_tool_actions`, then ran anything | In-workspace config that controls approval is an escalation path; Claude's `allow_always` → `settings.local.json` is the same shape |
| Zed GHSA-c3g6, -rqq3, -c99f (2026-05) | Terminal allowlist bypassed with `PAGER=… git diff`, variable-expansion chains and arithmetic expansion | Never auto-approve on regexes over shell strings; the v2 `command` subject is still a string |
| Zed GHSA-f2g4-87h6-4pxq (2026-02) | Tool parameters weren't shown on approval | Show the full raw input; the spec now says the same |
| Zed GHSA-786m-x2vc-5235 (2026-02) | Symlink escape in agent file tools | Root checks must use resolved paths at time of use |
| Zed GHSA-63qj (2026-05) | Command injection through unquoted env keys over SSH/WSL remoting | Remoting an agent launch is its own injection surface |
| TS SDK HTTP adapter (2026-09, three advisories) | Unbounded buffering; out-of-memory | Remote ACP endpoints need limits and authentication |
| Toad (ACP client) | `fs/write_text_file` joins `project_root / path`, so an absolute path escapes [16 §2.11] | Clients get root checks wrong |
| claude-agent-acp #1094 | Approval replay semantics after `session/load` are unspecified | Never treat replayed approvals as current |
| claude-agent-acp #866 | An out-of-turn permission request deadlocked a background subagent in v1 | Long-held prompts need v2 states or wicket-side handling |
| claude-agent-acp #1196 (open) | A permission request was sent while in `bypassPermissions` | Adapter permission behaviour drifts by release; conformance-test it |

---

## 2. wicket as an ACP client driving any ACP agent in a box (the T2 adapter)

Design §6 already places ACP agents at T2: the official crate, `protocolVersion` 1 pinned, `session/request_permission`
held, a follow-up prompt after a grant. This section makes the T2 adapter concrete.

### 2.1 Launch and `initialize`

- **Process.** `wicket-node` starts the agent inside the box as in §6: model base URL → LLM proxy, a placeholder
  credential, `HTTPS_PROXY` and CA variables, and a root-owned managed config. Its stdio is the ACP pipe. That pipe
  is the box's channel to wicket, and it *is* the identity (§3.2: the socket is the box). No ACP auth secret is
  needed.
- **What wicket advertises** in `clientCapabilities`:
  - `fs`: **absent**;
  - `terminal`: **absent**;
  - `auth.terminal`: **absent** (wicket never runs interactive vendor logins in or for the box);
  - `elicitation`: form mode only, when the zone allows operator prompts, else absent;
  - `subagents`: on, for attribution;
  - `notices` and `compaction`: on, for observability;
  - boolean config options: on.
- **What wicket checks** in the agent's answer:
  - `protocolVersion == 1`;
  - `mcpCapabilities.http` (needed for the gateway);
  - `sessionCapabilities.systemPrompt` (for the sandbox notice);
  - `loadSession` / `resume` (for parking);
  - `agentInfo`, used **only for logging**: identity comes from the LaunchPlan.
- **Authentication.** wicket calls no `authenticate` and runs no terminal method. Credentials are placeholders
  swapped at the proxy. If the agent answers `auth_required`, that is a launch bug, reported as such.
  - Where an agent supports `providers/set` (Claude adapter, unstable), wicket *may* use it to point the agent at
    the LLM proxy instead of env vars. The env-and-managed-config route stays the default, because it doesn't
    depend on an unstable method.
- **Session setup.** `session/new {cwd: <box workspace>, mcpServers: [gateway], systemPrompt: {mode: append,
  content: [wicket sandbox notice]}}`.
  - `additionalDirectories` come only from the manifest.
  - The notice is the §9.5 text: what the sandbox is, what a block looks like, `request_access` and `await_grant`.
    Now that `systemPrompt` is stable, T2 agents get it the same way T1 Claude gets `--append-system-prompt`.
- **Agent-specific `_meta`, set by wicket only.** For the Claude adapter: `_meta.claudeCode.options` with
  `strictMcpConfig: true` and a pinned `settingSources` (per §6 lockdown and the context-files question §21.11).
  Disallowed tools mirror the ceiling. The adapter's `/remote-control` command stays effectively off: it can't
  reach `/v1/code/sessions` unless the zone is `vendor_rc`.
  - Root-owned managed settings (`allowManagedHooksOnly`, `allowManagedMcpServersOnly`) remain the backstop,
    because `_meta` is merged, not exclusive.

### 2.2 Mapping permission requests to wicket's decisions

There are two layers, as §14.1.2 says. An ACP prompt asks whether the agent may *attempt* something in the box.
Gates decide what actually crosses the boundary.

| Prompt is about | wicket answers (zone `agent_prompts` policy) | Why |
|---|---|---|
| An operation a gate mediates: `fetch`, a network command, a git push, a gateway MCP tool | `allow_once` | Let it reach the gate. The gate returns the typed 403 or MCP error with `request_id` and remedies, and the agent can `await_grant`. An ACP reject would only say "user refused". |
| An in-box operation inside the ceiling (`read`, `edit`, `execute` on workspace paths) | `allow_once` | The box contains it; prompting adds fatigue, not safety |
| An operation matching a mirrored deny rule (writing `.git/hooks/*`, agent or editor settings, MCP config; anything the spec says to ask about) | `reject_once`, then a follow-up steer explaining why | The spec's prompt-injection guidance says to ask before writing files that "control execution or approval"; wicket's extraction gate checks these files too |
| A mode or config change that lowers oversight (`switch_mode`, Codex `agent-full-access`, plan-exit to bypass) | `reject_once` | The spec: agents SHOULD NOT lower oversight "without user action"; wicket sets these, the model doesn't |
| Anything else, when the zone sets `agent_prompts: ask_operator` | Held open and forwarded as an agent-local prompt to channels with `answer_agent_prompts`; first answer wins | §14.1.2 rule 4 |

Rules for every answer:
- **Choose by `kind`, then check that the `optionId` exists.** Never decide on the option `name` or the tool
  `title`; the spec forbids relying on those for automatic approval. If no `allow_once` or `reject_once` option
  exists, reply `cancelled` if the turn is cancelled, else hold the prompt for an operator.
- **Never select `allow_always` or `reject_always`.** Both are in-box policy writes; Claude writes
  `settings.local.json`. They fall under `AgentCaps::persistent_policy_writes`. A forwarded prompt shows humans
  only the once-options. The design already has this rule for Codex; ACP needs it too.
- **Match policy on structure, not strings.** Use `kind`, `locations`, `rawInput` and the v2 `command` subject
  (`command`, absolute `cwd`), parsed with the same `Op` classifier the gates use. Command-string regexes failed
  four times in Zed in 2026.
- **Record the prompt as reported attribution.** With subagent sessions, the child session id and its
  `title`/`description` feed the §11.1 "For:" line as *reported*, not proven.
- **After a resume or `session/load`, re-ask.** Replayed outcomes are history, not decisions (#1094).

### 2.3 Serving file and terminal capabilities: outside the box, or inside it?

- **Outside the box: never.** If wicket served `terminal/create` from the host, it would execute agent commands
  outside the box. That would be a second, worse sandbox. Serving `fs/*` from the host would make wicket a file
  server for an untrusted agent, with every root-check bug the clients above have shipped.
- **Inside the box: possible, but not worth it.** wicket could answer `fs/*` and `terminal/*` by forwarding them to
  `wicket-guest` exec inside the box. That gives an audit point and lets the conformance suite check root
  handling. But it mediates nothing new: the agent's native tools still work, Claude never calls these methods,
  Gemini bypasses them outside the root, and v2 deletes them.
- **Decision:** don't advertise them. The audit trail comes from `tool_call` updates (which carry `kind`,
  `locations` and `rawInput`) plus the gates. If a future agent *requires* client fs, serve it inside the box
  through `wicket-guest`, never from the host.

### 2.4 MCP: wicket's gateway as the only server

- **Today:** one HTTP entry, `{type: "http", name: "wicket", url: <in-box forwarder to the gateway>,
  headers: [{name: "Authorization", value: <session-scoped, short-lived capability>}]}`.
  - The header sits inside the box, so it is a capability token bound to this zone and session, not a secret
    (as 01 noted).
  - The managed config forbids other servers. Any `mcpServers` the agent's own config tries to add is refused
    there.
- **Later: MCP-over-ACP.** The gateway would answer `mcp/message` on the ACP pipe the box already has, and the
  in-box header would go away. Tool calls would also bind to the ACP session, which is the box's identity, with
  no second channel.
  - For agents that can't consume it natively (all of them today), the Rust polyfill provides a loopback HTTP
    endpoint. It would have to run *inside* the box, in front of the agent, which is the same shape as wicket's
    current forwarders.
  - The gain is small until agents support it natively. Keep it behind `AgentCaps::host_tools`, test it in E-ACP3,
    and don't build on it while it targets one MCP revision and sits behind an unstable flag.
- **MRTR fits wicket's pending pattern.** A gateway tool that needs approval can return `input_required` with
  opaque state. The spec's warning applies: wicket must bind that state to the principal and request, give it an
  expiry and single use. It already does this for grants.

### 2.5 Pending, parking, cancel and steering

- **Short waits.** Hold `session/request_permission` open (no spec timeout) while policy or a human decides.
- **Long waits.** Prefer the gate path (allow the attempt, let the gate answer `pending_approval`, and the agent
  calls `await_grant`) over holding an ACP request for hours. A held request is one JSON-RPC id on a pipe. It
  doesn't survive a VM restore unless the agent re-issues it. In v1 it can strand background work (#866).
- **Parking.** `session/resume` (no replay) or `session/load` after restore. After either, wicket re-asks any
  prompt it had pending and treats replayed tool calls as history.
- **Cancel.** `session/cancel`, then answer every held prompt `cancelled` (a MUST); `$/cancel_request` for
  single requests.
- **Steer.** In v1, a follow-up `session/prompt` after the turn ends ("R-123 granted, retry"). In v2, a
  `session/prompt` while running is inserted or queued by spec. That is a standard steer, which §6's
  `AgentSession::send` can use when v2 lands.
- **Settled signal.** v2 `state_update: idle` (plus an empty `background` list) is the clean "settled" signal for
  `AgentCaps::settled_signal`, and `requires_action` is the clean "waiting on a human" signal. Until then:
  `stopReason` plus no open tool calls.

### 2.6 Claude Code over ACP stays the fallback, not the default

T1 (stream-json spoken from Rust) remains better for Claude Code. It has `defer`, typed output and no Node adapter
in the path, and the adapter ships several releases a day. The ACP adapter is the route when Claude is shown in an
editor (§3).

**A policy question for the owner.** The adapter runs the unmodified `claude` binary *through the Agent SDK*. The
design's rule is "subscription tokens are for the unmodified Claude Code binary only", and Anthropic says Agent
SDK products "should use API key authentication". Whether the owner's own subscription may back
`claude-agent-acp` in single-owner mode is a reading of Anthropic's terms, which design §6 defers to. Until the
owner decides, a Claude-in-Zed zone should use the T1 path behind a renderer (§3.2, option B), not the adapter.
[M]

---

## 3. wicket as an ACP front: an editor drives an agent that lives in a wicket box

The goal: a Zed (or JetBrains, Neovim, Emacs) user picks "Claude (wicket: zone fix-flaky-sync)" in the agent
panel. They chat, see tool calls and diffs, and approve agent-local prompts. The agent runs in a box with no
network and no credentials. This is the editor counterpart of `wicket wrap` for Remote Control (§14.1.4).

### 3.1 Why `wicket wrap -- some-acp-agent` is not enough

`wicket wrap` connects stdio through. For Remote Control that was fine, because the far end is Anthropic's
session service, reached only through the egress proxy. For an ACP editor the far end is **the user's editor on
the user's host**, and ACP gives the agent requests *into* that editor:
- **`terminal/create`**: Zed spawns the command on the host with no check of its own (§1.6). That is a box
  escape.
- **`fs/write_text_file`**: confined to Zed's project worktree. But that worktree is the user's real checkout,
  outside the box, so the agent could plant `.git/hooks/*` or `.zed/settings.json` (GHSA-x34m).
- **The editor's `session/new`** carries:
  - Zed's MCP servers, including stdio command lines and their env, often tokens;
  - the editor's `cwd` and extra roots;
  - an editor-supplied `systemPrompt`;
  - possibly `_meta.claudeCode.options` (env, hooks, settings, executable path).

  Passed through, these would put the user's credentials in the box and let editor config reshape the agent.
- **The launch env** Zed gives the agent process can include provider keys: "Zed passes … `GEMINI_API_KEY`".
- **Terminal auth** makes the editor re-run the configured command with login args, an interactive vendor login
  wicket must never perform.

So the front must parse ACP and filter it. The protocol has a role for this: a proxy that rewrites capabilities
("remove one it blocks") and messages, presented to the editor as an agent, as the conductor does.

### 3.2 Shape

```
Editor ──stdio──► wicket acp (ACP Agent role, on the user's machine or an SSH node)
                     │  authenticated wicket API (SO_PEERCRED locally; tailnet/mTLS remotely)
                     ▼
                 wicketd ── wicket-node ──stdio──► box: ACP agent (claude-agent-acp, gemini --acp, …)
```

Two ways to build the inside:
- **(A) Filtering proxy.** The box runs an ACP agent. wicketd is its client (§2) *and* relays a filtered view to
  the front. This is quick to build with the Rust SDK's `Proxy` role. It works only for T2 agents.
- **(B) Renderer.** The front renders wicket's normalised `AgentEvent` stream (§6) as ACP and turns ACP input into
  `OperatorAction`s. Any tier, including T1 Claude Code over stream-json, shows up in the editor, and there is one
  control path whatever the agent.

Recommendation: build (A) first for ACP-native agents, and grow it into (B). The filter rules below hold for both.
In both, **wicketd remains the ACP client of the boxed agent**, and the editor is only an operator channel. That
avoids the "first answer wins" race becoming a security question, because the editor never talks to the agent
directly.

### 3.3 Message rules at the front

| Editor → front | Rule |
|---|---|
| `initialize.clientCapabilities` | Recorded for rendering only. `fs`, `terminal` and `auth.terminal` are **never** offered to the boxed agent (wicketd's own `initialize` already omits them) |
| `initialize` result to the editor | `authMethods: []`; `loadSession`/`resume` per the zone; `mcpCapabilities` false (the editor can't add servers); no `systemPrompt` capability unless the zone lets operators add instructions |
| `session/new {cwd, additionalDirectories, mcpServers, systemPrompt, _meta}` | `cwd` must name a project or zone the principal may use; it selects, it does not define. The zone's mounts come from the manifest. **Drop** `additionalDirectories`, `mcpServers`, `systemPrompt` and all `_meta` except `traceparent` (logged). Editor process env is never forwarded into the box. |
| `session/prompt` | `OperatorAction::Message`: a steer with origin `AcpFront(principal)`, never trusted task text (§14.1.2 rule 2). Embedded `resource` blocks become **Attach as data**, with taint. |
| `session/set_config_option` / `set_mode` | Allowed only for an allowlisted set (model within the zone's models, effort). Anything that changes approval policy, sandbox mode or permission profile is refused. |
| `session/cancel` | Interrupt (allowed for `AcpFront`) |
| `session/close`, `session/delete` | Detach this editor view. They never stop or delete the zone; lifecycle stays wicket-native |
| `session/list`, `session/load`, `session/resume` | Scoped to the principal's sessions, as the spec's multi-user rule says |

| Box agent → front → editor | Rule |
|---|---|
| `session/update` content | Passed through, with handles dereferenced only up to the principal's clearance (labels) |
| `tool_call` locations, diffs, paths | **Path-mapped** from box paths to the editor's project paths, or the box mounts the workspace at the same absolute path. ACP requires absolute paths, and a mismatch makes the editor open the wrong file. |
| `session/request_permission` | Held by wicketd. Shown to the editor only if the zone sets `ask_operator`, with **only the once-options** and the full `rawInput`. The answer becomes an `AnswerAgentPrompt`. |
| `fs/*`, `terminal/*` | Never reach the editor (the agent wasn't offered them). If they arrive anyway: `-32601` method not found, plus an anomaly event |
| `elicitation/create` (agent) | Form mode is passed through, marked as agent-authored. **URL mode from the agent is dropped** (an approval-phishing vector), so URL elicitations in this editor come only from wicket (§3.4). |
| Unknown `_meta`, `_`-methods, AIR extensions | Dropped by default; allowlist per extension |
| `notice` updates from the agent | Rendered as agent text. The editor can't tell who wrote a notice, so a notice never implies authority |

### 3.4 Where approvals are answered

- **Agent-local prompts** (ACP `request_permission`) may be answered in the editor when the zone allows it. They
  are advisory: an editor "Allow" lets the agent *try* inside the box.
- **wicket escalations** (a gate opened `R-123`) are **announced** in the editor and **decided only in wicket**.
  The announcement is a wicket-authored notice: the typed request, the binding code, "approve in wicket".
- **Proposed handoff:** the front sends a URL-mode `elicitation/create` whose URL is the console's approval page
  for `R-123`. The spec makes the editor show the host and ask consent, and open it in a context the agent can't
  read. The page then asks for the passkey assertion over the request digest (§14.1.3).
  - The editor's elicitation reply (`accept` or `decline`) carries no authority. The ledger records the passkey
    decision.
  - This is safe only because the front drops agent-originated URL elicitations (§3.3). Otherwise the agent could
    draw a look-alike.
- `ChannelAuthority` for `AcpFront`, unchanged from [09 §7.1]:
  - observe: yes;
  - steer: yes;
  - answer agent-local prompts: yes;
  - decide escalations: **never**;
  - lifecycle: interrupt only;
  - amend task: no.

### 3.5 Who the editor user is

- **The principal comes from the connection, not from ACP.** `clientInfo` is self-reported and the spec says not
  to use it for security.
  - Locally, `wicket acp` connects to wicketd's host socket, and `SO_PEERCRED` gives the OS user, mapped to a
    registered operator.
  - Remotely (§4), it uses wicket's API authentication (passkey session, tailnet identity or mTLS).
- **Each front connection is a `ChannelId`** with that principal. The audit log tags every steer and every
  agent-local answer with it, as for the other channels (§14.1.2 rule 4).
- **Editor-side settings are the editor's business.** Zed's `agent_servers` entry may set `command`, `args` and
  `env` for `wicket acp`. wicket reads only its own flags (`--zone`, `--agent`) and ignores the env for anything
  that reaches the box.
- **Several editors on one zone** are several channels. First answer wins for agent-local prompts. Each sees only
  sessions it may observe.

### 3.6 How this relates to `wicket wrap`, Remote Control and issue #22

- **Like `wrap`:** the session process runs in a box, spawned on the user's behalf by a program wicket doesn't
  control. **Unlike `wrap`:** the far end has powers over the user's host, so the front must speak ACP. A
  generic stdio wrap is right only when the far end is a vendor service behind the egress proxy.
- **Compared with `vendor_rc`:**
  - the transcript stays with wicket and the editor, with no vendor session store, so zones not cleared for
    `anthropic.session_store` can still have an editor UI;
  - it works for any ACP agent, not only Claude Code;
  - wicket needs no tap: as the ACP client it already has the structured transcript.

  That partly answers issue #22's "wicket-native view of the session transcript" for ACP sessions. For RC, the
  tap is still needed.
- **The Claude adapter's `/remote-control` command** can turn on RC from inside an ACP session. In a wicket box it
  fails closed, because the egress proxy denies `/v1/code/sessions/**` outside `vendor_rc`. The §6.1 suite
  should check this per release (it touches E-RC3 and E-RC5 in #22).

---

## 4. Remote transport and multi-host

- **Inside a node, keep ACP on stdio.** It runs between `wicket-node` and the box: no listener, no network
  identity, and the pipe is the box's identity (§3.2). Never expose a boxed agent's ACP on the network. The
  HTTP/WS transport has no authentication of its own, no replay in v1, and a fresh advisory history.
- **Between nodes and wicketd, use wicket's own channel** (SSH today, QUIC later, per §21.12). It carries
  normalised events and operator actions, with a numbered, acknowledged, resumable event stream. The things the
  ACP transport RFD defers to v2 (message ids, resumption, keepalive) are what wicket's node link must have
  anyway. Don't wait for ACP to provide them.
- **Pending prompts live in the ledger, not the pipe.** If an editor drops off, an agent-local prompt it was shown
  is shown again on reconnect. If the boxed agent restarts, wicket re-asks or re-derives. This is the same
  property E-CX3 checks for Codex app-server.
- **Editors on other machines: three routes.**
  1. *Local front, remote wicketd*: `wicket acp` runs on the laptop (stdio to the editor) and talks to wicketd
     over the authenticated API. This is the simplest route, and works for every editor.
  2. *Zed SSH remoting to a node*: Zed resolves and runs the agent command on the remote host [M]. So
     `wicket acp` runs on the node, and Zed's remote server serves the editor's file and terminal requests there,
     outside the box. The front's filtering (§3.3) is what keeps that safe. The editor's project directory on the
     node must be the zone's extracted workspace view (read-only, or patch-gated), not a live mount of the box.
  3. *ACP over WebSocket to wicketd*: once the RFD is stable and an editor supports it, wicketd could expose
     `/acp` behind its own authentication (passkey session cookie or mTLS; the RFD's mandatory cookie support
     helps). It needs body and stream limits from day one. Zed has no remote ACP client today (no HTTP or
     WebSocket in `agent_servers`) [M], so this is for web consoles first.
- **Several boxes, several hosts, one editor.** ACP subagent sessions (child session ids under a parent) are a
  natural way for the front to show a *crew* (§13.7) as one parent session with children per box. That is a
  rendering choice. The child "sessions" are wicket agents with their own identities, not the agent's subagents.
  [L]

---

## 5. What to borrow, what to avoid

**Borrow:**
1. **`systemPrompt: {mode: append}`** for the sandbox notice on T2 agents that advertise it. Content wicket trusts
   at system level, which is the only kind the spec says to send.
2. **The v2 `requires_action` / `idle` states and the `background` list** as `AgentCaps::settled_signal` and
   "waiting on a human", when v2 lands behind a flag.
3. **The v2 `command` permission subject** (command plus absolute `cwd`) as structured input to the `Op`
   classifier for agent-local prompts.
4. **The proxy/conductor model** (rewrite capabilities, wrap hops) for `wicket acp`. The Rust SDK's `Proxy` role
   and `agent-client-protocol-conductor` are reference code, and the editor sees one agent.
5. **The security page's rendering list**. It matches §14.1.3 almost line for line. Add its specific items:
   neutralise terminal control sequences in `terminal/output`, and throttle prompts and elicitations.
6. **URL-mode elicitation as the approval handoff** into the console's passkey page (§3.4), with agent URL
   elicitations dropped.
7. **Subagent sessions** for reported attribution (§11.1) in structured form.
8. **acp-tck** in §6.1, run against each pinned T2 agent and against `wicket acp` itself (as an agent).
9. **Registry metadata** for installs (command, args, env such as auto-update switches, sha256 for binaries),
   frozen into the image at build time with wicket's own hashes.
10. **W3C trace context in `_meta`** to correlate an ACP tool call with the gate decision and ledger entry in the
    audit log.

**Avoid:**
1. Treating any ACP permission answer, any editor click, or `clientInfo`/`agentInfo` as authority.
2. `allow_always` / `reject_always`, and any config option that lowers oversight.
3. Offering `fs`/`terminal` to a boxed agent, and above all relaying them to a real editor.
4. Passing editor `mcpServers`, env, `_meta`, `systemPrompt` or `additionalDirectories` into a box.
5. Auto-approval by regex over command strings or by `title`/`name`.
6. Exposing ACP over HTTP or WebSocket without wicket's own authentication and limits.
7. Following the registry's `latest` (hourly, unreviewed version bumps; npx entries without hashes).
8. Shipping v2, MCP-over-ACP, proxy chains or `providers/*` by default while they are Draft, Active or unstable.
   Use them behind flags with conformance tests.
9. Holding ACP permission requests for hours as the main pending mechanism (#866, and no replay). Use the gates'
   typed pending and `await_grant`.

---

## 6. Proposed design changes

1. **§6 T2 row: make the client posture explicit.** Proposed text:
   - "wicket advertises no `fs`, `terminal` or `auth.terminal`;
   - it sends the gateway as the only MCP server and the sandbox notice via `systemPrompt` append;
   - it answers prompts only with `allow_once` or `reject_once`, chosen by `kind` and matched on structure;
   - gate-mediated operations are allowed to reach the gate;
   - replayed approvals after `load`/`resume` are never honoured;
   - agent-specific `_meta` (`claudeCode.options`) is set by wicket only."
2. **§6 `AgentCaps`:** list ACP `allow_always` under `persistent_policy_writes`. For the Claude adapter it writes
   `.claude/settings.local.json`. Also add that file to the extraction gate's control-file list, with git hooks
   and editor or agent settings.
3. **§6.1 conformance, new cases:**
   - **(14)** the agent never calls `fs/*` or `terminal/*`, and gets `-32601` if it tries;
   - **(15)** after the suite, no `settings.local.json` or other "always" state was written;
   - **(16)** a replayed approval after `session/load` is not treated as current;
   - **(17)** `acp-tck` passes for the pinned agent;
   - **(18)** for the Claude adapter, `/remote-control` fails closed outside `vendor_rc`.
4. **§14.1.1: restore `ChannelKind::AcpFront`**, with `ChannelCaps {observe, message, control: interrupt only,
   answer_agent_prompts, decide_escalations: false}`. It was in [09 §7.1] but dropped from the design. Add a short
   **§14.1.5 "Editor front (`wicket acp`)"** with the rules of §3.3–§3.5: the filter table, path mapping, the
   principal from the connection, and the URL-elicitation handoff.
5. **§14.1.4 vendor coexistence:** say that for ACP-capable agents, the editor front is the preferred
   "comfortable remote UI" when the zone's labels don't clear a vendor session store.
6. **§21 open questions, add:**
   - whether the owner's subscription may back `claude-agent-acp` (the Agent SDK running the unmodified binary) in
     single-owner mode (§2.6);
   - what the editor's project directory is for a boxed session (extracted view, read-only mirror, or
     same-path mount) and how diffs flow back (§3.3, §4).
7. **§21.12 node transport:** note that the ACP HTTP/WS transport defers replay and keepalive to v2. wicket's own
   node link must provide them, and is not replaceable by ACP remote transport.

---

## 7. Experiments

- **E-ACP1:** drive `gemini --acp`, `goose acp`, `opencode acp` and `claude-agent-acp` from wicketd with no `fs`/`terminal`
  offered. Check that each still edits and runs commands in the box, and record what `request_permission`
  traffic each emits (kinds, option sets, `rawInput` shape).
- **E-ACP2:** hold a `request_permission` for 1 minute, 1 hour and across a park and resume, for each agent. Record
  timeouts, re-issues and stranded background work.
- **E-ACP3:** MCP-over-ACP with the polyfill inside the box against the gateway. Compare it with the HTTP-plus-header
  route for latency, failure modes, and whether the in-box header disappears.
- **E-ACP4:** a `wicket acp` front in Zed (local, then SSH remote). Red-team the filter: the agent tries
  `terminal/create`, `fs/write_text_file`, URL elicitations and look-alike notices; the editor sends MCP servers,
  env and `_meta.claudeCode.options`. Check path mapping on diffs and "follow agent".
- **E-ACP5:** a Codex-via-ACP config-option downgrade (`agent-full-access`) attempted from the front and from the
  model. It must be refused in both cases.

---

## Sources

Spec and RFDs (agentclientprotocol.com, mirrored in `github.com/agentclientprotocol/agent-client-protocol` `docs/`,
read at `8c390fb`):
- Overview, initialization, transports, session setup, prompt turn, tool calls, file system, terminals,
  authentication, extensibility, elicitation, session config options, session modes, agent plan, security:
  https://agentclientprotocol.com/protocol/v1/overview (and siblings under `/protocol/v1/`)
- v2: https://agentclientprotocol.com/protocol/v2/prompt-lifecycle, https://agentclientprotocol.com/protocol/v2/migration,
  https://agentclientprotocol.com/rfds/v2/overview, `/rfds/v2/permission-requests`,
  `/rfds/v2/client-filesystem-terminal-capabilities`, `/rfds/v2/background-work`
- RFDs: `/rfds/streamable-http-websocket-transport`, `/rfds/mcp-over-acp`, `/rfds/proxy-chains`,
  `/rfds/custom-llm-endpoint`, `/rfds/subagents`, `/rfds/auth-methods`, `/rfds/about`
- Announcements: `/announcements/acp-v2-draft`, `/announcements/transports-working-group`,
  `/announcements/client-system-prompt-stabilized`, `/updates`
- Community: `/community/governance`, `/community/working-interest-groups`
- Clients, agents, registry and testing: `/get-started/clients`, `/get-started/agents`, `/libraries/testing`

Repositories and data (via `gh api`, raw files and clones, 2026-11-10):
- Releases and health: `gh api repos/agentclientprotocol/{agent-client-protocol,rust-sdk,typescript-sdk,claude-agent-acp,codex-acp,registry}`
  and `/releases`
- Registry: https://cdn.agentclientprotocol.com/registry/v1/latest/registry.json and https://github.com/agentclientprotocol/registry
- Rust SDK: https://github.com/agentclientprotocol/rust-sdk (`agent-client-protocol` 5.1.0, `-http`, `-polyfill`,
  `-conductor`); crates.io API
- Claude adapter: https://github.com/agentclientprotocol/claude-agent-acp (`README.md`, `CHANGELOG.md`,
  `src/permissions/effects.ts`, `src/permissions/modes.ts`, `src/new-session-meta.ts`, `src/v1/acp-agent.ts`,
  `src/providers.ts`, `src/auth-methods.ts`, `src/remote-control.ts`); issues #866, #1094, #1196
- Codex adapter: https://github.com/agentclientprotocol/codex-acp (README)
- Gemini CLI: https://github.com/google-gemini/gemini-cli/blob/main/packages/cli/src/acp/acpFileSystemService.ts
- Zed: https://github.com/zed-industries/zed (`crates/agent_servers/src/acp.rs`, `crates/agent_servers/src/acp/v1.rs`,
  `crates/project/src/agent_server_store.rs`, `crates/acp_thread/src/acp_thread.rs`, `Cargo.toml`) and
  https://zed.dev/docs/ai/external-agents
- Advisories: `gh api repos/zed-industries/zed/security-advisories` (GHSA-x34m-39xw-g2wr, GHSA-c3g6-c3ff-69cg,
  GHSA-rqq3-p6x4-q866, GHSA-c99f-97vf-4h5h, GHSA-f2g4-87h6-4pxq, GHSA-786m-x2vc-5235, GHSA-63qj-jc2q-7hg5);
  `gh api repos/agentclientprotocol/typescript-sdk/security-advisories` (GHSA-p29f-jffj-96g8,
  GHSA-6q4g-4xp9-ch96, GHSA-xwmv-pq97-hp3w)

wicket context: design §3.2, §6, §9.5, §11.1, §14.1, §21.12; research [01 §2.1], [09 §2, §7.1], [16 §2.11];
issue #22 (`gh issue view 22 -R public/wicket`).
