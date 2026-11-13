# 01 — Inner agents: driving and boxing Claude Code and other agents

Research date: 2026-11-08. Scope: the agent *inside* a wicket zone. The harness treats it as a black box, but
should be Claude-first (Claude Code / Claude Agent SDK) and agent-agnostic.

Reference version: the Claude Code docs at code.claude.com are versioned only by "requires vX" notes; the latest
version referenced in the docs on 2026-11-08 is **v2.1.319**, which is also the version installed on the research box.
Claude Code changes almost daily (many docs sentences read "Before v2.1.2xx, …"), so every Claude Code fact below
should be treated as "true at 2.1.319" and re-checked by a CI conformance suite (see section 4.7).

Confidence markers: **[verified]** = read in a primary source today; **[likely]** = strong inference from primary
sources; **[unverified]** = could not confirm, treat as a hypothesis to test.

---

## TL;DR — facts that drive the design

1. **Claude Code is drivable headlessly over a documented NDJSON protocol.** `claude -p --input-format stream-json
   --output-format stream-json --verbose` gives a bidirectional stream; the Agent SDKs (Python, TypeScript) are thin
   wrappers that spawn the CLI and speak a `control_request`/`control_response` sub-protocol on the same pipes
   (`can_use_tool`, `hook_callback`, `mcp_message`, `interrupt`, `set_permission_mode`, …). There is **no official
   Rust SDK**; several community crates exist. Wicket should speak the wire protocol directly from Rust. [verified]
2. **Anthropic's own guidance is wicket's pattern.** The Agent SDK "Securely deploying AI agents" page recommends "a
   proxy outside the agent's security boundary that injects credentials into outgoing requests", via
   `ANTHROPIC_BASE_URL` for model traffic and a TLS-terminating `HTTPS_PROXY` (with its CA installed in the box) for
   everything else. Claude Code on the web does exactly this for GitHub (a "GitHub proxy" swapping a scoped credential
   for the real token) and for user "network secrets". [verified]
3. **The model credential can stay entirely outside the box**: set `ANTHROPIC_BASE_URL` to wicket's LLM proxy and
   `ANTHROPIC_AUTH_TOKEN` to a per-session *placeholder capability*; the proxy verifies it and substitutes the real
   API key. Claude Code then needs **no direct internet hosts at all** if nonessential traffic, auto-update, the
   WebFetch preflight and claude.ai connectors are switched off. Subscription (claude.ai OAuth) login is
   policy-restricted for third-party products; plan on API keys / cloud providers. [verified, with caveats in 1.9]
4. **Claude Code already has a native "permission pending" primitive.** A `PreToolUse` hook (or SDK hook) returning
   `permissionDecision: "defer"` ends the turn with `stop_reason: "tool_deferred"` and a `deferred_tool_use`
   record; the host later runs `claude -p --resume <id>` and the same tool call re-fires the hook, which can now
   allow/deny. No timeout. Limits: `-p` only, and only when the turn contains a single tool call. The SDK
   `canUseTool` callback may also stay pending indefinitely. MCP servers can answer a call with an **MCP task**
   (MCP tasks extension, protocol revision 2026-07-28; Claude Code public beta since v2.1.304). [verified]
5. **Hooks, permission rules, the built-in sandbox, OTel and stream-json are all agent-side.** They execute in the
   agent's own trust domain and are therefore *advisory telemetry and UX*, not enforcement. Complete mediation must
   come from the outer box (microVM/container with no route out except wicket's proxies). Anthropic's docs say the
   same: the built-in sandbox covers Bash only; file tools, MCP servers and hooks run outside it. [verified]
6. **Anthropic ships a reusable egress-decider design.** `@anthropic-ai/sandbox-runtime` (Apache-2.0, v0.0.81)
   includes `srt proxy`: a TLS-terminating HTTP proxy that holds no policy and asks an external **decider** process
   (NDJSON protocol v1) for an allow/deny/need_body verdict per request, with per-request credential injection.
   Its protocol is a good template for wicket's proxy↔policy interface even if wicket implements the proxy in Rust.
   [verified]
7. **ACP is the agent-agnostic tier.** Agent Client Protocol v1 (stable `protocolVersion` 1; v2 is a draft;
   governed by Zed + JetBrains) is JSON-RPC over stdio. It passes MCP servers per session in `session/new`, and
   `session/request_permission` is an ordinary request the client may hold open (the spec sets no timeout) and
   answer under policy. The spec says permissions are *advisory* and ACP does not sandbox. There is an official Rust
   crate, `agent-client-protocol` 5.0.0 (2026-11-02), with Client/Agent/Proxy/Conductor roles. Native or adapter
   support covers Gemini CLI, goose, OpenCode, Cline, Copilot CLI, Cursor, Codex (adapter over Codex app-server),
   Claude Code (adapter `@agentclientprotocol/claude-agent-acp`) and about 20 more. Draft RFDs worth watching:
   MCP-over-ACP (gateway tools ride the ACP pipe, no network path needed) and Configurable LLM Providers (a standard
   way to point any agent at an LLM proxy). [verified by sub-agent, section 2]
8. **Every surveyed agent can route its model traffic to an outside proxy** via a base-URL override (Codex
   `model_providers.*.base_url`, `GOOGLE_GEMINI_BASE_URL`, OpenCode `baseURL`, `GOOSE_PROVIDER__HOST`, aider
   `OPENAI_API_BASE`) with a dummy key, and each has a "managed" config layer that can be pinned read-only in the
   image (Codex `/etc/codex/requirements.toml`, Gemini `/etc/gemini-cli/settings.json`, OpenCode
   `/etc/opencode/opencode.json`). CA injection is fragmented (`NODE_EXTRA_CA_CERTS`, `CODEX_CA_CERTIFICATE`,
   `SSL_CERT_FILE`, system store), so wicket must set all of them. [section 2]
9. **Prior art has converged on "placeholder in the box, substitution at the egress proxy"** (Docker Sandboxes,
   E2B, Daytona, Cloudflare, Vercel, Codex cloud, Claude Code cloud, microsandbox, iron-proxy, srt). What nobody
   ships: a typed denial/escalation contract with a request id, attenuable placeholders, information-flow labels,
   generic handles, and one policy plane over HTTP, git, MCP and LLM traffic. Docker Sandboxes' approval queue
   (`sbx policy approval`) is the only productised per-request async approval. These are wicket's gaps to fill.
   [section 3]

---

## 1. Claude Code as the tier-1 inner agent

### 1.1 Headless / print mode and stream-json I/O [verified]

Source: <https://code.claude.com/docs/en/headless>, <https://code.claude.com/docs/en/cli-reference>.

- `claude -p "<prompt>"` runs non-interactively. Exit 0 on success, non-zero on failure; failures inside the run
  (e.g. missing auth) are printed as the result on stdout.
- `--output-format text|json|stream-json`. `json` yields one object with `result`, `session_id`, `total_cost_usd`
  plus per-model cost breakdown, usage, `permission_denials`, and — with `--json-schema '<schema>'` — a validated
  `structured_output` field (absent if the run ended without valid output, e.g. Claude declined).
- `stream-json` (requires `--verbose`; `--include-partial-messages` adds token deltas as `stream_event`) emits NDJSON:
  `system/init` (model, tools, `mcp_servers` with status, `mcp_server_errors`, plugins, and a `capabilities` array of
  protocol feature strings such as `interrupt_receipt_v1` for feature detection instead of version comparison),
  `assistant`/`user` messages (with `parent_tool_use_id` for subagent attribution), `system/api_retry`,
  `system/permission_denied`, `system/session_state_changed` (`idle | running | requires_action`), hook events
  (`--include-hook-events`), and a final `result` message.
- `--input-format stream-json` keeps stdin open as a message stream: the host can push further user messages
  mid-session (important: this is how wicket can *nudge* the agent after an escalation is granted, see 4.5).
  `--replay-user-messages` echoes them back for acknowledgement.
- Useful flags for a harness: `--bare` (skip auto-discovery of hooks, skills, plugins, MCP servers, CLAUDE.md, auto
  memory; "recommended mode for scripted and SDK calls, and will become the default for `-p`"), `--settings
  <file|json>`, `--setting-sources user,project,local`, `--mcp-config`, `--strict-mcp-config`, `--tools`,
  `--allowedTools`/`--disallowedTools`, `--permission-mode`, `--permission-prompt-tool`, `--permission-prompts
  host|none` (v2.1.259+), `--max-turns`, `--max-budget-usd`, `--session-id <uuid>`, `--resume <id|path.jsonl>`,
  `--no-session-persistence`, `--json-schema`, `--append-system-prompt[-file]`, `--model`, `--fallback-model`,
  `--add-dir`.
- SIGTERM → exit 143, in-progress turn left unfinished; SIGINT or SDK `interrupt()` ends the turn cleanly. Without
  `--bare`, a `-p` run still discovers and **executes the repository's `.claude/settings.json` hooks and connects
  `.mcp.json` servers without a trust dialog** (see 1.4) — a harness must not rely on defaults.
- Background work: after the turn, `-p` waits (default cap 10 min, `CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS`) for
  background commands/subagents. Wicket should usually set `CLAUDE_CODE_DISABLE_BACKGROUND_TASKS=1` so "turn
  ended" means "agent idle".

### 1.2 Agent SDK (TS/Python) and the Rust question [verified]

Sources: <https://code.claude.com/docs/en/agent-sdk/overview>, SDK source
<https://github.com/anthropics/claude-agent-sdk-python> (`_internal/query.py`, `_internal/transport/subprocess_cli.py`).

- The Agent SDK "is a library that runs the Claude Code binary". The Python transport literally builds
  `claude --output-format stream-json --verbose --input-format stream-json [--permission-prompt-tool stdio]
  [--mcp-config …] [--strict-mcp-config] [--settings …] …` and then exchanges messages.
- Control sub-protocol on the same pipes: the host sends `{"type":"control_request","request_id":…,"request":
  {"subtype":"initialize","hooks":…,"agents":…}}`; later `interrupt`, `set_permission_mode`, `set_model`,
  `mcp_status`, `mcp_reconnect`, `mcp_toggle`, `rewind_files`, `stop_task`, `get_context_usage`. The CLI sends
  the host `can_use_tool` (tool name, input, `tool_use_id`, `agent_id`, `decision_reason`, suggestions),
  `hook_callback` (for hooks registered by the host at initialize), and `mcp_message` (for in-process "SDK MCP
  servers"). Responses are `control_response` with `behavior: allow|deny`, `updatedInput`, `updatedPermissions`,
  `message`, `interrupt`. `control_cancel_request` cancels an outstanding request.
- The SDK docs explicitly say: "To drive the same agent loop from a language other than Python or TypeScript, run
  the CLI as a subprocess with the `-p` flag and `--output-format json`." The control sub-protocol itself is **not
  documented as a standalone spec**; its types are documented indirectly through the TypeScript SDK reference
  (<https://code.claude.com/docs/en/agent-sdk/typescript>). Treat it as a versioned-but-moving interface; gate
  features on the `capabilities` array.
- **Rust:** no official crate (Anthropic ships first-party SDKs for Python/TS/Go/Java/C#/PHP/Ruby for the *API*,
  and the Agent SDK only for Python/TS). Community crates: `claude-agent-sdk-rs` (0.6.x), `claude-code-agent-sdk`
  (0.1.x, Feb 2026), `rusty_claw`, an older `claude-agent-sdk` (Sept 2025). None is authoritative
  (<https://docs.rs/crate/claude-agent-sdk-rs/latest>, <https://lib.rs/crates/claude-code-agent-sdk>). **Recommendation:**
  wicket implements its own small Rust client for the wire protocol (it needs only: spawn, NDJSON framing, the
  ~6 message types it acts on, `can_use_tool`/`hook_callback` responders, interrupt), with a conformance test
  against each pinned CLI version. Avoid depending on a community crate for a security-relevant parser.
- Licensing/policy note: "Unless previously approved, Anthropic does not allow third party developers to offer
  claude.ai login or rate limits for their products, including agents built on the Claude Agent SDK. Use the API key
  authentication methods…" Agent SDK use is under the Commercial Terms.

### 1.3 Claude Managed Agents with self-hosted sandboxes — a "brain outside the box" variant [verified]

Source: <https://platform.claude.com/docs/en/managed-agents/self-hosted-sandboxes> (beta header
`managed-agents-2026-04-01`).

Anthropic now also offers **Managed Agents**: Anthropic runs the agent loop; a `self_hosted` environment is a work
queue served by an **environment worker** you run (`ant beta:worker poll`, or SDK workers in Python/TS/Go). The worker
claims a session, receives tool calls, runs them locally and posts results back. The worker needs only outbound
HTTPS. Partner guides exist for E2B, Daytona, Modal, Cloudflare, Fly.io Sprites, Vercel, GKE Agent Sandbox, AWS
Lambda MicroVMs and others.

Why it matters for wicket: this is the cleanest possible inner agent from a boxing perspective — the reasoning
process never runs inside the sandbox at all, so the box only executes tool calls. A wicket worker could hold the
environment key *outside* the zone and execute each tool call inside the zone's microVM, giving wicket a typed,
per-tool-call interception point with no agent process to trust. Caveats: tool inputs/outputs flow through
Anthropic; sessions are not ZDR/HIPAA eligible; only `memory_store` resources in self-hosted mode. Worth a
"tier 1b" adapter (section 4.3).

### 1.4 Settings, managed policy, permission rules [verified]

Sources: <https://code.claude.com/docs/en/settings>, <https://code.claude.com/docs/en/managed-settings>,
<https://code.claude.com/docs/en/permissions>, <https://code.claude.com/docs/en/settings-reference>.

- Precedence: managed (server-managed > MDM/OS policy > file) > CLI `--settings` > local > project > user. On Linux
  the file-based policy is `/etc/claude-code/managed-settings.json` (+ `managed-settings.d/` drop-ins and
  `managed-mcp.json`). **Wicket should materialise these as root-owned, read-only files in the box image** so the
  agent (running as an unprivileged user) cannot edit its own policy.
- Managed-only locks useful to a harness: `allowManagedPermissionRulesOnly`, `allowManagedHooksOnly`,
  `allowManagedMcpServersOnly` (+ `allowedMcpServers`/`deniedMcpServers`), `managedMcpServers`,
  `strictPluginOnlyCustomization`, `disableSideloadFlags` (rejects `--mcp-config`, `--plugin-dir`, `--agents`),
  `sandbox.network.allowManagedDomainsOnly`, `sandbox.filesystem.allowManagedReadPathsOnly`, `policyHelper`
  (executable that computes managed settings at startup), `forceRemoteSettingsRefresh`.
- An embedding host can pass *parent settings* via the SDK `managedSettings` option; Claude Code keeps only values
  that restrict, and ignores them when an admin source exists unless `parentSettingsBehavior: "merge"`.
- Permission rule syntax: `Tool` or `Tool(specifier)` in `permissions.allow|ask|deny`; e.g. `Bash(git diff *)`,
  `Read(./src/**)`, `Edit(...)`, `WebFetch(domain:example.com)`, `mcp__server__tool`, `mcp__server__*`,
  `Agent(name)`. Deny > ask > allow. Modes: `default`/Manual, `acceptEdits`, `plan`, `auto` (server-side classifier),
  `dontAsk`, `bypassPermissions`. Since v2.1.302, `-p` runs start in Manual mode when nothing sets a mode, and calls
  that would prompt are denied unless a host (`canUseTool` or `--permission-prompt-tool`) or a `PermissionRequest`
  hook approves.
- **Repository content is a config-injection vector.** Under `claude -p` in an untrusted folder, the repo's hooks,
  `env` block, `apiKeyHelper` and `.mcp.json` servers are *used without asking*; only `permissions.allow` rules
  wait for trust. Mitigations (from the docs): `--setting-sources user`, `--bare`, `--settings
  '{"disableAllHooks":true}'`, `disabledMcpjsonServers`, plus managed locks. For wicket, also: the repo's `env`
  block could set `ANTHROPIC_BASE_URL`/`HTTPS_PROXY` — harmless if the box has no other route out, but use
  `CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST` (makes Claude Code ignore provider/endpoint/auth variables from settings
  files) and pass everything via process env + managed settings.
- Claude Code's self-hosted runner has a `--confine-repo-settings enforce` guard that scans committed settings for
  out-of-workspace grants, non-empty `env` blocks and `sandbox.enabled:false`
  (<https://code.claude.com/docs/en/self-hosted-environments-deploy>). Wicket should do the equivalent scan before
  launch and record findings as labels.

### 1.5 Hooks: telemetry and an *extra* enforcement point, never the only one [verified]

Source: <https://code.claude.com/docs/en/hooks>.

Hook events include `SessionStart`, `Setup`, `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`,
`PostToolUse`, `PostToolUseFailure`, `PostToolBatch`, `PermissionDenied` (auto mode only), `Notification`,
`SubagentStart/Stop`, `Stop`, `PreCompact`, `SessionEnd`, `Elicitation`, and more. Handler types: `command`, `http`
(POSTs the hook JSON to a URL; header env interpolation only for `allowedEnvVars`; `onFailure: continue|block`,
v2.1.295+), `mcp_tool`, `prompt`/`agent`. SDK hosts can register hooks as in-process callbacks via the control
protocol (`hook_callback`).

`PreToolUse` decision control: `permissionDecision: allow|deny|ask|defer`, `permissionDecisionReason` (shown to
Claude on deny), `updatedInput` (rewrites the call), `additionalContext`. Precedence deny > defer > ask > allow.

How wicket can use hooks:
- **Telemetry**: an `http` hook (or SDK `hook_callback`) on `PreToolUse`/`PostToolUse`/`SubagentStart` streams
  typed tool-intent events (tool name, input, `tool_use_id`, agent id) to the control plane *before* execution, which
  lets the policy engine pre-warm escalations and correlate proxy denials with the tool call that caused them.
- **Early, friendly denials**: deny with a structured reason before a doomed network call, so the agent gets a clean
  message instead of a TLS error.
- **Defer** for pending escalations (1.10).

Why hooks must not be the only enforcement point:
1. They run *inside the agent's trust domain* (the agent process evaluates them; command hooks run as the agent's
   user). A compromised or prompt-injected agent that gains code execution can edit unmanaged settings, kill the
   hook server, or simply do the dangerous thing from a subprocess the hook never sees.
2. They see *intent strings*, not effects: `Bash(python x.py)` reveals nothing about the sockets `x.py` opens. Shell
   parsing is a known weak spot (the permissions doc has long sections on compound commands, wrappers, `eval`,
   `FOO=bar cmd` forms).
3. They fail open by default (`onFailure: "continue"`), are skipped in some modes (`--bare` ignores `--settings`
   hooks), and `defer` is ignored when a turn has several tool calls.
4. Semantics churn release to release (dozens of "Before v2.1.xxx" notes on the hooks page).
5. They cover only Claude's own tools — not MCP servers' outbound calls, not child processes, not WebSearch (which
   runs server-side at Anthropic).

So: hooks = "intent telemetry + UX", enforcement = outer box + egress proxy + MCP gateway, consistent with the
reference-monitor requirements in the origin brief (complete mediation, tamper-proof, small).

### 1.6 Built-in sandbox and Anthropic's sandbox-runtime (`srt`) [verified]

Sources: <https://code.claude.com/docs/en/sandboxing>, <https://code.claude.com/docs/en/sandbox-environments>,
<https://github.com/anthropics/sandbox-runtime> (README, `docs/srt-proxy.md`), blog
<https://www.anthropic.com/engineering/claude-code-sandboxing> (Oct 2025).

- **Built-in Bash sandbox** (off by default; `sandbox.enabled`): wraps Bash/PowerShell/Monitor commands only.
  macOS: Seatbelt (`sandbox-exec`, generated profiles). Linux/WSL2: bubblewrap + a network namespace with *no*
  network, plus socat bridges to HTTP and SOCKS5 proxies the Claude Code process runs on the host side (Unix sockets
  bind-mounted in). Allowed domains start empty; the proxy filters by hostname (no TLS inspection by default) and
  refuses names resolving to loopback/link-local/own addresses (metadata endpoint). Reads default to "most of the
  machine"; writes to cwd + temp + added dirs; protected paths (`.git/hooks`, `.claude/…`, shell rc files) stay
  write-denied.
- Escape hatch: on failure Claude may retry with `dangerouslyDisableSandbox`; disable with
  `allowUnsandboxedCommands: false` (strict mode) and `failIfUnavailable`.
- **New since the 2025 blog: credential masking.** `sandbox.credentials` entries with `mode: "mask"` show sandboxed
  commands a per-session *sentinel* and the sandbox proxy substitutes the real value on outbound requests to
  `injectHosts`, which requires the experimental `network.tlsTerminate`. It even re-signs AWS SigV4 requests. This
  is exactly wicket's "handles/placeholders, proxy injects" idea — but the real secret still lives *in the Claude
  Code process's memory and environment on the same machine*, so it protects against a sandboxed Bash command, not
  against a compromised agent process. Wicket's version must keep the secret in a different trust domain.
- `network.httpProxyPort` / `socksProxyPort` let you replace the built-in proxy with your own; or set
  `HTTPS_PROXY` and Claude Code "enforces the domain allowlist and then tunnels allowed connections through that
  upstream proxy".
- Limits stated by Anthropic: hostname-based filtering is vulnerable to domain fronting; Unix sockets
  (`/var/run/docker.sock`) are escapes; `enableWeakerNestedSandbox` (needed inside unprivileged Docker because bwrap
  can't mount `/proc`) "considerably weakens security"; MCP servers, hooks, file tools run outside.
- **`srt`** (`@anthropic-ai/sandbox-runtime`, Apache-2.0, npm v0.0.81 on 2026-11-08, "beta research preview")
  wraps a *whole process* (e.g. `srt claude`) in the same Seatbelt/bubblewrap boundary; also has an alpha Windows
  backend. Notable features for wicket: `--control-fd` (live-update network allowlists from the parent without
  restart: a natural fit for dynamic escalation), and **`srt proxy`**, a proxy-only mode that "holds no policy of its
  own: a request goes out only when the decider allows it". Decider protocol v1: NDJSON over an inherited socket;
  proxy sends `{"t":"req","id","method","host","port","sni","path","query","headers"}`; decider answers `allow`
  (with `setHeaders`/`removeHeaders` and `cred`/`credential` for per-request injection — client-supplied
  `authorization`, `x-api-key`, `cookie` are stripped first), `deny` (status + reason), or `need_body` (≤32 MiB).
  **Fail closed**: 5 s verdict timeout → 503 `X-Deny-Reason: decider_unavailable`; protocol violation kills the link;
  opaque (non-terminated) CONNECT tunnels are refused; refusals carry `X-Deny-Reason` codes (`host_not_allowed`,
  `decider`, `opaque_tunnel`, `misdirected`, `address_not_allowed`, …). The 5-second timer confirms the origin
  brief's point: you cannot hold connections open while a human decides.
- **Implication for wicket:** in a wicket zone the *outer* boundary is a microVM/container whose only egress is
  wicket's proxy. Claude Code's built-in sandbox is optional defence-in-depth inside it (bwrap works in a microVM with
  its own kernel if unprivileged user namespaces are enabled; in an unprivileged container it needs the weaker
  mode). Do **not** enable its `tlsTerminate`/masking inside a wicket box: double interception adds complexity and
  the secrets must not be in the box anyway. Consider adopting srt-proxy's decider protocol shape (or even the
  binary, as an interim) for wicket's proxy↔policy split.

### 1.7 Devcontainer reference [verified]

Source: <https://code.claude.com/docs/en/devcontainer>; reference config in
<https://github.com/anthropics/claude-code/tree/main/.devcontainer>; Dev Container Feature
`ghcr.io/anthropics/devcontainer-features/claude-code:1.0`.

Default-deny iptables firewall (`init-firewall.sh`) allowing only required domains; managed settings copied to
`/etc/claude-code/managed-settings.json`; `CLAUDE_CONFIG_DIR` on a named volume to persist `~/.claude` and
`.claude.json`; `containerEnv` with `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, `DISABLE_AUTOUPDATER=1`; pin the
version via `npm install -g @anthropic-ai/claude-code@X.Y.Z`. Anthropic's own warning: with
`--dangerously-skip-permissions` the container "does not prevent a malicious project from exfiltrating anything
accessible inside the container, including the Claude Code credentials stored in `~/.claude`" — i.e. the reference
container still puts the model credential in the box, which is precisely what wicket avoids. Also: Claude Code
refuses `--dangerously-skip-permissions` as root, so run the agent as a non-root user.

### 1.8 MCP config injection [verified]

Sources: <https://code.claude.com/docs/en/mcp>, <https://code.claude.com/docs/en/managed-mcp>.

- `--mcp-config <file|json …>` + `--strict-mcp-config` = "Only use MCP servers from `--mcp-config`, ignoring all
  other MCP configurations." With `-p`, Claude Code waits up to `MCP_TIMEOUT` (30 s) for servers before the first
  turn; invalid entries are skipped and reported in `system/init.mcp_server_errors` — wicket must fail the launch
  if that array is non-empty or the gateway's status isn't `connected`.
- Transports: stdio, HTTP (streamable), SSE, WebSocket. For wicket the right shape is **one remote HTTP MCP server =
  the wicket MCP gateway**, reachable at a box-local address, with a per-session placeholder bearer in `headers`
  (or `headersHelper`). Lock it with managed `allowManagedMcpServersOnly` + `allowedMcpServers`, or
  `managed-mcp.json` for exclusive control, and set `ENABLE_CLAUDEAI_MCP_SERVERS=false` / `disableClaudeAiConnectors`
  so claude.ai connectors (which route via `mcp-proxy.anthropic.com`, *outside* wicket's gateway) don't appear.
- Timeouts: per-server `timeout`, `MCP_TOOL_TIMEOUT` (default ~28 h), idle timeout 5 min for HTTP
  (`CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT`); progress notifications keep a call alive. Main-conversation calls >2 min are
  auto-backgrounded in interactive mode; not in `-p` unless `CLAUDE_AUTO_BACKGROUND_TASKS=1`.
- **MCP tasks** (public beta, v2.1.304+, MCP protocol revision 2026-07-28 via the
  [tasks extension](https://modelcontextprotocol.io/extensions/tasks/overview)): the gateway can answer a
  `tools/call` with a task (`taskId`, `status`, `statusMessage`, `pollIntervalMs`); Claude Code polls and delivers the
  result when done. This is a native "permission pending → result later" channel for MCP calls. Constraints: only in
  the main conversation (not subagents), only in interactive or stream-json/SDK sessions with
  `CLAUDE_AUTO_BACKGROUND_TASKS=1`, **and only when the session fetches feature flags** — which
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`/`DISABLE_TELEMETRY` turn off. Elicitation from a task in non-interactive
  mode is cancelled. So: usable, but trades against the "no nonessential traffic" posture; treat as optional.
- MCP tools marked `_meta["anthropic/requiresUserInteraction"]` cannot be auto-approved by hooks — the gateway can
  use this to force a host-side approval in the agent UX.

### 1.9 Environment variables, hosts, auth, and keeping the model credential out [verified unless noted]

Sources: <https://code.claude.com/docs/en/env-vars>, <https://code.claude.com/docs/en/network-config>,
<https://code.claude.com/docs/en/authentication>, <https://code.claude.com/docs/en/llm-gateway-connect>,
<https://code.claude.com/docs/en/llm-gateway-protocol>, <https://code.claude.com/docs/en/data-usage>,
<https://code.claude.com/docs/en/agent-sdk/secure-deployment>.

**Proxy / TLS**
- `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` (lowercase variants; first set wins in order `https_proxy, HTTPS_PROXY,
  http_proxy, HTTP_PROXY`). **No SOCKS support.** Proxy basic auth in the URL. WebSocket connections to loopback
  never go through the proxy.
- CA trust: bundled Mozilla set + OS store by default (`CLAUDE_CODE_CERT_STORE=bundled,system`; native installer
  can always read the OS store; npm installs need Node ≥22.15). `NODE_EXTRA_CA_CERTS=/path/ca.pem` adds a CA.
  mTLS: `CLAUDE_CODE_CLIENT_CERT/KEY/KEY_PASSPHRASE`. Note: subprocesses (curl, git, pip, cargo, Node `fetch`)
  each need their own CA/proxy config — install wicket's CA into the box's system trust store
  (`update-ca-certificates`) and set `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`,
  `NODE_EXTRA_CA_CERTS`, and `NODE_USE_ENV_PROXY=1` for Node ≥24 `fetch` (per the secure-deployment page). Tools
  that ignore proxy vars should hit a transparent redirect (iptables/nftables to the proxy) rather than a hole.

**Model endpoint and credential**
- `ANTHROPIC_BASE_URL` (Anthropic Messages format: `/v1/messages?beta=true`, optional `/v1/messages/count_tokens`;
  forward `anthropic-version` and `anthropic-beta` verbatim). Bedrock/Vertex/Foundry/AWS have their own base-URL
  variables. Requests carry `x-claude-code-session-id`, `x-claude-code-agent-id`, `x-claude-code-parent-agent-id`
  (and optional hint headers with `CLAUDE_CODE_GATEWAY_HINT_HEADERS=1`) — so wicket's LLM proxy can attribute every
  model call to a session and subagent **without trusting body parsing**.
- Credential precedence: cloud provider flags > `ANTHROPIC_AUTH_TOKEN` (sent as `Authorization: Bearer`) >
  `ANTHROPIC_API_KEY` (`x-api-key`; always used in `-p`) > `apiKeyHelper` (cached 5 min,
  `CLAUDE_CODE_API_KEY_HELPER_TTL_MS`; sent in both headers) > `CLAUDE_CODE_OAUTH_TOKEN` (1-year subscription
  token from `claude setup-token`) > Anthropic profiles / Workload Identity Federation > `/login` OAuth.
  `--bare` reads only `ANTHROPIC_API_KEY` or an `apiKeyHelper` from `--settings` (not OAuth tokens).
- `ANTHROPIC_CUSTOM_HEADERS` adds headers (newline-separated).
- `CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST`: for embedding hosts; Claude Code then ignores provider/endpoint/auth/model
  variables in settings files, so repo or user settings cannot re-route model traffic.

**Recommended credential routing for wicket (two options):**
- **A. LLM proxy via base URL (preferred).** `ANTHROPIC_BASE_URL=http://<host-side wicket llm-proxy>` (plain HTTP
  over vsock/veth is fine; no CA needed for model traffic), `ANTHROPIC_AUTH_TOKEN=<wicket session capability>`
  (a Biscuit/macaroon or opaque random token bound to zone + session + budget). The proxy verifies it, strips it,
  adds the real `x-api-key` (or signs for Bedrock/Vertex), enforces model allowlist/budget, and logs. This is the
  pattern Anthropic documents ("Option 1: ANTHROPIC_BASE_URL … can inspect and modify them (including injecting
  credentials)"). Side effects: Remote Control is disabled when the base URL isn't api.anthropic.com (fine); the fast
  mode availability check and the WebFetch domain-safety preflight still go to `api.anthropic.com` directly (set
  `skipWebFetchPreflight: true`, accept no fast mode, or allow those via the egress proxy).
- **B. Transparent injection on the egress proxy.** Leave the base URL at `api.anthropic.com`, put a placeholder in
  `ANTHROPIC_API_KEY`, have the TLS-intercepting egress proxy swap `x-api-key` for `api.anthropic.com` only. Needs
  wicket's CA trusted by Claude Code (OS store or `NODE_EXTRA_CA_CERTS`). Keeps feature-flag/fast-mode/preflight
  traffic working through one path. Use when you want "unmodified agent, unmodified endpoints".
- In both cases the placeholder in the box is worthless outside the zone: it only works through wicket's proxy, which
  checks it is presented from the zone's network identity.
- **Subscription (claude.ai) auth:** technically, `CLAUDE_CODE_OAUTH_TOKEN` is a bearer token and an outside proxy
  could inject it, but (a) third-party products may not offer claude.ai login without approval, (b) OAuth requests
  need extra `anthropic-beta` OAuth capability values that the proxy would have to reproduce, (c) token refresh
  goes to `platform.claude.com`. **[unverified]** whether proxy-injected OAuth works end to end; treat as
  out of scope for wicket-the-product and at most a personal-use experiment. Cloud sessions also note that
  subscription credentials always override `ANTHROPIC_API_KEY`/`AUTH_TOKEN` there.

**Turning off traffic wicket doesn't want**
- `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` (auto-updates, telemetry, error reporting, `/feedback`, release notes,
  PR badges, availability checks; disables feature-flag fetching and therefore some features, e.g. MCP tasks,
  Remote Control). Individually: `DISABLE_AUTOUPDATER` / `DISABLE_UPDATES`, `DISABLE_TELEMETRY` (any value incl. `0`
  opts out), `DO_NOT_TRACK=1`, `DISABLE_ERROR_REPORTING`, `DISABLE_FEEDBACK_COMMAND`,
  `CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY`, `CLAUDE_CODE_DISABLE_ARTIFACT=1`, `ENABLE_CLAUDEAI_MCP_SERVERS=false`.
  Settings: `skipWebFetchPreflight: true`, `disableClaudeAiConnectors`.
- Others worth setting: `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` (strip credential-looking env vars from Bash, hooks,
  stdio MCP subprocesses — belt and braces, since the box shouldn't hold credentials), `CLAUDE_CONFIG_DIR` (put
  session transcripts on a zone-labelled volume so `--resume` works after a VM snapshot/restore),
  `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` and `CLAUDE_CODE_DISABLE_CLAUDE_MDS=1` (memory is an information-flow channel;
  wicket should supply context explicitly), `CLAUDE_CODE_DISABLE_BACKGROUND_TASKS=1`, `CLAUDE_CODE_MAX_RETRIES`,
  `API_TIMEOUT_MS`, `MCP_TIMEOUT`, `MCP_TOOL_TIMEOUT`.

**Hosts Claude Code itself contacts** (network-config "Network access requirements"): `api.anthropic.com` (API,
WebFetch safety check, feature flags, telemetry), `claude.ai`, `claude.com`, `platform.claude.com`,
`sso.claude.com` (login/OAuth refresh), `mcp-proxy.anthropic.com` (claude.ai connectors), `downloads.claude.ai`
(native installer/updater, plugin binaries), `storage.googleapis.com` (plugin metadata), `registry.npmjs.org`
(plugins, `npx` MCP servers), `github.com`/`raw.githubusercontent.com` (marketplaces, release notes),
`bridge.claudeusercontent.com` (Chrome), `*.frame.claudeusercontent.com` (artifacts),
`http-intake.logs.us5.datadoghq.com` and `browser-intake-us5-datadoghq.com` (telemetry/error reports),
`code.claude.com` (docs lookups), `formulae.brew.sh` (Homebrew update checks), `*-review.googlesource.com` (Desktop
only). **With option A and the switches above, the minimum set is: wicket's LLM proxy, and nothing else.**
WebSearch is a *server-side* tool executed by Anthropic's backend: its results enter the context via the model API
and bypass the egress proxy entirely (relevant to taint labels — see 4.6). Disable it (`--disallowedTools
WebSearch`) in zones that must not ingest web content, or have the LLM proxy strip server tools from requests.

**Telemetry wicket can consume:** OpenTelemetry (`CLAUDE_CODE_ENABLE_TELEMETRY=1`, `OTEL_EXPORTER_OTLP_*` pointed at
a wicket collector; events such as `claude_code.tool_decision`, `claude_code.tool`, `claude_code.api_request`,
`claude_code.mcp_server_connection`, `claude_code.permission_mode_changed`; content gated by `OTEL_LOG_TOOL_DETAILS`
/ `OTEL_LOG_USER_PROMPTS`) — <https://code.claude.com/docs/en/monitoring-usage>. Like hooks, this is agent-reported.

### 1.10 How Claude Code reacts to denials, and whether "pending, retry with request id" works

What the docs establish [verified]:
- A denied tool call becomes an `is_error` tool result containing the deny message (`permissionDecisionReason`, the
  SDK `message`, or the proxy's response body); Claude reads it and decides what to do. stream-json emits
  `system/permission_denied` (best-effort) and the final `result.permission_denials`.
- With `--permission-prompts none`, Claude "is told that nobody can approve the request and not to retry it" —
  i.e. Claude Code already shapes retry behaviour through the denial text.
- The built-in sandbox "names the denied host in the command's result, so Claude sees what was blocked", and in auto
  mode with per-command hosts "Claude re-runs the command with the host added" — evidence that Claude reliably acts
  on structured, specific denial messages.
- `PermissionDenied` hook can return `retry: true`, which "adds a message to the conversation telling the model it
  may retry the tool call".
- **Native pending mechanisms:** (1) `PreToolUse` → `defer` → `stop_reason: "tool_deferred"` + `deferred_tool_use
  {id,name,input}`; host resumes with `--resume`; no timeout; single-tool-call turns and `-p` only. (2) `canUseTool`
  callback/`--permission-prompt-tool stdio` can stay pending indefinitely (process must stay alive — pair with VM
  pause). (3) MCP tasks for gateway-mediated tools. (4) Over stream-json input, the host can inject a follow-up user
  message ("request R-123 was granted: retry") at any time.

What is **[unverified]** and needs the experiment in 4.8:
- Whether Claude, on receiving a plain HTTP `403`/`428` from the egress proxy with a JSON body like
  `{"error":"wicket_permission_pending","request_id":"R-123","retry_after_s":60,"status_url":…}`, will wait and retry
  rather than route around (try another host, another tool, or give up). Anecdotally (and per Anthropic's sandbox
  design notes) Claude does read and follow such messages, but it also sometimes tries workarounds; and a
  *prompt-injected* agent will deliberately probe alternatives. Design consequence: every alternative route must be
  denied too (complete mediation), and the denial text must give the model a cheap, explicit action ("call the
  `wicket.await_grant` MCP tool with R-123" or "wait; you will be told") so the path of least resistance is the
  sanctioned one.
- Never return "pending" on the *model* endpoint: Claude Code's API client auto-retries 429/5xx (up to
  `CLAUDE_CODE_MAX_RETRIES`, default 10) and will misinterpret it.

---
## 2. Agent-agnostic driving: ACP and the other agent CLIs

_Researched by a parallel sub-agent on 2026-11-08 from primary sources and included as delivered, with headings renumbered. Confidence labels: **[H]** = read in the primary source, **[M]** = inferred from source/docs disagreement, **[U]** = unverified._

**Method.** I read primary sources only: the GitHub repos (fetched raw through `gh`/raw.githubusercontent), the official docs sites, crates.io, npm, PyPI, and the live ACP registry JSON. Each claim has a confidence mark: **[H]** means I read it in the primary source; **[M]** means it is inferred from source code, or the docs and code disagree slightly; **[U]** means I could not verify it. I installed and built nothing, and wrote no files.

**Version snapshot (checked 2026-11-08):**

| Component | Version and date |
|---|---|
| ACP stable protocol | `protocolVersion` 1 |
| ACP v2 | Draft, schema `v2.0.0-alpha.13` |
| ACP v1 schema | 1.29.1 (2026-11-02) |
| `agent-client-protocol` Rust crate | 5.0.0 (2026-11-02) |
| Codex CLI | rust-v0.167.0 (2026-11-06); npm `@openai/codex` 0.167.0 |
| Gemini CLI | v0.67.0 (2026-11-04) |
| OpenCode | v2.2.6 (2026-11-06), repo `anomalyco/opencode`, npm `@opencode/cli`. The V1 line is still on npm as `opencode-ai` 1.19.5 (2026-10-28) |
| goose | v1.57.0 (2026-10-28), repo now `aaif-goose/goose` |
| aider | PyPI `aider-chat` 0.86.2 (2026-02-12). Last GitHub release v0.86.0 (2025-08-09); last push 2026-05-22 |

---

### 2.1 Agent Client Protocol (ACP)

#### Status, governance, transport

- **Stable version.** "The current stable ACP protocol version is `1`." Wire compatibility is negotiated through `protocolVersion` in `initialize`. The crate and schema version numbers say nothing about wire compatibility. [H] https://github.com/agentclientprotocol/agent-client-protocol (README)
- **Repo and artifacts.** The canonical repo is `github.com/agentclientprotocol/agent-client-protocol` (Apache-2.0). Schema releases ship as `schema-v1.29.1` and `schema-v2.0.0-alpha.13`, both 2026-11-02. [H] https://github.com/agentclientprotocol/agent-client-protocol/releases
- **v2.**
  - A Draft was announced 2026-07-20 by Ben Brandt (Zed, ACP lead maintainer). The guidance is to gate v2 behind version negotiation **and** feature flags, and to keep serving v1. [H] https://agentclientprotocol.com/announcements/acp-v2-draft
  - v2 removes the client file-system and terminal APIs (`fs/*` and `terminal/*`) and session modes: "Use client-provided MCP servers when the Agent needs Client-side tools." [H]
  - In v2 the `session/prompt` response only acknowledges the prompt. Completion arrives later via `state_update`. [H]
  - v2 permission requests carry their own `title`/`description` and an extensible `subject`, for example `command`. [H]
  - Source: https://agentclientprotocol.com/protocol/v2/migration
- **Governance.** "Interim" model: ACP is jointly governed by **Zed and JetBrains**, "working toward transitioning to an independent foundation". Sergey Ignatov (JetBrains) became a lead maintainer on 2026-02-18. [H] https://agentclientprotocol.com/community/governance
- **Transport (v1).**
  - JSON-RPC 2.0, UTF-8, over **stdio**. The client spawns the agent. Messages are newline-delimited and must not contain embedded newlines. stdout carries only ACP messages; stderr is for logs. [H] https://agentclientprotocol.com/protocol/v1/transports
  - A Streamable-HTTP/WebSocket remote transport is an **Active RFD**, not yet stable. A Transports WG formed 2026-04-22 with goose's Alex Hancock. [H] https://agentclientprotocol.com/rfds/streamable-http-websocket-transport and https://agentclientprotocol.com/announcements/transports-working-group

#### Key v1 methods

Source: https://agentclientprotocol.com/protocol/v1/overview [H]

**Agent side (client calls these):**
- Baseline: `initialize`, `authenticate`, `session/new`, `session/prompt`.
- Optional:
  - `session/load` (needs `loadSession`; replays the full history as `session/update` and then responds)
  - `session/resume` (stabilized 2026-04-22; no replay)
  - `session/close`
  - `session/list` (stabilized 2026-03-09)
  - `session/delete`
  - `session/set_mode`
  - `logout`
- Notification: `session/cancel`.
- `$/cancel_request` (request cancellation) is also stabilized.

**Client side (agent calls these):**
- Baseline: `session/request_permission`.
- Optional, capability-gated:
  - `fs/read_text_file`, `fs/write_text_file`
  - `terminal/create`, `terminal/output`, `terminal/wait_for_exit`, `terminal/kill`, `terminal/release`
  - `elicitation/create` (stabilized 2026-07-24)
- Notifications: `session/update` carries message/thought chunks, `tool_call`/`tool_call_update`, plans, available commands, mode changes, notices and compactions. `elicitation/complete`.

**Rules:** all paths must be absolute; line numbers are 1-based.

**Session setup** (https://agentclientprotocol.com/protocol/v1/session-setup) [H]:
- `session/new` takes `{cwd, mcpServers[], additionalDirectories?, systemPrompt?}`.
- `cwd` plus `additionalDirectories` form the session "root set". The spec says the root set "confines shell commands only when a sandbox enforces it". In other words, ACP itself does not sandbox the agent.

#### Passing MCP servers to the agent

Source: https://agentclientprotocol.com/protocol/v1/session-setup#mcp-servers [H]

- Servers go in `session/new`, `session/load` and `session/resume` as `mcpServers`.
- **stdio** support is mandatory: `{name, command (absolute), args, env:[{name,value}]}`.
- **HTTP** is optional and requires the agent to advertise `mcpCapabilities.http`: `{type:"http", name, url, headers:[{name,value}]}`.
- SSE is deprecated.
- Agents SHOULD connect to all servers the client lists. "Clients MAY use this ability to provide tools directly to the underlying language model by including their own MCP server."
- Security guidance: agents should not log, echo or persist `env`/`headers` values, and should send headers only to the configured origin.
- **For wicket:** this is the natural way to inject the MCP gateway (an HTTP MCP URL plus a per-session header). The header will sit inside the sandbox, so make it a scoped, short-lived capability token, not a real secret.

**MCP-over-ACP** (Active RFD):
- An MCP server declared as `{"type":"acp","name":..,"serverId":..}`. Tool calls then travel over the existing ACP channel as `mcp/message`, with no extra listener or subprocess. It targets MCP 2026-07-28. [H] https://agentclientprotocol.com/rfds/mcp-over-acp
- In the Rust SDK it is opt-in behind the `unstable_mcp_over_acp` feature, and a polyfill proxy adapts it to HTTP for agents that cannot consume it natively. [H] https://github.com/agentclientprotocol/rust-sdk
- **For wicket:** tool traffic could stay on the ACP pipe, so the sandbox needs no network path to the gateway at all.

#### Permission flow

Source: https://agentclientprotocol.com/protocol/v1/tool-calls#requesting-permission [H]

- `session/request_permission` is a JSON-RPC **request** from the agent: `{sessionId, toolCall (ToolCallUpdate), options:[{optionId,name,kind}]}`.
- Option kinds: `allow_once`, `allow_always`, `reject_once`, `reject_always`.
- The client replies `{outcome:{outcome:"selected", optionId}}`, or `{outcome:{outcome:"cancelled"}}`. If the turn was cancelled, the client MUST reply `cancelled`.
- "Clients MAY automatically allow or reject permission requests according to the user settings." So deny and allow are both fully client-controlled.
- **Holding requests open:** because it is an ordinary JSON-RPC request, the client can hold the response open while it consults a policy engine or human. The spec sets **no timeout** [H: none stated]. Whether a particular agent imposes its own timeout is [U].
- The agent owns "always" decisions and their scope.
- Agents "SHOULD NOT treat an outcome they don't recognize as approval".
- Security model: "Permission requests are advisory: the Agent performs its own operations and is responsible for honoring the user's decision." [H] https://agentclientprotocol.com/protocol/v1/security
  - **For wicket:** enforcement must come from the sandbox, the egress proxy and the MCP gateway, not from ACP permission answers.
- **Intermediaries:** "SHOULD NOT answer permission requests ... except under user-configured policy." This explicitly permits a policy-driven proxy such as wicket. [H]
- **fs/terminal:** when the client advertises them, the client performs the operation and "is responsible for checking them" against the root set. [H] https://agentclientprotocol.com/protocol/v1/file-system and https://agentclientprotocol.com/protocol/v1/terminals
  - **For wicket:** in v1, an agent that delegates to the client lets wicket mediate file and exec operations. Do not rely on this: v2 removes these APIs, and many agents use their own tools regardless.

#### Rust crates

- `agent-client-protocol` **5.0.0** (2026-11-02; prior releases 3.6.0 on 2026-10-28, 3.5.0, and so on).
  - Repo: https://github.com/agentclientprotocol/rust-sdk. Owners on crates.io: `benbrandt`, `agu-z`, and the team `github:agentclientprotocol:rust-maintainers`. [H] https://crates.io/crates/agent-client-protocol
  - It provides the roles **Client, Agent, Proxy and Conductor**, with `Client.v1()`/`Agent.v1()`/`Proxy.v1()` and draft `.v2()` behind `unstable_protocol_v2`. [H]
  - Sibling crates:
    - `agent-client-protocol-http` (HTTP/SSE and WebSocket transports)
    - `-rmcp` (integration with the rmcp MCP SDK)
    - `-conductor` (orchestrates proxy chains)
    - `-polyfill`
    - `-trace-viewer`
    - `-cookbook`
  - The Rust and TypeScript SDKs reached 1.0.0 on 2026-06-25, so the 5.x crate number reflects several breaking API releases since then. [H] announcement `sdk-1-0-releases`
- `agent-client-protocol-schema` 1.15.1 (2026-11-02) holds the raw wire types and is the root crate of the spec repo. [H]
- **Proxy-chains RFD** (Draft): a conductor routes messages between client, proxies and agent. [H] https://agentclientprotocol.com/rfds/proxy-chains
  - **For wicket:** it could be implemented as an ACP proxy or conductor component.
- **Configurable LLM Providers RFD** (Draft): `providers/list`, `providers/set`, `providers/disable`, so "clients [can] route LLM requests through their own infrastructure (proxies, gateways...)". [H] https://agentclientprotocol.com/rfds/custom-llm-endpoint
  - **For wicket:** a future standard way to point any agent at an LLM proxy outside the sandbox. Not yet stable.

#### Which agents speak ACP

Sources: the live registry (`curl https://cdn.agentclientprotocol.com/registry/v1/latest/registry.json`, release `v2026.11.08-713a3d0`) and https://agentclientprotocol.com/get-started/agents [H]. The registry was stabilized 2026-03-09 and includes only agents that support ACP auth.

| Agent | How | Registry entry (cmd / version) |
|---|---|---|
| Claude Code (Claude Agent SDK) | Adapter `@agentclientprotocol/claude-agent-acp`. **Renamed twice**: `@zed-industries/claude-code-acp` (last 0.16.2, deprecated) → `@zed-industries/claude-agent-acp` (last 0.23.1, deprecated) → `@agentclientprotocol/claude-agent-acp`. Standalone binaries bundle the `claude` CLI; `CLAUDE_CODE_EXECUTABLE` overrides it | 0.101.0 (2026-11-05) |
| OpenAI Codex | Adapter `@agentclientprotocol/codex-acp`, replacing `@zed-industries/codex-acp` (deprecated, last 0.16.0). It **starts Codex App Server** and translates. Env: `CODEX_API_KEY`/`OPENAI_API_KEY`, `CODEX_PATH`, `CODEX_CONFIG` (JSON merged into config), `MODEL_PROVIDER`, `INITIAL_AGENT_MODE` (`read-only`/`workspace-write`/`agent`/`agent-full-access`/`permission-profile:<id>`), `NO_BROWSER`; "custom OpenAI-compatible gateway" auth capability | 2.5.0 (2026-10-29) |
| Gemini CLI | Native: `gemini --acp` | 0.67.0 |
| goose | Native: `goose acp` (stdio). `goose serve` runs ACP over HTTP/WebSocket | 1.57.0 |
| OpenCode | Native: `opencode acp` | 2.2.6 |
| Cline | Native: `cline --acp` | 3.0.74 |
| Augment (Auggie) | `auggie --acp`, with `AUGMENT_DISABLE_AUTO_UPDATE=1` | 0.37.0 |
| Kimi | "Kimi CLI (Legacy)" `kimi acp` 1.52.0; new "Kimi Code" `@moonshot-ai/kimi-code acp` | 2.5.2 |
| Others in the registry | GitHub Copilot CLI (`--acp`), Cursor (`cursor-agent acp`), Factory Droid (`droid exec --output-format acp-daemon`), Junie, Kiro, Mistral Vibe, Qwen Code, Devin, Grok Build (`grok agent stdio`), Kilo, Poolside, Qoder, Codebuddy, IBM Bob, Google Antigravity, and others | |

Sources for the adapter details: https://github.com/agentclientprotocol/claude-agent-acp, https://github.com/agentclientprotocol/codex-acp, https://www.npmjs.com/package/@zed-industries/claude-code-acp.

- **Useful for wicket:** registry entries carry install metadata (`npx`/`uvx`/binary URL, sha256, `args`, and `env`, such as auto-update disable variables).
- **Doc lag:** the agents page still links `zed-industries/claude-agent-acp`, while the repo and registry say `agentclientprotocol/claude-agent-acp`.

#### Competing or adjacent protocols

- **A2A** (agent-to-agent, Linux Foundation; JSON-RPC/gRPC/REST bindings): v1.0.0 on 2026-03-12, v1.0.1 on 2026-05-28. [H] https://github.com/a2aproject/A2A/releases
  - It covers peer agents and task delegation, not an editor or harness driving a local coding agent.
  - **Name clash:** IBM's *Agent Communication Protocol* (also "ACP") merged into A2A in Aug 2025 [M, secondary sources only: https://tyk.io/learning-center/agent-protocols-a-complete-guide-to-mcp-a2a-and-acp/]. It is unrelated to Zed's Agent Client Protocol.
  - A2A reportedly moved to AAIF on 2026-08-17 [U; secondary blog only].
- **AG-UI** (CopilotKit; `github.com/ag-ui-protocol/ag-ui`, active 2026-11): an event-stream protocol between an agent *backend* and a web *frontend* over HTTP/SSE, with lifecycle, text, tool and state-delta events. [M] https://www.copilotkit.ai/blog/introducing-ag-ui-the-protocol-where-agents-meet-users
  - It is not a protocol for driving a local CLI agent over stdio.
- **Codex app-server**: OpenAI's own rich-client protocol (details in B). `codex-acp` bridges it to ACP. Use app-server directly only if wicket wants Codex-specific depth.
- **Agent-specific headless JSONL** (no turn control or permission callback):
  - Codex `exec --json`
  - Gemini `--output-format stream-json`
  - goose `--output-format stream-json`
  - OpenCode `run --format json`
  - Claude Code's SDK stream-json and control protocol is the analogous Anthropic surface [U, not re-verified in this pass].

---

### 2.2 OpenAI Codex CLI (Rust, `openai/codex`)

**Docs moved:** `developers.openai.com/codex/*` now 308-redirects to `learn.chatgpt.com/...`.

#### Sandbox modes

Sources: https://learn.chatgpt.com/codex/sandboxing and https://learn.chatgpt.com/codex/agent-approvals-security [H]

- `read-only`: inspect files only; edits and commands need approval.
- `workspace-write`: edits and commands inside the workspace. **Network is off by default.**
- `danger-full-access`: no filesystem or network boundary.
- Protected read-only paths under writable roots: `.git`, `.codex`, `.agents`, `.aws`.
- Newer **permission profiles** (`default_permissions = "<name>"`, `[permissions.<name>.filesystem|network|workspace_roots]`) supersede `sandbox_mode`. Do not combine the two. [H] https://learn.chatgpt.com/codex/config-file/config-reference

#### Linux implementation

Source: https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md [H]

- **Bubblewrap is now the default.** It uses the first `bwrap` on PATH outside the cwd, otherwise a bundled `codex-resources/bwrap`.
- After bwrap sets up the filesystem view, it applies `PR_SET_NO_NEW_PRIVS` and a **seccomp** filter that blocks network syscalls when network is restricted, always blocks `AF_VSOCK`, and always blocks `io_uring`.
- Landlock is "legacy" and is *rejected* for filesystem-restricted policies ("cannot isolate app-server Unix sockets").
- Namespaces: `--unshare-user` and `--unshare-pid`, plus `--unshare-net` when network is restricted.
- In "managed proxy mode", tool traffic is routed via a TCP→UDS→TCP bridge so it can reach only the proxy.
- **It needs unprivileged user namespaces.** If bwrap cannot create them, Codex warns at startup.

macOS uses Seatbelt (built in). Windows uses a native sandbox in PowerShell and bubblewrap in WSL2; WSL1 is unsupported. [H] https://learn.chatgpt.com/codex/sandboxing

#### Inside an outer container or microVM

- Official guidance: "configure your Docker container to provide the isolation you need, then run `codex` with `--sandbox danger-full-access` (or `--dangerously-bypass-approvals-and-sandbox`)". The CLI help says that flag (alias `--yolo`) is "Only [for] use inside an externally hardened environment". [H] https://learn.chatgpt.com/codex/agent-approvals-security and https://learn.chatgpt.com/codex/cli/reference
- **Implication for wicket:**
  - In Docker with the default seccomp/AppArmor profile, unprivileged userns is usually blocked, so bwrap fails and Codex should run with `danger-full-access`.
  - In a microVM with its own kernel, Codex's bwrap layer can stay on as defense in depth. [M: inference from the userns requirement]

#### Network access settings

- `[sandbox_workspace_write] network_access = true`, or `[permissions.<name>.network] enabled = true` with `[...network.domains]` allow/deny rules.
- Domain enforcement needs `[features] network_proxy = true`; "deny always wins". [H] https://learn.chatgpt.com/codex/agent-approvals-security
- **Codex ships its own egress proxy**, `codex-network-proxy`, on HTTP :3128 and SOCKS5 :8081 [H] https://github.com/openai/codex/blob/main/codex-rs/network-proxy/README.md:
  - allowlist-first domain policy
  - "limited" mode (GET/HEAD/OPTIONS only)
  - HTTPS MITM with its own CA, injecting CA env vars into child processes
  - MITM hooks such as `strip_request_headers`
  - "credential substitution" (requires `mitm.version = 2`)
  - `allow_upstream_proxy` to chain to an outer `HTTPS_PROXY`
  - OTEL audit events
  - This overlaps conceptually with wicket's outer proxy. Inside wicket it can be left off, or chained via `allow_upstream_proxy`.

#### Proxy and custom CA

Sources: https://github.com/openai/codex/blob/main/codex-rs/http-client/README.md and `src/custom_ca.rs` [H]

- **CA:** Codex's own HTTP and WebSocket clients read **`CODEX_CA_CERTIFICATE`**, falling back to **`SSL_CERT_FILE`** (PEM bundle). Certificates are **added to native roots**, not substituted for them.
- **Proxy:** the env proxies `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` are honored (reqwest default path). An optional `respect_system_proxy` feature adds system/PAC/WPAD resolution.
- The managed proxy recognizes these CA env vars for child processes: `CODEX_CA_CERTIFICATE`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`, `BUNDLE_SSL_CA_CERT`, and others (11 keys in `network-proxy/src/certs.rs`). [H]

#### Config

Sources: https://learn.chatgpt.com/codex/config-file/config-reference, https://learn.chatgpt.com/codex/cli/reference, https://learn.chatgpt.com/codex/non-interactive-mode [H]

- **Location:** `$CODEX_HOME/config.toml`, default `~/.codex`. Project `.codex/config.toml` loads only if the project is trusted (`projects.<path>.trust_level`).
- Project-local files **ignore** `openai_base_url`, `chatgpt_base_url`, `model_provider(s)`, `notify`, `profile(s)` and `otel`. A malicious repo therefore cannot redirect the model endpoint.
- **Overrides:** `-c/--config key=value` (value parsed as TOML if possible, otherwise a literal string). `--profile/-p` with profile files at `$CODEX_HOME/<name>.config.toml`.
- `codex exec --ignore-user-config` skips `$CODEX_HOME/config.toml`; `--ignore-rules` skips execpolicy `.rules`.
- **Managed / enterprise** (https://learn.chatgpt.com/codex/enterprise/managed-configuration) [H]:
  - `/etc/codex/requirements.toml` holds non-overridable constraints:
    - `allowed_approval_policies`, `allowed_sandbox_modes`, `allowed_permission_profiles`
    - an `mcp_servers` allowlist ("present but empty" disables all MCP)
    - `[rules]`, `[network_proxy]` domain rules, `[features]` pins
    - `allow_managed_hooks_only` (requirements.toml only)
  - `/etc/codex/managed_config.toml` holds defaults that override user config **and `-c` CLI overrides** at startup.
  - Cloud and MDM layers sit higher.
  - **For wicket:** use `/etc/codex/requirements.toml` inside the sandbox image to pin policy that the agent's own `config.toml` edits cannot undo.

#### MCP client config

- `[mcp_servers.<id>]`:
  - stdio: `command`, `args`, `env`, `env_vars`, `cwd`
  - Streamable HTTP: `url`, `bearer_token_env_var`, `http_headers`, `env_http_headers`
  - control: `enabled`, `required` (exec exits with an error if a required server fails to start), `startup_timeout_sec`, `enabled_tools`, `disabled_tools`
  - [H] config reference
- Inject with `-c 'mcp_servers.gw.url="https://gw/mcp"'` or a pre-written `config.toml` under a wicket-owned `CODEX_HOME`.

#### Headless and I/O

- **`codex exec "<prompt>"`** (Stable):
  - Progress goes to stderr; the final message goes to stdout.
  - `--json` makes stdout JSONL with events `thread.started`, `turn.started`, `turn.completed` (with usage), `turn.failed`, `item.*` (agent message, reasoning, command execution, file change, MCP tool call, web search, plan update) and `error`.
  - `-o/--output-last-message <path>`, `--output-schema <file>`, `exec resume --last | <id>`, `--ephemeral`, `--skip-git-repo-check` (Git is otherwise required).
  - **Defaults: read-only sandbox**, and in source `approval_policy = Never` ("Default to never ask for approvals in headless mode").
  - "`--full-auto` is no longer supported."
  - [H] https://learn.chatgpt.com/codex/non-interactive-mode and `codex-rs/exec/src/lib.rs`
- **`codex app-server`** (Experimental) [H] https://learn.chatgpt.com/codex/app-server:
  - Transports: `--listen stdio://` (default, JSONL), `ws://IP:PORT` ("experimental and unsupported"), `unix://PATH`.
  - JSON-RPC 2.0 **without the `jsonrpc` field** on the wire.
  - Lifecycle: `initialize` → `initialized` → `thread/start|resume|fork` → `turn/start`, `turn/steer`, `turn/interrupt`.
  - Notifications: `item/started`, `item/completed`, `item/agentMessage/delta`, `turn/completed`.
  - **Server→client approvals:**
    - `item/commandExecution/requestApproval` → `accept | acceptForSession | decline | cancel | {acceptWithExecpolicyAmendment}`
    - `item/fileChange/requestApproval` → `accept | acceptForSession | decline | cancel`
    - `item/permissions/requestApproval` → a granted subset
  - On decline the item completes with status `declined`. No approval timeout is documented. `serverRequest/resolved` confirms clearing.
  - Schemas: `codex app-server generate-ts` / `generate-json-schema`.
  - Auth via `account/login/start`: `apiKey`, `chatgpt`, `chatgptDeviceCode`, or `chatgptAuthTokens` (experimental; the host supplies access tokens and handles `account/chatgptAuthTokens/refresh`).
- **`codex mcp-server` has been removed**; the docs point to app-server instead. [H] https://learn.chatgpt.com/codex/cli/reference (removal date [U]).

#### Auth and credential routing

- **ChatGPT login** stores tokens in `$CODEX_HOME/auth.json` or the keyring (`cli_auth_credentials_store = file|keyring|auto|ephemeral`). `auth.json` "contains access tokens" and refreshes automatically. [H] https://learn.chatgpt.com/codex/auth
  - Avoid it in wicket: it puts refresh-capable secrets in the sandbox.
- **API key:** `CODEX_API_KEY` for exec ("set only for the Codex invocation that needs it"), or `printenv OPENAI_API_KEY | codex login --with-api-key`. [H]
- **LLM proxy routing:**
  - `[model_providers.<id>]` supports `base_url`, `env_key`, `wire_api` (only `"responses"`), `query_params`, `http_headers`, `env_http_headers`, `requires_openai_auth`, `auth` (credential-helper command), `[...gateway_oauth]` and `supports_websockets`.
  - Top-level `model_provider` and `openai_base_url`.
  - `forced_login_method = chatgpt|api`.
  - [H] config reference
  - **For wicket:** set `model_provider` to a provider whose `base_url` is the outside LLM proxy, with `env_key` pointing to a dummy or scoped token. Alternatively keep the default provider with a dummy `OPENAI_API_KEY` and let the TLS-intercepting proxy replace `Authorization`.
  - Third-party guides warn that without `model_provider` set, Codex uses the built-in `openai` provider and bypasses a configured gateway. [M] https://zuplo.com/docs/ai-gateway/integrations/codex and https://coder.com/docs/ai-coder/ai-gateway/clients/codex

#### Approval policies and denial behaviour

- **Current values:** `on-request`, `never`, or `{ granular = { sandbox_approval, rules, mcp_elicitations, request_permissions, skill_approval } }`.
  - **`untrusted` is retired** ("can prevent either client from starting").
  - **`on-failure` is deprecated.**
  - [H] https://learn.chatgpt.com/codex/config-file/config-reference and https://learn.chatgpt.com/codex/agent-approvals-security
- `approvals_reviewer = user | auto_review` (auto-review "fails closed").
- **Under `never`** (the exec default), commands run in the sandbox, and a sandbox denial comes back to the model as a failed command; there is no escalation [M].
- **Via app-server**, a declined item ends `declined` and the turn continues [H].

#### Telemetry and update knobs

- `analytics.enabled = false` disables the Statsig metrics exporter.
- `feedback.enabled = false`.
- `check_for_update_on_startup = false`.
- `[otel] exporter = "none"`; OTEL is off by default.
- [H] config reference and agent-approvals-security
- Env scrubbing for spawned commands is controlled by `shell_environment_policy` (`inherit = all|core|none`, `exclude`, `include_only`, `set`, `ignore_default_excludes`). [H]

---

### 2.3 Gemini CLI (`google-gemini/gemini-cli`, v0.67.0, 2026-11-04)

Docs are in the repo `docs/`; links below are to `main`.

- **Headless:**
  - Triggered by a non-TTY or by `-p/--prompt` (appended to stdin).
  - `-o/--output-format text|json|stream-json`.
    - `json`: `{response, stats, error?}`.
    - `stream-json` (JSONL) events: `init`, `message`, `tool_use`, `tool_result`, `error`, `result`.
  - Exit codes: 0 success, 1 error, 42 input error, 53 turn limit.
  - [H] https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/headless.md
- **Approvals:** `--approval-mode default|auto_edit|yolo|plan`; `--yolo` is deprecated.
  - The policy engine (TOML rules) has decisions `allow`, `deny` and `ask_user`. **"In non-interactive mode, [ask_user] is treated as deny."**
  - `--allowed-tools` is deprecated in favour of policy rules.
  - [H] https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/cli-reference.md and https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md
- **Settings layers** (lowest to highest) [H] https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md:
  1. System defaults `/etc/gemini-cli/system-defaults.json` (overridable via `GEMINI_CLI_SYSTEM_DEFAULTS_PATH`)
  2. User `~/.gemini/settings.json` (root via **`GEMINI_CLI_HOME`**)
  3. Project `.gemini/settings.json`
  4. **System overrides `/etc/gemini-cli/settings.json`** (via `GEMINI_CLI_SYSTEM_SETTINGS_PATH`)
  - Settings support `$VAR`/`${VAR:-default}` substitution.
  - The CLI auto-loads `.env` (cwd upward, then `~/.env`).
  - Workspace trust: `GEMINI_CLI_TRUST_WORKSPACE=true` or `--skip-trust`.
  - Enterprise "Admin Controls" (Strict Mode = no yolo; MCP enable/disable plus a server allowlist; extensions) are "enforced globally and cannot be overridden by users locally". [H] https://github.com/google-gemini/gemini-cli/blob/main/docs/admin/enterprise-controls.md
- **MCP:**
  - `mcpServers.<name>`: `command/args/env/cwd` (stdio), `url` (SSE), **`httpUrl`** (streamable HTTP), `headers`, `timeout`, `trust` (bypasses confirmations), `includeTools`, `excludeTools`.
  - `mcp.allowed`/`mcp.excluded`; `--allowed-mcp-server-names`.
  - [H] configuration.md
- **Sandbox:**
  - `-s/--sandbox`, `GEMINI_SANDBOX=true|docker|podman|sandbox-exec|runsc|lxc`, or `tools.sandbox`.
  - macOS Seatbelt profiles (`permissive|restrictive|strict` × `open|proxied`).
  - Docker/Podman with image `ghcr.io/google/gemini-cli` (or a custom one), workspace mounted at the identical path.
  - gVisor `runsc` and LXC on Linux; native Windows sandbox.
  - Running Gemini *inside* Docker with sandboxing requires mounting `/var/run/docker.sock`.
  - `tools.sandboxNetworkAccess` defaults to false.
  - A newer `security.toolSandboxing` (default false) isolates individual tools; its Linux mechanism is [U].
  - [H] https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md
  - **For wicket:** leave Gemini's sandbox off. Its container modes need a container runtime and socket, which conflicts with a least-privilege box.
- **Proxy:**
  - The CLI reads `HTTPS_PROXY`/`https_proxy`/`HTTP_PROXY`/`http_proxy`/`ALL_PROXY` from the environment (`packages/cli/src/config/config.ts`, lines around 1039–1045). There is no `--proxy` flag in the current CLI reference.
  - `GEMINI_SANDBOX_PROXY_COMMAND` runs a sidecar proxy for the sandbox.
  - [H] https://github.com/google-gemini/gemini-cli/blob/main/packages/cli/src/config/config.ts and https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/enterprise.md
- **Custom CA:** `NODE_USE_SYSTEM_CA=1` (system store) or **`NODE_EXTRA_CA_CERTS=/path/ca.pem`**. [H] https://github.com/google-gemini/gemini-cli/blob/main/docs/resources/troubleshooting.md
- **Auth:**
  - `GEMINI_API_KEY` (Gemini API).
  - Vertex: `GOOGLE_GENAI_USE_VERTEXAI` + `GOOGLE_CLOUD_PROJECT`/`GOOGLE_CLOUD_LOCATION` + ADC/`GOOGLE_APPLICATION_CREDENTIALS`, or `GOOGLE_API_KEY` (express).
  - Google OAuth login (Code Assist).
  - `security.auth.enforcedType` pins the method.
  - [H] configuration.md
  - OAuth tokens are cached under `~/.gemini/` [M]. Avoid OAuth in the sandbox, because refresh tokens would live there.
- **Base URL override:**
  - **`GOOGLE_GEMINI_BASE_URL`** applies with `gemini-api-key` auth; **`GOOGLE_VERTEX_BASE_URL`** applies with Vertex.
  - "must use HTTPS unless pointing to `localhost`".
  - [H] configuration.md
  - **For wicket:** the LLM proxy must present a cert the sandbox trusts (via `NODE_EXTRA_CA_CERTS`) or be port-forwarded to localhost.
- **ACP mode:**
  - `gemini --acp` per https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/acp-mode.md; the registry uses `--acp`. `cli-reference.md` still lists `--experimental-acp` as "Experimental" [M: the docs are inconsistent].
  - Supports `session/load`, `setSessionMode`, `unstable_setSessionModel`, and **proxies file-system access through the client**.
  - In MCP permission requests it sets `toolCall._meta['gemini-cli'].mcp = {server_name, tool_name}`.
  - [H]
- **Telemetry and update:**
  - `privacy.usageStatisticsEnabled` (default **true**; set false).
  - `telemetry.enabled` (default off; `GEMINI_TELEMETRY_*` env).
  - `general.enableAutoUpdate` (default **true**) and `general.enableAutoUpdateNotification`.
  - [H] configuration.md
- **Env redaction:** best-effort redaction of secret-looking env vars (names containing TOKEN, KEY, SECRET, CERT and so on) before tool execution [H]. This may strip proxy variables such as `HTTPS_PROXY` with embedded credentials; behaviour for `NODE_EXTRA_CA_CERTS` is [U], because "CERT" in the name may match.

---

### 2.4 OpenCode (`anomalyco/opencode`; `sst/opencode` redirects there)

**Major change:** **OpenCode 2** (current release v2.2.6, 2026-11-06; npm `@opencode/cli`; installer `curl -fsSL https://opencode.ai/v2/install | bash`).

- **Three breaking areas:** plugins, the server API, and the TUI config.
- **Architecture:** a **shared per-user background service** that "owns sessions, configuration, integrations, permissions, and tool execution", unless you pass `--standalone`.
- **Version lines:** V1 continues as npm `opencode-ai` 1.19.5. The registry lists both "OpenCode" and "OpenCode V2" at 2.2.6, which is confusing [M].
- Sources: https://github.com/anomalyco/opencode/blob/dev/services/site/src/docs/content/migrate-v1.mdx and https://github.com/anomalyco/opencode/blob/dev/services/site/src/docs/content/cli/index.mdx [H]

**Config:**
- Files: JSON/JSONC `opencode.json(c)`.
  - Global: `~/.config/opencode/`.
  - Project: `opencode.json(c)` or `.opencode/opencode.json(c)`, searched upward.
  - **System/managed: `/etc/opencode/`** (highest precedence; also loads `agents/`, `commands/`, `skills/`, `plugins/`). macOS MDM is also supported.
  - Admin restrictions must be expressed as **`policies`**. Policies can only turn allow/ask into deny.
  - [H] https://github.com/anomalyco/opencode/blob/dev/services/site/src/docs/content/config.mdx and `policies.mdx`
- Env injection:
  - `OPENCODE_CONFIG` (path), `OPENCODE_CONFIG_DIR` and **`OPENCODE_CONFIG_CONTENT` (inline JSON)** are documented for V1 [H] (`packages/web/src/content/docs/config.mdx`).
  - The V2 source still reads `OPENCODE_CONFIG_CONTENT` and `OPENCODE_CONFIG_DIR` [H, code: `packages/core/src/config.ts`, `packages/cli/src/server-process.ts`], but the V2 docs no longer document them [M].
  - Variable substitution: `{env:VAR}`, `{file:path}`.
- **Update:** `"update": "disable" | "notify" | "auto"` (global config only). [H] config.mdx (v2)
- V1 env knobs, listed in the dev-branch V1 docs:
  - `OPENCODE_DISABLE_MODELS_FETCH`, `OPENCODE_MODELS_PATH` (pins the model catalog offline)
  - `OPENCODE_DISABLE_LSP_DOWNLOAD`, `OPENCODE_DISABLE_DEFAULT_PLUGINS`, `OPENCODE_DISABLE_PROJECT_CONFIG`
  - `OPENCODE_DISABLE_CLAUDE_CODE*`, `OPENCODE_PERMISSION` (inline JSON), `OPENCODE_PURE`
  - [H for V1; M for V2] https://github.com/anomalyco/opencode/blob/dev/packages/web/src/content/docs/cli.mdx

**Permissions (V2):**
- An ordered `permissions` array of `{action, resource, effect: allow|deny|ask}`; the last match wins and **no match means `ask`**.
- Actions renamed from V1: `bash`→`shell`, `task`→`subagent`, `write`/`patch`→`edit`.
- Replies: `once`, `always` (saves a durable project-scoped allow), `reject` (rejects **all** pending requests in the session).
- "Non-interactive clients must decide how to handle approval requests; configured `deny` rules always remain enforced."
- `opencode run --auto` auto-approves anything not explicitly denied.
- [H] https://github.com/anomalyco/opencode/blob/dev/services/site/src/docs/content/permissions.mdx and `cli/commands.mdx`
- Behaviour of `ask` in plain `opencode run` without `--auto` is [U].

**MCP:**
- V2 shape: `mcp.servers.<name>` with `type: "local"` (`command: [..]`, env) or `type: "remote"` (`url`, `headers`, `oauth: false|{...}`), plus `disabled`.
- **Remote servers use OAuth by default**; set `oauth: false` for header auth.
- CLI: `opencode mcp add`.
- [H] https://github.com/anomalyco/opencode/blob/dev/services/site/src/docs/content/mcp-servers.mdx

**Provider base URL:**
- V2: `providers.<id>.settings.baseURL` (for example to `https://llm-proxy.example.com/anthropic`); custom providers via `package: "@opencode/ai/providers/openai-compatible"`, with `env: ["ACME_API_KEY"]`. [H] https://github.com/anomalyco/opencode/blob/dev/services/site/src/docs/content/providers.mdx
- V1 used `provider.<id>.options.baseURL` [M].

**Server mode:**
- `opencode serve [--hostname --port 4096 --cors]` exposes a new V2 HTTP API (client `@opencode/client`).
- Basic auth with username fixed to `opencode` and password `OPENCODE_PASSWORD` (`OPENCODE_SERVER_PASSWORD` still accepted).
- `opencode api GET /api/...`.
- [H] migrate-v1.mdx and cli/commands.mdx

**Headless:** `opencode run [--standalone] [--format json] [--model] [--session] [--auto] "<prompt>"`. CI guidance is to use `--standalone`. [H]

**ACP:** `opencode acp` [H] https://github.com/anomalyco/opencode/blob/dev/services/site/src/docs/content/cli/acp.mdx
- Protocol v1 over stdio. It starts a **private server, does not use the shared service, and opens no network port**.
- Capabilities: `loadSession`, `mcpCapabilities.http` (no SSE, **no MCP-over-ACP**), `additionalDirectories`, `close`, `delete`, `fork`, `list`, `resume`.
- ACP-provided MCP servers replace same-named configured ones, with no OAuth and headers passed through.
- Permission options: `once` / `always` / `reject`.
- On cancel, pending permission requests are rejected.
- Auth uses the existing `opencode auth login` credentials; it returns `auth_required` otherwise.

**Proxy and CA:**
- `HTTP_PROXY`/`HTTPS_PROXY` plus **mandatory `NO_PROXY=localhost,127.0.0.1,::1`**, because the CLI talks to its local service over HTTP.
- `NODE_EXTRA_CA_CERTS`.
- With the background service, env must be persisted via `opencode service set env ...`; `--standalone` and `serve` use their own process env.
- [H] https://github.com/anomalyco/opencode/blob/dev/services/site/src/docs/content/network.mdx

**Own sandbox:** none; it relies on permission rules [M: no sandbox implementation in the docs or source tree]. The outer box is the only enforcement.

---

### 2.5 goose (now `aaif-goose/goose`, v1.57.0, 2026-10-28)

**Governance:** Block contributed goose as a founding project of the Linux Foundation's **Agentic AI Foundation (AAIF)**, announced 2025-12-09 alongside MCP and AGENTS.md. [H] https://www.linuxfoundation.org/press/linux-foundation-announces-the-formation-of-the-agentic-ai-foundation. The GitHub org is now `aaif-goose`; docs are at goose-docs.ai.

**Config:**
- `~/.config/goose/config.yaml`, plus `permission.yaml`, `secrets.yaml` (when the keyring is disabled) and `permissions/tool_permissions.json`.
- Env vars override config, for example `GOOSE_PROVIDER`, `GOOSE_MODEL`, `GOOSE_MODE`.
- **`GOOSE_PATH_ROOT`** relocates all config, data and state, which fits a per-run isolated root.
- `GOOSE_DISABLE_KEYRING` stores secrets in a file.
- `GOOSE_ALLOWLIST` is a URL listing allowed extensions.
- [H] https://github.com/aaif-goose/goose/blob/main/documentation/docs/guides/config-files.md and https://github.com/aaif-goose/goose/blob/main/documentation/docs/guides/environment-variables.md

**Extensions = MCP:**
- Types `builtin`, `platform`, `stdio` and `streamable_http`; SSE is unsupported. `available_tools` acts as an allowlist.
- CLI injection: `--with-extension "name:ENV=v cmd args"`, `--with-streamable-http-extension <url>`, `--with-builtin developer`.
- [H] config-files.md and https://github.com/aaif-goose/goose/blob/main/documentation/docs/guides/goose-cli-commands.md

**Headless:**
- `goose run -t "<text>" | -i file|- | --recipe x.yaml`.
- Flags: `--no-session`, `-q`, **`--output-format text|json|stream-json`**, `--max-turns`, `--provider`, `--model`, `--system`.
- [H] goose-cli-commands.md
- Headless "Tool Permissions: Uses configured defaults or fails safely". [H] https://github.com/aaif-goose/goose/blob/main/documentation/docs/tutorials/headless-goose.md

**Permission modes:**
- `GOOSE_MODE = auto` (**the default; fully autonomous**), `approve`, `smart_approve`, `chat`, with per-tool permissions.
- [H] https://github.com/aaif-goose/goose/blob/main/documentation/docs/guides/managing-tools/goose-permissions.md

**ACP:**
- `goose acp` over stdio. This is how goose Desktop talks to its backend.
- `goose serve` runs ACP over HTTP/WebSocket: default `127.0.0.1:3284`, requires `GOOSE_SERVER__SECRET_KEY` unless `--dangerously-unauthenticated`, optional TLS.
- [H] https://github.com/aaif-goose/goose/blob/main/documentation/docs/gdk/acp/index.md and goose-cli-commands.md
- The ACP server converts `session/new` stdio and HTTP `mcpServers` into goose extensions (SSE rejected), advertises `mcpCapabilities.http(true)` and `load_session(true)`. [H, code] https://github.com/aaif-goose/goose/blob/main/crates/goose/src/acp/server.rs
- The docs warn: "Permission callbacks are not a sandbox: goose's configured mode determines when approval is requested". [H]
- goose can also *consume* ACP agents as providers (`claude_acp`, `codex_acp`, `copilot_acp`, `pi_acp`, `amp_acp`). [H, source tree]

**Providers and base URL:**
- `GOOSE_PROVIDER__HOST` (plus `__TYPE`, `__API_KEY`).
- Per-provider hosts: `OPENAI_HOST` with `OPENAI_BASE_PATH`, `ANTHROPIC_HOST`, and others.
- Custom providers (OpenAI-, Anthropic- or Ollama-compatible JSON definitions with API URL and custom headers).
- [H] environment-variables.md and https://github.com/aaif-goose/goose/blob/main/documentation/docs/getting-started/providers.md

**Proxy:** `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`, plus OS proxy settings; env wins. [H] environment-variables.md and https://github.com/aaif-goose/goose/blob/main/documentation/docs/troubleshooting/known-issues.md

**Custom CA:** not documented.
- goose builds on reqwest 0.13 with the `rustls` feature, which uses the platform verifier and therefore the system trust store.
- **Install wicket's CA into the sandbox's system store** (`/etc/ssl/certs`). Whether `SSL_CERT_FILE` is honored is [U/M]. [M, code: https://github.com/aaif-goose/goose/blob/main/Cargo.toml and `crates/goose/Cargo.toml`]

**Own sandbox:** none [M: no sandbox code in the source tree]. The docs suggest container-based isolation, and `--container <id>` runs extensions in Docker.

**Telemetry and update:** `GOOSE_TELEMETRY_ENABLED` (default false); `goose update` is manual [H]. Whether goose has an automatic CLI update check is [U].

---

### 2.6 aider (`Aider-AI/aider`)

**Maintenance:** a slowdown. Last tagged GitHub release v0.86.0 (2025-08-09); PyPI 0.86.2 (2026-02-12); last push 2026-05-22. [H] https://github.com/Aider-AI/aider and https://pypi.org/project/aider-chat/

**Config:**
- `.aider.conf.yml` is loaded from home, then the git root, then cwd (last wins). `--config FILE` loads only that file.
- Every option has an `AIDER_*` env var.
- `.env` is loaded from the git root (`--env-file`).
- `--set-env VAR=val` and `--api-key provider=key`.
- [H] https://github.com/Aider-AI/aider/blob/main/aider/website/docs/config/options.md and `config/aider_conf.md`

**MCP:** **not supported in mainline.** PRs #3672 and #3937 ("Add MCP support") are closed. The only "mcp" hit in the repo is in `requirements/requirements.in`. The fork **cecli** (`cecli-dev/cecli`, formerly aider-ce) adds MCP. [H/M] https://github.com/Aider-AI/aider/pulls?q=MCP and https://github.com/cecli-dev/cecli. wicket's MCP gateway is not usable with stock aider.

**Credential routing:**
- `OPENAI_API_BASE` + `OPENAI_API_KEY` with `--model openai/<name>`, or `--openai-api-base`. Any litellm provider env works, such as `ANTHROPIC_API_KEY` or `*_API_BASE`.
- [H] https://github.com/Aider-AI/aider/blob/main/aider/website/docs/llms/openai-compat.md

**Proxy and CA:**
- `--verify-ssl/--no-verify-ssl` (`AIDER_VERIFY_SSL`). [H] options.md
- LLM calls go through LiteLLM. Its httpx/aiohttp clients read proxy env via `getproxies` and default to the **certifi** bundle, **not** the system store. A custom CA needs `SSL_CERT_FILE` (or `SSL_VERIFY=<path>`).
- [M: LiteLLM docs, not aider docs] https://docs.litellm.ai/docs/guides/security_settings
- **For wicket:** set `SSL_CERT_FILE` to a bundle that contains certifi plus the wicket CA, or the system CA bundle plus the wicket CA. Pointing it at the wicket CA alone breaks other TLS.
- LiteLLM may fetch its model-cost map from GitHub at startup [U]. Allowlist it or expect a fallback.

**Scripting:**
- `--message/-m`, `--message-file/-f` (single turn, then exit).
- `--yes-always` (`AIDER_YES_ALWAYS`) auto-confirms everything, including running suggested shell commands.
- `--no-auto-commits`, `--dry-run`, `--no-stream`, `--no-pretty`, `--no-suggest-shell-commands`.
- A Python API: `Coder.create(...).run(...)`.
- [H] options.md and https://github.com/Aider-AI/aider/blob/main/aider/website/docs/scripting.md
- There is no JSON event output [M], and no permission protocol beyond y/n confirmations. Behaviour of confirmations when there is no TTY and no `--yes-always` is [U].

**Telemetry and update:**
- `--analytics-disable` (permanent) or `--no-analytics` (PostHog; opt-in prompt).
- `--no-check-update` (`AIDER_CHECK_UPDATE=false`), `--no-show-release-notes`, `--disable-playwright`.
- [H] options.md and https://github.com/Aider-AI/aider/blob/main/aider/website/docs/more/analytics.md

**Own sandbox:** none.

---

### 2.7 Per-agent summary table

| | Codex CLI | Gemini CLI | OpenCode 2 | goose | aider |
|---|---|---|---|---|---|
| **Config injection** | `CODEX_HOME` dir with `config.toml`; `-c k=v` (TOML); `--profile`; `exec --ignore-user-config`; enforced `/etc/codex/requirements.toml` and `managed_config.toml` (beats `-c`) | `GEMINI_CLI_HOME`; system override `/etc/gemini-cli/settings.json` (`GEMINI_CLI_SYSTEM_SETTINGS_PATH`); `$VAR` substitution; `.env` autoload; `GEMINI_CLI_TRUST_WORKSPACE` | `/etc/opencode/opencode.json` (highest) plus `policies`; `OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR`, `OPENCODE_CONFIG_CONTENT` (in V2 code, V1 docs); `{env:}` | `GOOSE_PATH_ROOT` (whole tree); `config.yaml`; env vars override; `--with-*` flags | `--config` file; `AIDER_*` env; `--set-env`, `--api-key` |
| **Headless / I/O** | `exec --json` (JSONL: thread/turn/item events); `app-server` (JSON-RPC over stdio/ws/unix, rich approvals); ACP via `codex-acp` (wraps app-server) | `-p` + `-o json/stream-json`; `--acp` (native ACP) | `run --format json [--standalone] [--auto]`; `serve` (HTTP API, Basic auth); `acp` (native, private server) | `run -t/-i --output-format json/stream-json`; `acp` (stdio); `serve` (ACP over HTTP/WS) | `--message` + `--yes-always`; Python `Coder` API; no structured stream |
| **MCP and injection** | `[mcp_servers.*]` stdio or HTTP (`url`, `bearer_token_env_var`, `http_headers`), tool allow/deny, `required`; `-c mcp_servers.x.url=...`; ACP `mcpServers` via adapter | `mcpServers` (`httpUrl`, `headers`, `includeTools`/`excludeTools`, `trust`); ACP `mcpServers` | `mcp.servers` (`remote` + `headers` + `oauth:false`); ACP `mcpServers` (http and stdio, no MCP-over-ACP) | `extensions` (`streamable_http`/`stdio`); `--with-streamable-http-extension`; ACP `mcpServers` → extensions | **None** (fork cecli has it) |
| **Credential routing** | `model_providers.<id>.base_url` + `env_key` (or `auth` helper) + `model_provider=`; `openai_base_url`; or dummy `OPENAI_API_KEY`/`CODEX_API_KEY` swapped by the proxy. Avoid ChatGPT `auth.json` (refresh tokens) | `GOOGLE_GEMINI_BASE_URL` / `GOOGLE_VERTEX_BASE_URL` (HTTPS or localhost only) + dummy `GEMINI_API_KEY`; avoid OAuth | `providers.<id>.settings.baseURL`; custom openai-compatible provider with `env:[...]` | `GOOSE_PROVIDER__HOST`, `OPENAI_HOST`/`ANTHROPIC_HOST`, custom provider JSON | `OPENAI_API_BASE` / litellm `*_API_BASE` + dummy key |
| **Proxy + custom CA** | Env proxies honored; `CODEX_CA_CERTIFICATE` → `SSL_CERT_FILE`, added to native roots | `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` env; `NODE_EXTRA_CA_CERTS` or `NODE_USE_SYSTEM_CA=1` | `HTTP(S)_PROXY` + **`NO_PROXY=localhost,127.0.0.1,::1` required**; `NODE_EXTRA_CA_CERTS`; with the background service use `service set env` | `HTTP(S)_PROXY`/`NO_PROXY`; CA via system trust store (rustls platform verifier) [M] | Env proxies (litellm/httpx); `SSL_CERT_FILE` (certifi default, **not** system store) [M]; `--no-verify-ssl` |
| **Own sandbox / nesting conflict** | bwrap + seccomp (Linux), Seatbelt (macOS); needs unprivileged userns, so it typically fails in Docker. Use `--sandbox danger-full-access` + `-a never` (or `--yolo`) inside the outer box; in a microVM it can be kept as defense in depth. Also ships its own MITM egress proxy (`codex-network-proxy`) | Optional docker/podman/runsc/lxc/seatbelt; container modes need a runtime or `docker.sock`, so disable it in wicket | None | None | None |
| **Telemetry / update off** | `analytics.enabled=false`, `feedback.enabled=false`, `check_for_update_on_startup=false`, `[otel] exporter="none"` (default off) | `privacy.usageStatisticsEnabled=false` (default true), `general.enableAutoUpdate=false` (default true), `enableAutoUpdateNotification=false`; telemetry default off | `"update":"disable"`; V1 env `OPENCODE_DISABLE_MODELS_FETCH`/`OPENCODE_MODELS_PATH`, `OPENCODE_DISABLE_LSP_DOWNLOAD`, `OPENCODE_DISABLE_DEFAULT_PLUGINS` | `GOOSE_TELEMETRY_ENABLED=false` (default false); updates manual | `--analytics-disable`, `--no-check-update`, `--disable-playwright` |
| **On denied tool / permission** | exec defaults to `approval_policy=never`, so a sandbox denial comes back as a failed command and the model continues [M]. app-server `decline` gives item status `declined` and the turn continues [H]. `untrusted` retired, `on-failure` deprecated | Headless: policy `ask_user` = **deny** [H]; ACP: `session/request_permission` (reject means the tool is not run) | No match = `ask`; `reject` rejects all pending requests in the session; `deny` always enforced; `run --auto` approves non-denied; ACP options `once`/`always`/`reject` | Default `GOOSE_MODE=auto` (no prompts); `approve`/`smart_approve` prompt; headless "fails safely" | `--yes-always` approves all; otherwise y/n prompts (non-TTY behaviour [U]) |

---

### 2.8 Design implications for wicket (from the agent survey)

1. **Enforcement cannot live in ACP permission answers alone.** The v1 security page says permission is advisory and ACP does not sandbox. ACP v2 removes `fs/*` and `terminal/*`, so client-side mediation of file and exec operations is going away. The sandbox, the egress proxy and the MCP gateway must be the real controls. Use ACP permission requests as a policy and audit hook, answered by wicket under user-configured policy, which the spec explicitly allows for intermediaries.
2. **Build the driver on the Rust `agent-client-protocol` 5.x crate.**
   - Use its Client and Proxy roles; the Conductor and proxy chains are a candidate architecture.
   - Use the `agent-client-protocol-rmcp` integration, and possibly `unstable_mcp_over_acp`, so gateway tools can ride the ACP pipe with no network path from the sandbox.
   - Pin `protocolVersion` 1 and gate v2.
3. **Inject MCP per session** via `session/new.mcpServers` as HTTP entries. Codex (via the adapter), Gemini, OpenCode, goose and the Claude adapter all accept them; check `mcpCapabilities.http`. For non-ACP runs, use each agent's config (see the table). aider has no MCP.
4. **Credentials:**
   - Prefer base-URL overrides pointing at an LLM proxy outside the sandbox: Codex `model_providers`, `GOOGLE_GEMINI_BASE_URL`, OpenCode `settings.baseURL`, `GOOSE_PROVIDER__HOST`, `OPENAI_API_BASE`.
   - Alternatively, use the TLS-intercepting proxy with a dummy key in env.
   - Avoid ChatGPT, Google and other OAuth flows, which persist refresh tokens in the sandbox.
   - Codex app-server's `chatgptAuthTokens` lets a host push short-lived access tokens without a refresh token, if ChatGPT plans are required.
   - Watch the ACP "Configurable LLM Providers" RFD (Draft); it would standardize this.
5. **CA distribution needs several mechanisms at once:**
   - the system store (goose and other rustls platform-verifier users)
   - `NODE_EXTRA_CA_CERTS` (Gemini, OpenCode, Claude adapter, npm adapters)
   - `CODEX_CA_CERTIFICATE` or `SSL_CERT_FILE` (Codex)
   - `SSL_CERT_FILE` with a *combined* bundle (aider/litellm, which defaults to certifi)
   - `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO` (tools the agents spawn)
   - Always set `NO_PROXY` for loopback; OpenCode breaks without it.
   - Gemini's env redaction may scrub some of these from tool subprocesses [U].
6. **Pin policy with each agent's "managed" layer inside the image,** so agent-writable user or project config cannot loosen it: Codex `/etc/codex/requirements.toml`, Gemini `/etc/gemini-cli/settings.json`, OpenCode `/etc/opencode/opencode.json` with `policies`. Also disable auto-update, telemetry and model-catalog fetches so the egress allowlist can stay tight.

**Unverified or flagged items:**
- Agent-specific permission timeouts.
- Gemini `security.toolSandboxing` mechanism on Linux.
- How OpenCode `run` handles `ask` without `--auto`.
- Whether goose honors `SSL_CERT_FILE`.
- aider's non-TTY confirm default.
- The date `codex mcp-server` was removed.
- A2A's move to AAIF.
- The Gemini `--acp` vs `--experimental-acp` documentation inconsistency.

---

## 3. Other harnesses and sandbox orchestrators (prior art)

_This section was researched by a parallel sub-agent on 2026-11-08 and is included as delivered, with headings renumbered. Its confidence labels are **[H]** = primary source states it, **[M]** = implied or secondary, **[U]** = unverified._

**Method.** I read official docs, engineering blogs and GitHub READMEs (through `gh api`) on 2026-11-08. Doc pages are "living" pages, so the date I give for them is when I read them, not when they were published. Confidence labels: **[H]** a primary source states it directly; **[M]** a primary source implies it, or only secondary sources state it; **[U]** I could not verify it. Everything I could not verify is collected in §14.

---

### 3.0 Comparison at a glance

| System | Isolation | Egress control | TLS MITM | Credentials injected outside the sandbox? | MCP mediation | Snapshot / pause | How a denial reaches the agent | Per-request async human approval |
|---|---|---|---|---|---|---|---|---|
| Docker Sandboxes (`sbx`) | microVM, custom VMM on HVF/WHP/KVM | Host proxy; rules on host/IP/CIDR plus HTTP method/path/query; UDP and ICMP blocked | Yes (CA merged into the trust bundle) | **Yes**: the sandbox sees a sentinel or placeholder, the host proxy swaps in the real value | Per-sandbox MCP gateway on the host | VM persists until `rm`; no snapshot API found | Text message "Approval required for <host>"; the triggering request fails | **Yes**: `sbx policy approval ls/respond`, scoped to exact destination, method and path |
| E2B | Firecracker [M] | `allowOut`/`denyOut` (CIDR/IP/domain); domains matched by Host header (port 80) or SNI (port 443); BYO SOCKS5 | Only for hosts with rules (E2B CA) | **Yes (public beta)**: `network.rules[host].transform.headers`, `Secret.fill`, per-request workload-identity tokens | None | Pause/resume with memory; filesystem-only option | Connection may look accepted and then fail | No |
| Daytona | Container, or VM with its own kernel | Block-all, CIDR list, or domain list (by host name) | Yes, for allowed hosts (Daytona CA) | **Yes**: `dtn_secret_…` placeholders, HTTPS headers only, per-secret host list, echoed values rewritten in responses | None | Pause, fork, hot snapshot (VM only) | Not documented | No |
| Modal | gVisor or a VM under KVM | CIDR allowlist; domain allowlist by SNI only (beta); optional sidecar proxy | No (SNI only) | No (secrets are env vars), unless you build it in a sidecar | None | Filesystem snapshots; memory snapshots (experimental) | Blocked TLS is logged to the sandbox's system output | No |
| Cloudflare Sandbox/Containers | Firecracker microVM per instance | Outbound Workers written as code; `allowedHosts`/`deniedHosts` | Yes, an ephemeral CA per instance | **Yes**: Worker code adds headers; keys per instance through `ctx.containerId` | MCP portals (separate Zero Trust product) | Directory backup/restore to R2 | Whatever the handler returns (403/405 plus a body) | Possible in code (handlers can be swapped at runtime); the blog suggests it but nothing is built in |
| Browser Use | Unikraft micro-VM | VM can reach only the control plane (private VPC) | n/a | **Yes, at the application level**: the control plane holds every credential and the agent calls control-plane APIs | n/a | Suspend/resume | Application-defined | n/a |
| OpenHands | Docker container plus action-execution server | Not documented | No | **No**: secrets resolve inside the sandbox and are masked in output | Agent-side | No | n/a | Confirmation mode at the agent level [M] |
| Claude Code cloud | Anthropic-managed VM | Security proxy; None/Trusted/Full/Custom levels | [U] for the general proxy; GitHub proxy is protocol-aware | **Yes**: GitHub proxy (scoped credential swapped for the real one) and "network secrets" (agent proxy) | Connectors go through Anthropic servers, outside the VM | Setup-script filesystem snapshot (about 7-day cache) | GitHub proxy returns 403 with an explanatory message | Local CLI: yes (sandbox-runtime asks before new domains); cloud: approval for MCP tool calls |
| sandbox-runtime (`srt`) | bubblewrap+seccomp / Seatbelt / Windows WFP account | Host HTTP+SOCKS proxy over a Unix socket; allow/deny domains; resolved-address check | Optional (`tlsTerminate`) | **Yes**: `credentials.mode:"mask"` with sentinels; SigV4 re-signing | n/a | n/a | 403 whose status phrase carries a model-facing reason, plus a `<sandbox_violations>` block | **Yes**: async `SandboxAskCallback` |
| Copilot cloud agent | Actions runner, or "cloud sandbox" (default from Oct 2026) | Firewall allowlist (domains, or URL+path prefix) | Implied by URL rules [U] | No proxy injection documented; scoped token and branch limits instead | MCP servers are **outside** firewall coverage | Cloud sandbox is snapshotted while stopped | Warning in the PR body or a comment | No (add the host, start a new session) |
| gh-aw (Agentic Workflows) | Docker (AWF), Cloud Hypervisor microVM in preview | Squid plus iptables; SSL Bump for URL rules | Optional | **Yes for LLM keys** (API-proxy sidecar); GitHub writes go through "safe outputs" | MCP gateway, one container per server | n/a | Logs and audit | Approval labels only |
| Codex cloud | Container/VM | Off/limited/full; domain presets; GET/HEAD/OPTIONS-only option (legacy) | Yes, for secret hosts | **Yes (new UI)**: "HTTP secrets" placeholders on port 443; legacy secrets are setup-only | — | Container cache 12 h (legacy); VM state kept 7 days | Not documented | No |
| Vercel Sandbox | Firecracker | allow-all/deny-all/user rules; SNI domains plus CIDR | Only for domains that have rules (per-sandbox CA) | **Yes**: `transform.headers`, plus `forwardURL` with an OIDC token | — | Persistent sandboxes | `response` rule (status, headers, body) | No |
| microsandbox (Rust) | libkrun microVM, smoltcp | Host policy; rules, profiles, DNS | Yes (`interceptTls`) | **Yes**: placeholder, then substitution in header, query or body | — | Snapshot, fork, restore | **JSON 403 `{code, message, domain}`** with a configurable message | No |
| iron-proxy (Go) | n/a (a proxy) | Default-deny MITM proxy plus its own DNS | Yes | **Yes**: proxy tokens swapped at egress; Postgres `SET ROLE` | "MCP-aware policy interceptor" [M] | n/a | 403 plus a JSON audit record | No |

---

### 3.1 Docker Sandboxes (`sbx`) and Docker MCP Gateway

**Docker Sandboxes**
- **Product and dates.** A standalone `sbx` CLI; it does not need Docker Desktop. The Desktop-integrated `docker sandbox` is deprecated. The architecture blog post is dated 2026-04-16 [H] (https://www.docker.com/blog/why-microvms-the-architecture-behind-docker-sandboxes/). The GA date is disputed (claims of Jan, Mar and Sep 2026) [U] (https://forums.docker.com/t/what-is-the-current-release-status-of-docker-sandboxes-early-access-experimental-or-ga/151749).
- **Isolation.** Docker wrote its own cross-platform VMM on Hypervisor.framework (macOS), Windows Hypervisor Platform and KVM, because Firecracker is Linux-only. Each VM has its own kernel and a private Docker daemon, so agents get `docker build`/`compose` without mounting the host socket [H] (blog above). The agent is non-root with sudo inside the VM; the hypervisor is the boundary [H] (https://docs.docker.com/ai/sandboxes/security/isolation/).
- **Workspace modes.**
  - Direct mount (virtiofs).
  - Mountless.
  - Clone mode: host repo mounted read-only at `/run/sandbox/source`, the agent works in a private clone, and changes come back through a `sandbox-<name>` git remote. Caveat: `.env` and ignored files are still readable [H] (https://docs.docker.com/ai/sandboxes/architecture).
- **Egress.** All outbound TCP goes through a host-side proxy: a forward proxy for HTTP(S) and transparent forwarding for other TCP. UDP is off by default, ICMP is always blocked, and DNS goes through an internal resolver that enforces policy [H] (isolation page).
  - Rules match a hostname, IP or CIDR; HTTP rules can also match method, path and query; non-HTTP rules take a port (`sbx policy allow network "myhost:22"`).
  - Presets: `allow-all`, `balanced` (default deny plus a baseline of AI APIs, package registries, code hosts, etc.) and `deny-all`.
  - Rules are global or per-sandbox, and a deny from any source wins [H] (https://docs.docker.com/ai/sandboxes/governance/local/).
  - A TLS-proxy CA is merged into the sandbox trust bundle (v0.35.0 release notes) [H], which implies MITM is needed for the path rules (https://github.com/docker/sbx-releases/releases/tag/v0.35.0).
- **Credentials.**
  - The agent sees a sentinel. The host proxy checks that policy permits the provider domain, then swaps in the real credential header. Only the forward proxy injects [H] (architecture and isolation pages).
  - `sbx secret set` stores values in the OS keychain, globally or per sandbox.
  - `sbx secret set-custom` binds a value to a target domain, an env-var name and an optional placeholder.
  - GitHub: `sbx secret set github --command 'gh auth token'`.
  - Claude subscription `/login` OAuth runs in the sandbox, but the token stays on the host.
  - Since v0.35.0, host env vars are no longer injected automatically [H/M] (https://docs.docker.com/ai/sandboxes/get-started.md, search summary of https://docs.docker.com/ai/sandboxes/security/credentials.md, which returned 404 when fetched).
  - **Caveat:** SSH-agent forwarding is on by default, so any process in the VM can ask the host agent to sign [H] (isolation page).
- **MCP.** One MCP gateway endpoint per sandbox, running **on the host**. Stdio servers run on the host, never in the VM. Tool calls, resource reads and prompts are policy-checked at the gateway, separately from the HTTP proxy [H] (architecture page).
- **Denials and approvals (closest match to wicket's "dynamic escalation").**
  - Under the balanced or deny-all preset, a destination no rule covers is blocked and an approval entry is recorded. Org policy can also say "allow, but require approval". Deny rules never prompt.
  - The agent sees the text "Approval required for api.example.com", pointing at `sbx policy approval ls`.
  - The **triggering request is denied and does not wait**; an agent that retries gets the new access on its next attempt.
  - Repeated attempts collapse into one entry.
  - Approval is exact: one destination (not a pattern), one port, one sandbox, and for HTTP rules one method+path (`GET api.example.com:443/v1/data`).
  - Requests that cannot be recorded as a rule (for example percent-encoded paths) are blocked with no entry.
  - CLI: `sbx policy approval ls | inspect <ID> | respond <ID> --option allow|dismiss`.
  - No HTTP status or error schema is documented [H] (https://docs.docker.com/ai/governance/local/approvals.md).
- **Snapshots.** The VM persists across stop/start until `sbx rm`. I found no snapshot or fork API [M].

**Docker MCP Gateway** (`docker/mcp-gateway`, Go, v0.44.3, 2026-10-26) [H]
- Each catalog MCP server runs in its own container, with per-server `--cpus`/`--memory` limits.
- `--secrets` reads from the Docker Desktop secrets API or `.env` files.
- `--block-secrets` (on by default) scans tool arguments and results for anything that looks like a secret.
- `--block-network` restricts tools' network access.
- `--verify-signatures` checks server images.
- `--log-calls` is on by default.
- `--interceptor when:type:target`, where `when` is before/after and `type` is exec/docker/http (https://docs.docker.com/reference/cli/docker/mcp/gateway/run/).
- A *before* interceptor that returns a non-empty response short-circuits the tool call, which can be used as a policy or approval hook. *After* interceptors see only the result [M] (https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Docker-MCP-Gateway).
- Profiles group servers and can be pushed and pulled as OCI artifacts [H] (README).
- How secrets reach server containers (env var or file) is described inconsistently [U].

### 3.2 E2B

- **Isolation.** Firecracker microVMs [M] (Vercel's comparison https://vercel.com/kb/guide/vercel-sandbox-vs-e2b). The open-source infra is now `e2b-dev/runtime` (Go, release 2026.30, 2026-09-10) [H].
- **Egress** (https://docs.e2b.dev/network/internet-access) [H]:
  - `allowOut` takes IP, CIDR or domain; `denyOut` takes IP or CIDR only. **Allow beats deny.**
  - Domains are matched by **Host header on port 80 and SNI on port 443**. Other ports are CIDR-only. QUIC/UDP cannot be domain-filtered.
  - **DNS hole:** whenever a domain is allowed, 8.8.8.8 is auto-allowed **for all traffic**, and listing it in `denyOut` does not remove it. `dnsServers` replaces the resolvers but does not touch `/etc/resolv.conf`.
  - **Denied TCP may appear to connect**, because the firewall accepts the connection first; the docs say to check application-level responses.
  - `updateNetwork` replaces the whole config at runtime. `allowPublicTraffic`, `maskRequestHost` and `httpsPorts` are create-only.
- **Credential injection** (public beta) [H]:
  - `network.rules[host].transform.headers` applies to HTTPS only.
  - Header values can be `Secret.fill(...)`, which the egress proxy resolves outside the sandbox.
  - `transform` can be a callback that reads workload-identity tokens `iam.tokens.<name>`, minting **a fresh token per request**.
  - Rules do not grant egress by themselves; the host must also be in `allowOut`.
  - One rule per host; the most specific wildcard wins.
  - Limits: 10 domains per sandbox, 20 headers per rule.
  - The E2B CA is installed into the system bundle and **may change on resume**, so clients that pin certificates must reload.
- **BYO egress proxy** (e2b@2.41.0): SOCKS5 tunnelling happens on the host *after* allow/deny evaluation and fails closed. UDP/DNS is not tunnelled. Not available in self-hosted OSS infra [H] (https://github.com/e2b-dev/E2B/releases/tag/e2b%402.41.0).
- **Snapshots.** Pause keeps filesystem and memory (about 4 s per GiB of RAM); `keepMemory:false` keeps disk only; auto-pause on timeout [H] (https://docs.e2b.dev/sandbox/persistence).
- **MCP.** None found.
- **SDK.** JS and Python. No official Rust SDK found [M].

### 3.3 Daytona

- **Isolation.** Container sandboxes (namespaces plus limits), and VM sandboxes (Linux and Windows) with their own kernel. Pause/resume, fork and hot snapshots are **VM-only**. The container runtime is not named [H/U] (https://www.daytona.io/docs/en/isolation.md).
- **Egress** (https://www.daytona.io/docs/en/network-limits, docs v0.231) [H]:
  - Three mutually exclusive modes: `networkBlockAll`, `networkAllowList` (at most 10 IPv4 CIDRs) or `domainAllowList` (at most 100, `*.` wildcards).
  - An optional create-time `outboundProxyUrl`.
  - The egress proxy **terminates TLS for allowed hosts** and re-encrypts with a Daytona CA.
  - Live updates through `POST /api/sandbox/{id}/network-settings` (tier 3/4 only).
  - Tier 1/2 orgs get a forced allowlist of "essential services".
- **Secrets** (https://www.daytona.io/docs/en/secrets/) [H]:
  - Org-level secret with `name`, `value` and `hosts`. Mounted as an env var whose value is a placeholder `dtn_secret_<random>`; the placeholder stays stable across rotation.
  - Substitution happens **only in HTTPS request headers**, with Basic auth decoded, substituted and re-encoded. Not in bodies, query strings or plain HTTP, and not in transformed placeholders.
  - **Responses that echo the real value are rewritten back to the placeholder.**
  - Omitting `hosts` makes the secret substitutable for any host, which the docs warn makes it readable by anyone who can mount it.
  - `manage:secrets` can widen hosts without re-entering the value, which is a privilege-escalation path the docs call out.
  - Updates take effect within about 30 s and are audit-logged.
  - The docs conflict on whether responses are rewritten (v2 isolation page says no) [M/U].
- **Denials.** Not documented.

### 3.4 Modal Sandboxes

- **Isolation.** gVisor, or a dedicated VM with its own kernel under KVM [H] (https://modal.com/docs/guide/sandbox-networking).
- **Egress:**
  - `block_network=True` blocks everything.
  - `outbound_cidr_allowlist` (any protocol).
  - `outbound_domain_allowlist` (beta): **TLS on port 443 only, matched by SNI**. Modal resolves the hostname itself, but **does not decrypt**, so Host, path and body are not inspected. No ECH. Domain fronting is called out, and a Sidecar is the recommended fix.
  - The two allowlists are additive. DNS is unrestricted unless all network is blocked.
  - `proxy_traffic_via_sidecar` (experimental) routes port 443 through a sidecar that has its own egress policy.
  - Runtime updates: `_experimental_set_outbound_network_policy` (alpha) **terminates established connections** that the new policy no longer permits.
  - Inbound: tunnels (`encrypted_ports`, `h2_ports`) and connect tokens, with the app receiving an `X-Verified-User-Data` header.
  - Blocked TLS is logged to the sandbox's system output [H].
- **Credentials.** `secrets=` are injected as **env vars inside** the sandbox. No credential injection is documented [H/M].
- **Snapshots.** `snapshot_filesystem()` returns an Image (30-day default TTL). Memory snapshots exist behind an experimental flag and expire after 7 days [H] (https://modal.com/docs/guide/sandbox-snapshots.md).

### 3.5 Browser Use: "two ways to sandbox agents"

- Larsen Cundric, published 2026-02-25 [H] (https://browser-use.com/posts/two-ways-to-sandbox-agents).
- **Pattern 1** isolates only the tool. **Pattern 2** isolates the *whole agent*, which "should have nothing worth stealing and nothing worth preserving". Browser Use moved to Pattern 2.
- **Runtime.** The same image runs as a Unikraft micro-VM in production (Unikraft Cloud REST API, bare metal in AWS, under 1 s boot, suspend when idle and resume on request) and as Docker in dev and evals.
- **What the VM gets.** Only `SESSION_TOKEN`, `CONTROL_PLANE_URL` and `SESSION_ID`, which are deleted from `os.environ` after they are read. The VM sits in a private VPC that can reach only the control plane. Python ships as bytecode with the `.py` files removed, and privileges are dropped to a `sandbox` user.
- **Control plane.** A stateless FastAPI service that authenticates every call by session token.
  - It **owns the conversation**: the sandbox sends only new messages, and the control plane rebuilds context, enforces cost caps and bills.
  - Files go through **session-scoped presigned S3 URLs** ("handles not contents").
  - Agent code programs against `AgentGateway{invoke_llm, persist_messages}`, with `ControlPlaneGateway` in production and `DirectGateway` locally.
- **Tradeoffs they state.** An extra hop on every operation, and three services to run instead of one.
- **Relevance to wicket.** This pattern needs **a cooperating agent** (they control the agent code). For black-box agents like Claude Code, wicket has to get the same property with a transparent proxy plus placeholders. Unikraft's customer story repeats these points (https://unikraft.com/customer-stories/browser-use-sandboxing) [vendor].

### 3.6 Cloudflare Sandbox SDK and Containers

- **Isolation.** "Each container instance runs in a Firecracker microVM with its own kernel and network" [H] (https://developers.cloudflare.com/containers/platform-details/architecture/). Containers and Sandboxes went GA on 2026-04-13 (https://developers.cloudflare.com/changelog/post/2026-04-13-containers-sandbox-ga/).
- **Outbound Workers** (2026-04-13; needs `@cloudflare/sandbox` 0.8.9 or `@cloudflare/containers` 0.3.0) [H] (https://blog.cloudflare.com/sandbox-auth/, https://developers.cloudflare.com/changelog/post/2026-04-13-sandbox-outbound-workers-tls-auth/):
  - Egress handlers are **ordinary Worker code** running outside the sandbox on the same machine: `static outbound`, `outboundByHost`, named `outboundHandlers`, and `setOutboundHandler(name, params)` / `setOutboundByHost()` **at runtime**, without restarting.
  - A changed handler takes effect on the next request on an already-open connection.
  - `allowedHosts`/`deniedHosts` globs; setting `allowedHosts` makes the policy deny-by-default.
  - **TLS:** a per-instance ephemeral CA, trusted by default in Sandboxes (Containers opt in with `interceptHttps = true`). The private key stays in the runtime sidecar.
  - **Identity:** `ctx.containerId` gives per-sandbox identity, used to look up per-sandbox keys in KV or scope R2 paths. Handlers can call Worker **bindings** (KV, R2, service bindings) directly, so the sandbox needs no credentials for them.
  - **Denials** are whatever the handler returns (the examples use 403 and 405 with bodies).
  - Logs go to Workers observability and Logpush.
  - Local dev: a `proxy-everything` sidecar with TPROXY nftables rules.
  - The blog suggests a future flow where the agent asks the user and the rules are updated, but it is not built in.
- **Snapshots.** `createBackup()`/`restoreBackup()` of directories to R2 (FUSE overlay), 2026-02-23 [H] (https://developers.cloudflare.com/changelog/post/2026-02-23-sandbox-backup-restore-api/index.md).
- **MCP server portals** (Cloudflare One/Access, GA 2026-09-24): several remote MCP servers behind one endpoint, with Access OAuth and logging of tool, prompt and resource activity [H] (https://developers.cloudflare.com/changelog/post/2026-09-24-mcp-portals-ga/).
- **AI Gateway** is a separate product for model traffic [M].

### 3.7 OpenHands runtime

- **Architecture.** The backend builds an "OH runtime image" on top of the user's base image and starts a container. An **action execution server** inside it runs an `ActionExecutor` (bash, browser, Jupyter/VS Code plugins). The backend sends Actions over REST and gets Observations back. Runtimes: `docker_runtime.py`, `local_runtime.py`, `remote_runtime.py` [H] (https://docs.openhands.dev/openhands/usage/architecture/runtime.md). Third-party runtimes (Modal, Daytona, etc.) are listed by secondary sources [M].
- **Secrets.** The SDK's `LookupSecret` references are resolved lazily **by the agent server inside the sandbox**, so values do enter the sandbox. The SecretRegistry masks them in output and supports rotation [H/M] (https://docs.openhands.dev/sdk/guides/agent-server/cloud-workspace.md, arXiv 2511.03690).
- **Network.** Egress controls are not documented [H]. Release v1.37.0 (2026-11-06) [H].
- **Relevance.** OpenHands mediates at the action level (the harness owns the tool loop). It does not broker credentials, and it is not a fit for black-box agents.

### 3.8 Claude Code cloud sessions, the Oct 2025 blog post, and sandbox-runtime

**Cloud environments** (docs read 2026-11-08) [H] (https://code.claude.com/docs/en/claude-code-on-the-web, https://code.claude.com/docs/en/cloud-environments)
- **Isolation.** An Anthropic-managed VM per session, or a self-hosted environment where isolation is the customer's responsibility.
- **Network levels:** **None / Trusted (default allowlist) / Full / Custom** (`*.` wildcards, optionally plus the defaults).
  - Changes reach running sessions within about 1 minute.
  - **These bypass the allowlist at every level:** GitHub (its own proxy); MCP connectors (their traffic goes through Anthropic servers, not the VM); network-secret hosts; and the Anthropic API ("even at None", which the docs flag as a possible exfiltration channel).
- **Security proxy.** All outbound HTTP(S) passes through it, for "protection against malicious requests" and rate limiting. TLS-interception details are not published [U]. Bun is documented as incompatible with it.
- **GitHub proxy:**
  - The in-VM git client uses a **scoped credential, which the proxy verifies and swaps for the real token**.
  - `gh` and `GH_TOKEN` read the placeholder `proxy-injected`.
  - **Rejected:** branch deletion, and pushes of anything that is not a branch (such as tags). It does **not** limit *which* branch can be pushed; the docs say to use GitHub rulesets for that.
  - **Repository scope:** API calls to repos not attached to the session get a 403 whose message begins `GitHub access to … is not enabled for this session`. Archive and codeload URLs are scoped the same way, even for public repos.
  - **GraphQL is rejected entirely** with a 403 that names the REST fallback, so `gh pr` and `gh issue` fail.
  - Credentials "stay encrypted on Anthropic's servers and never enter a session's VM".
- **Network secrets:**
  - Added per environment: allowed hosts plus a header name, prefix and value (Bearer by default; other secret types available).
  - The agent proxy attaches them after the request leaves the VM.
  - Hosts that **never** get a secret: GitHub, the Anthropic API, public registries, setup-script requests (Claude Code connects to the proxy only after setup), and telemetry.
  - Secret hosts become reachable even outside the access level.
  - Overlapping host patterns mean only one secret is sent.
  - Self-hosted environments have no network secrets.
- **Snapshots.** If the setup script finishes in about 5 minutes, the **filesystem is snapshotted** and reused. The cache lasts about 7 days and is rebuilt when the script or the allowed hosts change. Running processes are not kept. Idle VMs are reclaimed; the conversation is restored but background jobs are not.
- **Denials.** Explicit messages are documented only for the GitHub proxy (above). How a general allowlist block appears is not documented [U].

**"Beyond permission prompts: making Claude Code more secure and autonomous"**: David Dworken and Oliver Weller-Davies, 2025-10-20 [H] (https://www.anthropic.com/engineering/claude-code-sandboxing)
- **Local sandboxed bash:** bubblewrap on Linux and Seatbelt on macOS, applied to the command and all its subprocesses. Writes are limited to the working directory.
- Network goes **only through a Unix-socket proxy outside the sandbox**, which restricts domains and **asks the user to confirm new domains**.
- Result: **84% fewer permission prompts** internally.
- **Web:** "sensitive credentials (such as git credentials or signing keys) are never inside the sandbox". The git proxy checks the scoped credential *and the contents of the git operation* (for example, that a push targets the configured branch), then attaches the real token. (The current docs say only non-branch pushes and deletions are rejected; see above.)

**`anthropic-experimental/sandbox-runtime` (`srt`)**: TypeScript, Apache-2.0, about 7k stars, v0.0.81 (2026-10-20), last push 2026-11-06 [H] (README through `gh api repos/anthropic-experimental/sandbox-runtime/readme`)
- **Network path.** HTTP proxy plus SOCKS5 proxy on the host. On Linux the sandbox has **no network namespace at all**; the proxies are reached through Unix sockets bind-mounted into bubblewrap. Windows (alpha) uses a dedicated `srt-sandbox` account fenced by WFP.
- **Resolved-address check.** Allowlisted names are resolved once and denied addresses (IMDS, loopback, etc.) are dropped, to stop DNS-rebinding attacks.
- **Async approval: `SandboxAskCallback`.**
  - Called for destinations that no deny, allow or per-command rule decides.
  - Returns `true`, `false`, or `{allow:false, reason}`.
  - **The reason reaches the model** in a `<sandbox_violations>` block **and the client** as the status phrase of the 403 answering its CONNECT.
  - Reasons are sanitised (control and invisible characters, `<>` removed; 500 chars max).
  - `deniedDomainReasons` gives model-facing reasons per deny entry, such as the sanctioned alternative.
  - Violations are attributed to the command that caused them (`commandId`).
- **TLS termination** (experimental `network.tlsTerminate`) enables `filterRequest`, which can allow with header edits (`setHeaders`/`removeHeaders`) or deny with a chosen status.
  - `excludeDomains` covers mTLS upstreams and certificate-pinning clients.
  - `refuseOpaqueTunnels`.
  - `requireHostMatch` answers 421 when SNI and Host differ, which blocks domain fronting.
  - Ambiguous request targets are refused with `X-Proxy-Error`.
  - TRACE and TRACK are refused.
  - Proxy errors carry `X-Proxy-Error` headers.
- **Credential masking.** `credentials.envVars`/`files` with `mode:"deny"` (withhold) or `mode:"mask"` (a sentinel inside the sandbox, the proxy substitutes on egress to `injectHosts`). Masking **requires TLS termination** unless `allowPlaintextInject` is set. **`credentials.sigv4`** re-signs AWS requests at the proxy.
- **Hot reload.** `--control-fd` lines update the domain lists, MITM settings and SigV4 policy per request. Filesystem rules are fixed for the life of the command.

### 3.9 GitHub Copilot cloud agent firewall and Actions-based runners

- **Firewall** [H] (https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall):
  - On by default, with a recommended allowlist (OS package repos, container registries, language registries, CAs, Playwright browser hosts).
  - Org settings: enabled, disabled, or let repositories decide; org custom rules are combined with repo rules and cannot be removed at repo level.
  - Rules are **domains** (domain plus subdomains) or **URLs** (scheme, host and path prefix).
  - **It does not cover:** MCP server processes, processes started by setup steps, or anything outside the Copilot environment. GitHub warns that "sophisticated attacks may bypass the firewall".
  - **Denials** appear as a warning in the PR body or a comment, showing the blocked address and the command.
  - The enforcement mechanism is not documented [U].
- **Cloud sandboxes** (Oct 2026) [H] (https://github.blog/changelog/2026-10-28-work-from-anywhere-with-a-new-connected-copilot-cloud-experience/, https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/about-cloud-sandboxes):
  - Sessions now default to GitHub-hosted "secure, fast, resumable" sandboxes; Actions-based sessions remain an option.
  - Cloud sandboxes follow the same firewall. **Allowlist changes do not reach running sessions**, so you start a new one.
  - State is snapshotted while a session is stopped ($0.005 per GiB-month).
  - The isolation technology is not named.
  - OIDC setup steps work only in Actions sessions.
- **Other mitigations** [H] (https://docs.github.com/en/copilot/concepts/agents/cloud-agent/risks-and-mitigations):
  - Pushes go to a single branch (`copilot/…` per Microsoft Learn [M]).
  - Workflows do not run until a human clicks "Approve and run".
  - The agent cannot approve or merge, and the requester cannot approve.
  - Hidden HTML comments are stripped from prompts.
  - Commits are signed.
- **GitHub Agentic Workflows (gh-aw, v1.2.1; AWF firewall v0.29.10, 2026-11-08)** [H] (https://github.github.com/gh-aw/introduction/architecture/, https://github.com/github/gh-aw-firewall):
  - The agent job is **read-only**. Writes are **buffered as "safe outputs"**, checked by an AI threat-detection job (warn mode by default), and applied by separate jobs that hold write tokens. This is the "handles/intents, not capabilities" pattern.
  - AWF: Squid proxy plus iptables redirect, with capabilities dropped before launch. `--ssl-bump` enables URL/path rules. DLP scanning.
  - An **API-proxy sidecar holds LLM keys** so they never reach the agent.
  - The MCP gateway runs one isolated container per server.
  - Preview backends: Cloud Hypervisor and NVX/OpenVMM microVMs.
  - gh-aw's docs say the agent ID mounted in the container "is not a strong security boundary".
- **Agent HQ** (Universe, 2025-10-28): Mission Control plus governance over third-party agents, covering allowed agents, branch controls and agent identity. It is not a sandbox or broker in itself [H] (https://github.blog/news-insights/company-news/welcome-home-agents/).

### 3.10 OpenAI Codex cloud

- **Legacy Codex Cloud** [H] (https://learn.chatgpt.com/docs/cloud/internet-access, https://learn.chatgpt.com/docs/environments/cloud-environment.md):
  - The setup phase has internet access. The agent phase is **off by default**, or limited/unrestricted.
  - Domain presets: None, Common dependencies, All.
  - Optional **HTTP method restriction to GET/HEAD/OPTIONS**.
  - **Secrets are available only to setup scripts and removed before the agent phase.** Files written during setup (for example `.npmrc`) persist, which is a known leak path [M].
  - Container state is cached for up to 12 h.
  - All traffic goes through an HTTP(S) proxy.
- **New Codex Cloud environments** [H] (https://learn.chatgpt.com/docs/environments/cloud-environments.md):
  - **"HTTP secrets"** (key, value, allowed domains): programs get a placeholder and "the proxy substitutes the real value for allowed destinations" on HTTPS port 443, during both setup and tasks. Saving a secret adds its domains to the allowlist. "Allowing a destination doesn't supply credentials."
  - **OIDC** gives short-lived cloud credentials (most AWS/GCP services; Azure is limited).
  - **Tailscale VPN** through an HTTP CONNECT proxy at `proxy:8088`. **TCP tunnels do not intercept TLS or inject secrets.**
  - Egress IP feed at `openai.com/chatgpt-agents.json`.
  - VM state is recoverable for 7 days.
  - Denial behaviour and isolation technology are not documented.

### 3.11 Gateways, brokers and other sandboxes

**MCP and AI gateways**
- **agentgateway.** Rust, Apache-2.0, v1.7.0 (2026-10-27), about 6k stars [H] (https://github.com/agentgateway/agentgateway). Created by Solo.io and donated to the Linux Foundation on 2025-08-25; reportedly moved to the Agentic AI Foundation in 2026 [M] (https://solo.io/products/agentgateway).
  - One proxy for LLM, MCP (stdio/HTTP/SSE/streamable HTTP, OpenAPI to MCP) and A2A traffic.
  - JWT/API-key/OAuth auth; **CEL-based RBAC per MCP tool**, with unauthorised tools filtered out of `tools/list`; guardrails (regex, moderation, Bedrock/Model Armor, webhooks); OTel; budgets.
  - **MCP authz** docs: https://agentgateway.dev/docs/standalone/latest/mcp/mcp-authz/.
  - The most reusable Rust component for wicket's MCP gateway pillar. I did not confirm whether it does upstream token exchange or credential injection [U].
- **Microsoft MCP Gateway.** C#, for Kubernetes [H] (https://github.com/microsoft/mcp-gateway).
  - Reverse proxy, a tool-gateway router, a control plane (bearer/RBAC).
  - **Now requires MCP spec `2026-07-28`: stateless, with every request independently authorised and no transport sessions.**
  - Wicket's MCP gateway should target that spec revision.
- **Envoy AI Gateway.** MCPRoute aggregation with OAuth and **upstream API-key/header injection** from Kubernetes secrets [H] (https://aigateway.envoyproxy.io/docs/capabilities/mcp/).
- **Kong AI MCP OAuth2 plugin** (Enterprise) [H/M] (https://developer.konghq.com/plugins/ai-mcp-oauth2/).
- **Pomerium MCP.** Pomerium runs the upstream OAuth and keeps the internal token. The client gets only an external token, and Pomerium proxies with the real one [H] (https://www.pomerium.com/docs/capabilities/mcp/reference.md).
- **Lasso MCP gateway.** Open source (MIT, April 2025); plugin-based scanning and masking [M] (https://lasso.security/resources/lasso-releases-first-open-source-security-gateway-for-mcp).

**Tool-auth brokers**
- **Arcade.dev.** Tokens live in Arcade's runtime and never reach the model. **Just-in-time, per-tool-scope OAuth challenges** [vendor] (https://www.arcade.dev/blog/arcade-keeps-credentials-away-from-llm). An integration guide notes the URL-mode elicitation path was declined in one client [M].
- **Composio and Smithery.** Hosted tool routers and registries with brokered OAuth [M/vendor]. The reported Arcade–Smithery acquisition is single-source [U].

**Workload identity and identity-aware gateways**
- **Aembit MCP Identity Gateway.** Beta 2026-02-24. Holds downstream credentials in memory and injects them per request, default-deny, token exchange [vendor] (https://docs.aembit.io/changelog/entry/2026-02-24-mcp-identity-gateway-enters-beta-with-mcp-server-and-component-copying).
- **Astrix Agent Control Plane.** Short-lived credentials plus a policy engine (RSA 2026) [vendor] (https://astrix.security/learn/blog/securing-ai-agents-at-scale/).
- **Tailscale Aperture.** Self-hosted AI gateway. **Identity comes from the tailnet; provider keys are injected so clients hold none (some need a placeholder key).** Connectors proxy remote MCP servers and HTTP APIs, and Cerbos can authorise tool calls [H] (https://tailscale.com/docs/aperture/what-is-aperture.md).

**Credential-injecting egress proxies (OSS)**
- **iron-proxy.** Go, Apache-2.0, v0.56.0 (2026-11-04). The repo moved from `ironsh` to `paradigmxyz/iron-proxy` [H] (https://github.com/paradigmxyz/iron-proxy).
  - MITM proxy with its own DNS server, default-deny (403).
  - Upstream deny-CIDRs (IMDS and loopback by default).
  - **Proxy tokens swapped for real secrets at egress** (env, AWS SSM, 1Password, GCP service-account tokens [M]).
  - Per-request JSON audit records (which secrets were swapped, which rules matched); WebSocket and SSE support.
  - A Postgres MITM that injects `SET ROLE` and walks the SQL AST.
  - The closest OSS analogue to wicket's egress pillar.

**Other sandbox platforms**
- **Vercel Sandbox.** Firecracker. Firewall docs last updated 2026-09-16 [H] (https://vercel.com/docs/sandbox/concepts/firewall).
  - Modes: allow-all (default), deny-all (no DNS), or user rules.
  - SNI matching; TLS is terminated **only** for domains that have rules (per-sandbox CA).
  - Rules (first match wins, matchers on path, method, query and headers): **`transform` (credential brokering; overwrites headers the sandbox set, can pin `Host` to stop fronting)**, **`forwardURL`** (your own proxy, which receives a **`vercel-sandbox-oidc-token`** whose audience is the forward URL, plus claims for team, project and sandbox ID), and **`response`** (a direct status, headers and body).
  - Live updates replace the whole policy.
  - Documented bypasses: IP literals and custom resolvers inside allowed CIDRs skip SNI, brokering and proxying; a `*` catch-all lets traffic without SNI pass unmodified.
  - Postgres: domain policy over TLS.
  - Header injection announced 2026-02-23 (https://vercel.com/changelog/safely-inject-credentials-in-http-headers-with-vercel-sandbox).
- **Fly.io Sprites.** Firecracker. Persistent; sleeps and wakes in under 1 s; checkpoint/restore that includes running services. The egress allowlist "cannot be widened from inside" (yet the Sprites MCP server can set policy). Rust crate `sprites` 0.1.0 [H/M] (https://fly.io/ai-agents/, https://docs.rs/crate/sprites/latest).
- **Northflank.** Kata plus Cloud Hypervisor by default (gVisor for GPU). FQDN egress policies. **Secrets "added to outbound requests at egress"**, plus workload-identity tokens [vendor] (https://northflank.com/product/sandboxes).
- **kubernetes-sigs/agent-sandbox.** Go, v1.0.10 (2026-11-06) [H] (https://github.com/kubernetes-sigs/agent-sandbox).
  - CRDs: `Sandbox` (singleton stateful pod, stable identity), `SandboxTemplate`, `SandboxClaim`, `SandboxWarmPool`.
  - Delegates isolation to gVisor or Kata through RuntimeClass.
  - Sandbox Router (HTTP reverse proxy); Go and Python SDKs.
  - No credential brokering of its own.

**Rust and microVM projects**
- **microsandbox** (`superradcompany/microsandbox`). Rust; **libkrun + smoltcp**; v0.7.13 (2026-11-01); about 9k stars; SDKs for **Rust**, TypeScript, Python, Go and Ruby [H] (https://github.com/superradcompany/microsandbox).
  - Network policy is controlled from the host. By default private networks, the host and metadata endpoints are blocked. There is a multi-tenant profile.
  - `interceptTls`.
  - **Secrets** (https://docs.microsandbox.dev/sandboxes/secrets.md): the guest gets a placeholder; substitution outside the guest is bound to a host. **Locations are opt-in:** headers including Basic (on by default), query and body (off by default; HTTP/1 bodies up to 16 MiB; HTTP/2 bodies are blocked). Header allow-lists stop echo attacks.
  - **Violation actions:** block, block-and-log, block-and-terminate.
  - **Denials are structured: JSON `403 {code:"secret_policy_denied"|…, message, domain}` with a configurable message** (for example "Ask the user for network access.") (https://docs.microsandbox.dev/networking/overview.md).
  - Snapshot, fork and restore with CoW memory.
  - The closest existing Rust codebase to wicket's sandbox plus egress pillars.
- **Smaller Rust projects** (third-party index data) [M] (https://iii.dev/blog/why-agent-sandboxes-are-converging-on-libkrun-not-firecracker/): smolvm (libkrun, macOS/Linux), krunai (libkrun agent runner), ArcBox (KVM microVM).
- **VMMs.** Firecracker and Cloud Hypervisor are both Rust (rust-vmm).

---

### 3.12 Synthesis

#### State of the art, late 2026: "the agent runs with no secrets and the control plane brokers everything"

1. **Placeholder plus egress substitution has become the standard pattern.** Since Feb–Apr 2026, Docker, E2B, Daytona, Cloudflare, Vercel, Codex (new), Claude Code cloud, microsandbox, iron-proxy, srt and Northflank all ship it: the sandbox sees an opaque or sentinel value, and a proxy outside the sandbox swaps it in, but only for an allowed host, usually only in HTTPS headers, and usually by MITM with a per-sandbox CA.
2. **Specialised, protocol-aware brokers are layered on top** for high-value services: Anthropic's GitHub proxy (git-aware, repo-scoped, GraphQL blocked), gh-aw's safe outputs, iron-proxy's Postgres `SET ROLE`, srt's SigV4 re-signing, and the LLM-key sidecars in AWF and Browser Use.
3. **MCP mediation is moving out of the sandbox.** Docker runs the gateway on the host; Claude Code connectors run on Anthropic servers; gh-aw runs one container per MCP server. Gateways (agentgateway, Pomerium, Aembit, Arcade) hold upstream OAuth and expose only gateway-issued tokens. Spec `2026-07-28` (stateless, per-request authorisation) is being adopted.
4. **Policy that changes at runtime is common** (E2B, Daytona, Modal, Cloudflare, Vercel, srt `--control-fd`, Claude cloud within about 1 minute). **Per-request human approval is rare.**
5. **Isolation has settled on microVMs:** Firecracker (E2B, Vercel, Cloudflare, Fly), custom or libkrun VMMs for macOS (Docker, microsandbox), Kata+CH (Northflank, k8s), with gVisor as the lighter alternative (Modal, GKE). Copilot, Claude and Codex do not name their isolation technology.

#### Who actually injects credentials outside the sandbox, and who only restricts egress

- **Inject (generic HTTP):**
  - Docker sbx
  - E2B (beta)
  - Daytona
  - Cloudflare (code)
  - Vercel
  - Codex (new HTTP secrets)
  - Claude Code cloud (network secrets plus the GitHub proxy)
  - microsandbox
  - iron-proxy
  - srt (mask mode)
  - Northflank [vendor]
  - Tailscale Aperture (LLM and connectors)
  - AWF (LLM keys only)
- **Inject, but at the MCP or app layer only:** Docker MCP Gateway (into server containers), Pomerium, Aembit, Arcade, Composio, Envoy and Kong; Browser Use (its control plane).
- **Restrict only, with secrets inside the sandbox or none at all:**
  - Modal (unless you build a sidecar)
  - Copilot cloud agent firewall (scoped token plus branch limits, no proxy injection documented)
  - Codex legacy (secrets in setup only, then removed)
  - OpenHands (secrets in the sandbox, masked in output)
  - k8s agent-sandbox (out of scope for it)

#### Per-request policy with async human approval

- **Docker sbx approvals** are the only productised version. They are asynchronous and out-of-band, scoped to destination, port, method, path and sandbox; duplicate attempts collapse into one entry; and they rely on **the agent retrying** (the triggering request fails).
- **srt `SandboxAskCallback`** is an async allow/deny hook per destination, with a model-readable reason. It is per host, not per request, and is used by local Claude Code for "confirm new domains".
- **Cloudflare** lets you build it (handlers can be swapped at runtime), and the blog says so, but nothing ships.
- **Docker MCP Gateway** `before` interceptors and **Arcade** just-in-time OAuth are the MCP or tool equivalent.
- **gh-aw** applies policy after the fact (threat detection plus approval labels) rather than per request.
- **Copilot** requires a manual allowlist edit and a new session. **Codex, E2B, Daytona, Modal and Vercel** have no approval flow.

#### Gaps wicket could fill

1. **A typed, machine-readable denial-and-escalation contract.** Today's denials are a plain-text message (Docker), a 403 status phrase plus a transcript block (srt), JSON `{code,message,domain}` without a request id (microsandbox), whatever user code returns (Cloudflare, Vercel), a message prefix (Claude's GitHub proxy), or something easy to miss (an E2B connection that looks accepted). **No system returns a request id the agent can quote or poll, a retry hint, or an escalation reference, and none uses the same schema for HTTP, git and MCP.** A standard error (for example `application/problem+json` with `wicket-request-id`, `scope_requested` and `retry-after`, mirrored as an MCP tool error) plus a "wait or poll for decision" path would be new. Docker's behaviours (collapse duplicates, scope approval exactly, deny the triggering request) are worth copying.
2. **Attenuable credentials.** Every placeholder today is opaque and flat. Anthropic's "scoped credential" and Vercel's OIDC token identify the sandbox but cannot be narrowed by the agent for subagents. Capability tokens such as biscuit or macaroons, used as placeholders and checked by the proxy and MCP gateway, are absent from every system surveyed.
3. **Information-flow labels.** No system tracks taint from tool results or fetched content through to egress decisions. The closest are Docker's `--block-secrets` content scanning, gh-aw's AI threat detection and integrity labels, and Daytona's response rewriting. Label-aware egress ("a session that read label X cannot POST to host Y") is open territory.
4. **Handles, not contents, as a general mechanism.** Only bespoke versions exist: Browser Use's presigned URLs, Cloudflare bindings, gh-aw safe outputs. A generic handle broker (the sandbox gets an opaque reference and the gateway dereferences it under policy) is missing.
5. **One policy plane across HTTP, git, MCP and LLM.** Docker sbx comes closest (proxy plus MCP gateway, both on the host, with org governance). Elsewhere the planes are split, and **side channels bypass the allowlist**: Claude cloud (Anthropic API at "None"; connectors and GitHub outside the allowlist) and Copilot (MCP and setup steps not covered by the firewall).
6. **Git-protocol-aware brokering as a component.** Only Anthropic does it, and its current docs admit it does not restrict which branch is pushed. A Rust smart-HTTP and receive-pack-aware proxy (ref and namespace policy, no tags or deletions, an LFS policy) would be reusable and distinctive.
7. **Black-box agent support with cooperative clients optional.** Browser Use's clean control-plane design needs agent cooperation. Wicket's transparent-proxy approach should treat these as known pitfalls:
   - SNI-only matching and domain fronting (Modal, Vercel, E2B on 443). Use srt-style `requireHostMatch` or Host pinning.
   - DNS exfiltration: E2B's auto-allowed 8.8.8.8, Modal's unrestricted DNS, Vercel's `subnets.allow`. Run your own DNS as iron-proxy and Docker do.
   - IP literals and custom resolvers bypassing domain rules (Vercel).
   - Certificate-pinning and mTLS clients (srt `excludeDomains`). CA rotation on resume (E2B).
   - Placeholders transformed by the client (Daytona), and body or HTTP/2 substitution limits (microsandbox).
   - Echo endpoints leaking the substituted value back. Daytona rewrites responses; microsandbox restricts which headers are substituted.
   - Setup-phase windows. Codex `.npmrc` persistence; Claude network secrets not sent during setup.
   - SSH-agent forwarding as a signing oracle (Docker default).
8. **Self-hostable, Rust, agent-agnostic.** Rust building blocks exist: microsandbox (libkrun, secrets, structured 403), agentgateway (MCP/LLM, CEL authz), Firecracker and Cloud Hypervisor. No single OSS project combines the microVM, a credential-injecting proxy with approval, an MCP gateway and attenuable tokens. Wicket's niche is that combination, plus pillars 1–4.

---

### 3.13 Useful patterns to copy (with sources)

- **Docker approvals:** exact-scope approvals, duplicate attempts collapsed into one entry, the triggering request denied and the agent expected to retry (https://docs.docker.com/ai/governance/local/approvals.md).
- **srt** (README):
  - sanitised, model-facing deny reasons
  - `deniedDomainReasons` naming the sanctioned alternative
  - resolved-address check
  - `requireHostMatch`
  - masking that requires TLS termination
  - SigV4 re-signing
  - hot reload over a control fd
- **Vercel:**
  - first-match rules with transform, forward or direct-response actions
  - an OIDC token from the sandbox to your own forward proxy, with `aud` set to the forward URL
  - injected headers that overwrite whatever the client set

  (https://vercel.com/docs/sandbox/concepts/firewall)
- **E2B:** a fresh workload-identity token minted per request in a transform callback (https://docs.e2b.dev/network/internet-access).
- **Cloudflare:** policy written as code keyed by sandbox identity (`ctx.containerId`); handlers swapped at runtime, effective on the next request on an open connection (https://blog.cloudflare.com/sandbox-auth/).
- **microsandbox:** opt-in substitution locations; violation actions including terminate; JSON 403 (https://docs.microsandbox.dev/sandboxes/secrets.md).
- **Daytona:** stable placeholder across rotation; rewriting echoed secrets in responses; the warning that permission to widen a secret's hosts is a privilege escalation (https://www.daytona.io/docs/en/secrets/).
- **gh-aw:** read-only agent, writes buffered as safe outputs, applied by a separate privileged job (https://github.github.com/gh-aw/introduction/architecture/).
- **Claude GitHub proxy:** repo-scoped 403s with actionable messages; GraphQL blocked because it is hard to scope (https://code.claude.com/docs/en/cloud-environments).

### 3.14 Unverified or uncertain items

- Docker Sandboxes GA date (claims of Jan, Mar and Sep 2026 conflict).
- Docker MCP Gateway: how secrets reach server containers (env var or not).
- Docker sbx: exact HTTP rule syntax. The `credentials.md` page returned 404, so I used search summaries for it.
- E2B's use of Firecracker: from Vercel's comparison, not an E2B page I read.
- Daytona's container runtime. Its docs also conflict on response rewriting (current secrets page: yes; v2 isolation page: no).
- Claude Code cloud security proxy: TLS-interception details, and how a general allowlist denial appears to the agent.
- Copilot firewall enforcement mechanism, and the isolation technology of its cloud sandboxes.
- Codex isolation technology and denial format. The GET/HEAD/OPTIONS option is documented only on the legacy page.
- agentgateway: upstream token exchange or credential injection, and its current foundation (LF vs AAIF).
- iron-proxy: the full list of secret backends and the "MCP-aware interceptor" (from its changelog via search).
- Vendor-only claims: Northflank egress injection, Aembit, Astrix, Arcade, Composio, Smithery, and the reported Arcade–Smithery acquisition.
- Fly Sprites: whether the agent can change policy from inside (Fly's page contradicts itself).
- OpenHands confirmation mode and security analyzer: from my own knowledge, not re-read in current docs.
- Third-party star counts and dates for smolvm, krunai and ArcBox.

---

## 4. Recommended `InnerAgent` adapter abstraction (Rust)

### 4.1 Principles

1. **The adapter is not part of the trusted computing base for enforcement.** Everything an adapter configures
   inside the box (settings, hooks, permission rules, the agent's own sandbox) is defence-in-depth and UX. The
   enforcement points are the zone boundary (microVM/container), the egress proxy, the LLM proxy and the MCP gateway,
   all outside the box and agent-independent. An adapter bug may make an agent stall or behave badly; it must never
   widen what the zone can reach.
2. **Everything that crosses the box boundary is a gate.** That includes the adapter's own control channel (stdio
   NDJSON, ACP JSON-RPC, files in an outbox). Parse it as untrusted input with size limits; never let free text from
   it reach a decider with wider capabilities (origin brief: "judge the request, not the reasoning").
3. **No secrets in the launch spec.** The adapter may only emit *placeholders* (session capabilities) and
   *routes* (base URLs, proxy URLs, CA paths); the credential router outside the box binds placeholders to real
   credentials.
4. **Feature-detect, pin, and conformance-test.** Agents change weekly. Adapters declare capabilities, pin a version
   range, and are validated by a conformance suite run in CI against each pinned version.

### 4.2 Shape of the trait

```rust
/// Static description of an adapter; no I/O.
pub trait InnerAgent: Send + Sync + 'static {
    fn kind(&self) -> AgentKind;                 // ClaudeCode, ManagedAgentWorker, Acp(name), Codex, Process, ...
    fn tier(&self) -> Tier;                      // T1 | T1b | T2 | T3
    fn caps(&self) -> AgentCaps;                 // see below; refined at runtime by the agent's handshake
    fn supported_versions(&self) -> semver::VersionReq;

    /// Pure function: task + zone environment -> everything needed to start the agent in a box.
    fn plan(&self, task: &TaskSpec, zone: &ZoneEnv) -> Result<LaunchPlan, PlanError>;

    /// Attach to a started process (or remote worker) and return a live session.
    fn attach(&self, io: BoxIo, plan: &LaunchPlan) -> Result<Box<dyn AgentSession>, AttachError>;
}

pub struct AgentCaps {
    pub io: IoProtocol,                 // ClaudeStreamJson | Acp{version} | CodexAppServer | CodexExecJson | StdioText | None
    pub model_route: ModelRouteSupport, // BaseUrlOverride{var} | ProxyOnly | ProviderSpecific | None
    pub honours_https_proxy: bool,
    pub custom_ca: CaSupport,           // EnvVar(&'static str) | SystemStore | None
    pub mcp: McpInjection,              // CliFlag | ConfigFile | AcpSessionNew | None
    pub permission_host: PermissionHost,// ControlProtocol | McpPromptTool | AcpRequestPermission | HookOnly | None
    pub defer: DeferSupport,            // NativeDefer{single_call_only} | IndefinitePending | McpTasks | None
    pub structured_output: bool,        // e.g. --json-schema / --output-schema
    pub resume: ResumeSupport,          // SessionId | TranscriptFile | None
    pub inject_message_mid_run: bool,   // stream-json input, ACP session/prompt
    pub own_sandbox: OwnSandbox,        // what to disable or nest
}

pub struct LaunchPlan {
    pub image: ImageRequirement,              // rootfs/OCI ref + pinned agent version + digest
    pub argv: Vec<String>,
    pub env: BTreeMap<String, EnvValue>,      // EnvValue::Literal | Placeholder(CapabilityRef) | Route(RouteRef)
    pub files: Vec<MaterialisedFile>,         // managed settings, MCP config, CA bundle, AGENTS.md...; mode + owner
    pub writable: Vec<PathBuf>,
    pub egress_needs: Vec<EgressNeed>,        // ModelEndpoint, McpGateway, Optional(Telemetry), Never(AutoUpdate)
    pub credential_routes: Vec<CredentialRoute>,
    pub result_contract: ResultContract,      // schema for typed fields + outbox paths for handles
    pub preflight: Vec<Preflight>,            // e.g. scan repo .claude/settings.json, .mcp.json, AGENTS.md
}

pub enum CredentialRoute {
    /// Agent talks to wicket's LLM proxy; proxy swaps placeholder for real key.
    LlmProxy { base_url_var: String, token_var: String, header: AuthHeader, upstream: ModelUpstream },
    /// Agent talks to the real host; TLS-intercepting egress proxy injects on match.
    EgressInject { host: String, header: AuthHeader, cred: CredRef },
    /// Credential needed only by the MCP gateway (agent never sees it).
    GatewayOnly { provider: ProviderId, cred: CredRef },
}

#[async_trait]
pub trait AgentSession: Send {
    async fn start(&mut self, prompt: TaskPrompt) -> Result<()>;
    fn events(&mut self) -> BoxStream<'_, AgentEvent>;             // normalised, labelled, size-bounded
    async fn send(&mut self, msg: HostMessage) -> Result<()>;      // only if caps.inject_message_mid_run
    async fn answer(&mut self, req: PermissionReqId, d: Decision) -> Result<()>;
    async fn interrupt(&mut self) -> Result<()>;
    async fn checkpoint(&mut self) -> Result<ResumeToken>;          // for VM snapshot / defer
    async fn finish(self: Box<Self>) -> Result<AgentOutcome>;
}

pub enum AgentEvent {
    Ready { model: String, tools: Vec<String>, mcp: Vec<McpStatus>, agent_caps: Vec<String> },
    ToolIntent { id: ToolUseId, agent: Option<SubagentId>, name: String, input: Handle },   // hooks / can_use_tool
    ToolResult { id: ToolUseId, is_error: bool, body: Handle },
    PermissionRequested { id: PermissionReqId, typed: Option<CapabilityRequest>, raw: Handle },
    Deferred { tool: ToolUseId, resume: ResumeToken },
    Denied { id: ToolUseId, by: DenySource },
    Usage { tokens: u64, cost_usd_est: f64 },
    State(AgentState),                    // Running | Idle | RequiresAction | Exited(code)
    Text(Handle),                         // free text is never inlined
}

pub struct AgentOutcome {
    pub typed: serde_json::Value,         // validated against result_contract.schema; low-information fields only
    pub handles: Vec<LabelledHandle>,     // transcript, diff, final message, artefacts — content behind handles
    pub exit: ExitStatus,
    pub denials: Vec<DenialRecord>,
}
```

### 4.3 Tiered support model

| Tier | Agents | I/O protocol | Permission host | Pending/escalation path | Result extraction |
|---|---|---|---|---|---|
| **T1** | Claude Code CLI (and anything built on the Claude Agent SDK) | stream-json + control protocol, spoken natively from Rust | `--permission-prompt-tool stdio` → `can_use_tool` control requests answered by wicket; hooks registered at `initialize` as `hook_callback` | `defer` (single call) or indefinitely-pending `can_use_tool` + VM pause; MCP tasks for gateway tools (opt-in); mid-run user message after grant | `--json-schema` → `structured_output` typed fields; transcript JSONL + `git diff` as handles |
| **T1b** | Claude Managed Agents, self-hosted sandbox worker | Managed Agents session events API (outside the box) + wicket worker executing tool calls inside the box | wicket worker itself: every tool call is a typed request before it executes | worker simply doesn't post the tool result until granted (bounded by Anthropic-side timeouts — **[unverified]**) | session events; files staged out of the box as handles |
| **T2** | ACP agents (Gemini CLI, goose, OpenCode, Cline, Copilot CLI, Codex via `codex-acp`, Claude Code via `claude-agent-acp`, …); optionally Codex `app-server` directly | JSON-RPC over stdio via the official `agent-client-protocol` Rust crate (pin `protocolVersion` 1, gate v2) | `session/request_permission` answered by wicket under policy (explicitly allowed for intermediaries); Codex app-server `item/*/requestApproval` | hold the permission request (no spec timeout; per-agent timeouts unverified) or deny with structured text; follow-up `session/prompt` after grant; `session/load`/`resume` after VM restore | final message + `stopReason`; typed fields via Codex `--output-schema` or a required outbox file validated by wicket |
| **T3** | Arbitrary process (aider, custom scripts, other CLIs) | none (stdin/stdout text, exit code) | none — enforcement purely at proxy/gateway | structured HTTP/MCP denial text + retry; long waits → restart with checkpointed workspace | outbox convention: `/wicket/out/result.json` (validated) + everything else as handles |

(T2 details for each agent are in section 2.)

### 4.4 What a Claude Code (T1) adapter emits

Process env (no secrets):
```
ANTHROPIC_BASE_URL=http://wicket-llm.zone.internal:8080      # option A
ANTHROPIC_AUTH_TOKEN=wkt_cap_<opaque, zone+session bound>
CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST=1
CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1  DISABLE_AUTOUPDATER=1  DISABLE_TELEMETRY=1  DISABLE_ERROR_REPORTING=1
ENABLE_CLAUDEAI_MCP_SERVERS=false  CLAUDE_CODE_DISABLE_ARTIFACT=1
CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1  CLAUDE_CODE_DISABLE_AUTO_MEMORY=1  CLAUDE_CODE_DISABLE_BACKGROUND_TASKS=1
CLAUDE_CONFIG_DIR=/wicket/state/claude                      # zone-labelled, snapshot-able
HTTPS_PROXY=http://wicket-egress.zone.internal:3128  NO_PROXY=wicket-llm.zone.internal,wicket-mcp.zone.internal
NODE_EXTRA_CA_CERTS=/etc/wicket/ca.pem  SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt  (CA also in system store)
CLAUDE_CODE_ENABLE_TELEMETRY=1  OTEL_EXPORTER_OTLP_ENDPOINT=http://wicket-otel.zone.internal:4318   # optional
```
argv:
```
claude -p --bare --input-format stream-json --output-format stream-json --verbose
  --permission-prompt-tool stdio --permission-mode default
  --settings /etc/wicket/claude-settings.json --setting-sources ""   # [unverified] empty list semantics; else "user"
  --mcp-config /etc/wicket/mcp.json --strict-mcp-config
  --json-schema /etc/wicket/result.schema.json  --session-id <uuid>  --max-budget-usd <n>
  --disallowedTools WebSearch     # zone-dependent
```
(Note `--bare` ignores hooks passed via `--settings`; wicket's hooks therefore go through the control protocol
`initialize.hooks` → `hook_callback`, which the SDK uses, or through managed settings — **[unverified]** whether
`--bare` also suppresses managed-settings hooks; test it.)

Root-owned `/etc/claude-code/managed-settings.json`: `allowManagedPermissionRulesOnly`, `allowManagedHooksOnly`,
`allowManagedMcpServersOnly` + `allowedMcpServers: [{serverUrl: "http://wicket-mcp…"}]`, `disableSideloadFlags`
(*careful*: this would also reject wicket's own `--mcp-config`; use `managed-mcp.json` instead), `skipWebFetchPreflight:
true`, `disableClaudeAiConnectors: true`, `permissions.deny` mirroring the zone ceiling (cheap early denials),
optional `sandbox.enabled` with `allowUnsandboxedCommands:false` as inner defence-in-depth.

Preflight: scan the workspace for `.claude/`, `.mcp.json`, `CLAUDE.md`, `AGENTS.md`, `.devcontainer` and label
them (untrusted instructions are a taint source even though `--bare` won't auto-load most of them).

### 4.5 Detecting "stalled on denial" and un-stalling

Signals, strongest first (all but the first are agent-reported, so they inform rather than decide):
1. **Outside-the-box facts**: wicket's proxy/gateway issued denial or pending ticket `R` for this zone at time t, and
   the LLM proxy has seen no model request from this session (`x-claude-code-session-id`) for > N s, or has seen ≥k
   near-identical denied requests (retry loop). The LLM proxy is the best liveness sensor: every agent turn passes
   through it, for every tier that supports a base-URL override.
2. T1: `system/session_state_changed: requires_action`, an outstanding `can_use_tool`, a `result` with
   `stop_reason: tool_deferred`, `permission_denials` non-empty, `system/permission_denied`.
3. T2: outstanding `session/request_permission`; `stopReason` of the last prompt turn; no `session/update` for N s.
4. T3: process alive, no CPU, no egress and no model traffic for N s; or exit with non-zero after a denial.

Un-stalling strategies by tier:
- **Short waits (seconds–minutes; auto-grant or parent-agent decision):** T1/T2 keep the permission request open
  and answer it when the decision lands. For HTTP denials, the agent retries; wicket can nudge with a host message
  ("R-123 granted for `GET api.github.com/repos/x/y/contents/infra/ci.yml`, valid 10 min; retry").
- **Long waits (human):** T1 `defer` → kill/snapshot the VM → on grant restore and `claude -p --resume <id>`; or keep
  `can_use_tool` pending and pause the microVM (Firecracker snapshot) so the waiting agent costs nothing. T2: answer
  the ACP permission request late after VM resume (**[unverified]** how each ACP agent tolerates a very late answer).
  T3: checkpoint workspace, terminate, restart the agent with a resumption prompt that includes the typed grant.
- **Ratchet/budget** checks happen in the escalation engine, not the adapter; the adapter just converts agent-side
  permission requests into `PermissionRequested{typed: Some(CapabilityRequest)}` when it can map them (e.g.
  `Bash(git push origin main)` → `{git.push, repo:X, ref:main}`) and otherwise passes them as an opaque handle that
  the decider must not read as instructions.

### 4.6 Result extraction: typed fields vs handles

- Typed fields: use the agent's native schema-constrained output where available (Claude `--json-schema` →
  `structured_output`; Codex `--output-schema` per section 2). Otherwise require the agent to write
  `/wicket/out/result.json`; the harness validates it against the task's schema *outside* the box, rejects
  free-text fields above a small size/entropy budget, and labels it with the zone's label.
- Handles: transcript (`$CLAUDE_CONFIG_DIR/projects/…/<session>.jsonl`), final message text, diffs, artefacts —
  stored content-addressed with the zone label + taint flag; parents get only the handle.
- Taint sources specific to Claude Code: WebFetch and Bash network reads (visible at egress proxy), **WebSearch
  results (server-side, invisible to egress — the LLM proxy must mark the session tainted whenever a response
  contains `server_tool_use`/web search result blocks)**, MCP tool results (visible at gateway), repo files.

### 4.7 Conformance suite (per adapter, per pinned agent version)

Run in CI inside a real wicket zone: (1) agent starts with zero direct egress and reaches only the LLM proxy + MCP
gateway; (2) no real credential is readable in the box (grep env, files, `/proc`); (3) a denied HTTP request
produces the expected event and the agent does not route around; (4) defer/pending round-trip works and resumes;
(5) structured output arrives and validates; (6) repo-supplied `.claude/settings.json` hooks / `.mcp.json` /
`env` blocks are ignored; (7) the agent's `capabilities`/protocol version matches what the adapter expects.

### 4.8 Experiments to run first

1. **Pending-retry behaviour.** 20 tasks × 3 denial styles (bare 403; structured JSON "pending, retry with R"; MCP
   tool `await_grant`) × {Claude Code, Codex, Gemini CLI}. Measure: waits/retries correctly, routes around, gives
   up. This settles the origin brief's "most agents handle permission pending fine" claim (currently unverified).
2. **Defer at scale.** How often turns contain >1 tool call (which makes `defer` fall back to normal flow); if often,
   prefer pending `can_use_tool` + VM pause.
3. **Option A vs B credential routing** with all nonessential traffic off: list every connection Claude Code
   attempts in a 30-minute session.

---

## 5. Biggest open risks

1. **Agent-side behaviour under denial is the least-known quantity.** Whether black-box agents wait/retry on a
   structured "pending, request R" response, or route around it, is unverified for all agents (experiment 4.8.1).
   If they route around, the escalation UX must move into the agent's own permission channel (T1 control protocol,
   ACP `request_permission`), which only cooperative tiers have.
2. **Protocol churn.** Claude Code ships near-daily (2.1.319 on the research date) with an undocumented-as-a-spec
   control protocol; ACP is at crate 5.0.0 after several breaking releases since June 2026 with v2 in draft (v2
   drops `fs/*`/`terminal/*` and changes turn completion); the Claude ACP adapter has been renamed twice; Codex
   retired approval modes and removed `codex mcp-server`. Adapters need version pins and a conformance suite.
3. **Side channels outside the egress proxy.** Server-side tools (Claude WebSearch; Codex web search), provider
   features that call home directly (Claude fast-mode check, WebFetch preflight, feature flags), and claude.ai
   connectors routed via Anthropic's MCP proxy all bypass wicket's egress mediation unless explicitly disabled or
   proxied. The LLM proxy must be treated as both an egress and a taint-ingress point.
4. **Native "pending" mechanisms have sharp edges.** Claude `defer` works only in `-p` and only for single-tool-call
   turns; MCP tasks require feature-flag fetching (conflicts with "no nonessential traffic") and don't apply to
   subagents; ACP has no defined behaviour for very late permission answers.
5. **Subscription/OAuth credentials.** Anthropic forbids third-party products offering claude.ai login without
   approval; ChatGPT and Google OAuth flows persist refresh tokens in the box. Wicket should support API keys,
   cloud-provider credentials and gateway tokens only, and treat OAuth injection as unsupported.
6. **Nested sandboxes.** Agents' own sandboxes (Claude bwrap, Codex bwrap+seccomp, Gemini docker/podman) need
   unprivileged user namespaces or a container runtime; in unprivileged containers they fail or need weakened modes.
   In microVMs they can stay on as defence in depth; in containers, turn them off and rely on the outer boundary.
7. **The control channel is an attack surface.** stream-json, ACP JSON-RPC and outbox files carry agent-controlled
   data into the harness. Parse with strict size limits, and never let free text from them reach a decider with
   wider capabilities.

## 6. Unverified items (consolidated)

From section 1 (Claude Code), in addition to those listed by the sub-agents in sections 2 and 3:
- End-to-end proxy injection of a claude.ai OAuth token (`CLAUDE_CODE_OAUTH_TOKEN`) — not tested, policy-restricted.
- Whether feature-flag fetches follow `ANTHROPIC_BASE_URL` or always go to `api.anthropic.com` (self-hosted docs say
  `api.anthropic.com`; behaviour under a custom base URL not confirmed).
- `--setting-sources ""` (empty) semantics, and whether `--bare` suppresses hooks from managed settings.
- How Claude reacts to wicket-style structured HTTP denials (needs experiment 4.8.1).
- Managed Agents self-hosted worker: Anthropic-side timeout on a tool call the worker holds pending.
- Repository naming: the Claude Code docs link `github.com/anthropics/sandbox-runtime` and the raw README fetched
  from that path today; the sub-agent read it as `anthropic-experimental/sandbox-runtime` (the original org; GitHub
  redirects between them). Same package, `@anthropic-ai/sandbox-runtime` v0.0.81.

## 7. Primary sources used in section 1 (all read 2026-11-08)

- Headless / CLI: <https://code.claude.com/docs/en/headless>, <https://code.claude.com/docs/en/cli-reference>
- Agent SDK: <https://code.claude.com/docs/en/agent-sdk/overview>, <https://code.claude.com/docs/en/agent-sdk/typescript>,
  <https://code.claude.com/docs/en/agent-sdk/permissions>, <https://code.claude.com/docs/en/agent-sdk/user-input>,
  <https://code.claude.com/docs/en/agent-sdk/secure-deployment>, <https://github.com/anthropics/claude-agent-sdk-python>
- Settings / policy: <https://code.claude.com/docs/en/settings>, <https://code.claude.com/docs/en/settings-reference>,
  <https://code.claude.com/docs/en/managed-settings>, <https://code.claude.com/docs/en/managed-mcp>,
  <https://code.claude.com/docs/en/permissions>, <https://code.claude.com/docs/en/permission-modes>
- Hooks: <https://code.claude.com/docs/en/hooks>
- Sandbox: <https://code.claude.com/docs/en/sandboxing>, <https://code.claude.com/docs/en/sandbox-environments>,
  <https://github.com/anthropics/sandbox-runtime> (README, `docs/srt-proxy.md`),
  <https://www.anthropic.com/engineering/claude-code-sandboxing>
- Devcontainer: <https://code.claude.com/docs/en/devcontainer>
- MCP: <https://code.claude.com/docs/en/mcp>, <https://modelcontextprotocol.io/extensions/tasks/overview>
- Network / auth / gateways: <https://code.claude.com/docs/en/network-config>, <https://code.claude.com/docs/en/authentication>,
  <https://code.claude.com/docs/en/env-vars>, <https://code.claude.com/docs/en/llm-gateway-connect>,
  <https://code.claude.com/docs/en/llm-gateway-protocol>, <https://code.claude.com/docs/en/data-usage>,
  <https://code.claude.com/docs/en/monitoring-usage>, <https://code.claude.com/docs/en/tools-reference>
- Cloud / self-hosted: <https://code.claude.com/docs/en/cloud-environments>,
  <https://code.claude.com/docs/en/self-hosted-environments-deploy>
- Managed Agents: <https://platform.claude.com/docs/en/managed-agents/self-hosted-sandboxes>
- Community Rust crates: <https://docs.rs/crate/claude-agent-sdk-rs/latest>, <https://lib.rs/crates/claude-code-agent-sdk>
