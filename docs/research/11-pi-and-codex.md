# 11 — pi and Codex: as inner agents and as harness designs

*2026-11-08. Researched for the owner's question "research pi and Codex and how they might affect wicket's design".*

**Confidence marks:** **[H]** = read in primary source (code or the project's own docs at the commit below);
**[M]** = inferred from source, or source and docs disagree slightly; **[U]** = unverified.

**Sources collected (read only; nothing built, installed or run; in-repo `AGENTS.md` files treated as data):**

| Local path | Upstream | Commit / date | Licence |
|---|---|---|---|
| `refs/repos/pi-mono` | `github.com/badlogic/pi-mono` → redirects to **`earendil-works/pi`** | `f064465d10d6` (2026-11-08), packages at **1.5.0** (released 2026-11-02) | MIT |
| `refs/repos/codex-harness` (new sparse clone: app-server, exec, model-provider-info, login, config, cli, hooks, transport, daemon) | `github.com/openai/codex` | `748ab55ca7de` (2026-11-08); latest stable **rust-v0.167.0** (2026-11-06), alphas 0.169.0-alpha.3 | Apache-2.0 |
| `refs/repos/codex` (existing sparse clone by another agent: execpolicy, sandboxes, network-proxy, core) | same | same commit | Apache-2.0 |
| `refs/repos/gondolin` (existing, covered in [07]) | `earendil-works/gondolin` | — | Apache-2.0 |

Codex sandbox, seatbelt and network-proxy internals are in [07]; Codex basics already established in
[01 §2.2] are not repeated except where they changed or matter for the design.

---

## TL;DR

1. **"pi" is Mario Zechner's pi** (pi.dev, `earendil-works/pi`, formerly `badlogic/pi-mono`, npm
   `@earendil-works/pi-*`, CLI `pi`). Earendil (Armin Ronacher's company) took it over in 2026; it reached 1.0
   on 2026-10-01 and ~120k GitHub stars. It powers OpenClaw. No other coding agent called "pi" is
   prominent; Inflection's *Pi* is a consumer chatbot and Physical Intelligence's *π* models are robotics
   models. [H for repo; M for history from secondary sources]
2. **pi's stance is wicket's premise.** "Pi does not include a built-in permission system … If you need
   stronger boundaries, containerize or sandbox Pi" (`README.md`, `docs/security.md`). There is no in-box
   permission layer to fight, no managed-settings layer, and every policy hook is an in-process extension.
   **My belief that pi has no MCP is out of date:** built-in MCP (stdio + streamable HTTP, OAuth) arrived in
   **0.99.0 (2026-09-29)**, exposed by default through *codemode*, not as direct tools. [H]
3. **pi is a natural T1 agent over RPC** (`pi --mode rpc`, strict JSONL), with a small wicket-authored
   extension providing the permission channel (`tool_call` can block or await; extension dialogs travel over
   the same RPC pipe and need no timeout), typed output via a terminating tool, steering, resume and forks
   of a tree-structured JSONL session. It has no native structured-output mode. [H]
4. **Codex app-server is a T1 protocol, not a T2 detour.** It has host-answered approvals with no timeout,
   `turn/steer`, `outputSchema` per turn, `thread/resume|fork|rollback`, **client-provided "dynamic tools"
   served over the same pipe** (`item/tool/call`), approval replay on reconnect, and checked-in JSON Schema
   for every message. `codex exec` is now just an in-process app-server client that *rejects* approval
   requests. `codex-acp` is a lossy translation of app-server; use it only as a fallback. [H]
5. **Codex can be locked down from outside the agent's reach**: root-owned `/etc/codex/requirements.toml`
   can pin `model_provider` and the full `model_providers` table, the MCP allowlist, rules, allowed sandbox
   modes and approval policies, `allow_remote_control = false`, managed hooks only, and a local model
   catalogue. Codex speaks **only the Responses API** (`wire_api = "chat"` is now a hard error), over SSE or,
   for the built-in OpenAI provider, WebSockets. [H]
6. **Codex now has its own "Remote Control"**: the app-server enrols with
   `chatgpt.com/backend-api/wham/remote/control/...` and relays full app-server JSON-RPC to the ChatGPT
   desktop and mobile apps. It needs a ChatGPT login and allows only `*.chatgpt.com`. It is the same shape as
   Claude's RC, so §13.1.4 should generalise to `vendor_rc{claude|codex}`. [H]
7. **Both projects converge on "brain outside, hands inside"**: Codex `exec-server` and `environments`,
   pi-env's Rust daemon, pi's pluggable tool `Operations` (the Gondolin and SSH extensions), the Vercel AI SDK
   pi harness, and Claude Managed Agents (T1b). wicket should make **placement** (whole agent in box vs split
   brain and hands) an axis orthogonal to tier. [H]
8. **For wicket's own trusted LLM calls, don't adopt pi-ai** (Node, five vendor SDKs, credential stores,
   OAuth). Keep a small Rust `Model` trait whose only upstream is wicket-llm, and borrow pi-ai's *design*
   (unified context, cross-provider handoff, faux provider, per-provider compat flags, cost model). [M,
   judgement]
9. **Borrow from Codex execpolicy**: rules with inline `match`/`not_match` examples validated at load time,
   strictest-decision-wins, executable path pinning, and a tree-sitter "plain words only, else opaque" Bash
   parser. Also borrow its `prompt-user` checkpoint (fresh human decision, never satisfied by session
   approvals) and its `responses-api-proxy`. [H]

---

## 1. pi

### 1.1 What "pi" is in late 2026

- **Identity.** Repo `earendil-works/pi` (`badlogic/pi-mono` redirects there, `gh api repos/badlogic/pi-mono`
  → `full_name: earendil-works/pi`), MIT, created 2025-08-09, about 120.7k stars on 2026-11-08, releases
  v1.0.0 (2026-10-01) through v1.5.0 (2026-11-02). npm scope `@earendil-works`. Install via
  `curl https://pi.dev/install.sh` or `npm install -g --ignore-scripts @earendil-works/pi-coding-agent`; needs
  Node ≥ 22.19. [H] `README.md`
- **History.** Zechner's design essay was published in Nov 2025. Earendil (Armin Ronacher and Colin Daymond
  Hanna) took pi over in 2026, and Zechner leads it there. It ships with Radius, Earendil's AI gateway and
  provider. [M: secondary — https://www.eesel.ai/de/blog/pi-coding-agent-erklaert ,
  https://www.gradually.ai/en/harnesses/pi/ ; Radius is in `docs/providers.md` [H]]
- **Other "pi"s.** Inflection's *Pi* is a chat assistant, not a coding agent, and Physical Intelligence's *π0/π0.5* are
  robot policies. Neither fits "inner agent". Zechner's pi is the referent. [M]
- **Packages** (all 1.5.0, `packages/*/package.json`) [H]:

  | Package | Role |
  |---|---|
  | `pi-ai` | multi-provider LLM API (Anthropic, OpenAI Responses/Completions, Google, Vertex, Bedrock, Mistral, xAI, OpenRouter, Groq, ~35 providers + any OpenAI-compatible) |
  | `pi-agent-core` | agent loop, tool calling, state |
  | `pi-coding-agent` | the `pi` CLI and SDK |
  | `pi-tui` | differential-rendering terminal UI |
  | `pi-mcp` | standalone MCP client |
  | `pi-codemode` | QuickJS-in-WASM sandbox "where the only capability is calling injected tools" |
  | `pi-durable` | experimental durable harness: commits turns and tool calls before showing them, child tasks, task graph |
  | `pi-env` | Rust daemon + client: "an agent's tools run on another machine … while the Durable worker, its storage and credentials stay local" |
  | `pi-schema`, `pi-telemetry`, `chord` | JSON Schema without eval, telemetry contracts, object runtime |

### 1.2 Architecture and the minimal core

- **Loop** (`docs/how-pi-works.md`) [H]:
  - Each turn builds a request from the system prompt, the active branch, the tools and the model
    settings.
  - It streams the assistant response and executes the tool calls, then loops while tool results or queued
    messages remain.
  - Steering messages enter after the current assistant turn. Follow-ups enter after the run ends.
- **Default tools: `read`, `bash`, `edit`, `write`** [H].
  - Off-by-default built-ins: `grep`, `find`, `ls` and `powershell`.
  - Off-by-default built-in extensions: `codemode` and `tool_search`.
  - Sources: `docs/cli.md` §Tools; `src/core/system-prompt.ts` `normalizeBuildSystemPromptOptions` defaults
    `selectedTools` to `["read","bash","edit","write"]`.
- **System prompt** (`src/core/system-prompt.ts`, `buildSystemPromptSections`) [H]:
  - The preamble is one sentence: *"You are a coding assistant running inside pi, a coding agent harness.
    Help users inspect files, run commands, and modify code."*
  - Then one-line tool snippets and a handful of rules ("Be concise", "Show file paths clearly").
  - Then a docs pointer, optional `<addendum>`, `<project_context>` (context files), `<skills>` and `<cwd>`.
  - Sections are XML-tagged and patched by name in later system messages, so the cache stays warm.
- **Prompt and tool size.** Secondary sources put the prompt plus tools under 1,000 tokens [M]. The 1.0
  changelog says a request with default tools *plus codemode* is about 3,300 tokens
  (`CHANGELOG.md` 1.0.0) [H].
- **Missing on purpose:** "skips features like sub-agents and plan mode" (`README.md`). These are
  extensions or packages instead. [H]

### 1.3 Provider abstraction: can wicket's LLM proxy sit under pi? Yes, cleanly.

- **`models.json`** (`<agent-dir>/models.json`, `docs/models-configuration.md`) [H]:
  - `providers.<id>.baseUrl` "Also applies to the provider's built-in models". So you redirect `anthropic`
    or `openai` without copying the catalogue.
  - `apiKey` is a literal, `"$ENV"`, or `"!command"`.
  - `headers` values resolve the same way. `authHeader` sends the key as `Authorization: Bearer`.
  - `api` is one of `anthropic-messages`, `openai-responses`, `openai-completions`, `google-generative-ai`,
    `bedrock-converse-stream`, ….
- **Extensions can re-register providers**, e.g. `pi.registerProvider("anthropic", { baseUrl, headers })`
  ("Redirect an existing provider", `docs/custom-provider.md`). [H]
- **Proxy.** `HTTP_PROXY`/`HTTPS_PROXY` are honoured. A `httpProxy` setting "can only be set in
  agent-directory settings" (`docs/settings.md:125`, `src/core/http-dispatcher.ts`
  `applyHttpProxySettings`). The HTTP client is undici. [H]
- **CA.** Node, so `NODE_EXTRA_CA_CERTS`. [M: standard Node behaviour, not pi-specific code read]
- **Credential sources, in precedence order** [H] (`packages/ai/README.md` §Auth, `docs/providers.md`):
  1. stored credential (`auth.json`, API key or OAuth);
  2. env var;
  3. ambient (AWS chain, gcloud ADC).

  A stored credential "owns its provider: environment variables are only consulted when nothing is
  stored". So wicket must ensure no `auth.json` exists. Anthropic also supports **workload identity
  federation** (`ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_IDENTITY_TOKEN_FILE`).
- **Footguns for wicket** [H]:
  - **`!command` values** in `apiKey`, `headers`, MCP `env`/`headers` and `auth.json` keys execute
    commands. Agent-dir config is code.
  - **OAuth subscription logins** ("Claude Pro/Max", "ChatGPT Plus/Pro via OpenAI Codex", Copilot) write
    refresh-capable tokens to `auth.json`. Never in wicket.
  - **Identity headers.** `User-Agent: pi/<ver> …` and optional attribution headers (`PI_ATTRIBUTION`,
    OpenRouter/NIM/OpenCode only); `PI_TELEMETRY=0` turns attribution off. Harmless through a proxy.
  - **Anthropic "message threads"**, a server-side continuation that sends only new messages, default on
    only for `api.anthropic.com` (`supportsMessageThreads`). With a proxy base URL it is off, which is what
    the proxy wants.
  - **`cacheWarming`** defaults to `"streaming"`: pi sends prompt-cache refresh requests during active runs
    (`docs/settings.md:21`, `src/core/cache-warmer.ts`). A run blocked on a pending permission is still
    "active" [M]. So warming requests would defeat wicket-llm's "no model request for N s = waiting"
    liveness sensor and cost money while a human decides. **Set `cacheWarming: "off"`.**
  - **`transport`** may pick WebSocket for some providers. Set `"sse"`.
- **Network chatter.** pi fetches a model catalogue from pi.dev and checks versions. `PI_OFFLINE=1` ("Disable
  automatic network activity, including model catalog refreshes"), `PI_SKIP_VERSION_CHECK=1` and
  `PI_TELEMETRY=0` (`docs/environment-variables.md`) close these, so **pi needs no internet hosts** beyond
  the LLM proxy and the MCP gateway. [H]

### 1.4 Modes and how a harness drives pi

`docs/cli-integration.md`, `docs/rpc.md`, `docs/rpc-commands.md`, `docs/json.md`,
`src/modes/rpc/rpc-types.ts`, `src/modes/rpc/rpc-mode.ts` [H]:

| Mode | Use for wicket |
|---|---|
| Interactive TUI | none |
| `--print` | final text only; non-zero exit on `error`/`aborted`/`length` |
| `--mode json` | one-shot JSONL event stream: session header, `agent_start`, `turn_*`, `message_*` (delta-only updates), `tool_execution_*`, `queue_update`, `compaction_*`, `auto_retry_*`, `agent_end`, **`agent_settled`** |
| **`--mode rpc`** | long-lived JSONL commands on stdin, `response` + the same events on stdout. Commands: `prompt` (with `streamingBehavior: steer|followUp` while running), `steer`, `follow_up`, `abort`, `get_state`, `get_messages`, `set_model`, `compact`, `bash`, `switch_session`, `fork`, `clone`, `get_tree`, `get_entries`, `get_last_assistant_text`, … |
| SDK (`createAgentSession`) | in-process Node/Bun only; not useful to a Rust host except via an in-box shim |

- **Framing gotcha.** Split on LF only. Node `readline` mis-splits on U+2028/9. The Rust reader must split
  on `\n` bytes only. [H]
- **`agent_end` ≠ done.** Retries, overflow compaction and queued follow-ups can follow; wait for
  `agent_settled`. wicket's `AgentState` needs both. [H]
- **Extension UI subprotocol** (`docs/rpc-extension-ui.md`) [H]:
  - Extension dialogs (`select`, `confirm`, `input`, `editor`) become `extension_ui_request` on stdout and
    **block until** `extension_ui_response` arrives on stdin.
  - They auto-resolve only if the extension passes a `timeout` (`rpc-mode.ts` `createDialogPromise`). This
    is the channel for an indefinitely pending permission prompt over the existing pipe.
  - Fire-and-forget `notify`, `setStatus` and `setWidget` can carry wicket notices.
- **Shutdown.** Close stdin, or SIGTERM/SIGHUP, for an orderly drain. A second signal exits at once. [H]
- **Typed integrations already exist.** Several projects drive `pi --mode rpc` from another process
  (Kurrent `kcap-cli`, a T3 Code draft PR, `pi-acp-jetbrain`, `@geohar/pi-acp`), which supports RPC as the
  stable seam. [M: https://github.com/kurrent-io/kcap-cli/pull/497 , https://github.com/pingdotgg/t3code/pull/6319]

### 1.5 Sessions: JSONL trees

`docs/session-format.md`, `src/core/session-manager.ts` [H]:
- `~/.pi/agent/sessions/--<cwd>--/<ts>_<id>.jsonl`, overridable with `PI_CODING_AGENT_SESSION_DIR` or
  `--session-dir`. Header `{"type":"session","version":3,...,"parentSession"?}`.
- **Every entry has `id` and `parentId`.** The file is a tree. "Continuing from an earlier entry creates
  another branch in the same file", and `/fork` and `/clone` copy history into a new file.
- Compaction inserts a summary entry but **keeps the originals**.
- System messages persist prompt sections and tool loadouts as patches, so replay reconstructs exactly what
  the model saw.
- CLI: `--session <path|id>`, `--session-id <id>` (create-or-open, so the harness can choose the ID),
  `--fork <id>`, `--no-session`. RPC: `fork`, `clone`, `switch_session`, `get_tree`.

**Why wicket cares:** entry-level IDs give wicket a natural address for **labels per entry** and for
handles of the form `(session, entry_id)`. They also allow **"rewind to the last untainted ancestor"**: fork
the session at the entry before a tainted read, and continue the push-capable path from there. Codex
(`thread/fork`, `thread/rollback`) and Claude (`--fork-session`) can do coarser versions. See §3.6.

### 1.6 Extensions, hooks, custom tools, skills

`docs/extensions.md` [H]:
- **What extensions are.** TypeScript modules loaded in-process (via jiti) from
  `<agent-dir>/extensions/`, `.pi/extensions/` (only once the project is trusted), `-e <path>`, settings
  `extensions`/`packages`, or `builtin:<name>`. "Extensions run with your full system permissions."
- **Events.** About 40 of them. The ones that matter for wicket:
  - **`tool_call`**: *can block*. Returns `{block:true, reason, terminate?}`, and may mutate `event.input`
    without re-validation. It is an async handler, so it **can await an external decision for as long as
    it likes** [M: no tool_call timeout found].
  - `tool_result`: middleware that can rewrite the result.
  - `before_provider_headers` and `before_provider_request`: rewrite headers or payload.
  - `after_provider_response` and `provider_stream_event`.
  - `project_trust`: an extension may decide trust.
  - `context`: transform context.
  - `before_agent_start`: can replace the whole system prompt.
- **Custom tools.** `pi.registerTool` with TypeBox/JSON-Schema parameters, optional `outputSchema` +
  `structuredContent`, and **`terminate: true`** to end the run on that call
  (`examples/extensions/structured-output.ts`).
- **Remote execution.** Built-in tools take pluggable `ReadOperations`, `WriteOperations`,
  `BashOperations`, …, and `createBashTool(cwd, {spawnHook})` can rewrite command, cwd and env. This is how
  the Gondolin (micro-VM) and SSH examples move tool execution elsewhere (`examples/extensions/gondolin/`,
  `ssh.ts`).
- **Examples in the repo:** `permission-gate.ts` (regex on bash, `ctx.ui.select`), `protected-paths.ts`,
  `confirm-destructive.ts`, `plan-mode/`, `subagent/`.
- **Skills** (`docs/skills.md`): on-demand instruction files listed in the prompt (`<skills>`), loaded
  from `<agent-dir>/skills`, `.pi/skills`, and `.agents/skills` in the cwd or its ancestors (trust-gated).
  `--no-skills` and `--skill <path>`.

### 1.7 MCP and permissions: what pi actually does now

- **MCP is built in since 0.99.0 (2026-09-29)** (`CHANGELOG.md` 0.99.0: "Added codemode, tool search, and
  MCP support as built-in extensions") [H] (`docs/mcp.md`):
  - Config: `~/.pi/agent/mcp.json` and project `.pi/mcp.json` (trust-gated). Same `mcpServers` shape as
    Claude. stdio + streamable HTTP; SSE rejected. OAuth with CIMD/DCR, and tokens in
    `~/.pi/agent/mcp-auth.json`.
  - **Exposure** per server or tool: `codemode` (*default*: callable only from codemode scripts, not
    declared to the model), `deferred` (via `tool_search`), `direct`, `hidden`.
  - **Gotcha for wicket:** with defaults, gateway tools such as `wicket.await_grant` would be invisible to
    the model unless it writes a codemode script that searches for them. **Set `exposure: "direct"` for the
    wicket gateway.**
  - Text results over 20 KB are middle-truncated with the full text in a temp file.
  - `--no-mcp` and `-builtin:mcp` disable it.
  - "Every MCP call passes through Pi's tool pipeline", so `tool_call` gates apply to MCP tools too.
- **Permissions: none, deliberately.** "Pi does not include a built-in permission system for restricting
  filesystem, process, network, or credential access" (`README.md`). "It does not ask for approval before
  every tool call … Watching the transcript, using project trust, and reviewing changes do not create a
  security boundary" (`docs/security.md`). [H]
- **Project trust is a loading gate, not a sandbox** [H] (`docs/security.md` §project-trust):
  - It gates `.pi/settings.json`, `.pi/mcp.json`, `.pi/extensions|skills|prompts|themes`,
    `.pi/SYSTEM.md`/`APPEND_SYSTEM.md` and project `.agents/skills`.
  - Headless modes default to *skip* unless `defaultProjectTrust: "always"`; `--no-approve` forces skip.
  - **Context files `AGENTS.override.md`, `AGENTS.md` and `CLAUDE.md` load regardless of trust** (disable
    with `-nc`).
  - **Known leak:** the project `sessionDir` setting is read *before* trust is resolved. So a hostile
    `.pi/settings.json` can redirect where sessions are written. wicket must pass `--session-dir`
    explicitly, which takes precedence.
- **No managed or system layer.** Config lives only in `<agent-dir>` (`PI_CODING_AGENT_DIR`) and `.pi/`
  (`docs/configuration.md`). There is no `/etc` equivalent of Claude's managed-settings or Codex's
  `requirements.toml` [H: grep for managed/system/`/etc` in docs finds nothing]. Anything wicket wants
  pinned must be pinned by **file ownership plus launch flags**.
  - pi writes `models-store.json`, `trust.json`, `crashes.json`, `mcp.log` and the `npm/` and `git/` package
    dirs into the agent dir (`src/core/models-store.ts`, `crash-log.ts`, `package-manager.ts`). Whether it
    runs with a read-only agent dir is **[U]**: conformance experiment E-PI1.

### 1.8 Isolation story and the ecosystem

`docs/containerization.md` lists four patterns [H]:
- **plain Docker** (credentials passed in);
- **Docker Sandboxes** (`sbx`): a proxy substitutes the real key for a placeholder. It even documents an
  `sk-ant-oat01-{rand}` OAuth-shaped placeholder for Claude subscriptions. Kit `docker.io/sbx/pi-kit`;
- **NVIDIA OpenShell**: policy sandbox with inference routing so raw model keys stay outside;
- **Gondolin extension**: pi on the host, built-in tools in a QEMU micro-VM. It explicitly warns that host
  env vars leak into the VM.

Other pi-based harnesses [M, from search results; not cloned, since none is a primary design input]:
- **Vercel AI SDK `@ai-sdk/harness-pi`** (experimental): pi runs in the host Node process and treats the
  sandbox as a remote filesystem and shell. It offers `permissionMode: allow-reads|allow-edits` and
  `fileToolPathPolicy` ("not a security boundary for agent commands"), and **"Pi doesn't support structured
  output"**. https://ai-sdk.dev/providers/ai-sdk-harnesses/pi
- **`agentic-pi`**: one-shot worker with an optional Gondolin VM.
- **`@groeponline/pi-agent-orchestrator`**: subagents, worktrees, swarms.
- **ACP adapters**, all community, none in the ACP registry [M]: `@geohar/pi-acp` (spawns `pi --mode rpc`),
  `pi-acp-jetbrain`, `victor-software-house/pi-acp` (SDK), `DxTa/pi-acp`, Rust `pi-acpinator`.
- **OpenClaw** embeds pi.

The pattern across all of these: **pi is the loop, the sandbox is someone else's job, and the interesting
work is credential substitution and tool placement**. That is exactly wicket's niche.

### 1.9 What pi's philosophy implies for wicket

1. **Least friction of any inner agent.** No inner sandbox to disable, no permission modes to fight, no
   auto-update or telemetry beyond three env vars, no vendor session service. With pi, Principle 1 ("in-box
   controls are telemetry and UX only") is simply true by construction.
2. **pi is a T1 agent through a wicket extension** (see §3.1). The extension is in-box code, and so as
   untrusted as Claude's own CLI. It only *routes* permission questions to wicket over the RPC pipe; it
   doesn't enforce anything.
3. **pi suits the "split" placement.** Its tool `Operations` interfaces and pi-env show how to run the loop
   in one box and the tools in another. But the loop process still ingests untrusted model output and
   repo-derived context. A split doesn't make the brain trusted: the brain box gets the LLM route and no
   workspace, and the hands box gets the workspace and no LLM route. That is a labelling and smuggling win
   (the workspace can't rewrite agent config or transcripts), not a trust win.
4. **pi-ai / pi-agent-core as wicket's own trusted LLM layer: no** (§3.5).
5. **Cheap model agnosticism for experiments.** pi drives any provider through wicket-llm. So E1 ("does the
   agent wait or route around a denial?") can be run with *one harness × many models*, separating model
   behaviour from harness behaviour. That's a better experimental design than Claude Code vs Codex vs Gemini
   CLI alone. Add pi + {Claude, GPT, Gemini, open-weights} to E1.

---

## 2. Codex as an inner agent and as a harness design

Delta from [01 §2.2]: app-server is now the centre of Codex. `codex exec` is an in-process app-server
client, and the TUI, desktop app, mobile app (via Remote Control), IDE extensions and `codex-acp` all speak
it.

### 2.1 app-server protocol

Sources: `codex-rs/app-server-protocol/src/protocol/v2/*.rs`, the generated schema in
`codex-rs/app-server-protocol/schema/{json,typescript}` (290 v2 JSON schemas, 686 TS types),
`codex-rs/app-server/README.md`, https://learn.chatgpt.com/codex/app-server [H].

- **Transport.** `codex app-server --listen stdio://` (default; JSONL, JSON-RPC 2.0 without the `jsonrpc`
  field), `unix://PATH`, or `ws://` (experimental; capability-token auth flags). [H]
- **Handshake.** `initialize {clientInfo, capabilities:{experimentalApi, requestAttestation,
  requiredHumanApproval?, optOutNotificationMethods?, ...}}` → `initialized`. Experimental fields are
  filtered out unless `experimentalApi: true` (the `#[experimental(...)]` attributes in `v2/thread.rs`).
  [H] `InitializeCapabilities.ts`
- **Client → server (selection, ~110 methods):**
  - Threads: `thread/start|resume|fork|read|list|rollback|revert|archive|delete|inject_items|compact/start|shellCommand`.
  - Turns: `turn/start|steer|interrupt`.
  - Config and accounts: `config/read|value/write|batchWrite`, `configRequirements/read`,
    `account/login/start|read|logout`, `modelProvider/list|config/write`.
  - MCP: `mcpServerStatus/list`, `mcpServer/tool/call`.
  - Host-like powers: **`command/exec`**, **`fs/readFile|writeFile|remove|...`**.
  - Plugins and skills: `plugin/*`, `skills/*`.
  - Remote control: `remoteControl/*`.

  [H] `schema/typescript/ClientRequest.ts`
- **`thread/start`** carries `model`, `modelProvider`, `cwd`, `approvalPolicy`, `approvalsReviewer`, `sandbox`,
  `config` (arbitrary overrides), `baseInstructions` and `developerInstructions`, `ephemeral`. Under
  experimental it adds `permissions` (profile), `dynamicTools`, `environments`, `runtimeWorkspaceRoots` and
  `historyMode`. [H] `v2/thread.rs:62-160`
- **`turn/start`** carries `input`, `cwd`, `approvalPolicy`, `sandboxPolicy`, `model`, `effort` and
  **`outputSchema`** ("Optional JSON Schema used to constrain the final assistant message for this turn").
  [H] `v2/turn.rs:174-300`
- **Server → client requests** (the host answers) [H] `ServerRequest.ts`:
  - `item/commandExecution/requestApproval`. Decisions: `accept | acceptForSession |
    {acceptWithExecpolicyAmendment} | {applyNetworkPolicyAmendment} | decline | cancel`. Params include
    `kind`, `command`, `cwd`, `reason`, `networkApprovalContext`, `environmentId` and `approvalId`.
  - `item/fileChange/requestApproval`.
  - `item/permissions/requestApproval` (request a permission-profile delta).
  - **`item/tool/call`**: a *dynamic tool* implemented by the client.
    `{threadId, turnId, callId, namespace, tool, arguments}` → `{contentItems, success}`.
  - `mcpServer/elicitation/request`, `item/tool/requestUserInput`, `account/chatgptAuthTokens/refresh`,
    `attestation/generate`.
- **Notifications** (~100) [H]:
  - `thread/started|status/changed|tokenUsage/updated|compacted`;
  - `turn/started|completed|diff/updated|plan/updated`;
  - `item/started|completed`, `item/agentMessage/delta`, `item/commandExecution/outputDelta`;
  - `serverRequest/resolved`, `hook/started|completed`, `model/rerouted`, `remoteControl/status/changed`,
    `warning`, `error`.
- **Approval lifetime.** No server-side approval timeout found in `app-server/src` [M]. The README says
  "Pending prompts use the normal approval replay flow when a capable client reconnects" (§"Managed human
  command checkpoints") [H]. That is exactly what parking needs: kill or snapshot the host side, reconnect,
  and get the still-pending request replayed.
- **`humanCommand` checkpoints** (experimental, rust-v0.167.0, PR #58045) [H]:
  - A managed `requirements.toml` `prefix_rule` with `decision = "prompt-user"` "requires a fresh human
    decision, including when the thread uses automatic review. … Session and persistent approvals cannot
    satisfy the checkpoint. … With no capable connection when approval is requested, the command is
    rejected."
  - This is prior art for wicket's "one use, never standing" human grants.
- **Schema generation.** `codex app-server generate-ts | generate-json-schema` (`cli/src/main.rs`
  `AppServerCommand`), and the schemas are checked in. **The `codex-app-server-protocol` crate on crates.io
  is stale** (0.63.0, 2025-12-11) [H: crates.io API]. So wicket should generate Rust types from the JSON
  schema of the pinned Codex tag (typify), not depend on the crate.

### 2.2 `codex exec`

- **Implementation.** It is now an `InProcessAppServerClient` (`exec/src/lib.rs` imports). It starts
  threads with `approval_policy: Some(AskForApproval::Never)` (line 632), and **rejects** every
  `CommandExecutionRequestApproval` and `FileChangeRequestApproval` with "approval is not supported in exec
  mode" (lines 2250-2275). [H]
- **Events.** `--json` emits `thread.started`, `turn.started|completed|failed`, `item.started|updated|completed`
  and `error` (`exec/src/exec_events.rs`). [H]
- **Flags:** `--output-schema FILE`, `-o/--output-last-message`, `--ephemeral`, `--ignore-user-config`,
  `--ignore-rules`, `--skip-git-repo-check`, `--strict-config`, and `exec resume --last|<id>`
  (`exec/src/cli.rs`). [H]
- **For wicket:** `exec --json` is a **T3 with structured events and typed output**. A denial at wicket's
  proxy reaches the model as a failed command, with no host channel to say "pending". Use it only where
  app-server is unavailable.

### 2.3 Config injection and lock-down

- **Layers** (`config/src/loader/mod.rs`, `layer_io.rs`) [H]:
  - system `/etc/codex/config.toml`;
  - `$CODEX_HOME/config.toml`;
  - profiles;
  - project `.codex/config.toml` (only if the project is trusted);
  - `-c k=v` / `thread/start.config`;
  - `/etc/codex/managed_config.toml` (overrides user config *and* `-c`);
  - **`/etc/codex/requirements.toml`** (constraints).
- **`requirements.toml` fields** (`config/src/config_requirements.rs:1140-1185`) [H]:
  - `model_provider` ("Exact provider selection, overriding local and session configuration") and
    **`model_providers`** ("Complete provider definitions; each entry replaces the configured provider");
  - `model_catalog_json`, `check_for_update_on_startup`;
  - `allowed_approval_policies`, `allowed_approvals_reviewers`, `allowed_sandbox_modes`,
    `allowed_permission_profiles`, `default_permissions`, `allowed_web_search_modes`;
  - `allow_managed_hooks_only`, `allow_browser_and_computer_use`, **`allow_remote_control`**;
  - `mcp_servers` (allowlist), `rules` (execpolicy overlay), `network_proxy`/`permissions.network`,
    `features`, `otel`, `enforce_residency`, `additional_developer_instructions`.
- **For wicket:** root-owned `/etc/codex/requirements.toml` is the one Codex knob the agent cannot undo.
  - It pins the LLM route and the MCP allowlist, and turns Remote Control and browser/computer use off.
  - Pair it with a wicket-written `$CODEX_HOME`, labelled state.
  - Clients *can* write config through `config/value/write` and `modelProvider/config/write`, and so can
    the model through `fs/*` or shell. Requirements are what make those writes harmless.
- **Memory hazard.** Approving with `acceptWithExecpolicyAmendment` persists a rule into
  `$CODEX_HOME/rules/default.rules` (`core/src/exec_policy.rs` `default_policy_path`,
  `append_amendment_and_update`). That is state that outlives the turn (§12 memory). **wicket's adapter
  must never send amendment decisions.**

### 2.4 Model providers: can wicket-llm front Codex? Yes, if it speaks Responses.

- **Responses only.** `WireApi` has one variant, `Responses`. `"chat"` deserialises to
  `CHAT_WIRE_API_REMOVED_ERROR` (`model-provider-info/src/lib.rs:113-148`). [H]
- **`ModelProviderInfo` fields** [H]:
  - `base_url`, `env_key`, `experimental_bearer_token`, `auth` (command-backed bearer), `gateway_oauth`,
    `aws` (SigV4);
  - `wire_api`, `capabilities{remote_compaction, external_web_access, cyber_access_programs}`,
    `query_params`, `http_headers`, `env_http_headers`;
  - retries and timeouts, `requires_openai_auth`, **`supports_websockets`** (the built-in OpenAI provider
    uses WebSockets; custom providers default to false), `supports_standalone_web_search`.
  - Built-ins: `openai` (`CHATGPT_CODEX_BASE_URL = https://chatgpt.com/backend-api/codex` for ChatGPT auth),
    `amazon-bedrock`, `gcp` (new in 0.165.0), `ollama`, `lmstudio`.
- **Prior art for wicket-llm: `codex responses-api-proxy`** (`responses-api-proxy/README.md`) [H]:
  - "A strict HTTP proxy that forwards `POST /v1/responses` … Other requests are rejected with 403."
  - It reads the key from **stdin** and is meant to run as a privileged user, so the unprivileged agent
    can't read it.
  - Optionally it exchanges GitHub Actions OIDC for short-lived OpenAI credentials.
  - Codex's own docs show wiring it in as `model_providers.<id>.base_url`. This is wicket-llm's design in
    miniature, and a reference to diff against.
- **LLM-proxy requirements from Codex** [M]:
  - `POST {base_url}/responses` with SSE.
  - Avoid `/models` discovery by pinning `model_catalog_json`.
  - Remote compaction: set capability to local, or support it.
  - **Hosted `web_search`**, server-side and invisible to egress: `allowed_web_search_modes = ["disabled"]`,
    or the proxy marks taint on `web_search_call` items.
  - Whether Codex uses `store`/`previous_response_id` against a custom provider [U].
- **Workload identity federation** (`OPENAI_FEDERATION_RULE_ID`, `OPENAI_IDENTITY_TOKEN_FILE`;
  `login/src/auth/workload_identity.rs`) and Agent Identity JWT (`CODEX_ACCESS_TOKEN`) [H]. Together with
  Anthropic's WIF (§1.3), both big vendors now let a workload swap an OIDC token for short-lived API
  credentials. **This belongs in wicket's vault, not in the box:** wicket-llm can authenticate upstream via
  WIF instead of holding a static key.

### 2.5 Auth and where tokens live

Delta from [01 §2.2]:
- **Sources.** `CODEX_API_KEY` and `OPENAI_API_KEY` (`login/src/auth/manager.rs:1049-1066`),
  `CODEX_ACCESS_TOKEN` (agent identity), WIF, or ChatGPT login.
- **Storage.** ChatGPT login tokens go in `$CODEX_HOME/auth.json` or the keyring ("CODEX_AUTH" secret,
  `storage.rs:303`).
- **Host-supplied tokens.** app-server `chatgptAuthTokens` lets the host push access tokens and answer
  `account/chatgptAuthTokens/refresh`, so a refresh token never enters the box.
- **wicket's default** is a custom provider with `env_key` = placeholder and `requires_openai_auth = false`.
  There is then no OpenAI credential of any kind in the box. [H for mechanisms; M for the combination]

### 2.6 MCP, AGENTS.md, hooks, skills

- **MCP client.** `[mcp_servers.<id>]` (stdio/HTTP, `bearer_token_env_var`, `required`,
  `enabled_tools`/`disabled_tools`). Shared MCP connections get per-chat leases (0.167.0).
  **`codex mcp-server` is gone**: there is no `McpServer` variant in `cli/src/main.rs` `Subcommand` at this
  commit. [H]
- **AGENTS.md.** `AGENTS.override.md` then `AGENTS.md`, from the project root down to the cwd, plus
  `$CODEX_HOME/AGENTS.md`, budgeted by `project_doc_max_bytes` (`core/src/agents_md.rs:42-51, 281`). [H]
  These are preflight taint sources, alongside `.codex/` and `.agents/skills`.
- **Hooks.** Claude-style command hooks: `pre-tool-use` (`allow|deny|ask`), `permission-request`
  (`allow|deny`), `post-tool-use`, `session-start|end`, `user-prompt-submit`, `stop`, `subagent-*`,
  `pre/post-compact`, `model-request`, `interrupt` (`hooks/schema/generated/*.json`). **No `defer`
  decision.** `allow_managed_hooks_only` lives in requirements. [H]

### 2.7 execpolicy and approval policies

- **Language** (`codex-rs/execpolicy/README.md`, `src/{parser,rule,policy}.rs`) [H]:
  - Starlark `prefix_rule(pattern=[...], decision="allow|prompt|forbidden", justification, match=[...],
    not_match=[...], canonical_matching?)`.
  - `host_executable(name, paths=[...])` pins which absolute paths a basename rule may resolve to.
  - **The strictest decision across matches wins.**
  - **`match`/`not_match` examples are validated at load time** ("think of them as unit tests").
  - Rules load from each config layer's `rules/*.rules` in precedence order, with requirements as an
    overlay (`core/src/exec_policy.rs` `policy_files`, `load_exec_policy`).
  - `codex execpolicy check --rules F cmd...` prints JSON.
- **Bash parsing** (`shell-command/src/bash.rs`, via GitHub API) [H]:
  - `parse_shell_lc_plain_commands` uses tree-sitter-bash. It returns argv lists **only** if the
    `bash -lc` script is plain words joined by `&& || ; |`. Parentheses, redirections, substitutions and
    control flow give `None`, and the whole argv is then evaluated as one opaque command
    (`exec_policy.rs` `commands_for_exec_policy_for_platform`).
  - A separate literal-word extractor exists for *dangerous* detection and "must not be used to prove that
    a command is safe".
- **Approval policies** (`AskForApproval.ts`) [H]:
  - `on-request | never | {granular:{sandbox_approval, rules, skill_approval, request_permissions,
    mcp_elicitations}}`, and `untrusted`, which is still in the schema although the docs call it retired [M].
  - `approvalsReviewer: user | auto_review | guardian_subagent`.
  - Under `danger-full-access` there is no sandbox to escape. So **in-box approvals then fire only for
    execpolicy `prompt` rules, MCP approvals and elicitations, and permission requests** [M]. That is the
    hook wicket uses to get early, typed prompts (see the LaunchPlan).

### 2.8 Sandbox modes inside wicket's box

Mechanics are in [07]. What matters for the harness [M]:
- **Codex's network-off is wicket's network-off.** `workspace-write` turns network off by default by
  unsharing the netns, and that also cuts tool commands (`gh`, `git push`, `curl`) off from wicket's egress
  proxy. If the inner sandbox is kept on, set `network_access = true` (or a profile with network enabled),
  so the inner seccomp allows sockets and `HTTPS_PROXY` routing reaches wicket.
- **bwrap needs unprivileged user namespaces.** In wicket's `process` jail (already inside a userns built by
  `wicket-jail`) nested userns may or may not be allowed. Under gVisor it is plausible. Default to
  `danger-full-access` with `allowed_sandbox_modes = ["danger-full-access"]` pinned in requirements, and
  test `workspace-write` per backend as defence in depth (E-CX2).
- **Inner MITM: off.** Codex's own network proxy (`features.network_proxy`) can chain upstream
  (`allow_upstream_proxy`), but the TLS-intercepting layer belongs to wicket. Two layers of MITM double the
  CA plumbing for no security gain.

### 2.9 Operator surfaces: Codex has a Remote Control

- **What it is.** `codex remote-control [start|stop|pair]` and `codex app-server daemon
  enable-remote-control | bootstrap --remote-control` (`cli/src/remote_control_cmd.rs`,
  `app-server-daemon/README.md`: "used by remote clients such as the desktop and mobile apps … Codex
  instances launched over SSH"). [H]
- **Mechanism** (`app-server-transport/src/transport/remote_control/*`) [H]:
  - The app-server *enrols* as a server at `chatgpt.com/backend-api/wham/remote/control/server/enroll`
    (`auth.rs:413`) and keeps a WebSocket to the relay.
  - Paired clients' JSON-RPC is multiplexed by `client_id`/`stream_id`/`seq_id` (`protocol.rs`
    `ServerEnvelope`).
  - Hosts are restricted to `chatgpt.com`, `chatgpt-staging.com` and their subdomains, or loopback
    (`protocol.rs:209-224`).
  - Auth is the ChatGPT account (`load_remote_control_auth`).
- **Implication.** Remote clients reach the *full* app-server surface, including `command/exec`,
  `fs/writeFile` and `config/value/write` [M: no per-client method gate found; `connection_rpc_gate.rs` is
  lifecycle-only]. Inside wicket that is bounded by the box, like everything else. But it is an instruction
  ingress *and* a transcript egress to OpenAI, so it is the same risk class as Claude RC
  ([09], §13.1.4).
- **Kill switch.** `allow_remote_control = false` in requirements forces it off.
- **Other surfaces:**
  - **Codex cloud** (`codex cloud`, `cloud-tasks`) runs tasks in OpenAI-hosted containers, not in wicket
    ([01 §3.10]).
  - `remote_sandbox_config` and `environments` point at remote executors.
  - IDE extensions and the desktop app are app-server clients.

### 2.10 Brain/hands split: `exec-server` and `environments`

- **What it is** (`codex-rs/exec-server/README.md`, via GitHub API) [H]:
  - `codex exec-server` / `codex-exec-server` is "a small JSON-RPC server for spawning and controlling
    subprocesses" plus filesystem handlers.
  - It listens on `ws://` (capability-token or bearer auth) or `--listen stdio`, or registers with a
    remote environment registry over a Noise relay.
  - app-server selects it per thread or turn via the experimental `environments`, `environment/add` and
    `environments.toml`. `CODEX_EXEC_SERVER_URL` bypasses daemon attach.
  - Labels `CODEX_THREAD_ID`/`CODEX_TOOL_CALL_ID` "support correlation, not authorization".
- **For wicket:** a split placement. The app-server (brain) runs in a box with only the LLM route and the
  control pipe. `exec-server` (hands) runs in the workload box with the workspace and the egress proxy.
  Experimental and moving fast [M].
- **codex-acp** (v2.6.0, 2026-11-08): it "starts the Codex App Server, translates ACP requests into Codex
  operations". Its feature list has no output-schema support [M]. It adds an AIR extension layer of its own.
  https://github.com/agentclientprotocol/codex-acp

### 2.11 2026 changes that matter

From stable release notes 0.162–0.167 (`gh api repos/openai/codex/releases`) [H]:
- `prompt-user` managed checkpoints (0.167);
- approval and permission settings preserved across resume and fork (0.166, 0.163);
- MITM hooks with "scoped request-body secret substitution" (0.166);
- the network proxy now checks permission *before* DNS and rejects duplicate `Host` headers (0.163);
- the built-in GCP Vertex provider (0.165);
- runtime auth integrated into model requests (0.166);
- credential masking in remote Bash (0.164);
- the standalone executor shipped in release packages (0.166).

Earlier in 2026 [01 §2.2]: Chat wire API removed, `codex mcp-server` removed, `on-failure` deprecated,
permission profiles superseding `sandbox_mode`, bubblewrap default on Linux.

---

## 3. Design impact

### 3.1 Tiers: classify by protocol class, with placement as a separate axis

The current §6 table puts Codex in T2 via `codex-acp`. The evidence says:

| Agent / protocol | Host-answered permission | Hold indefinitely | Mid-run inject | Typed output | Resume | Host tools over the pipe | Tier |
|---|---|---|---|---|---|---|---|
| Claude Code stream-json control | `can_use_tool` | yes | stream-json input | `--json-schema` | `--resume` | `initialize` hooks; SDK MCP servers [01] | **T1** |
| **Codex app-server** | `item/*/requestApproval` | yes [M], replayed on reconnect [H] | `turn/steer`, `thread/inject_items` | `turn/start.outputSchema` | `thread/resume`, `fork`, `rollback` | **`dynamicTools` → `item/tool/call`** (experimental) | **T1** |
| **pi RPC + wicket extension** | `tool_call` → `extension_ui_request` | yes (no timeout) | `steer`, `follow_up` | terminating `wicket_result` tool | `--session-id`, `switch_session`, `fork` | extension tools (`pi.registerTool`) | **T1** |
| ACP agents | `session/request_permission` | yes (spec) | `session/prompt` | outbox only | `session/load`, `resume` | MCP-over-ACP (RFD) | T2 |
| Codex `exec --json`, `pi --mode json` | none | — | no | Codex `--output-schema`; pi no | `exec resume` / `--session` | no | T3 (structured events) |
| any process | none | — | no | outbox | checkpointed workdir | no | T3 |

So:
- **T1 = "native control protocol"**. The adapter speaks the agent's own rich protocol, answers its
  permission prompts, injects messages and reads typed output. Three members: Claude stream-json, Codex
  app-server, pi RPC.
- **T2 = ACP (generic).** It stays the long tail and the fallback for Codex (`codex-acp`) and pi (community
  adapters).
- **T3 = process**, optionally with a structured event stream (`EventStream::Jsonl{schema}`), which gives
  better liveness and transcripts than plain T3.
- **Placement** (new, orthogonal): `Whole` (agent process in the workload box) |
  `Split { brain: BoxSpec, hands: HandsProtocol }`, where `HandsProtocol` is Codex `ExecServer`,
  pi `ToolOperations`/pi-env, Claude Managed Agents worker (today's "T1b"), or wicket's own `wicket-guest`
  exec. **T1b becomes `Split` + Claude Managed Agents** rather than a tier.

### 3.2 Missing `AgentCaps` fields

The current sketch ([01 §4.2]) lacks these, each motivated by pi or Codex:

```rust
pub struct AgentCaps {
    // existing: io, model_route, honours_https_proxy, custom_ca, mcp, permission_host, defer,
    //           structured_output (→ replaced), resume, inject_message_mid_run (→ replaced), own_sandbox
    pub permission_host: PermissionHost,   // + CodexAppServerApproval | ExtensionDialog{ext: ExtRef}
    pub typed_output: TypedOutput,         // NativeSchema{per_turn: bool} (Claude, Codex) | TerminatingTool (pi) | Outbox
    pub steer: SteerSupport,               // { steer: bool, follow_up: bool, inject_items: bool }
    pub host_tools: HostToolChannel,       // None | CodexDynamicTools | AcpMcpOverAcp | PiExtensionTool
    pub model_wire: Vec<WireApi>,          // what wicket-llm must speak: AnthropicMessages | OpenAIResponses{websocket: bool} | OpenAIChat | Google
    pub server_side_tools: Vec<ServerTool>,// taint ingress invisible to egress: Claude WebSearch, Codex hosted web_search; pi: none
    pub config_lockdown: ConfigLockdown,   // ManagedFile{path} (Claude managed-settings, Codex requirements.toml) | FileOwnershipOnly (pi)
    pub config_exec_vectors: Vec<&'static str>, // config keys that run commands: pi "!cmd" values; Codex model_providers.*.auth, aws.credential_export
    pub context_files: Vec<&'static str>,  // auto-loaded instructions → preflight taint: AGENTS.md, AGENTS.override.md, CLAUDE.md, .agents/skills, ...
    pub persistent_policy_writes: Vec<PolicyWrite>, // in-box state an approval can persist (Codex execpolicy amendments) → never send
    pub session_store: SessionStore,       // ClaudeJsonl | CodexRollout{sqlite_state} | PiTreeJsonl — for handles, labels, fork-at-entry
    pub fork_at: ForkSupport,              // None | SessionOnly | AtEntry (pi, Codex rollback/fork)
    pub settled_signal: bool,              // distinguishes run-ended from will-not-continue (pi agent_settled, Codex turn/completed)
    pub native_remote: Option<NativeRemoteKind>, // + CodexRemoteControl{relay: "chatgpt.com"}
    pub placement: Vec<PlacementSupport>,  // Whole | Split{hands: CodexExecServer | PiToolOperations | ManagedAgentsWorker}
    pub background_traffic: Vec<BackgroundTraffic>, // e.g. pi cacheWarming, Codex model refresh — must be off or labelled for liveness
}
```

### 3.3 Denial, pending, typed output, resume and operator channels per agent

**Codex app-server**
- **Early denial.** Mirror the zone ceiling into `requirements.toml` `[rules]` as `prompt` or `forbidden`
  prefix rules, e.g. `git push`, `gh api -X POST`, `curl -X POST`. app-server then asks the host *before*
  the command runs. The adapter maps the argv (when `parse_shell_lc_plain_commands`-style parsing succeeds)
  to a typed `CapabilityRequest`, and otherwise passes an opaque handle.
- **Answers.** `decline` gives item status `declined` and the turn continues. Never send `accept*` variants
  that amend policy.
- **Pending.**
  - Short waits: hold `requestApproval` open.
  - Long waits: park (snapshot or kill), then restart app-server with `thread/resume`. The pending approval
    is replayed to the reconnecting client [H for replay; whether it survives a process restart rather than
    a client reconnect is **[U]**, E-CX3].
  - Gateway-side pending: `wicket.await_grant` via MCP, or a wicket **dynamic tool** held open as
    `item/tool/call` (no network path at all).
- **Typed output.** `outputSchema` on the final `turn/start`. wicket still validates outside the box.
- **Operator channels.** wicket console (default). `vendor_rc{codex}` is possible later; see §3.4.

**pi RPC**
- **Early denial and pending.** `wicket-pi` extension:
  - `tool_call` builds a typed request (bash argv via the same plain-words parse; `write`/`edit` paths
    directly; MCP tool names) and sends `ctx.ui.select("wicket:permission", …)` with **no timeout**, which
    arrives as `extension_ui_request`.
  - wicket answers `extension_ui_response`, or keeps it open.
  - On deny it returns `{block:true, reason:"<problem+json summary with request_id>"}`.
- **Gateway-side pending.** `await_grant` via the MCP gateway with `exposure: "direct"`.
- **Long waits.** `abort` (or snapshot), then restart with `--session-id <same>` and `follow_up "R-123
  granted; retry"`.
- **Typed output.** The extension registers `wicket_result` with the result contract's JSON Schema and
  `terminate: true`. Enable strict tool schemas where the provider supports them (`supportsStrictTools`).
  Validate outside.
- **Operator channels.** No vendor remote UI. wicket console only (Slack via `pi-chat` is out of scope).

### 3.4 Operator channels: generalise `vendor_rc`

- **Generalise the mode.** `operator_mode: vendor_rc{claude|codex}`. The shared design from §13.1.4 holds:
  bridge on the host or tokens pushed in, path-allowlisted egress, an observe-only tap, a kill switch, and
  RC answers never become wicket grants.
- **Codex specifics:**
  - the relay is `chatgpt.com/backend-api/wham/remote/control/*` (WebSocket);
  - it needs ChatGPT auth;
  - `chatgptAuthTokens` lets wicket push access tokens (no refresh token in the box): better than the
    Claude bridge's account credential;
  - remote clients get the whole app-server method set (exec, fs, config writes), so the tap must flag
    those as RC-origin instructions;
  - `allow_remote_control=false` in requirements is the default.
- **`ChannelCaps` gains a field:** `answers_are_policy_writes: bool`, because Codex `acceptForSession` and
  amendments write in-box policy. Such answers stay advisory, but wicket must strip or deny the
  amendment-bearing variants from any channel.

### 3.5 wicket's own trusted LLM calls: pi-ai vs a Rust `Model` trait

- **Against pi-ai inside wicketd** [H for dependencies, `packages/ai/package.json`]:
  - It is Node. Its dependencies are `@anthropic-ai/sdk`, `openai`, `@google/genai`, the AWS Bedrock SDK,
    proxy agents and more.
  - Credential stores and OAuth refresh are its core concern, and it runs `!command` key resolution.
  - The parent-tier decider, the quarantined reader and the manifest proposer are TCB-adjacent. They should
    be small and Rust, and go through **wicket-llm**, which already holds keys, budgets and audit.
- **Decision.** Keep `trait Model` in Rust with one implementation: an in-process call into wicket-llm's
  upstream module (Anthropic Messages, OpenAI Responses, later Chat/Google). The same code path, budgets,
  logs and taint marking as agent traffic.
- **Borrow from pi-ai** (MIT, design only):
  - one `Context` type serialisable across providers ("Cross-Provider Handoffs");
  - per-provider `compat` flags instead of if-chains (`docs/models-configuration.md` §Compatibility);
  - a **faux provider for tests** (`packages/ai/README.md` §Faux Provider), so deciders are tested with
    scripted model replies;
  - normalised stop reasons and usage plus cost tables;
  - constrained-sampling tools for quarantined readers.
- **Optional data reuse.** pi's generated model catalogue (context windows, prices) is MIT data that could
  seed wicket-llm's model table [M].

### 3.6 Lessons to borrow

1. **Tool and prompt minimalism** (pi):
   - wicket's gateway tool descriptions and `wicket.*` tools should be few and terse;
   - prompt sections should be named and patched, not rewritten (cache-friendly);
   - **expose gateway tools directly**: pi's codemode default and Claude's tool search can hide them.
2. **Exposure modes for gateway tools** (pi `direct|deferred|codemode|hidden`). The gateway already chooses
   which adapter tools exist. Add a per-zone exposure hint so large adapter catalogues don't flood the
   context.
3. **Session trees → labelled entry trees** (pi). Store transcripts as entry trees with labels per entry.
   Handles may point at `(session, entry)`. "Rewind to clean ancestor" becomes a first-class recovery from
   taint: for agents with `fork_at: AtEntry`, a zone tainted by one web read can fork from the entry before
   that read for the push path. That is the cheapest form of the planned "disposable tainted children"
   (§17 Q2).
4. **Examples-as-tests in policy** (Codex execpolicy `match`/`not_match`). Add `examples: {allow: [...],
   deny: [...]}` to adapter DSL rules and to dangerous-pattern entries, validated at load by the
   interpreter. They seed §10 step 5's matrix and stop silent regressions when rules are regenerated.
5. **Bash → typed `Op` mapping, advisory only** (Codex `parse_shell_lc_plain_commands`):
   - Map only plain-word commands joined by `&& || ; |`. Anything with substitutions, redirections or
     control flow is `Opaque` (R4 / human).
   - Use `host_executable`-style pinning: `git` means `/usr/bin/git` in the image, not `./git`.
   - This lives in the adapter (in-box prompt UX). **Enforcement stays at the proxies**: the mapping only
     produces early, well-typed requests.
6. **Strictest-wins composition** (execpolicy) matches wicket's "dangerous patterns can only raise". Keep
   it explicit in `wicket-adapter`.
7. **`prompt-user` checkpoints** (Codex): a rule class that no session or persistent approval can satisfy.
   wicket already has `HumanApproval`. Make "fresh per use, not cacheable by ratchet or fatigue promotion"
   a declared property for R4 and money ops.
8. **`responses-api-proxy`** (Codex): its key-on-stdin, privileged process, single endpoint and 403-else
   design is a good conformance reference for wicket-llm's OpenAI path. **WIF upstream** (OpenAI,
   Anthropic) lets the vault avoid long-lived model keys.
9. **Run-ended vs settled** (pi `agent_end` / `agent_settled`). Add `AgentState::Settled`, and only
   extract results after it.
10. **Approval replay on reconnect** (Codex) is the protocol property parking needs. Make it a conformance
    test ("pending request survives host restart") for every T1/T2 adapter.

### 3.7 Conflicts with current decisions

| Current text | Conflict | Proposed resolution |
|---|---|---|
| §6 table: Codex is T2 via `codex-acp` | app-server has everything T1 needs; `codex-acp` drops `outputSchema` [M], dynamic tools and network-approval context | Codex app-server is T1. `codex-acp` is a T2 fallback |
| §6 "LLM proxy … Anthropic Messages API first, then the OpenAI Responses and Chat APIs" | Codex is Responses-only (Chat removed); pi can use any API | Order: Messages → **Responses** (needed by Codex and GPT via pi) → Google → Chat (only for open-weights servers) |
| §9.3 liveness: "no model request for N s after a denial means waiting" | pi `cacheWarming: "streaming"` sends requests during active runs; Codex may refresh models | Turn background traffic off in LaunchPlans, and classify cache-warm requests (no new user/tool content) as non-liveness |
| §9.2 / §6: inject the gateway as MCP and the agent will see `wicket.*` tools | pi's default MCP exposure is `codemode` (invisible) | pi LaunchPlan sets `exposure: "direct"`. Conformance check: "the model's declared tool list contains `wicket.await_grant`" |
| §6 Claude-specific preflight list | pi loads `AGENTS.md`/`CLAUDE.md` *regardless of trust*; pi reads project `sessionDir` before trust; Codex loads `AGENTS.override.md` | Preflight list per adapter (`AgentCaps::context_files`). Always pass explicit session-dir flags |
| §13.1.4 is Claude-only | Codex has an equivalent RC | Generalise to `vendor_rc{vendor}` (§3.4) |
| §6.1 conformance item 6 ("repo-supplied config ignored") | pi has no managed layer, so "ignored" depends on `--no-approve` and file ownership | Add E-PI1 (read-only agent dir) and E-PI2 (`.pi/` in the repo has no effect with `--no-approve`) |
| §16 "API-key auth only" | Unchanged. Codex `chatgptAuthTokens` and RC are the only reasons to revisit, and only for `vendor_rc{codex}` | Keep. Note WIF for the vault |
| T1b as a tier | Codex exec-server, pi-env and Managed Agents are all the same split shape | Fold T1b into `Placement::Split` |

---

## 4. Changes to design.md (section by section)

**§1 "What the research changed"** — add rows:
- "Codex is a T1 agent": app-server with host approvals, steer, `outputSchema`, dynamic tools, replay on
  reconnect; `codex exec` rejects approvals. [11 §2.1–2.2]
- "pi is a sandbox-is-your-job agent with no permission layer and (since 2026-09-29) built-in MCP via
  codemode". [11 §1.7]
- "Codex has its own Remote Control via chatgpt.com". [11 §2.9]

**§2 Principles** — no change. pi is the cleanest confirmation of Principle 1.

**§3 Architecture diagram** — the inner-agent label becomes "Claude Code / Codex app-server / pi / ACP
agent / any process". Add `OPENAI_BASE_URL-equivalent via requirements.toml` beside `ANTHROPIC_BASE_URL`,
or relabel that edge "model base URL (per adapter)".

**§6 Inner agents**
1. Replace the tier table with §3.1's (T1 = native control protocol: Claude, Codex app-server, pi RPC; T2 =
   ACP; T3 = process, optionally with JSONL events). Add **`Placement { Whole | Split }`** as its own axis,
   and fold T1b into `Split`.
2. Extend `AgentCaps` with the fields in §3.2. Replace `structured_output: bool` with `typed_output`, and
   `inject_message_mid_run` with `steer`.
3. Add `AgentState::Settled` to the event model.
4. Add the Codex and pi launches next to the Claude launch (draft text in §5 below).
5. Change "Model agnosticism" to list wire APIs in the order Messages → Responses → Google → Chat. Note that
   Codex needs Responses (SSE; WebSocket off via `supports_websockets = false`) and has a hosted
   `web_search` taint source.
6. Change "wicket's own LLM calls": keep the Rust `Model` trait, implemented over wicket-llm's upstream
   module. Explicitly *not* pi-ai or other Node libraries in the TCB. Borrow pi-ai's context/compat/faux
   design. Optionally authenticate upstream via workload identity federation.

**§6.1 Conformance suite** — add:
- (8) a pending request survives a host-side restart or reconnect (Codex replay; pi re-dialog);
- (9) the model's declared tool list includes the `wicket.*` tools (pi exposure);
- (10) no background model traffic while parked (pi cache warming, Codex refresh);
- (11) no in-box policy persistence after approvals (Codex `rules/default.rules` unchanged);
- per-agent experiments **E-PI1** (read-only agent dir), **E-PI2** (`--no-approve` ignores repo `.pi/`),
  **E-CX1** (requirements.toml pins the provider against `-c`, `thread/start.config` and
  `modelProvider/config/write`), **E-CX2** (`workspace-write` nested per backend), **E-CX3** (approval
  replay across an app-server restart).

**§7 Sandboxes** — under parking, note that Codex replays pending approvals to a reconnecting client.

**§9.2 MCP gateway** — add "Host-tool transports": besides MCP over UDS, the gateway can serve its tools
over the agent's control pipe where supported (Codex `dynamicTools` → `item/tool/call`, ACP MCP-over-ACP,
pi extension tools). The sandbox then needs no network path to the gateway. Add a per-zone exposure hint
(direct vs deferred).

**§9.3 LLM proxy** — add:
- the Responses API as the second wire format;
- recognising cache-warm requests for liveness;
- taint on Codex `web_search_call` items;
- a reference to `codex responses-api-proxy` as differential prior art;
- vault-side WIF.

**§10 Provider adapters** — add **inline examples** (`examples.allow` / `examples.deny`) to rules and
dangerous patterns, validated at load (from execpolicy). Add strictest-wins as an explicit composition
rule.

**§11 Escalation** — add a "fresh per use" grant property (Codex `prompt-user`) that excludes a request
type from ratchet credit and fatigue promotion. Default it for R4 and `money`. Add: the adapter never
forwards policy-amending approval variants.

**§12 Memory** — add the agent-side policy stores as memory: Codex `$CODEX_HOME/rules/*.rules`
(amendments), `config.toml` writes via app-server, pi `trust.json` and `models-store.json`. Add
`(session, entry)` handles and **fork-at-clean-ancestor** as a taint-recovery mechanism.

**§13.1.1 ChannelCaps** — add `answers_are_policy_writes`. `NativeRemoteKind` gains `CodexRemoteControl`.

**§13.1.4** — retitle "Coexisting with vendor remote UIs". Make `vendor_rc{claude|codex}` generic, and add
the Codex facts from §2.9 and the `chatgptAuthTokens` credential option.

**§14 Crates** — `wicket-agent` gains `codex` (T1, app-server; types generated from the pinned JSON schema
with typify, not the stale crates.io crate) and `pi` (T1, RPC). Add a tiny TypeScript asset
`adapters/pi/wicket-ext/` (the in-box extension: advisory, versioned with the adapter, hash-pinned in the
image).

**§15 Milestones** — M3/E1 matrix becomes {Claude Code, Codex app-server, pi × {Claude, GPT, an
open-weights model}, Gemini CLI}. M9 (ACP) stays. Add **M3c**: Codex and pi T1 adapters pass conformance
1–11.

**§16 Decisions** — add:
- "Codex via app-server, not ACP";
- "no third-party LLM library in the TCB; Rust `Model` over wicket-llm";
- "agent config lock-down by managed files where they exist, by ownership plus flags where they don't".

**§17 Open questions** — add:
- Codex approval replay across process restart;
- pi read-only agent dir;
- whether to implement `Placement::Split` for Codex (exec-server is experimental) or pi before v1.

---

## 5. Draft LaunchPlans

The style follows design §6 / [01 §4.4]. Hostnames are illustrative. Everything is a placeholder or a
route, with no secrets.

### 5.1 Codex (T1, app-server, `Placement::Whole`)

**Root-owned `/etc/codex/requirements.toml`** (the agent cannot override it):
```toml
model_provider = "wicket"
[model_providers.wicket]
name = "wicket-llm"
base_url = "http://wicket-llm.zone.internal:8080/v1"
env_key = "WICKET_LLM_TOKEN"          # zone+session-bound placeholder; the proxy swaps it
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
[model_providers.wicket.capabilities]
external_web_access = false           # zone-dependent; otherwise the proxy marks web taint
# remote_compaction = local           # [U] exact spelling; or the proxy supports compaction triggers

model_catalog_json = "/etc/wicket/codex-models.json"   # no catalogue fetch from chatgpt.com
check_for_update_on_startup = false
allow_remote_control = false          # true only in vendor_rc{codex}
allow_managed_hooks_only = true
allow_browser_and_computer_use = false
allowed_web_search_modes = ["disabled"]
allowed_sandbox_modes = ["danger-full-access"]   # "workspace-write" only where E-CX2 passes
allowed_approval_policies = [{ granular = { sandbox_approval = true, rules = true, skill_approval = true, request_permissions = true, mcp_elicitations = true } }]  # [U] boolean semantics
[mcp_servers.wicket]                  # allowlist: only the gateway (McpServerRequirement shape [U])
[rules]                               # overlay mirroring the zone ceiling: cheap early prompts, advisory only
# prefix_rule(pattern=["git","push"], decision="prompt", justification="wicket: pushes are brokered")
# prefix_rule(pattern=["gh","api"], decision="prompt")
# prefix_rule(pattern=["curl", ["-X","--request"]], decision="prompt")
```

**`/etc/codex/managed_config.toml`** (beats user config and `-c`):
```toml
[mcp_servers.wicket]
url = "http://wicket-mcp.zone.internal:8081/mcp"
bearer_token_env_var = "WICKET_MCP_TOKEN"   # scoped capability placeholder, not a secret
required = true
[analytics]
enabled = false
[feedback]
enabled = false
[otel]
exporter = "none"                         # or wicket's OTLP endpoint
[shell_environment_policy]
inherit = "core"
exclude = ["WICKET_*"]                    # tool subprocesses don't see placeholders [M]
```

**Env:**
```
CODEX_HOME=/wicket/state/codex            # labelled, snapshot-able; config.toml written by wicket; rules/ read-only
WICKET_LLM_TOKEN=wkt_cap_<zone,session>   WICKET_MCP_TOKEN=wkt_mcp_<zone,session>
HTTPS_PROXY=http://wicket-egress.zone.internal:3128  HTTP_PROXY=…  NO_PROXY=wicket-llm.zone.internal,wicket-mcp.zone.internal,localhost,127.0.0.1,::1
CODEX_CA_CERTIFICATE=/etc/wicket/ca.pem   SSL_CERT_FILE=/etc/wicket/ca-bundle.pem (system roots + zone CA)
NODE_EXTRA_CA_CERTS=/etc/wicket/ca.pem  REQUESTS_CA_BUNDLE=… CURL_CA_BUNDLE=… GIT_SSL_CAINFO=…
# deliberately absent: OPENAI_API_KEY, CODEX_API_KEY, CODEX_ACCESS_TOKEN, OPENAI_FEDERATION_*, auth.json
```

**argv:** `codex app-server --listen stdio://`

**Session script** (adapter → agent):
```
initialize {clientInfo:{name:"wicket",version}, capabilities:{experimentalApi:true, requiredHumanApproval:true, requestAttestation:false}}
thread/start {cwd:"/workspace", approvalPolicy:<pinned>, sandbox:"danger-full-access",
              developerInstructions:<wicket notice: denials, request ids, await_grant>,
              dynamicTools:[wicket.await_grant, wicket.request_access]   # optional, experimental; else MCP
              ephemeral:false}
turn/start  {threadId, input:[task prompt], outputSchema:<result contract>}
```

**Handling:**
- `item/commandExecution/requestApproval` → map argv to a typed request (plain-words parse, else opaque).
  Answer `accept` / `decline` / `cancel` only, **never** the amendment variants.
- `item/fileChange/requestApproval` → path rules.
- `item/permissions/requestApproval` → `decline` (wicket owns permissions).
- `item/tool/call` → gateway decision, held open while pending.
- `turn/steer` delivers "R-123 granted; retry".
- `turn/completed` + `outputSchema` → typed fields, validated outside.
- The rollout (`$CODEX_HOME/sessions/**`) becomes a handle.

**Credential routes:**
`LlmProxy{base: requirements.model_providers.wicket.base_url, token_var: WICKET_LLM_TOKEN, header: Authorization Bearer, upstream: OpenAIResponses}`;
`GatewayOnly{github…}`; `EgressInject{api.github.com…}` for `gh`/`git` through the egress proxy.

**Egress needs:** none beyond the LLM proxy and the gateway (verify in conformance item 1: no
`chatgpt.com`, `ab.chatgpt.com` or `api.openai.com` connections).

**Preflight taint:** `AGENTS.md`, `AGENTS.override.md`, `.codex/**` (`config.toml`, `rules`, hooks),
`.agents/skills/**`, `.mcp.json` (if present). Do not mark the project trusted
(`projects.<path>.trust_level` unset).

**Pending path:**
- Hold the approval or the dynamic tool call.
- Long waits: snapshot, then on restore `thread/resume`, expecting the approval replay (E-CX3). Otherwise
  `decline` with a request-id reason before parking, and `turn/steer` after the grant.

**Operator mode:** `wicket` (default). `vendor_rc{codex}` flips `allow_remote_control`, supplies ChatGPT
access tokens via `account/login/start {chatgptAuthTokens}` + refresh answers (host-held refresh), and
path-allowlists `chatgpt.com/backend-api/wham/remote/control/*` through the egress proxy.

### 5.2 pi (T1, RPC, `Placement::Whole`)

**Root-owned agent dir `/etc/wicket/pi-agent/`** (`PI_CODING_AGENT_DIR`). It is read-only if E-PI1 passes.
Otherwise copy it to `/wicket/state/pi-agent` at launch and hash-check it at exit.

`settings.json`:
```json
{
  "defaultProjectTrust": "never",
  "httpProxy": "http://wicket-egress.zone.internal:3128",
  "defaultTools": ["read", "bash", "edit", "write"],
  "extensions": ["/etc/wicket/pi-agent/extensions/wicket", "-builtin:llama.cpp"],
  "cacheWarming": "off",
  "transport": "sse",
  "autoEnableCodemode": false
}
```

`models.json` (no `!command` values anywhere; the adapter rejects them):
```json
{ "providers": {
    "anthropic": { "baseUrl": "http://wicket-llm.zone.internal:8080", "apiKey": "$WICKET_LLM_TOKEN" },
    "openai":    { "baseUrl": "http://wicket-llm.zone.internal:8080/v1", "apiKey": "$WICKET_LLM_TOKEN" } } }
```

`mcp.json`:
```json
{ "mcpServers": { "wicket": {
    "url": "http://wicket-mcp.zone.internal:8081/mcp",
    "headers": { "Authorization": "Bearer ${WICKET_MCP_TOKEN}" },
    "exposure": "direct", "description": "wicket gateway: brokered tools, await_grant, request_access" } } }
```

No `auth.json`, `mcp-auth.json`, `skills/`, `prompts/` or `SYSTEM.md`.

**`extensions/wicket/index.ts`** (advisory, in-box, hash-pinned):
- `project_trust` → no.
- `tool_call` → typed request → `ctx.ui.select("wicket:permission:<request-json>", ["allow","deny"])`
  with **no timeout**. On deny → `{block:true, reason:<problem+json summary>}`.
- Registers `wicket_result` (JSON Schema from the result contract, `terminate:true`).
- `before_provider_headers` adds `x-wicket-session`.
- `tool_result` reports MCP and bash results for labelling (telemetry only).

**Env:**
```
PI_CODING_AGENT_DIR=/etc/wicket/pi-agent   PI_CODING_AGENT_SESSION_DIR=/wicket/state/pi/sessions
PI_OFFLINE=1  PI_SKIP_VERSION_CHECK=1  PI_TELEMETRY=0
WICKET_LLM_TOKEN=wkt_cap_<zone,session>   WICKET_MCP_TOKEN=wkt_mcp_<zone,session>
HTTPS_PROXY=…  HTTP_PROXY=…  NO_PROXY=wicket-llm.zone.internal,wicket-mcp.zone.internal,localhost,127.0.0.1,::1
NODE_EXTRA_CA_CERTS=/etc/wicket/ca.pem  SSL_CERT_FILE=/etc/wicket/ca-bundle.pem  (+ REQUESTS_/CURL_/GIT_SSL_ vars)
# deliberately absent: ANTHROPIC_API_KEY/AUTH_TOKEN/OAUTH_TOKEN, OPENAI_API_KEY, *_FEDERATION_*, AWS_*, GOOGLE_*
```

**argv:**
```
pi --mode rpc --no-approve --session-dir /wicket/state/pi/sessions --session-id <uuid>
   --provider anthropic --model <zone-allowed model> --thinking <level>
   --no-skills --no-prompt-templates --no-themes
   --append-system-prompt /etc/wicket/pi-notice.md
   [-nc]          # zone policy: drop AGENTS.md/CLAUDE.md entirely; otherwise load and label as taint
```

**Session script:** `{"id":"1","type":"prompt","message":<task prompt>}`; stream events; then wait for
`agent_settled`. Typed output is the `wicket_result` tool's arguments
(`tool_execution_end` / `message_end`). The session JSONL becomes a handle.

**Handling:**
- `extension_ui_request{method:"select", title:"wicket:permission:…"}` → escalation broker; answer, or hold.
- `steer` / `follow_up` for "R-123 granted; retry".
- `abort` on kill.
- Operator steer uses `steer` with an origin tag in wicket's log.

**Credential routes:**
`LlmProxy{base: models.json providers.<p>.baseUrl, token: WICKET_LLM_TOKEN (x-api-key or Bearer), upstream: per zone}`,
`GatewayOnly`, `EgressInject`.

**Egress needs:** none beyond the LLM proxy and the gateway.

**Preflight taint:** `AGENTS.md`, `AGENTS.override.md`, `CLAUDE.md` (loaded regardless of trust),
`.pi/**` (ignored under `--no-approve`, but `sessionDir` is read pre-trust, so the explicit
`--session-dir` is mandatory), `.agents/skills/**`.

**Pending path:**
- Hold the dialog.
- Long waits: `abort` and snapshot. On restore, `pi --mode rpc --session-id <same>` and `follow_up` with
  the grant notice.
- Fork-at-entry is available for taint recovery.

**Operator mode:** `wicket` only.

---

## 6. Unverified items and experiments

- **E-PI1:** does pi run with a read-only `PI_CODING_AGENT_DIR` (`models-store.json`, `trust.json`,
  `crashes.json`, `mcp.log` writes)?
- **E-PI2:** `--no-approve` with a hostile repo `.pi/` (settings, mcp.json, extensions): only `sessionDir`
  leaks, and an explicit `--session-dir` neutralises it?
- **E-PI3:** does a `tool_call` handler awaiting for hours keep pi healthy (no internal tool timeout,
  memory)? Does pi cache-warm while a tool call is pending if warming is left on?
- **E-CX1:** `requirements.toml` `model_provider(s)` beats `-c`, `thread/start.config`,
  `modelProvider/config/write`, and a model-edited `$CODEX_HOME/config.toml`.
- **E-CX2:** `workspace-write` inside the `process` jail and gVisor (userns, netns, reaching the egress
  proxy with `network_access=true`).
- **E-CX3:** do pending approvals replay after an app-server *process* restart plus `thread/resume`, or only
  on client reconnect to a live server?
- **E-CX4:** with `danger-full-access`, do `granular` approval policies plus `prompt` rules actually yield
  `requestApproval` for matching commands? (The semantics of the granular booleans are [U].)
- **[U]** Exact `McpServerRequirement` and `remote_compaction` spellings. Whether Codex uses
  `store`/`previous_response_id` with custom providers. Whether `attestation/generate` matters for
  API-key auth (probably ChatGPT-auth only).
- **[M]** No per-method gate for Remote Control clients. No `outputSchema` in `codex-acp`.

## 7. Sources

Primary, read at the commits above:
- pi:
  - `README.md`;
  - `packages/coding-agent/docs/{how-pi-works,security,containerization,cli,cli-integration,rpc,rpc-commands,rpc-extension-ui,json,sdk,session-format,configuration,settings,environment-variables,providers,models-configuration,custom-provider,mcp,extensions}.md`;
  - `packages/coding-agent/src/core/{system-prompt,http-dispatcher,cache-warmer,models-store,auth-storage}.ts`;
  - `packages/coding-agent/src/modes/rpc/{rpc-mode,rpc-types}.ts`, `src/cli/args.ts`;
  - `packages/coding-agent/examples/extensions/{structured-output,permission-gate,gondolin/index}.ts`;
  - `packages/coding-agent/CHANGELOG.md` (0.99.0, 1.0.0);
  - `packages/{ai,durable,env,codemode}/README.md` and the `package.json` files.
- Codex (`refs/repos/codex-harness`, `refs/repos/codex`):
  - `codex-rs/app-server/README.md`;
  - `app-server-protocol/src/protocol/v2/{thread,turn}.rs` and `schema/typescript/{ClientRequest,ServerRequest,ServerNotification,InitializeCapabilities}.ts`;
  - `schema/typescript/v2/{ThreadStartParams,AskForApproval,SandboxMode,ApprovalsReviewer,CommandExecutionApprovalDecision,CommandExecutionRequestApprovalParams,DynamicToolCall*}.ts`;
  - `exec/src/{lib,cli,exec_events}.rs`;
  - `model-provider-info/src/{lib,capabilities}.rs`;
  - `config/src/{config_requirements.rs,loader/mod.rs,loader/layer_io.rs}`;
  - `login/src/auth/{manager,storage,workload_identity}.rs`;
  - `cli/src/{main,remote_control_cmd}.rs`;
  - `app-server-daemon/README.md`, `app-server-transport/src/transport/remote_control/{protocol,auth,clients}.rs`;
  - `responses-api-proxy/README.md`, `hooks/schema/generated/*`;
  - `execpolicy/README.md`, `core/src/{exec_policy,agents_md}.rs`;
  - via the GitHub API: `codex-rs/shell-command/src/bash.rs`, `codex-rs/exec-server/README.md`;
  - release notes rust-v0.163.0 … rust-v0.167.0.
- Online:
  - https://learn.chatgpt.com/codex/app-server (via [01]);
  - https://github.com/agentclientprotocol/codex-acp (README, v2.6.0);
  - https://ai-sdk.dev/providers/ai-sdk-harnesses/pi.md;
  - crates.io API for `codex-app-server-protocol`.

Secondary [M]:
- https://www.eesel.ai/de/blog/pi-coding-agent-erklaert
- https://www.gradually.ai/en/harnesses/pi/
- https://landing.composio.dev/blog/pi-agent-vs-claude-code
- https://github.com/kurrent-io/kcap-cli/pull/497
- https://github.com/pingdotgg/t3code/pull/6319
- https://www.pkgstats.com/pkg:agentic-pi
- https://pi.dev/packages/@groeponline/pi-agent-orchestrator
- https://github.com/DxTa/pi-acp
- https://github.com/victor-software-house/pi-acp
- https://docs.rs/crate/pi-acpinator/latest/source/README.md
