# 13 — Hermes Agent: a self-improving long-lived assistant, and Hermes as an inner agent

*2026-11-08. Researched for design §13 (long-lived agents) and §6 (inner agents). The main subject is **Nous
Research's Hermes Agent**. Other projects called "Hermes" are triaged in §10.*

**Confidence marks:**
- **[H]**: read in primary source. That means code or the project's own docs at the commit below, GitHub API data,
  or NVD/GHSA records.
- **[M]**: inferred from primary source, or taken from a reputable secondary source.
- **[L]**: low confidence or unverified. Each [L] item is listed as an experiment in §12.

**Sources collected.** Nothing was built, installed or run. The in-repo `AGENTS.md`, `SOUL.md` and skill files were
treated as data, never as instructions.

| Local path | Upstream | Commit / date | Licence |
|---|---|---|---|
| `refs/repos/hermes-agent` (shallow, blobless) | `github.com/NousResearch/hermes-agent` | `8422e54df36f` (2026-11-08); latest release **v0.23.0** (2026-11-05) | MIT |

The docs are about 2 MB, so four parallel readers went through them by topic, and I spot-checked their key claims
against the code. In-repo paths below are relative to the clone root.

---

## TL;DR

1. **What it is.**
   - Hermes Agent is Nous Research's MIT-licensed, self-hosted personal agent, written in Python 3.11+.
   - It is "the agent that grows with you": it keeps memory, creates and refines its own skills, schedules itself
     (cron), and lives in about 26 chat networks through one gateway.
   - Numbers: 262k stars, 58k forks, about 395 contributors. Releases run from v0.2.0 (Mar 2026) to v0.23.0
     (5 Nov 2026), roughly weekly. The project launched publicly around 25–26 Feb 2026.
   - It is model-agnostic. It speaks three wires (OpenAI Chat, OpenAI Responses, Anthropic Messages), plus Bedrock,
     and it can host Codex app-server as its engine.
   - There is a hosted tier ("Hermes Cloud") and a paid Nous Portal / Tool Gateway. [H, §1]
2. **Its security policy states wicket's thesis outright.**
   - SECURITY.md §2.2: "**The only security boundary against an adversarial LLM is the operating system.** Nothing
     inside the agent process constitutes containment — not the approval gate, not output redaction, not any
     pattern scanner, not any tool allowlist."
   - Its terminal backends (Docker, SSH, Modal, …) sandbox **only shell and file tools**. `execute_code`, MCP
     subprocesses, plugins, hooks, skills, the agent loop and the model keys all stay on the host.
   - The supported posture for untrusted input is **whole-process wrapping**: their Docker image or NVIDIA
     OpenShell. That is what wicket's `Placement::Whole` is. [H, §3]
3. **Architecture changed in v0.23: one gateway owns each `HERMES_HOME`.**
   - A single long-lived "gateway authority" daemon writes `state.db`.
   - The CLI, `-q`, the TUI, Desktop, ACP, the API server, chat adapters and cron are all viewers of it.
   - Under wicket that means one Hermes gateway per box. The adapter attaches to it. [H, §2]
4. **Hermes is a clean T1 agent.**
   - Its `hermes-gateway-v1` JSON-RPC (stdio or WebSocket) sends **server→client `approval` requests** that the
     host answers. It also offers `session.steer` / `redirect` / `interrupt`, `session.resume` / `branch`, and
     typed events.
   - `open_requests` are replayed on reconnect, and answers are fenced by `execution_generation`. That is
     Codex-grade pending-approval durability.
   - ACP (`hermes acp`) is a full T2 fallback, with `session/request_permission`, `fork_session` and
     `resume_session`.
   - `hermes chat -q --format stream-json` is T3+. It is typed, but approvals are decided by a config switch.
     [H, §5]
5. **Its credential story is "keys in the agent process".**
   - Keys live in `.env`, `auth.json` (OAuth refresh tokens) and credential pools. By default Hermes also reads and
     refreshes `~/.claude/.credentials.json` and `~/.codex/auth.json` (`auth.adopt_external_logins: true`).
   - Its own **iron-proxy** egress feature gives Docker sandboxes placeholder keys, `HTTPS_PROXY` and a MITM CA. That
     is wicket's §9.1 model, but it applies only to the terminal sandbox and is cooperative ("raw sockets bypass").
   - Under wicket, the whole process gets wicket's version of that. [H, §4, §6]
6. **Long-lived memory is where Hermes teaches wicket the most.**
   - Hermes writes durable state **with no human in the loop by default**: proactive `memory` writes;
     `skill_manage`; a forked **background-review agent** that replays the whole transcript (tool output included)
     every 10 turns and turns it into memory and skills; a curator; and `cronjob_manage`, with which the agent
     schedules its own future runs.
   - It also ships the staging hook wicket needs: `memory.write_approval` and `skills.write_approval` stage writes
     into `pending/{memory,skills}/` for approval.
   - wicket should map its §13.4 promotion gate onto that staging and keep the skill and memory stores read-only
     in the box. [H, §7]
7. **The agent can rewrite its own advisory policy.**
   - `config.yaml` and `auth.json` are deliberately **writable** by the agent's file tools (#45947).
   - `mcp_servers` edits are hot-reloaded.
   - `manage_connections` installs MCP servers with **no approval in headless runs**.
   - "Always" approvals persist to `command_allowlist`.
   - `~/.hermes/hooks/` is "trusted by placement": Python dropped there is imported at gateway start with no
     consent.
   - Managed scope (`/etc/hermes`) pins only the leaf keys it names.
   - So wicket must **regenerate `HERMES_HOME`'s config surface from the LaunchPlan on every wake** and never let
     it persist (design §13.4 already says this). [H, §6]
8. **Chat approvals are OpenClaw's lesson again.**
   - Any allowlisted user in a chat can approve dangerous commands, by native button, `/approve`, or a plain "yes".
   - In library mode with no callback, dangerous commands are **auto-approved with a log warning**.
   - wicket keeps its rule: chat apps announce and steer, and never decide. [H/M, §8]
9. **Track record.** NVD/GHSA list about 15 CVEs for Mar–Jul 2026:
   - CVE-2026-53869: DNS rebinding into WebSocket `/api/pty`, CVSS 7.5.
   - CVE-2026-53870: world-readable webhook HMAC secrets.
   - CVE-2026-7112 / 7113: API-server and webhook auth.
   - CVE-2026-9352: env leak to tools.
   - CVE-2026-9366, 9353, 10220, 10221: bypasses of the context-file scanner, Skills Guard, `skill_view` and the
     compression path.

   Many were filed by a CNA as "vendor did not respond", because SECURITY.md declares bypasses of in-process
   heuristics out of scope. [H, §9]
10. **Recommendations** (§11):
    - Adopt Hermes as a **T1 adapter** with `Placement::Whole`, `terminal.backend: local`, and approvals routed to
      wicket over `hermes-gateway-v1`.
    - Answer prompts only `once` / `deny`.
    - Map `pending/` onto the promotion gate.
    - Disable `cronjob`, `connections`, `catalog`, `computer_use` and the Tool Gateway.
    - Regenerate config on every wake.
    - Seed the charter into a read-only `SOUL.md`.
    - Borrow: Hermes' trust-boundary statement, its approval-transport contract (request digest, fail-closed,
      first answer wins), staged memory and skill writes with provenance, the relay pattern (platform tokens held
      outside the agent), and per-server MCP `trust: untrusted` plus spend limits.

---

## 1. What Hermes Agent is

- **Identity [H: `gh api`].**
  - Repo `NousResearch/hermes-agent`, created 2025-07-22. Description: "The agent that grows with you".
  - Homepage `hermes-agent.nousresearch.com`. MIT.
  - 261,709 stars and 58,174 forks on 2026-11-08. About 395 contributors (contributors API pagination).
  - The v0.23.0 notes claim ~10,080 commits and 666 contributors since v0.22.0.
- **Release history [H: releases API].**
  - Tags were calendar-style from `v2026.3.12` (named "v0.2.0") to `v2026.9.24` ("v0.21.5"), then switched to semver
    (`v0.21.6` on 2026-10-08, through `v0.23.0` "The Hearth Release" on 2026-11-05).
  - CVE records therefore cite both forms ("2026.4.23", "0.12.0").
- **Launch [M].** Secondary sources put the public launch at 25 or 26 Feb 2026. Hermes Desktop launched on
  Product Hunt on 3 Jun 2026. [heyuan110](https://www.heyuan110.com/posts/ai/2026-04-14-hermes-agent-guide),
  [Product Hunt](https://www.producthunt.com/products/hermes-4/launches/hermes-desktop),
  [DataCamp](https://www.datacamp.com/tutorial/hermes-agent).
- **Positioning.**
  - "The only agent with a built-in learning loop": skills from experience, memory nudges, FTS5 session search,
    Honcho user modelling. agentskills.io-compatible skills.
  - Six built-in terminal backends; "a $5 VPS, a GPU cluster, or serverless". Research mode produces trajectories
    for training tool-calling models. [H: `README.md`]
  - Nous pitches it as a better harness for open-weights models [M].
- **Scale of the code [H].**
  - 23.1k tracked files.
  - More than 60 `hermes_state_*.py` modules for the session database alone.
  - The architecture page cites about 25k tests.
  - The docs site (`website/docs`) runs to about 2 MB of Markdown.
- **Commercial surface [H].**
  - **Nous Portal**: an OAuth login giving 300+ models plus the **Tool Gateway** (web search, image, TTS and cloud
    browser routed through `*.nousresearch.com`, `TOOL_GATEWAY_DOMAIN`).
  - **Hermes Cloud**: hosted instances, managed via a Portal MCP server.
  - **Remote Config**: `HERMES_CONFIG_BACKEND=remote`, default plane `config-config.nousresearch.com`.
  - Sources: `guides/manage-hermes-cloud-with-mcp.md`, `user-guide/features/tool-gateway.md`,
    `reference/environment-variables.md`.
- **Relation to OpenClaw [H].**
  - `hermes import-agent openclaw` (the `agent-importers` plugin) migrates `~/.openclaw` / `~/.clawdbot` setups,
    "including API keys" with `--migrate-secrets`. It also imports Claude Code, Codex and Cursor setups.
  - The two are direct competitors in the personal-assistant niche [12 §1]. Source: `guides/migrate-from-openclaw.md`.

---

## 2. Architecture and the agent loop

### 2.1 Process model: one gateway authority per home [H]

- **Entry points.** CLI (`cli.py`), messaging gateway (`gateway/run.py`), ACP (`acp_adapter/`), API server, batch
  runner, and the Python library, all over one `AIAgent` (`developer-guide/architecture.md`).
- **The v0.23 change** ("every conversation lives in one place: a single gateway owns each session, and the CLI,
  TUI, Desktop, editors, bots and cron all sit down at the same table"; release notes):
  - The gateway daemon is the only writer of `$HERMES_HOME/state.db`. Everything else attaches as a viewer.
  - Code: `acp_adapter/entry.py:206` ("MCP discovery and execution belong to the gateway daemon; this process is a
    viewer").
  - Docs: `developer-guide/gateway-classic-cli.md`.
- **Ownership lock.** The standalone stdio JSON-RPC server (`tui_gateway/entry.py`) reserves the home via
  `gateway.lock`, and refuses to run beside a live gateway. Its own docstring says no product surface launches it
  any more; it is kept for dev and e2e harnesses against a sandbox home.
- **Profiles.** Each profile is a separate `HERMES_HOME` (`~/.hermes/profiles/<name>`). One process can serve several
  (`gateway.multiplex_profiles`). Profiles are **not** a sandbox: OAuth falls back to the root `auth.json`
  (`user-guide/profiles.md`).

**For wicket.** One box holds one Hermes home and one Hermes gateway process. The adapter is a client of that
gateway. That fits the "one zone, one agent process" model, and the gateway is a daemon in the way OpenClaw's
is [12 §6.2].

### 2.2 The loop [H]

- **Code layout.** `AIAgent` (`run_agent.py` facade). The loop is `agent/conversation_loop.py:run_conversation()`, and
  the turn phases are `agent/turn_*.py`.
- **Message format.** Internally OpenAI-style (`role`/`content`/`tool_calls`, `role:"tool"`). Reasoning is kept in
  `assistant_msg["reasoning"]`.
- **API modes** (`hermes_cli/runtime_provider.py:135`):
  - `chat_completions`, `codex_responses` (OpenAI Responses), `anthropic_messages`, `bedrock_converse`, and
    `codex_app_server` (the whole turn handed to a `codex app-server` child).
  - The mode is resolved from an explicit setting, then the provider, then **base-URL heuristics**
    (`api.anthropic.com` or a path ending `/anthropic` → Messages; official OpenAI hosts → Responses; anything
    else → Chat).
- **Turn sequence.** Build the cached system prompt, then preflight compression, convert to wire format, inject
  ephemeral layers (budget, context pressure), set Anthropic cache markers, then make an interruptible API call
  in a background thread. Tool calls loop back.
- **Tools.**
  - A single call runs inline; several run in a `ThreadPoolExecutor`. `clarify` forces sequential execution.
  - Per call: `pre_tool_call` hook, then dangerous-command check, then the approval callback, then the handler,
    then `post_tool_call`.
  - `todo`, `memory`, `session_search` and `delegate_task` are intercepted in `agent/tool_executor.py` and never
    reach the registry.
- **Budget.**
  - `IterationBudget` defaults to 500 (`agent.max_turns`, `HERMES_MAX_ITERATIONS`).
  - Subagents get independent budgets, capped by `delegation.max_iterations`. The docs disagree on the default:
    50 in `agent-loop.md`, 250 in `delegation.md`.
  - Total iterations across parent and children can exceed the parent's cap.
- **Fallback.** `fallback_providers` is tried in order on 429, 5xx or 401/403 (after a credential refresh). Each
  auxiliary task (vision, compression, title, approval, background review, goal judge) has its own provider chain
  under `auxiliary.*`, default `provider: auto` = the main model.
- **Compression.**
  - Triggered at `compression.threshold` 0.50, raised to a 0.75 floor for windows under 512K. The gateway also
    compresses between turns at 85%.
  - Memory is flushed first. The middle turns are summarised and the last 20 messages are kept intact
    (`protect_last_n`).
  - `in_place: true` soft-archives the old rows. A new lineage id is created.
- **Steering** (`agent/interrupt_control.py`):
  - `steer(text)` queues a user row after the current tool batch.
  - `redirect(text)` cancels only the in-flight model request.
  - `interrupt()` discards the in-flight response; no partial reply is injected.
  - The gateway's busy-input mode is `interrupt|steer|queue`.

### 2.3 Prompt assembly [H]

The system prompt is built in three tiers (`developer-guide/prompt-assembly.md`, `agent/system_prompt.py`):
1. **stable**: `SOUL.md` (identity) and tool guidance.
2. **context**: the system message, **one** project context file (§7.4), a git snapshot, platform hints.
3. **volatile**: the skills index, MEMORY and USER snapshots, the external memory-provider block, timestamp, cwd.

Memory is a **frozen snapshot taken at session start**. Writes reach disk mid-session but not the prompt. "Prompt
stability" (no mid-conversation prompt mutation, for cache hits) is a stated design principle.

---

## 3. Security model as stated, and as implemented

### 3.1 Trust model (SECURITY.md) [H]

- **Single-tenant personal agent.** The "trust envelope" is whatever the operator's account can reach.
- **The only load-bearing boundary is the OS.** There are two postures (§2.2):
  - **Terminal-backend isolation.** It confines shell and file tools. It does **not** confine `execute_code`
    (a host subprocess), MCP subprocesses, plugin loading, hook dispatch or skill loading, "all imported into the
    agent interpreter".
  - **Whole-process wrapping.** Hermes' own Docker image and Compose setup, or **NVIDIA OpenShell** ("credentials are
    injected from a Provider store and never touch the sandbox filesystem"). This is "the supported posture when the
    agent ingests content from surfaces the operator does not control … and for production or shared deployments".
- **Credential scoping is "not containment".** Env filtering for subprocesses "reduces casual exfiltration";
  in-process code reads everything.
- **In-process heuristics are not boundaries.** That covers the approval gate ("Shell is Turing-complete; a denylist
  over shell strings is structurally incomplete"), output redaction and Skills Guard.
- **Plugins** run "with full agent privileges"; the only control is review before install.
- **External surfaces** (§2.6): chat adapters, HTTP surfaces, ACP and the TUI gateway. Every network-exposed adapter
  needs an allowlist and must fail closed without one. "Within the authorized set, all callers are equally trusted.
  Hermes Agent does not model per-caller capabilities."
- **Out of scope** (§3.2):
  - heuristic bypasses;
  - "prompt injection per se";
  - consequences of the chosen posture;
  - break-glass flags;
  - community skills and plugins;
  - public exposure without external controls;
  - preconditions that need write access to operator config.

**For wicket.** This is the clearest vendor statement yet of wicket Principle 1, and of why a meta-harness exists.
Hermes says, in effect, "for untrusted input, wrap the whole process". Its own wrappers (Compose with
`network_mode: host`; iron-proxy only for the Docker terminal) do not do that for the network. OpenShell does, and
HermesClaw (§10) packages that. wicket is the general version of the same idea.

### 3.2 Dangerous-command approval [H]

- **Detection is regex, not semantics** (`tools/approval_detection.py`):
  - `HARDLINE_PATTERNS` is an always-on floor (`rm -rf /`, fork bombs, `mkfs`, `dd` to block devices, curl-to-sh).
  - About 290 lines of `DANGEROUS_PATTERNS` are matched against normalised and deobfuscated variants, recursing
    through `bash -c` and `env -S`.
  - Content checks flag secret-bearing `curl`/`wget` bodies and invisible or bidi Unicode.
- **Modes** (`approvals.mode`):
  - `smart` (**default**): after a regex hit, an **auxiliary LLM** sees only the command (in an "untrusted" wrapper,
    `max_tokens=16`) and answers APPROVE (this command only), DENY or ESCALATE (to a human). Code:
    `tools/approval_smart.py`.
  - `manual`.
  - `off`, which equals `--yolo`, `/yolo` or `HERMES_YOLO_MODE=1`.
  - YOLO still keeps the hardline floor, `approvals.deny` globs, MCP spend limits and the protected
    instruction-file gate (§6.3).
- **Choices:** `once | session | always | deny`.
  - `always` **appends to `command_allowlist` in `config.yaml`**, silently approved in all future sessions. Rule
    keys there apply even on unattended surfaces.
  - `session` is in-memory, for that session.
  - Timeout is `approvals.timeout` (300 s), and fails closed.
- **Headless contexts:**
  - `cron_mode`, `single_query_mode` (`-q`) and `unattended_mode` (webhook, API, msgraph) all default to `deny`.
  - **Gap:** when none of the CLI, gateway or ask contexts applies, as in library embedding without a callback,
    flagged commands are **auto-approved** with the log prefix "AUTO-APPROVED dangerous command in non-interactive
    non-gateway context" (`tools/approval.py:1204`).
- **Container skip.** Guards are skipped entirely for Docker without host bind mounts, and for
  Modal/Daytona/Vercel. Only `approvals.deny` still applies there.
- **Approval transports** (`hermes_cli/approval_transport.py`):
  - A plugin can supply the human-approval *presentation* (`ctx.register_approval_transport`). It receives an
    immutable, redacted `ApprovalRequest` with a `request_digest`, and returns an `ApprovalDecision` bound to that
    exact request id and digest.
  - Timeout, error or an invalid response **denies** (`security.approval.transport_fallback: deny`).
  - "Presentation only: plugins cannot detect, suppress, or auto-approve commands outside a correlated human
    response." This is a good contract, and close to wicket's request digest (§14.1.3).

### 3.3 Other in-process guards [H]

- **File writes** (`agent/file_safety.py`, `tools/file_tools_write_guards.py`):
  - Hard-blocked paths: `~/.ssh`, `~/.aws`, `~/.kube`, `.env`, `.anthropic_oauth.json`, `vault/`, `mcp-tokens/`,
    `pairing/`, and others.
  - `HERMES_WRITE_SAFE_ROOT` restricts `write_file`/`patch` to the listed prefixes. The official image sets it to
    `/opt/data`.
  - The code itself says this is "defense-in-depth — not a security boundary; the terminal tool can still bypass".
- **Protected instruction files.** Writes to any `agents.md`, `claude.md`, `soul.md` or `.cursorrules` basename, in
  any directory and case-insensitively, plus the project `.hermes` tree, **always ask a human, even under YOLO**,
  and fail closed headless (`security.protected_instruction_files`). This is a port of Roo-Code's
  `RooProtectedController`.
- **Untrusted-output wrapping.** `web_*`, `browser_*` and `mcp_*` results are wrapped in
  `<untrusted_tool_result source=…>` with delimiters defanged. Terminal and file output is **not** wrapped
  (`agent/tool_dispatch_helpers.py`).
- **SSRF guard** (`tools/url_safety.py`). It blocks private, loopback, link-local, CGNAT and metadata addresses, and
  re-validates every redirect. It fails closed on DNS errors, **unless** a proxy env var is set, in which case an
  unresolvable host is allowed through for the proxy to resolve. The terminal tool has no URL guard.
- **Scanners** (`tools/threat_patterns.py`). One regex scanner serves context files, memory, cron prompts and Skills
  Guard. These are the components the CVEs in §9 bypass.
- **Supply-chain advisory catalogue** (`hermes_cli/security_advisories.py`). It flags known-compromised packages in
  the venv, for example the May 2026 `mistralai 2.4.6` poisoning.

---

## 4. Sandboxing and execution backends

| Backend | What is isolated | Network | Persistence | Notes |
|---|---|---|---|---|
| `local` (**default**) | nothing | host | host | file tools use the host FS directly (`uses_host_filesystem=True`) [H] |
| `docker` | shell + file tools | **default bridge on** (`terminal.docker_network: true`); `false` → `--network=none` | `container_persistent` bind-mounts `/root`, `/workspace` from `~/.hermes/sandboxes/docker/<task>/` | `--cap-drop ALL` + `DAC_OVERRIDE,CHOWN,FOWNER`, `no-new-privileges`, pids 2048, tmpfs `/tmp`; one long-lived `sleep infinity` container per task [H: `tools/environments/docker.py`] |
| `ssh` | shell + file tools on another host | that host's | that host's | ControlMaster; env via `SendEnv` [H] |
| `modal`, `managed_modal` | shell + file tools | provider default | snapshots | `managed_modal` goes through the Nous tool gateway [H] |
| `daytona` | shell + file tools | provider default | stop/resume ("hibernates when idle") | [H] |
| `vercel_sandbox` | shell + file tools (microVM) | provider default | task-scoped snapshots | [H] |
| plugins: `singularity`, `sprites`, **bubblewrap** (v0.23), WSL containers | varies | varies | varies | registered via `ctx.register_terminal_environment_provider`; can't shadow built-ins [H] |

- **What never moves into a backend.** The agent loop, provider keys and auxiliary LLM calls always stay in the host
  process. `execute_code` runs as a **host** Python child on the local backend. It talks AF_UNIX RPC back to the
  agent (`HERMES_RPC_SOCKET` + `HERMES_RPC_TOKEN`), can call a whitelisted set of tools, and is limited to 300 s,
  50 calls and 50 KB of stdout. It can `subprocess` freely. [H: `tools/code_execution_tool.py`]
- **Delegation.**
  - Subagents are `AIAgent` threads **in the same process**, each with its own context and terminal session. They
    inherit the parent's key and provider.
  - Leaf children lose `delegate_task`, `clarify`, `memory`, `send_message` and `cronjob`.
  - `max_spawn_depth: 1`, `max_concurrent_children: 10`, `subagent_auto_approve: false`.
  - Per-task `output_schema` with JSON Schema validation and one retry.
  - So delegation provides no isolation. [H]
- **Hibernate and wake** come from the backend (Daytona stop/resume, Modal and Vercel snapshots). The agent's own
  identity and memory are always in `HERMES_HOME` on the host. [H]
- **Browser and computer use.**
  - `browser_exec` runs Python over CDP. Endpoint order: env `BU_CDP_*`, then `/browser connect`, then a local
    sidecar, then cloud providers (Browser Use, Browserbase, Firecrawl, Nous), then a packaged headless Chromium.
  - `browser.auto_local_for_private_urls: true` opens private URLs in a **host** Chromium.
  - `computer_use` drives the gateway host's screen through cua-driver over MCP.
  - Both are off-limits inside wicket v1. [H/M]

**For wicket.** Run with `terminal.backend: local` inside the wicket box. The box is then the backend for every code
path, as SECURITY.md recommends. Docker-in-gVisor is avoided, and the file tools stay consistent with the shell.

---

## 5. Driving Hermes from a host (tiers)

| Surface | Start | Approvals | Steer | Typed output | Resume / fork | wicket tier |
|---|---|---|---|---|---|---|
| **TUI gateway JSON-RPC** `hermes-gateway-v1` (stdio `tui_gateway/entry.py`, or WS `/api/ws` with a single-use ticket from `hermes gateway attach --json`, minted over a same-uid UDS with `SO_PEERCRED`) | `session.create` → `prompt.submit` | **server→client request** `approval` `{command, description, request_id}` → result `{choice}`; also `clarify`, `sudo`, `secret`, `connection`. The client must send `client.capabilities {server_requests:true}`, or questions are withdrawn. `request.cancel` on withdrawal; `open_requests` replayed on `session.resume`; answers fenced by `execution_generation` | `session.steer`, `session.redirect`, `session.interrupt`, `subagent.steer` | events `message.delta/complete`, `tool.start/complete`; no per-turn output schema | `session.resume`, `session.branch`, `session.compress`, `prompt.submit` with rewind | **T1** [H: `developer-guide/programmatic-integration.md`, `tui_gateway/`] |
| **ACP** `hermes acp` (stdio; `acp` SDK, `use_unstable_protocol=True`) | `new_session` (accepts editor `mcpServers`) → `prompt` | `session/request_permission` with `allow_once`, `allow_session`, `allow_always`, `reject_once`, `deny_always`; timeout → deny; separate `kind="edit"` requests; modes `default`, `accept_edits`, `dont_ask` | `/steer <text>` inside prompt text only | ACP tool-call and diff blocks; `stopReason` | `load_session`, `resume_session`, `fork_session` | **T2** [H: `acp_adapter/{gateway_server,permissions,modes}.py`] |
| **API server** (`API_SERVER_ENABLED`, Bearer `API_SERVER_KEY`, `127.0.0.1:8642`) | `POST /v1/runs` (idempotency key), `/v1/chat/completions`, `/v1/responses` | run parks in `waiting_for_approval`; `POST /v1/runs/{id}/approval` `{request_id, execution_generation, choice}` | `POST /v1/runs/{id}/steer` (409 if not running) | SSE events; no `response_format` | `previous_response_id`, `/api/sessions/*` fork | T1-ish over HTTP [H: `user-guide/features/api-server.md`] |
| **CLI one-shot** `hermes chat -q "…" --format stream-json` (`--query-file -`, `-z` for final text only) | argv | none interactive; `approvals.single_query_mode: deny\|approve` | no | JSONL: `system{init,session_id}`, `text`, `tool_use`, `tool_result`, `result{exit_code,…}` | `--resume <id>`, `-c` | **T3+** [H: `reference/cli-commands.md`] |
| **Python library** `from run_agent import AIAgent` | `run_conversation()` | `set_approval_callback`; **auto-approve if no callback and no interactive or gateway env** | `steer()`, `redirect()`, `interrupt()` | dict result | via the session DB | not for wicket (in-process, TCB-adjacent) |

There is no `--mode rpc`. The docs map every pi RPC command to a TUI-gateway method, for example `steer` →
`session.steer`, `fork` → `session.branch`, `ui_request` → server→client requests. [H]

**Recommendation.**
- **T1 via `hermes-gateway-v1`.** Use stdio if the home-owning `tui_gateway.entry` process is acceptable; its own
  code calls it a dev and e2e harness, hence [M] stability. Otherwise use a WS to the in-box gateway, bridged to a
  UDS.
- **ACP as the T2 fallback.**
- The approval request carries the command and a description written by the model, so it is **advisory**, the same
  as Codex `requestApproval` (§14.1.2).

**Hermes as a harness host [H].**
- `model.openai_runtime: codex_app_server` makes Hermes spawn `codex app-server`. It writes a
  `hermes_tools_mcp_server` entry into `~/.codex/config.toml`, and translates Codex approvals into Hermes prompts.
- Bundled skills drive `claude -p …` and other coding CLIs through the terminal tool.

Under wicket these nested agents share the box's boundary, but each needs its own model route (§11.3). They are off
by default in the LaunchPlan.

---

## 6. Credentials, config and MCP

### 6.1 Providers and base-URL override [H]

- **Custom endpoint** (`integrations/providers.md`):
  - Either `model.provider: custom` with `model.base_url`, or a named entry under `providers.<name>` with
    `api` (aliases `base_url`, `url`), `transport` / `api_mode` (`chat_completions | anthropic_messages |
    codex_responses`), `key_env` / `api_key` / **`key_cmd`**, `discover_models`, `ssl_ca_cert`, `ssl_verify`,
    `extra_headers` and `extra_body`.
  - Select it with `model.provider: custom:<name>`.
  - Set `transport` explicitly, because URL heuristics would choose Chat for a proxy hostname.
- **Env vars:**
  - `ANTHROPIC_BASE_URL`.
  - `OPENAI_BASE_URL`, **only** for the `openai-api` provider.
  - `CUSTOM_BASE_URL` for bare `custom`.
  - `HERMES_CODEX_BASE_URL`, `OPENROUTER_BASE_URL`, per-vendor `*_BASE_URL`.
  - `HERMES_INFERENCE_MODEL`, `HERMES_MODEL`.
- **Anthropic credential order** (`agent/anthropic_credentials.py`): `ANTHROPIC_TOKEN` / `CLAUDE_CODE_OAUTH_TOKEN`,
  then `ANTHROPIC_API_KEY`, then `auth.json` OAuth, then `~/.claude/.credentials.json` / Keychain.
- **Separate model routes.** Auxiliary tasks, `delegation.*`, `fallback_providers` and cron jobs can each carry their
  own `provider`, `base_url` and `api_key`. Each one is a separate model route the LaunchPlan must pin.

### 6.2 Where credentials live [H]

| Store | Contents | Notes |
|---|---|---|
| `$HERMES_HOME/.env` | API keys, platform tokens | loaded **with override** (beats shell env); also `.op.env` and a project/install-root `.env` |
| `$HERMES_HOME/auth.json` (0600, locked) | OAuth refresh tokens: Nous Portal, ChatGPT/Codex (own copy), xAI, Qwen, MiniMax, Anthropic PKCE; credential pools | named profiles fall back to the root file; also `.anthropic_oauth.json`, `shared/` Nous store |
| Borrowed logins | `~/.claude/.credentials.json`, `~/.codex/auth.json` | **read and refreshed by default** (`auth.adopt_external_logins: true`) |
| `mcp-tokens/<server>.json` | MCP OAuth | |
| `vault/` | website logins and cards for `browser_vault` | auto-detects and runs `op` / `bw` |
| Secret sources | `secrets.bitwarden` (`bws`, `auto_install: true` downloads), `secrets.onepassword` (`op`, `binary_path`), **`secrets.command.command` run via `/bin/sh -c`** at startup | plugin `ctx.register_secret_source` |
| `providers.*.key_cmd` | **command run repeatedly** to mint a bearer | |
| `hermes proxy start` ("subscription proxy") | serves the user's Nous/xAI OAuth on `127.0.0.1:8645/v1` to other apps, unauthenticated | not relevant in a box |

**Env passed to children** [H: `user-guide/security.md`, `tools/mcp_tool_config.py:147`,
`tools/environments/local_env_policy.py`]:
- The local terminal uses a **blocklist** of provider and messaging secrets. The AWS chain is deliberately inherited,
  and `CLAUDE_CODE_OAUTH_TOKEN` is not on the list.
- `execute_code` drops any variable whose name contains KEY, TOKEN, SECRET, AUTH, … and then passes only safe
  prefixes.
- MCP stdio children get only `PATH HOME USER LANG LC_ALL TERM SHELL TMPDIR XDG_*` plus their own `env:` block.
- So **`HTTPS_PROXY` does not reach MCP stdio children or `execute_code` children** unless it is added to `env:` or
  `terminal.env_passthrough`. Under wicket that fails narrow (no route, so the call fails) rather than leaking.

### 6.3 Config layering and what the agent can write [H]

- **Layers.** CLI flags, then `config.yaml` (with `${VAR}` substitution), then env, then defaults.
- **Managed scope** (`/etc/hermes/{config.yaml,.env}`, relocatable by `HERMES_MANAGED_DIR`):
  - The merge is **leaf-level**. It pins only the keys it names; everything else stays editable.
  - `hermes config set` refuses pinned keys. The docs say the agent's subprocesses are not hard-blocked; filesystem
    permissions are the enforcement.
  - Source: `user-guide/managed-scope.md`, `hermes_cli/managed_scope.py`.
- **Agent-writable on purpose.** `agent/file_safety.py:193`: "auth.json, auth.lock, config.yaml and
  webhook_subscriptions.json are deliberately NOT here: #45947 freed those control files on purpose ('true containment
  belongs in Docker/remote backends and OS permissions')". They are read-denied, not write-denied.
- **Live reload.** `mcp_servers` changes are hot-reloaded (`mcp.auto_reload_on_config_change: true`; the gateway
  picks them up within about a minute).
- **Other persistent-policy writes:**
  - `manage_connections` (`install` / `enable` / `authorize` MCP servers): "Where no card exists an MCP target runs at
    once" (`tools/connectors/tool.py:85`). Headless, cron and messaging runs have no approval step.
  - "Always" approvals go to `command_allowlist`.
  - `/model --global`, `/codex-runtime`, `/approvals` and others write `config.yaml`.
  - Consent answers (telemetry, hooks) are written back to config.
- **Remote config** (`HERMES_CONFIG_BACKEND=remote`). It fails closed and polls every 5 minutes. Secret-shaped keys
  take only `${VAR}`. It is not usable in a no-egress box unless wicket served it [L].

**Keys and paths that execute commands or load code** (all must be rejected by the LaunchPlan validator
(`config_exec_vectors`), or left absent):

| Vector | Kind |
|---|---|
| `mcp_servers.*.command` / `args` / `cwd` | stdio subprocess |
| `hooks:` (shell hooks; `hooks_auto_accept`, `HERMES_ACCEPT_HOOKS`, `--accept-hooks`, `shell-hooks-allowlist.json`) | subprocess per event; `pre_tool_call` can block or modify |
| **`$HERMES_HOME/hooks/<name>/{HOOK.yaml,handler.py}`** | **in-process import at gateway start, no consent, not skipped by `HERMES_SAFE_MODE`** ("trusted-by-placement") |
| `plugins.enabled`, `$HERMES_HOME/plugins/**`, `plugins/model-providers/<name>` (overrides bundled providers), pip entry points, `plugins.host.launcher` | in-process code |
| `quick_commands.*` (`type: exec`) | shell |
| `secrets.command.command`, `secrets.onepassword.binary_path`, `secrets.bitwarden.auto_install` | shell / download |
| `providers.*.key_cmd` (and legacy `custom_providers`) | shell, repeatedly |
| `model.openai_runtime: codex_app_server` | spawns Codex, writes `~/.codex/config.toml` |
| goal quality gates (`/goal gate add <cmd>`) | shell at turn boundaries |
| cron `no_agent` scripts in `$HERMES_HOME/scripts/`, cron pre-run scripts | shell on schedule |
| `HERMES_LOCAL_STT_COMMAND`, `browser.executable_path` / `chromium_args` | shell / binary |
| skill `scripts/` + `required_environment_variables` (auto env passthrough) | shell with declared env |

**Policy-weakening keys** (pin or reject): `approvals.mode: off`, `command_allowlist`, `terminal.backend`,
`terminal.env_passthrough`, `docker_forward_env`, `credential_files`, `mcp_servers.*.sampling` (sampling is **on by
default**), `auth.adopt_external_logins`, `security.allow_private_urls`, `HERMES_YOLO_MODE`.

### 6.4 Proxy, CA and background traffic [H]

- **Proxy.**
  - LLM httpx clients read `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` (either case) from the environment
    (`agent/process_bootstrap.py`). `NO_PROXY` supports CIDR, `*.domain` and `host:port`, and loopback always
    bypasses (`agent/proxy_bypass.py`).
  - MCP HTTP honours the same.
  - Some internal clients use `trust_env=False`: the gateway's OAuth, SSH and reach helpers.
  - There is **no unix-socket transport** for providers or MCP: no `http+unix` or `unix://` handling was found [M].
    wicket needs loopback TCP endpoints in the box that bridge to its UDS proxies.
- **TLS.**
  - Hermes uses **`truststore`, so the OS trust store**. `HERMES_CA_BUNDLE` affects only the Nous login. Per-provider
    `ssl_ca_cert` *replaces* trust for that endpoint.
  - `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` are still read by plain `requests`/`urllib` tool calls
    and by child tools.
  - **So wicket must install its CA into the box's system store** (`update-ca-certificates`), not only through env
    vars (`user-guide/security.md` "TLS certificate trust").

**Background calls and their switches:**

| Call | Default | Off |
|---|---|---|
| Update check (GitHub API, once per 24 h) | on | `updates.check: false` |
| Plugin update check | 24 h | `plugins.auto_update_check_hours: 0` |
| Model catalog (`hermes-agent.nousresearch.com`, raw GitHub) | on | `model_catalog.enabled: false` |
| models.dev registry (`agent/models_dev.py`: 4 h refresh, cache `models_dev_cache.json`) | on | **no off switch found** [M]: pre-seed the cache in the image, or set `models_dev.url` to a wicket mirror; otherwise it fails at egress |
| `/v1/models` discovery on custom endpoints | on | `providers.*.discover_models: false` |
| Shared metrics (`telemetry.nousresearch.com`) | off, but asks once interactively | pin `telemetry.shared_metrics.{enabled,send}: false` |
| Lazy installs of optional deps (PM) | on | `security.allow_lazy_installs: false` / `HERMES_DISABLE_LAZY_INSTALLS` |
| Nous Tool Gateway (web, image, TTS, browser) | on with a Portal login | no Portal login; `TOOL_GATEWAY_*` unset |
| Smart approvals, background review, curator, title generation | auxiliary model calls | `approvals.mode: manual`, `auxiliary.background_review.enabled: false`, curator off (see §7) |

### 6.5 MCP [H]

- **Transports:** stdio (`command`), Streamable HTTP (`url`), SSE (`transport: sse`). The 2026-07-28 stateless
  `server/discover` probe is supported (`protocol: auto|stateless|…`).
- **Per-server keys:**
  - `headers` (with `${VAR}`), `env`, mTLS `client_cert`;
  - `tools.include` / `exclude` globs, where include wins; `resources`, `prompts`;
  - `auth: oauth` (PKCE, device flow);
  - `sampling` (server-initiated LLM calls, **default on**), `elicitation` (default on), experimental `events`;
  - **`trust: untrusted`**: every tool without `readOnlyHint: true` needs approval;
  - **`tool_costs` + `spend_limit`**: a costed call that would exceed the per-chat limit asks even under YOLO, and is
    refused headless;
  - `lazy`, `idle_timeout_seconds`.
- **Naming.** Tools are named `mcp_<server>_<tool>`.
- **Hermes as an MCP server.** This is now the separate `mcp-serve` plugin.
- Source: `reference/mcp-config-reference.md`, `user-guide/features/mcp.md`.

**For wicket.** The gateway entry should set `sampling.enabled: false` (or route sampling to wicket-llm with a
budget). `elicitation` should be left on, because it maps to clarify questions. Do not set `trust: untrusted` on the
wicket gateway: its denials are the real ones, and an in-box prompt only adds noise.

---

## 7. Memory and persistence (the long-lived part)

### 7.1 On-disk layout under `HERMES_HOME` [H]

| Path | What | In prompt? |
|---|---|---|
| `SOUL.md` | identity / persona (seeded if missing; only ever from `HERMES_HOME`) | every session, stable tier |
| `memories/MEMORY.md`, `memories/USER.md` (+ `.lock`) | agent notes and user profile; `§`-separated plain text, **no per-entry provenance**; caps 2,200 / 1,375 chars | frozen snapshot at session start |
| `skills/<cat>/<name>/SKILL.md` + `references/ templates/ scripts/ assets/` | procedural memory | index every session (~3k tokens); bodies on demand |
| `skills/.hub/{lock.json,quarantine/,audit.log}`, `.usage.json` (`created_by`), `.archive/`, `.curator_ledger.jsonl`, `.curator_backups/` | hub provenance, curator state | — |
| `pending/{memory,skills}/<id>.json` | **staged writes awaiting approval** | — |
| `state.db` (SQLite WAL) | sessions, messages, FTS5 (`messages_fts`, trigram), lineage, gateway routing, delegation and delivery obligations, worker ledger | via `session_search` |
| `cron/jobs.json`, `cron/executions.db`, `cron/notepad.db`, `cron/output/` | scheduled jobs; per-job notepad **injected into every run's prompt** | per job |
| `scripts/` | no-agent cron scripts | — |
| `checkpoints/store/` | shadow git for rollback (**off by default**) | — |
| `config.yaml`, `.env`, `auth.json`, `mcp-tokens/`, `vault/`, `pairing/`, `hooks/`, `plugins/` | config and credentials (§6) | — |
| `home/` | HOME for container backends / `terminal.home_mode: profile` | — |
| `logs/`, `backups/`, `state-snapshots/`, caches | | — |

Sources: `user-guide/{configuration,which-file-does-what,profiles}.md`, `developer-guide/session-storage.md`,
`tools/memory_tool_store.py`, `tools/write_approval.py`.

### 7.2 How it writes memory and skills [H]

- **Tools.**
  - `memory` (`add` / `patch` / `remove`; target `memory` | `user`).
  - `skill_manage` (`create`, `patch`, `delete`, `write_file`, `remove_file`).
  - Read side: `skills_list`, `skill_view`, `session_search` (FTS5/BM25, raw messages, no LLM).
- **Nudged by design.** The system prompt tells the agent to save memory proactively and to turn non-trivial
  workflows into skills.
- **Background review** (`agent/background_review.py`):
  - Every `memory.nudge_interval` (10 user turns) and `skills.creation_nudge_interval` (10 tool iterations), a
    **forked `AIAgent` on a daemon thread replays the whole conversation, tool output included**, and writes to the
    stores.
  - It may dispatch only memory/skills tools plus `read_file` and `search_files`. A skill-nudge review gets no
    memory tool. Unattended reviews always stage `patch`/`remove` memory ops.
  - Config: `auxiliary.background_review.{enabled,provider,model,…}`.
  - **This is a taint-laundering pump.** A web page read at turn 3 can become an unreviewed skill by turn 10.
- **Curator** (`agent/curator.py`):
  - Weekly idle pass (`curator.interval_hours: 168`, `min_idle_hours: 2`) with deterministic stale/archive at 14 and
    30 days. LLM consolidation is off by default.
  - It manages only `created_by: agent` skills, and has pin, lock, rollback and ledger.
  - The ledger holds per-file sha256 before/after, with actor `curator|agent|user`. It is telemetry, not a gate.
- **Gates exist but are all off by default:**
  - `memory.write_approval` (interactive CLI prompts inline; elsewhere writes are staged and resolved with
    `/memory pending|approve|reject`);
  - `skills.write_approval` (all skill writes staged; `/skills pending|diff|approve`);
  - `skills.guard_agent_created` (scan, then ask). Its own code comment admits "terminal() runs the same code
    ungated".
- **Scanning.** Memory content is regex-scanned on write and again on load; a hit becomes `[BLOCKED: …]`.
  `MEMORY.md` and `skills/` are not on the file-tool denylists, so the terminal tool can edit them directly [M].

### 7.3 Skills supply chain [H]

- **Format.** `SKILL.md` frontmatter (`name`, `description`, `version`, `platforms`, `metadata.hermes.*`,
  `required_environment_variables`). agentskills.io-compatible. Progressive disclosure.
- **Hub sources:** `official` (`optional-skills/`), `skills-sh`, `well-known` (`/.well-known/skills/index.json`),
  GitHub taps, **`clawhub`** (the registry of ClawHavoc fame [12 §4.4]), `lobehub`, `browse-sh`, `url`.
- **Skills Guard** (`tools/skills_guard.py`, `skills-guard-v10`):
  - trust levels `builtin`, `trusted` (a fixed list of org repos), `community`, `agent-created`;
  - `community` blocks `caution` and `dangerous` verdicts;
  - installs go through `quarantine/`; `lock.json` records URL, content hash and findings.
  - **No signature verification.** NVIDIA's `skill.oms.sig` appears only in comments. Pinning is by hash.
- **Project skills** (`.hermes/skills/`, `.agents/skills/`) load only after `hermes skills trust`. They then
  **override same-named global skills**.

### 7.4 Context files auto-loaded from the workdir (preflight taint list) [H]

From `agent/prompt_builder.py` and `user-guide/features/context-files.md`. **One** project type is loaded, first
match wins:
1. `.hermes.md` / `HERMES.md`: the nearest one, walking up to the git root.
2. The AGENTS chain from git root down to cwd. In each directory, the first non-empty of `AGENTS.override.md`,
   `AGENTS.md`, `agents.md`.
3. `CLAUDE.md` / `claude.md` (cwd).
4. `.cursorrules` + `.cursor/rules/*.mdc` (cwd).

There are two more ways project content gets in:
- **Progressive subdirectory hints** (`agent/subdirectory_hints.py`). When a tool argument touches a path, Hermes
  walks up to 5 parents and **appends** `AGENTS.md`, `CLAUDE.md` or `.cursorrules` content to the **tool result**
  mid-session (capped at 32k). So removing files from the cwd at launch is not enough. They must be absent from the
  agent's whole view of the tree, per design §12.
- **Project skills and plans.** Trusted project skills load from `.hermes/skills/` and `.agents/skills/`. `/plan`
  writes to `<project>/.hermes/plans/`.

Two switches exist, and neither fits wicket:
- `--ignore-rules` / `HERMES_IGNORE_RULES` skips AGENTS.md, SOUL.md, .cursorrules, **memory** and preloaded skills.
  That is too blunt for a long-lived agent, because it also drops memory.
- `skip_context_files` applies only to subagents and workdir-less cron.

Scanner hits block project files, but the scanner is a heuristic (CVE-2026-9366).

### 7.5 Sessions, branching, wake sources [H]

- **Session operations.**
  - Resume: `--resume <id|title|latest>`, `-c`.
  - Branch: `/branch` (`session.branch`).
  - Rewind: `/rewind [N | fork N]`; also `/undo`.
  - Lineage via `parent_session_id`, so a wicket "fork at the last clean entry" (§12) maps onto `session.branch` or
    `rewind fork`.
  - Read-only import of Claude Code and Codex transcripts.
- **Self-scheduling.**
  - `cronjob_manage` lets the agent create jobs, including `no_agent` script jobs that it writes into `scripts/`.
  - The gateway ticks every 60 s and runs each due job in a fresh `AIAgent` with memory.
  - Cron-started agents cannot schedule more jobs (`cron.allow_agent_scheduling: false`).
  - Delivery goes to any chat platform.
- **Self-waking in a session.** `/heartbeat every <interval> <prompt>`, `/loop` and `/goal` (judged by an auxiliary
  model, with shell "quality gates") inject user turns while idle and survive restart. These are slash commands, so
  they are operator-initiated [M].
- **External memory providers** (Honcho, RetainDB, Mem0, Supermemory, Hindsight, …). They receive **every turn's
  transcript including tool output**, plus session-end and pre-compress dumps, after a regex secret scrub. Recalled
  context is injected every turn.

### 7.6 Mapping onto wicket §13

| Hermes | wicket |
|---|---|
| `SOUL.md` | render the **charter** into a read-only `SOUL.md` (operator-signed TrustedText) |
| `memories/*.md`, `skills/**` | **memory stores**, versioned, mounted read-only in the box; the version is the label carrier |
| `pending/{memory,skills}/` with `write_approval: true` | **staging layer**: wicketd reads the staged records at sleep or on demand and runs the promotion gate (typed facts auto, skills or instruction-like text to quarantined reader or human); approved items become the next store version |
| background review / curator | disable in v1 (the review replays tainted transcripts); later allow as a *proposer* whose output only lands in `pending/` |
| `state.db` | session store: writable, labelled, checkpointed with the workdir; `session.branch` for taint recovery |
| `cronjob_manage`, `scripts/` | disabled; a schedule becomes a wicket `Subscription` the operator grants (§13.2: agents can't subscribe themselves) |
| `/heartbeat`, `/loop`, `/goal` | wicket `Wake::Schedule`, owned by wicketd; goal gates are rejected (`config_exec_vectors`) |
| Daytona or Modal hibernate | wicket's own Sleeping/Hibernated tiers; Hermes needs only `state.db` + `HERMES_HOME` to rebuild |
| external memory providers | off; if wanted, a declared destination at egress with the zone's labels cleared for it |

---

## 8. Messaging gateway and remote control

- **One `GatewayRunner`** holds about 26 adapter plugins: telegram, discord, slack, whatsapp, whatsapp_cloud, signal,
  matrix, mattermost, email, sms, teams, google_chat, feishu, wecom, dingtalk, qqbot, weixin, line, irc, simplex,
  bluebubbles, ntfy, photon, raft, buzz, a2a. Core ingress adds `api_server`, `webhook` and `msgraph_webhook`.
  Session key: `agent:{ns}:{platform}:{chat_type}:{chat_id}`. [H]
- **Authorization**, checked in order: per-platform `*_ALLOW_ALL_USERS`, `*_ALLOWED_USERS`, DM pairing
  (`hermes pairing approve <platform> <code>`), then global `GATEWAY_ALLOWED_USERS` / `GATEWAY_ALLOW_ALL_USERS`,
  otherwise deny. An optional admin tier gates only slash commands. [H]
- **Approvals from chat:**
  - native buttons on Telegram, Discord, Slack, Teams, Matrix, Feishu, QQ and WhatsApp Cloud;
  - otherwise `/approve [session|always|all]` / `/deny`, **or a plain "yes", "ok" or "go"**;
  - **any authorized user in that chat's session** can answer. The Telegram callback checks only the allowlist; no
    requester-only check was found [M].
  - This is the same weakness as OpenClaw [12 §5.3]: the approver's identity is whatever the platform claims, and
    the prompt sits in a transcript the agent controls.
- **Webhooks.** Port 8644, `/webhooks/<route>`. GitHub `X-Hub-Signature-256`, GitLab token, or generic
  `X-Webhook-Signature-V2` + timestamp (±300 s). `INSECURE_NO_AUTH` was CVE-2026-7113. Approvals follow
  `unattended_mode`. [H]
- **Relay** (experimental):
  - A connector service **holds the platform tokens**. The gateway dials out over a WebSocket and receives `inbound`
    frames. Button clicks return as authenticated responses.
  - Enrolment uses a Nous Portal token or your own IdP. [H: `user-guide/messaging/relay.md`]
  - This is the pattern wicket wants for chat Ingress: channel credentials outside the agent's box [12 §8, item 4].
- **A2A.** Port 9900, Agent Card, `A2A_PEER_TOKENS`; localhost-only without a token; remote peers can't run slash
  commands. [H]
- **Desktop and Webapp.** v0.23 serves the Desktop workspace in a browser tab from the gateway (loopback, CSP,
  sign-in providers). CVE-2026-53869 (DNS rebinding on `/api/pty`, `/api/ws`) shows how dangerous this surface is.
  [H]

**For wicket.**
- v1 runs Hermes **with no chat adapters in the box**, the same as the OpenClaw "front desk" decision [12 §6.2].
- If chat is wanted later, use a relay-style connector outside the box, terminated by wicket's Ingress surface,
  with approvals disabled on the chat path.
- Whether Hermes can keep chat adapters while routing *all* approvals to a non-chat client is unverified: E-HM5.

---

## 9. Security track record (2026)

The NVD/GHSA entries for `hermes-agent` [H: NVD API, GitHub advisory DB]:

| CVE | Published | CVSS | Component | Issue |
|---|---|---|---|---|
| CVE-2026-7112 | 2026-04-27 | 5.6 | `gateway/platforms/api_server.py` `_check_auth` | improper API-key auth (v0.8.0) |
| CVE-2026-7113 | 2026-04-27 | 5.6 | `gateway/platforms/webhook.py` | `_INSECURE_NO_AUTH` missing auth |
| CVE-2026-9352 | 2026-05-24 | 5.3 | `tools/environments/local.py` `_make_run_env` | env/secret disclosure to tools via the messaging gateway |
| CVE-2026-9353 | 2026-05-24 | 7.3 | `agent/skills_guard.py` | Skills Guard pattern bypass ("injection") |
| CVE-2026-9366 | 2026-05-24 | 7.3 (later 5.5) | `agent/prompt_builder.py` `_scan_context_content` | context-file scanner bypass |
| CVE-2026-9368 / 9369 | 2026-05-26 | med / low | — | "sandbox issue" / incorrect comparison (GHSA summaries only) [M] |
| CVE-2026-10220 | 2026-06-01 | 7.3 | `tools/skills_tool.py` `_serve_plugin_skill`/`skill_view` | injection |
| CVE-2026-10221 | 2026-06-01 | 7.3 | `run_agent.py` `_compress_context` | injection via compression |
| CVE-2026-10222–10224 | 2026-06-01 | low–med | — | injection; resource consumption (GHSA summaries only) [M] |
| CVE-2026-53869 | 2026-06-17 | **7.5** | FastAPI WS endpoints `/api/pty`, `/api/ws`, `/api/pub`, `/api/events` | **DNS rebinding**: HTTP middleware doesn't run on WS upgrades, so Host/Origin checks were skipped (fixed in 0.16.0) |
| CVE-2026-53870 | 2026-06-17 | 5.5 | `response_store.db`, `webhook_subscriptions.json` | world-readable (0644) transcripts and HMAC secrets (fixed in 0.16.0) |
| CVE-2026-14625 | 2026-07-04 | 6.3 | `tui_gateway/server.py` `shell.exec` | protection-mechanism failure (≤ 0.15.2) |

**Reading.**
- Most of the 7.3s are CNA-filed (VulDB-style) bypasses of regex heuristics, with "the vendor was contacted early …
  did not respond". That is consistent with SECURITY.md §3.2 putting heuristic bypasses out of scope.
- The real boundary bugs are the **local web surfaces**: WS auth and DNS rebinding, file modes, webhook and API auth.
- v0.23 itself still shows the stream of heuristic fixes: "a stale approval card can no longer approve the next
  request", "MCP consent shows what will run", "approval prompts … reveal hidden Unicode".

**Lessons for wicket's console and red-team suite:**
1. Validate Host and Origin on **WebSocket upgrades** separately from HTTP middleware (CVE-2026-53869).
2. Create every state file 0600, and test it (CVE-2026-53870).
3. Never ship a no-auth flag on an ingress.
4. Bind each approval card to one request digest and one generation, so a stale card cannot approve the next
   request.
5. Publish a trust-boundary and out-of-scope statement like SECURITY.md, so reports can be triaged.

---

## 10. Other projects called "Hermes" (triage)

| Project | What | Relevance |
|---|---|---|
| **Nous Hermes models** (Hermes 2 Pro / 3 / 4) | open-weights LLMs whose tool calls are JSON inside `<tool_call>…</tool_call>` in ChatML text; tools offered in `<tools>`; vLLM `--tool-call-parser hermes` | **Relevant to wicket-llm's Chat wire for open-weights upstreams**: the server parses the tags into `tool_calls`, so wicket-llm sees ordinary Chat. If wicket ever talks raw completions, it must parse these tags and apply its chat-template token stripping ([12 §6.4, item 10]) [M: [HF model card](https://huggingface.co/NousResearch/Hermes-4-14B), [fast.io guide](https://fast.io/resources/hermes-3-function-calling-guide/)] |
| **HermesClaw** (TheAiSingularity, 75★, Mar–Apr 2026) | community packaging of Hermes inside **NVIDIA OpenShell**: OPA + CONNECT proxy egress allowlist, Landlock (`~/.hermes`, `/sandbox`, `/tmp`), seccomp, an `inference.local` privacy router that strips credentials; preset policies strict/gateway/permissive | closest prior art to "wicket + Hermes"; confirms the whole-process shape. Inactive since April [H: `gh api`, README] |
| **E2B `hermes` template** | `hermes chat -Q --yolo --provider … -q "<prompt>"`, **real provider key passed in `envs`**, open internet by default | the anti-pattern wicket avoids [H: [E2B docs](https://docs.e2b.dev/agents/hermes)] |
| **agentkernel `hermes-sandbox`** | Dockerfile template; keys exported into the sandbox; `network = true` | same [H: [agentkernel docs](https://thrashr888.github.io/agentkernel/agents/hermes)] |
| **NVIDIA NemoClaw** | reference stack putting OpenClaw/Hermes/Deep Agents in OpenShell | covered in [12 §7] |
| **hermes_mcp** (CloudWalk, Elixir) | MCP client/server SDK, forked and renamed **anubis-mcp** from v0.13 | an SDK, not a harness; not relevant [M: [Elixir Forum](https://elixirforum.com/t/anubis-formerly-hermes-mcp-model-context-protocol-implementation-for-elixir/71410), [hexdocs](https://hexdocs.pm/hermes_mcp/0.2.2/home.html)] |
| Meta's Hermes JS engine; Hermes IBC relayer (Cosmos) | unrelated | not covered |

This document covers **Nous Research's Hermes Agent**. The others are listed only so the name collision is settled.

---

## 11. Hermes as an inner agent under wicket, and what to borrow

### 11.1 Fit

**Good:**
- Its own policy asks for exactly wicket's posture.
- It has a native T1 protocol with host-answered approvals, steer and interrupt, resume and branch, and replay of
  pending requests.
- Every provider can be pointed at a custom base URL with an explicit wire.
- It honours `HTTPS_PROXY`.
- All state lives under one `HERMES_HOME`, which makes rebuild-on-wake simple.
- It has built-in staging for memory and skill writes.

**Misfit:**
- **It is a daemon.** The gateway authority model means one long-lived process per home, so wicket's "settled" signal
  must come from the protocol (turn end, no open requests), not from process exit.
- **It is very large and very fast-moving.** About 10k commits a release, weekly releases and Python, so the adapter
  pin and the conformance suite carry a lot of weight.
- **It writes its own config by design** (§6.3).
- **Its value is self-modification:** skills, memory, cron. wicket must gate exactly what makes Hermes attractive.

### 11.2 Feature disposition

| Hermes feature | Under wicket | Why |
|---|---|---|
| `terminal.backend: local` | **Keep** | the box is the backend (SECURITY.md whole-process posture) |
| Docker/Modal/Daytona/Vercel/SSH backends, bubblewrap plugin | **Disable** | nested sandboxes; need sockets/keys/egress |
| iron-proxy (`proxy.enabled`) | **Disable** | wicket-egress already does it outside the box; avoid two MITMs |
| `approvals.mode` | **`manual`**, prompts routed to wicket over `hermes-gateway-v1` | `smart` is an in-box LLM decider and spends budget (Principle 4) |
| Approval choices | answer **`once` or `deny` only** | `always` writes `command_allowlist`; `session` widens silently |
| `approvals.deny`, hardline floor, protected instruction files | **Keep** (early denials) | cheap, fail closed |
| `HERMES_YOLO_MODE`, `--yolo`, `/yolo`, `approvals.mode: off` | **Reject** in LaunchPlan; managed-pin `approvals.mode` | — |
| `memory.write_approval`, `skills.write_approval` | **true** (managed-pinned) | staging for the promotion gate |
| Background review, curator LLM consolidation, `/learn` from URLs | **Off** in v1 | tainted transcripts become instructions |
| `cronjob`, `connections`, `catalog`, `kanban`, `computer_use`, `browser`, `image_gen`, `video_gen`, `tts`, `x_search` toolsets | **Disable** (`agent.disabled_toolsets`) | self-scheduling, MCP self-install, host browser, paid/Nous gateway egress |
| `delegation` | Keep (same zone); use `wicket.spawn` for different authority | in-process threads, no isolation |
| `code_execution` | Keep | runs in the box; RPC over AF_UNIX in-box |
| `web` toolset | Keep **only if** zone reach includes the search provider; otherwise disable | it's an egress like any other |
| MCP `mcp_servers` | only `wicket` (HTTP, loopback endpoint bridged to the gateway UDS) | — |
| MCP sampling | **Off** on the wicket server | server-initiated LLM calls |
| `auth.adopt_external_logins` | **false**; no `~/.claude`, `~/.codex` in box | borrowed logins |
| Secret sources, vault `op`/`bw`, `key_cmd` | **Absent** | exec vectors; no secrets in box |
| Gateway hooks dir, plugins dir, shell hooks | **Empty, read-only**; `hooks: {}` | in-process code by placement |
| Chat adapters, webhooks, A2A, API server, dashboard/Webapp | **Off** in v1 | Ingress later via relay-style connector outside the box |
| Update checks, model catalog, telemetry, lazy installs, plugin auto-update | **Off** | no internet hosts needed (like Claude Code's launch) |
| Checkpoints (shadow git) | Off (wicket's CoW workdir + git S&F do this) | — |
| Codex app-server runtime, `claude -p` skills | **Off** by default | nested agents with their own model routes |

### 11.3 Model credentials and the owner's rule

- wicket-llm fronts Hermes with `transport: anthropic_messages`, or `codex_responses` / `chat_completions` for
  other upstreams, plus a placeholder `key_env`. No key ever enters the box.
- **Settled (2026-11-08): no Claude subscription for Hermes.** The owner's rule is "never an Anthropic API key;
  Claude Code CLI with my subscription", and Anthropic's Claude Code legal and compliance page reserves
  subscription OAuth for "ordinary use of Claude Code and other native Anthropic applications" (design §6).
  The Hermes adapter targets non-Anthropic upstreams the owner chooses (Nous Portal, OpenRouter, open-weights),
  or stays unused.
- Hermes would happily read `CLAUDE_CODE_OAUTH_TOKEN` if it were present. The conformance suite must show it is
  absent.

### 11.4 Borrow

1. **SECURITY.md's structure.**
   - One named load-bearing boundary.
   - An explicit list of in-process heuristics that are *not* boundaries.
   - Per-surface authorization rules ("session identifiers are routing handles, not authorization boundaries").
   - An out-of-scope list.

   wicket's docs and its `wicket doctor` should state wicket's boundaries the same way, alongside [12 §6.4, item 7].
2. **The approval-transport contract.** An immutable, redacted request; a `request_digest`; a decision bound to the
   request id and digest; fail-closed on timeout, error or invalid response; "presentation only". Also
   `execution_generation` fencing, and `open_requests` replay on reconnect. These go into the `AgentSession::answer`
   conformance tests (§6.1, item 8).
3. **Staged memory and skill writes with origin** (`pending/…`, `origin: background_review`, the `[auto]` tag), and a
   curator ledger with sha256 before/after per file and actor. These are good shapes for wicket's staging layer and
   memory-version audit.
4. **The protected instruction-file gate.** Basename match in any directory, realpath first, always-ask even under
   YOLO, fail-closed headless. The idea is cheap and right; in wicket it becomes a dangerous-pattern rule on
   `Op`s that touch the store and the workdir.
5. **MCP `trust: untrusted` + `readOnlyHint`, plus per-tool `tool_costs` / `spend_limit`** that ask even under YOLO
   and refuse headless. These map onto per-server risk floors and money budgets in the gateway (§9.2, §8.5).
6. **Relay connectors.** Chat platform tokens held by a connector service, an outbound-only WS from the agent, and
   approvals as authenticated responses. This is the shape of wicket's Ingress for chat.
7. **`<untrusted_tool_result source=…>` wrapping with delimiter defanging.** Cheap UX-layer labelling for model
   context, never a boundary.
8. **The supply-chain advisory catalogue** (known-poisoned package versions, kept forever) for `wicket doctor` and
   image builds.

### 11.5 Avoid

1. Approvals answered by any allowlisted chat member with "yes", and in-box LLM deciders (`smart` mode).
2. Auto-approve when no approval callback is wired. wicket's adapters must fail closed when no answerer is attached.
3. Control files writable by the agent "because containment belongs in the OS". That is true, but then the OS layer
   (wicket) must regenerate them, and Hermes' `config_lockdown` is weaker than Claude Code's managed settings.
4. "Trusted by placement" code directories.
5. Leaf-only managed pins. wicket's LaunchPlan validator works on the whole config and rejects anything not on an
   allowlist.
6. Env **blocklists** for subprocesses (the AWS chain inherited, `CLAUDE_CODE_OAUTH_TOKEN` not stripped). wicket's
   answer is that there are no secrets in the env at all.
7. Background self-review over the full transcript writing straight to memory and skills.
8. Hub registries without signatures (`clawhub`, `skills-sh`, `url`) and "trusted org" lists.

---

## 12. Draft LaunchPlan: Hermes as an inner agent (T1, `Placement::Whole`)

The style follows [11 §5] and [12 §9]. Hostnames inside the box are illustrative loopback names. There are no
secrets, only placeholders and routes. Unverified key shapes are marked **[L]**.

**Zone shape:** `lifetime: Standing{lease: 24h renewable}` (or `delete_when_done` for a one-shot),
`sandbox: {isolation: gvisor}` (Python, SQLite WAL, ripgrep, git), `operator_mode: wicket`, no ingress.

**Image (read-only):** `/opt/hermes` (pinned release, venv, bundled skills), plus models.dev and model-catalog caches
pre-seeded at build. `pip`, `uv` and PM are not reachable at runtime.

**Mounts:**

| Path in box | Mode | Source | Label |
|---|---|---|---|
| `/etc/hermes/config.yaml` (managed scope) | root-owned, ro | rendered from the LaunchPlan | trusted |
| `$HERMES_HOME=/wicket/state/hermes` | rw (agent uid) | standing store | agent's floating label |
| `…/config.yaml` | **regenerated every wake**; root-owned ro bind if Hermes tolerates it (E-HM1), else rw and **diffed and discarded at sleep** | LaunchPlan | trusted (render) |
| `…/SOUL.md` | ro | charter (operator-signed) | trusted |
| `…/memories/`, `…/skills/` | ro | approved memory version N | label of version N |
| `…/pending/` | rw | staging | agent's floating label |
| `…/state.db*`, `…/logs/`, caches | rw | session store | agent's floating label |
| `…/hooks/`, `…/plugins/`, `…/scripts/`, `…/cron/` | empty, ro | — | — |
| `…/.env`, `auth.json`, `mcp-tokens/`, `vault/` | **absent** | — | — |
| `/work` | CoW overlay | repo / workdir | per-ref label |
| `/usr/local/share/ca-certificates/wicket.crt` | ro, then `update-ca-certificates` in image entry | zone CA | — |

**`/etc/hermes/config.yaml` (managed pins; key shapes per the docs, [L] where noted):**
```yaml
model:
  provider: custom:wicket
  default: <zone-allowed model>
providers:
  wicket:
    api: http://wicket-llm.box.internal:8080          # loopback endpoint bridged to wicket-llm's UDS
    transport: anthropic_messages                     # or codex_responses / chat_completions per upstream
    key_env: WICKET_LLM_TOKEN
    discover_models: false
auxiliary:                                            # every side task pinned to the same route [L: per-task key shape]
  compression: { provider: custom:wicket }
  vision: { provider: custom:wicket }
  title: { provider: custom:wicket }
  background_review: { enabled: false }
delegation: { provider: custom:wicket, max_concurrent_children: 4 }
fallback_providers: []
terminal: { backend: local, env_passthrough: [], cwd: /work }
approvals:
  mode: manual
  timeout: 3600                                       # held open while wicket decides; pending survives via open_requests
  cron_mode: deny
  single_query_mode: deny
  unattended_mode: deny
  deny: ["git push*", "gh api*"]                      # early denial mirroring the ceiling; pushes are brokered
command_allowlist: []
security:
  approval: { transport: builtin, transport_fallback: deny }
  protected_instruction_files: true
  allow_lazy_installs: false
  allow_private_urls: false
memory: { write_approval: true, nudge_interval: 0 }   # [L] 0 = never nudge
skills: { write_approval: true, guard_agent_created: true, project_discovery: false, creation_nudge_interval: 0 }
curator: { enabled: false }                           # [L] key name
checkpoints: { enabled: false }
cron: { allow_agent_scheduling: false }
agent:
  max_turns: 200
  disabled_toolsets: [cronjob, connections, catalog, kanban, computer_use, browser, image_gen, video_gen, tts, x_search, project, desktop_ui]
mcp_servers:
  wicket:
    url: http://wicket-mcp.box.internal:8081/mcp
    headers: { Authorization: "Bearer ${WICKET_MCP_TOKEN}" }
    sampling: { enabled: false }
    trust: full
mcp: { auto_reload_on_config_change: false }          # [L] whether a managed pin stops agent-added servers
hooks: {}
hooks_auto_accept: false
plugins: { enabled: [], auto_update_check_hours: 0 }
auth: { adopt_external_logins: false }
updates: { check: false }
model_catalog: { enabled: false }
telemetry: { shared_metrics: { enabled: false, send: false } }
secrets: { command: { enabled: false } }
vault: { onepassword: { enabled: false }, bitwarden: { enabled: false } }
platforms: {}                                         # no chat adapters, no api_server, no webhook [L: shape]
```

**Env:**
```
HERMES_HOME=/wicket/state/hermes   HERMES_MANAGED_DIR=/etc/hermes
HERMES_WRITE_SAFE_ROOT=/work:/wicket/state/hermes/pending    # file tools: workdir + staging only
WICKET_LLM_TOKEN=wkt_cap_<zone,session>   WICKET_MCP_TOKEN=wkt_mcp_<zone,session>
HTTPS_PROXY=http://wicket-egress.box.internal:3128  HTTP_PROXY=…  ALL_PROXY=…
NO_PROXY=wicket-llm.box.internal,wicket-mcp.box.internal,localhost,127.0.0.1,::1
SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt  REQUESTS_CA_BUNDLE=…  CURL_CA_BUNDLE=…  NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/wicket.crt
HERMES_DISABLE_LAZY_INSTALLS=1   OTEL_SDK_DISABLED=true
# deliberately absent: ANTHROPIC_*, CLAUDE_CODE_OAUTH_TOKEN, OPENAI_*, OPENROUTER_*, NOUS/portal tokens, TOOL_GATEWAY_*,
#   GITHUB_TOKEN, AWS_*, GOOGLE_*, *_ALLOWED_USERS, API_SERVER_*, HERMES_YOLO_MODE, HERMES_ACCEPT_HOOKS, ~/.claude, ~/.codex
```

**argv** (one process, the home owner): `/opt/hermes/.venv/bin/python -m tui_gateway.entry` (stdio JSON-RPC).
Alternatives:
- `hermes gateway run --no-supervise` plus `hermes gateway attach --json` for a WS ticket, with the WS bridged to a
  UDS [M].
- T2: `hermes acp`, which starts or attaches the gateway [M].

**Preflight:**
- `hermes config validate` / `hermes doctor` with the same env, offline [L: command names].
- Reject any rendered key in `config_exec_vectors` (§6.3).
- Compute `context_files`.

**Adapter session (T1, `hermes-gateway-v1`):**
```
→ runtime.describe ; client.capabilities {server_requests:true}
→ session.create {cwd:"/work"} ; prompt.submit {text: <TaskPrompt>}
← message.delta/complete, tool.start/complete           → AgentEvents (free text as handles)
← request "approval" {request_id, command, description}  → advisory AgentPrompt; answer {choice:"once"|"deny"} only
← request "clarify"                                      → operator question (wicket channel), or {} to cancel
← request "secret"/"sudo"/"connection"                   → always cancel/deny
→ session.steer {text:"R-123 granted; retry"}  /  session.interrupt  /  session.branch (taint recovery)
on reconnect: session.resume → open_requests replayed (pending survives a host-side restart)
settled: turn complete ∧ no open_requests ∧ no running process_manage jobs
```

**Typed output:**
- Hermes has no per-turn schema for the main agent.
- Use a terminating `wicket.result` tool on the wicket MCP gateway (as with pi), or the `/wicket/out` outbox.
- `delegate_task`'s `output_schema` exists only for children.

**Credential routes:**
- `LlmProxy{base: providers.wicket.api, token: WICKET_LLM_TOKEN}`, for every auxiliary and delegation route.
- `GatewayOnly{wicket.*}`.
- Egress injections only for adapter-mapped hosts in the zone ceiling. Hermes' own `gh`/`git` use is brokered by git
  store-and-forward.

**Egress needs:**
- none beyond wicket-llm and wicket-mcp when the toolsets above are disabled;
- the zone's declared reach for `web`, `terminal` and `code_execution` traffic;
- no `nousresearch.com`, `models.dev`, `api.github.com` (update checks) or `clawhub.ai`.

**Preflight taint (`context_files`), removed from the agent's view for untrusted refs, otherwise labelled:**
- `.hermes.md`, `HERMES.md` (up to the git root);
- `AGENTS.override.md`, `AGENTS.md`, `agents.md` (git root to cwd);
- `CLAUDE.md`, `claude.md`, `.cursorrules`, `.cursor/rules/*.mdc`;
- the same names in **any subdirectory** (subdirectory hints);
- `.hermes/skills/**`, `.agents/skills/**`, `.hermes/plugins/**`, `.hermes/plans/**`;
- project `.env*` (read-denied by Hermes too).

On the `HERMES_HOME` side, each item carries the label of its source:
- `SOUL.md`: charter, trusted;
- `memories/*.md`, `skills/**`: the memory version's label;
- `state.db`: session label.

**`persistent_policy_writes` (diffed at sleep, never promoted, regenerated on wake):**
- `config.yaml` (`command_allowlist`, `mcp_servers`, `providers`, `hooks`);
- `shell-hooks-allowlist.json`;
- `hooks/`, `plugins/`, `scripts/`, `cron/`;
- `skills/.hub/`;
- `auth.json`.

**Pending path:**
- An egress or gateway denial returns a structured 403 / MCP error with `request_id`. The agent can call
  `wicket.await_grant`.
- In-box approval prompts are held open (`approvals.timeout`) while wicket's escalation is decided. Then wicket
  answers `once` and `session.steer`s the result.
- Across sleep, a pending request is a ledger entry; on wake the session is resumed.

**Unsupported in this plan (the zone view says so):** chat platforms, webhooks, A2A, the API server and dashboard,
browser and computer use, Nous Tool Gateway and Portal, external memory providers, cron and self-scheduling,
Codex runtime, nested `claude -p`.

---

## 13. Changes to design.md (proposed)

- **§6 tier table.** Add **Hermes Agent** to T1 (`hermes-gateway-v1`: server→client `approval` requests,
  `session.steer`, `session.branch`, `open_requests` replay), with ACP as T2. Add a launch bullet pointing at §12
  here.
- **§6 `AgentCaps`.**
  - `config_lockdown: ManagedLeafPins` (weaker than Claude's managed settings).
  - `config_exec_vectors`: the §6.3 table.
  - `persistent_policy_writes`: §12 list.
  - `settled_signal: protocol` (the process is a daemon).
  - `background_traffic`: models.dev, update and catalog checks (disable or pre-seed).
  - `self_scheduling: true`, a new field: the agent can create its own wake sources, so the adapter must disable
    it.
- **§6.1 conformance.**
  - (a) No dangerous command runs without an attached answerer (catches the library-mode auto-approve).
  - (b) Answers are only `once` / `deny`, and `config.yaml` is byte-identical after a run apart from Hermes'
    bookkeeping keys (E-HM1).
  - (c) `HTTPS_PROXY` is absent from MCP stdio and `execute_code` children → fails closed.
  - (d) Subdirectory-hint injection: a planted `sub/AGENTS.md` is never appended to a tool result.
  - (e) No `models.dev` or GitHub traffic.
- **§9.1 / §7.** The zone CA must go into the **system trust store**. Env vars alone are not enough for `truststore`
  clients (Hermes). All proxy and LLM endpoints must also be reachable as loopback TCP inside the box, because
  Hermes and most Python agents have no UDS transport.
- **§12.**
  - Add "background self-review" to the smuggling list: an in-agent process that turns transcript content into
    instructions for later runs.
  - Add subdirectory hints as a context-file vector that works *after* launch.
- **§13.4.** Note that Hermes' `pending/` is a ready-made staging layer. The promotion gate should consume
  agent-native staging where it exists, and fall back to diffing the store otherwise.
- **§13.2.** Agent-native self-scheduling (`cronjob_manage`, heartbeat/loop/goal) is disabled. A request to be woken
  later becomes a typed escalation for a `Subscription`.
- **§14.1.2.** Cite Hermes, alongside OpenClaw, as the second assistant that lets any allowlisted chat member approve
  with "yes".
- **§14.1.3.** Add a Host/Origin check on WebSocket upgrades (CVE-2026-53869), 0600 state files (CVE-2026-53870), and
  approval cards bound to a generation.
- **§21.** Open question: can a Claude subscription token be used for a non-Claude-Code inner agent (§11.3)?

---

## 14. Unverified items and experiments

- **E-HM1.** Does Hermes start and run with `config.yaml` root-owned and read-only (it writes parse backups, consent
  answers and `onboarding.seen`)? If not, wicket will diff and discard at sleep instead.
- **E-HM2.** Do placeholder keys through `providers.wicket` cover *every* model call (auxiliary, compression,
  delegation, title, approval) with `discover_models: false`? Is there no models.dev or catalog traffic with
  pre-seeded caches?
- **E-HM3.** `python -m tui_gateway.entry` as a supported long-run host in the box, versus `hermes gateway run` plus
  `attach --json`. `open_requests` replay across a host-side reconnect, and across a gVisor checkpoint/restore.
- **E-HM4.** With `memory.write_approval` and `skills.write_approval` true and `memories/` and `skills/` read-only:
  do writes land only in `pending/`? Does anything (curator, terminal) fail loudly rather than corrupt state?
  `nudge_interval: 0` semantics.
- **E-HM5.** Can chat adapters run while every approval is routed to a non-chat client (needed before any Ingress
  work)?
- **E-HM6.** Is a managed pin on `mcp_servers` / `mcp.auto_reload_on_config_change` respected when the agent edits
  user `config.yaml` (§6.3)? How does `manage_connections` behave when its toolset is disabled?
- **E-HM7.** Subdirectory hints: is there an off switch? If not, preflight removal must cover the whole tree.
- **E-HM8.** Denial behaviour (design E1): does Hermes retry around a 403 from wicket-egress (`curl` → `python
  requests` → `execute_code`)?
- **[L] key shapes** in §12: `auxiliary.<task>.provider`, `curator.enabled`, `platforms: {}`, `nudge_interval: 0`,
  `hermes config validate`. `configuration.md` and `hermes_cli/config_defaults.py` at the pinned tag decide them.
- Owner decision on subscription tokens: settled, see §11.3.

---

## 15. Sources

**Primary** (local clone at `8422e54`) [H]:
- `README.md`, `SECURITY.md`, `Dockerfile`, `docker-compose.yml`, `pyproject.toml`
- `website/docs/developer-guide/`: `architecture`, `agent-loop`, `prompt-assembly`, `provider-runtime`, `tools-runtime`,
  `session-storage`, `gateway-internals`, `gateway-classic-cli`, `programmatic-integration`, `acp-internals`,
  `terminal-environment-plugin`, `memory-provider-plugin`, `secret-source-plugin`, `middleware`, `cron-internals`,
  `egress-internals`, `subagent-lifecycle-api`
- `website/docs/user-guide/`: `security`, `managed-scope`, `remote-config`, `which-file-does-what`, `configuration`,
  `profiles`, `docker`, `checkpoints-and-rollback`, `egress/{network-isolation,iron-proxy}`, `secrets/*`,
  `messaging/{index,webhooks,relay,a2a}`
- `website/docs/user-guide/features/`: `memory`, `memory-providers`, `skills`, `curator`, `cron`, `heartbeat`, `goals`,
  `loops`, `context-files`, `mcp`, `hooks`, `acp`, `api-server`, `codex-app-server-runtime`, `delegation`,
  `code-execution`, `tool-gateway`, `credential-vault`, `credential-pools`, `subscription-proxy`, `fallback-providers`,
  `plugins`
- `website/docs/reference/`: `environment-variables`, `mcp-config-reference`, `toolsets-reference`, `tools-reference`,
  `cli-commands`
- `website/docs/integrations/providers.md`, `website/docs/guides/{migrate-from-openclaw,manage-hermes-cloud-with-mcp}.md`
- Code:
  - `agent/`: `file_safety.py`, `background_review.py`, `prompt_builder.py`, `subdirectory_hints.py`,
    `process_bootstrap.py`, `proxy_bypass.py`, `models_dev.py`, `anthropic_credentials.py`
  - `tools/`: `approval.py`, `approval_detection.py`, `approval_smart.py`, `file_tools_write_guards.py`,
    `mcp_tool_config.py`, `memory_tool.py`, `skills_guard.py`, `connectors/tool.py`, `environments/docker.py`,
    `code_execution_tool.py`
  - `hermes_cli/`: `approval_transport.py`, `config_defaults.py`, `managed_scope.py`, `runtime_provider.py`
  - `tui_gateway/entry.py`, `acp_adapter/{entry,permissions,gateway_server}.py`

**GitHub / NVD [H]:**
- https://github.com/NousResearch/hermes-agent (repo, releases incl. v0.23.0 notes)
- https://github.com/advisories?query=hermes-agent (GHSA-4pqm-j46f-795x, GHSA-99f9-j8r3-p853, GHSA-pgp4-xr4j-h5cg,
  GHSA-238w-f66p-w349, GHSA-xq8w-9jvx-gm3v, GHSA-wm96-9gfh-vvgq, …)
- https://nvd.nist.gov/vuln/detail/CVE-2026-53869 , https://nvd.nist.gov/vuln/detail/CVE-2026-53870 ,
  https://nvd.nist.gov/vuln/detail/CVE-2026-9366 , https://nvd.nist.gov/vuln/detail/CVE-2026-9352 ,
  https://nvd.nist.gov/vuln/detail/CVE-2026-9353 , https://nvd.nist.gov/vuln/detail/CVE-2026-10220 ,
  https://nvd.nist.gov/vuln/detail/CVE-2026-10221 , https://nvd.nist.gov/vuln/detail/CVE-2026-14625 ,
  https://nvd.nist.gov/vuln/detail/CVE-2026-7112 , https://nvd.nist.gov/vuln/detail/CVE-2026-7113
- https://github.com/TheAiSingularity/hermesclaw (README) ; https://github.com/NVIDIA/OpenShell

**Secondary [M]:**
- https://www.heyuan110.com/posts/ai/2026-04-14-hermes-agent-guide
- https://www.datacamp.com/tutorial/hermes-agent
- https://www.producthunt.com/products/hermes-4/launches/hermes-desktop
- https://docs.e2b.dev/agents/hermes ; https://thrashr888.github.io/agentkernel/agents/hermes
- https://huggingface.co/NousResearch/Hermes-4-14B ; https://fast.io/resources/hermes-3-function-calling-guide/
- https://elixirforum.com/t/anubis-formerly-hermes-mcp-model-context-protocol-implementation-for-elixir/71410 ;
  https://hexdocs.pm/hermes_mcp/0.2.2/home.html
- https://alphasignalai.substack.com/p/hermes-just-made-codex-the-engine (Codex as engine, v0.13)
