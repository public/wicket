# 09 — Operator channels: Remote Control, wicket's admin UI, and human oversight of inner agents

Research date: 2026-11-08. Claude Code reference version: **2.1.319** (installed on this box and the latest the docs
reference). New requirement from the owner: humans must be able to oversee and interact with inner agents comfortably
through **both** (1) Claude-style Remote Control (claude.ai/code, the Claude apps, phone push) and (2) wicket's own remote
admin interface.

Confidence markers used below:

- **[verified]** read today in a primary source (official docs, changelog, CLI `--help`). Confidence high unless noted.
- **[observed]** seen on this machine read-only: `ps`, `/proc/<pid>/environ` *names only*, `ss`, `strings` on the
  2.1.319 binary. Strings show that code exists, not how it behaves; confidence is given per claim (H/M/L).
- **[inferred]** reasoning from the above. Confidence given.
- **[unverified]** a hypothesis to test; each one feeds an experiment in §9.

Hard limits respected while observing: no Claude process was started, stopped or signalled; no credential file, token
value, cookie or debug log was read; only environment variable *names* (plus three non-secret values) were printed.

---

## TL;DR

1. **Remote Control (RC) and wicket's default Claude Code launch are mutually exclusive today.** RC needs a full-scope
   claude.ai subscription login (no API key, no `ANTHROPIC_AUTH_TOKEN`, no `apiKeyHelper`, no `setup-token` token),
   `ANTHROPIC_BASE_URL` unset or `api.anthropic.com`, feature-flag fetching on (so no
   `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`), and an organization that is not ZDR/HIPAA. wicket's T1 launch
   ([design §6]) sets every one of those the other way. [verified]
2. **RC is outbound-only HTTPS to `api.anthropic.com`.** The `claude remote-control` "bridge" registers as an
   *environment* (`POST /v1/environments/bridge`) and long-polls for work; each session is a child
   `claude --print --sdk-url https://api.anthropic.com/v1/code/sessions/<cse_id> --input-format stream-json
   --output-format stream-json` whose **entire SDK control protocol** (user messages, `can_use_tool`, interrupts,
   model/permission-mode changes) rides an SSE stream plus POSTed events to Anthropic's session service, which acts as
   the SDK host and fans out to every connected device. [verified for the shape; observed for the endpoints, H]
3. **wicket cannot sit in the session channel as a relay.** `--sdk-url` is undocumented and, in 2.1.319, accepts only
   `https:` URLs with no port or userinfo whose origin is `api.anthropic.com` / `api-staging.anthropic.com` (or the
   OAuth config's own API origin). Anything else fails with "rejected by allowlist". [observed, H] A TLS-intercepting
   egress proxy *can* see the channel (no app-level pinning found; corporate TLS-inspecting proxies are a supported
   configuration), but the protocol is private, changes almost daily, carries per-frame device-attestation status and
   optional client-event signing, so **tap for observation and whole-channel cut-off only; never rewrite or inject
   frames.** [observed M; inferred]
4. **There is no official API to mirror an SDK/stdio-driven session to RC.** The supported integration points are:
   `CLAUDE_CODE_PROCESS_WRAPPER` (wraps the session processes `claude remote-control` spawns, so wicket can jail
   them), **Channels** (an MCP server that pushes events into a session and can receive and answer *relayed
   permission prompts*), hooks, and — on Team/Enterprise — **self-hosted environments** whose runner `--exec-path`
   wrapper is a documented place to put each session in a sandbox. [verified]
5. **What leaves via RC:** the full transcript (prompts, Claude's replies, tool calls and tool results), working-tree
   diffs for the diff pane, file/photo uploads both ways, directory listings for `@` completion, session titles, and
   push-notification text. It is stored on Anthropic servers under the account's retention (30 days commercial and
   consumer-without-training; 5 years if the consumer opted into training); deleting the session deletes its events.
   For IFC, RC is a **destination** (`anthropic.session_store` + the account's devices) that a zone's labels must be
   cleared for. [verified]
6. **RC approvals are never wicket grants.** An RC "Allow" answers Claude Code's own in-box permission prompt, which
   wicket already treats as advisory UX ([design §2.1]); the decision travels Anthropic → box → wicket, so the box could
   forge it. wicket's escalations are approved only on wicket's own surfaces (CLI, web UI with passkey step-up, push
   deep-link). A tightly fenced exception (an Anthropic-attested approval frame observed on the proxy before the box
   sees it) is noted in §7.3 as research, off by default.
7. **Recommended design:** one `OperatorChannel` abstraction with two families: **wicket-native** (API + web UI/PWA +
   CLI + push; authoritative for grants, pause/kill, zone state) and **vendor-native** (RC first; a *mirror and steering*
   surface whose messages enter as `operator:vendor` input, whose approvals stay agent-local, and which exists only in
   zones compiled in an explicit **`vendor_rc` mode**: subscription credential, base URL at Anthropic, egress-proxy
   path allowlist on `api.anthropic.com`, transcript destination cleared by labels, cross-session messaging off).

---

## 1. Remote Control mechanics

### 1.1 What the user-facing product is [verified]

Source: <https://code.claude.com/docs/en/remote-control>, `claude remote-control --help`, `claude --help`.

- Three ways in: **server mode** `claude remote-control` (persistent server, many concurrent sessions,
  `--spawn same-dir|worktree|session`, `--capacity N` default 32, pre-creates one session unless
  `--no-create-session-in-dir`); **interactive** `claude --remote-control [name]` / `--rc` (one terminal session that
  is also remotely controllable); **in-session** `/remote-control` (`/rc`) in the CLI, VS Code or Desktop.
  Auto-connect for all interactive sessions via `remoteControlAtStartup` (user/managed settings only; a repo can turn
  it off but not on).
- "Claude and its commands run on this computer; claude.ai and the app only show the session."
- Server-mode flags placed *before* `remote-control` are refused unless dropping them is harmless (`--verbose`,
  `--model`); e.g. `--settings` makes the server refuse to start. `--sandbox`/`--no-sandbox` were removed in v2.1.300:
  "To sandbox the sessions the server starts, turn on sandboxing in a settings file."
- Connected devices see the conversation live, subagent and workflow progress (and can stop them), compaction and
  `/clear`, a **diff pane** of the git working tree, and can change **model**, **effort**, and run a whitelisted set of
  slash commands (`/compact`, `/clear`, `/model`, `/effort`, `/mcp reconnect`, `/config key=value` from mobile, …).
  Photos/files attached on the phone are downloaded into the session's machine and passed as `@` references.
- **Permission prompts and `AskUserQuestion` stay open until answered** from any surface; other forwarded dialogs
  expire after `dialogExpiry` (default 5 min) with their no-action default.
- **Mobile push**: "Push when Claude decides" (proactive; Claude can also be asked to push) and "Push when actions
  required" (permission prompts and questions). No per-event configuration. Pushes are skipped while you are at the
  terminal; `CLAUDE_CLIENT_PRESENCE_FILE` extends that.
- **Trusted Devices** (beta; per-user on Pro/Max/Ultra, org-wide on Team/Enterprise): each viewing/steering device
  enrolls a credential right after a full sign-in, and the sign-in must be ≤18 h old, refreshed by a biometric/passkey
  step-up. The machine running Claude Code gets its own credential automatically at CLI sign-in.
- Limits: one RC session per interactive process; server mode gives up after ~10 minutes without network; tolerates
  HTTP 403 from "a network edge, or a proxy, VPN, or firewall" for 3 minutes (v2.1.238) and then names the refuser.

### 1.2 Architecture: who connects where [verified + observed]

Docs ("Connection and security"): "Your local Claude Code session makes outbound HTTPS requests only and never opens
inbound ports on your machine. When you start Remote Control, it registers with the Anthropic API and polls for work.
When you connect from another device, the server routes messages between the web or mobile client and your local
session over a streaming connection. … The connection uses multiple short-lived credentials, each scoped to a single
purpose and expiring independently." The self-hosted-environments page adds: "Session streaming uses server-sent
events over HTTPS, so a proxy in the path must not buffer responses." [verified]

What this box shows [observed]:

- The service runs `claude remote-control --chrome --spawn same-dir --permission-mode bypassPermissions --debug-file …`
  (PID 1624556). Its children are `…/versions/2.1.319 --print --sdk-url https://api.anthropic.com/v1/code/sessions/cse_…
  --session-id cse_… --input-format stream-json --output-format stream-json --replay-user-messages
  --resume=https://api.anthropic.com/v1/code/sessions/cse_…`. The child's stdin and stdout are **sockets to the
  parent bridge**, not a terminal.
- The child's environment (names only) includes `CLAUDE_CODE_ENVIRONMENT_KIND=bridge`,
  `CLAUDE_CODE_SESSION_ACCESS_TOKEN` (value not read), `CLAUDE_CODE_WORKER_EPOCH`,
  `CLAUDE_CODE_BRIDGE_OWNER_ACCOUNT_UUID`, `CLAUDE_CODE_BRIDGE_OWNER_ORG_UUID`, `CLAUDE_CODE_BRIDGE_MCP_CARRIER`,
  `CLAUDE_CODE_BRIDGE_PROMPT_SHA256`, `CLAUDE_CODE_ENTRYPOINT=sdk-cli`. There is **no** `CLAUDE_CODE_OAUTH_TOKEN`
  or `ANTHROPIC_*` variable, so model calls presumably use the user's stored claude.ai login from the config dir
  (inferred, M — not checked, because that would mean reading the credential store).
- A background session started with `claude --bg … --remote-control --name <name>` runs under
  `claude daemon run` → `claude bg-pty-host` → the session binary (`CLAUDE_CODE_SESSION_KIND=bg`): the agent-view
  background service, here also RC-connected.
- `ss` shows only outbound TCP/443 from these processes (to `api.anthropic.com` and a handful of other hosts).

Endpoint and transport names in the 2.1.319 binary [observed; H for existence, M for roles]:

| Role | Endpoints (from `strings`) |
|---|---|
| RC server ("bridge") registration and work queue | `POST /v1/environments/bridge` (body: `machine_name`, `directory`, `branch`, `git_repo_url`, `max_sessions`, `worker_type`, tool-host advert), `GET /v1/environments/{id}/work/poll`, `…/work/{id}/ack`, `…/heartbeat`, `…/stop`, `/v1/environments/{id}/bridge/reconnect`, `DELETE /v1/environments/bridge/{id}`, `/offline`. Errors such as "This folder is already served by another Claude Code on this device." The same `environments/…/work` family is what Managed Agents self-hosted workers use (beta header `managed-agents-2026-04-01`), see [01 §1.3]. |
| Session child ("worker", CCR v2) | `POST /v1/code/sessions/{id}/worker/register` (returns `worker_epoch`), **SSE** `GET …/worker/events/stream` (inbound client events, with sequence numbers, keepalives and a long-poll fallback), `POST …/worker/events` (outbound events), `…/worker/events/delivery` (received/processed receipts), `…/worker/heartbeat`, `PUT …/worker` (worker state), `…/worker/internal-events`, `…/worker/diagnostics`. Class names `SSETransport`, `CCRClient`. |
| Session CRUD and discovery | `/v1/code/sessions`, `/v1/code/sessions/watch`, `/v1/code/sessions/{id}/mark_read`, `/v2/ccr-sessions/{id}/…` |
| Delivered connectors and other MCP | `/v2/session_ingress/shttp/mcp/…`, `/v2/session_ingress/mcp/ws/…`, `/v1/code/mcp/…`, `/v2/ccr-sessions/{id}/mcp`. The self-hosted docs confirm the connector paths `api.anthropic.com/v2/ccr-sessions/*`, `/v1/code/sessions/*`, `/v1/code/mcp/*`. |
| Other account-level APIs the same binary can call | `/v1/code/triggers` (scheduled cloud agents), `/v1/code/webhook-triggers`, `/v1/code/channels`, `/v1/code/memory/`, `/v1/code/github/…`, `/v1/code/runners/self-hosted/…`, `/v1/code/auth/refresh` |

Control messages the session accepts from the remote side include `set_model`, `set_permission_mode`, `interrupt`,
`stop_task`, `end_session`, `rename_session`, `mcp_authenticate`, `reload_plugins`, `apply_flag_settings`,
`bash_command`, and `update_environment_variables` (used to deliver `CLAUDE_CODE_OAUTH_TOKEN` rotations on
self-hosted runners). Device-attestation statuses on inbound frames: `VERIFIED`, `VERIFIED_BY_GATE`, `UNCHECKED`,
`VERIFIED_KEYLESS_DEVICE`, `SERVICE_VOUCHED`, `SERVER_AUTHORED`, `SERVER_REPLAYED`, `TRANSITIVELY_VOUCHED`; the
transport has a "device floor" that refuses frames below it, and a `clientEventSigner` signs outbound events ("the
session refused a request that only the computer it is bound to can sign"). [observed, M: names only; semantics
inferred]

### 1.3 What `--sdk-url` does [observed H, inferred M]

- It is **not documented**: absent from `claude --help` and from the CLI reference page. [verified]
- It requires `--input-format stream-json --output-format stream-json` ("Error: --sdk-url requires both …") and
  conflicts with `--await-initialize` / `--await-claim`. [observed]
- It replaces the stdio SDK host with the remote session service. The same message schemas as the Agent SDK protocol
  ([01 §1.1]) are used: a `control_request` with `subtype: "can_use_tool"`, `tool_name`, `input`, `tool_use_id`,
  `decision_reason_type`, `classifier_approvable` is posted as an event; claude.ai or the app renders it; the answer
  returns as an inbound client event. So yes: **with `--sdk-url`, can_use_tool, user messages, interrupts and mode
  changes all flow through Anthropic's session service, not stdio.** stdin is still connected to the parent (the
  bridge or the self-hosted runner) and carries host-side control, such as token rotation. [observed H for the schema,
  inferred M for the routing; the self-hosted docs confirm "The child's stdin is the runner's control channel. Token
  rotations and session-end signals arrive on it."]
- **Origin allowlist** (2.1.319, decompiled string): a URL is accepted only if the protocol is `https:`, it has no
  username, password or port, and its origin equals the configured `BASE_API_URL` origin or — unless
  `CLAUDE_CODE_CUSTOM_OAUTH_URL` is set — one of `https://api.anthropic.com`, `https://api-staging.anthropic.com`.
  Failure: "ccr-session --sdk-url rejected by allowlist". [observed, H]

### 1.4 `--spawn`, `--bg`, `--remote-control <name>` [verified + observed]

- `--spawn same-dir` (all sessions share cwd), `worktree` (each on-demand session gets a git worktree, or a
  `WorktreeCreate` hook), `session` (classic single session, exits with it). `w` toggles at runtime and the choice is
  saved per folder. Capacity default 32. Crashed sessions are re-served when a device messages them (≥2.1.238).
- **The spawned session processes go through `CLAUDE_CODE_PROCESS_WRAPPER` / `processWrapper`** (≥2.1.210; user or
  managed settings `env`, not a shell export). The launcher receives Claude Code's command line appended and must
  `exec` into it. This is the documented hook for putting each RC session into a wicket jail. [verified,
  <https://code.claude.com/docs/en/corporate-launcher>]
- `claude --bg` starts a session under the agent-view background service (`claude daemon`), printing an id for
  `claude attach|logs|stop|rm`; with `--remote-control` that background session is also RC-controllable. [verified
  `--help`; observed]
- `claude --remote-control <name>` starts an interactive terminal session that is also RC-controllable; both surfaces
  can type. [verified]

### 1.5 Auth and policy [verified]

| Question | Answer |
|---|---|
| Subscription required? | Yes: Pro, Max, Ultra, Team, Enterprise. "API keys are not supported." Console API keys, Bedrock, Vertex ("Agent Platform"), Foundry, and the Claude apps gateway are all excluded. |
| Which credential? | A full-scope claude.ai OAuth login (`/login`). The 1-year `claude setup-token` / `CLAUDE_CODE_OAUTH_TOKEN` "can only make model requests, so they can't establish Remote Control sessions". If `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` or `apiKeyHelper` is set, RC is disabled even with a claude.ai login present (changelog 2.1.139). |
| Model calls through a custom `ANTHROPIC_BASE_URL` while RC goes to Anthropic? | **No.** "Remote Control is now disabled when `ANTHROPIC_BASE_URL` points at a non-Anthropic host" (2.1.196); "even if you sign in with claude.ai". Transparent TLS interception of `api.anthropic.com` is the only way for wicket to see model traffic in an RC session. |
| Session channel vs model credential | Docs: "multiple short-lived credentials, each scoped to a single purpose". Observed: a per-session `CLAUDE_CODE_SESSION_ACCESS_TOKEN` in the child's env (self-hosted docs: a JWT prefixed `sk-ant-cc-` whose `act` claim names the session creator); inference uses the account OAuth token (bridge) or a ~30-minute session-scoped OAuth token (`CLAUDE_CODE_OAUTH_TOKEN`, self-hosted runner, rotated over stdin). |
| Feature flags | `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` or `DISABLE_GROWTHBOOK` make RC unavailable. `DISABLE_TELEMETRY`/`DO_NOT_TRACK` are fine from 2.1.283 unless the org requires Trusted Devices. |
| Org/enterprise controls | Team/Enterprise: off by default; an Owner enables the **Remote Control** toggle (server-side) at `claude.ai/admin-settings/claude-code`; custom roles need both "cloud sessions" and "Claude Code remote control" permissions; **Require trusted devices** under Capabilities > Remote sessions; ZDR and HIPAA orgs cannot enable RC. Device-level: `disableRemoteControl: true` in managed settings (MDM). Policy is re-fetched about hourly; turning it off disconnects and archives sessions. |
| Workspace trust | `claude remote-control` asks `Trust <dir>? [y/N]`; without a TTY it exits with "Workspace not trusted". |

### 1.6 Inside a box whose only egress is a TLS-intercepting proxy [verified + inferred]

- Claude Code honours `HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, `CLAUDE_CODE_CERT_STORE`, mTLS variables ([01 §1.9]).
  The self-hosted runner docs explicitly support corporate egress proxies and warn that "an intercepting proxy that
  answers the poll with its own page produces a response the runner can't parse", which implies interception of
  `api.anthropic.com` itself is an expected deployment. [verified]
- No application-level certificate pinning for Anthropic hosts appears in the binary (only Bun runtime internals such
  as `checkServerIdentity` and test-only SPKI block lists). [observed, M]
- Requirements on the proxy: do not buffer SSE (`text/event-stream`), allow long-lived responses, keep HTTP 403s rare
  (RC treats a persistent 403 as a network refusal and disconnects after 3 minutes), pass WebSockets for the delivered
  connector and git paths if those are used. [verified]
- Hosts an RC zone needs at minimum: `api.anthropic.com` (session channel, inference, feature flags, JWKS, OAuth
  refresh via `/v1/code/auth/refresh` on runners). An interactive sign-in additionally needs `claude.ai`,
  `platform.claude.com` and captcha hosts — which should happen on the host, never in the box. [verified for runners;
  unverified for bridge-mode children, E-RC1]

**Conclusion:** RC should work through wicket's egress proxy with wicket's CA. Unverified end to end (E-RC1).

### 1.7 Putting a harness in the middle [observed + inferred]

| Option | Feasible? | Robust? | Allowed? | Verdict |
|---|---|---|---|---|
| Point `--sdk-url` at a wicket relay | **No**: origin allowlist (§1.3). Only via `CLAUDE_CODE_CUSTOM_OAUTH_URL` / a changed `BASE_API_URL`, which are internal knobs that also redirect auth. | — | Not a documented interface. | Rejected. |
| Tap at the egress proxy (TLS-terminate `api.anthropic.com`) and **observe** | Yes, with wicket's CA (§1.6). | Medium: private protocol, near-daily releases; parse leniently, never fail the session on a parse error. | Corporate TLS inspection is an accepted deployment; observing your own traffic is ordinary. | **Adopt** for audit, liveness, labels and mirroring into wicket's UI. |
| Tap and **filter or inject** frames | Technically possible for unsigned frames. | Low: epochs, sequence numbers, delivery receipts, device attestation on inbound frames, optional signing of outbound events. A dropped frame desynchronises the session; injected frames may be refused by the device floor. | Interfering with a vendor's private session protocol is at best unsupported, likely against the terms. | **Reject**, except a whole-channel cut (deny the path) as a kill switch. |
| wicket owns stdio and mirrors to RC | No official API. Stdio mode and `--sdk-url` mode are alternatives for the same child: whoever is the SDK host answers `can_use_tool`. | — | — | Not possible; wicket's own UI mirrors instead. |
| `claude remote-control` on the **host**, sessions jailed via `CLAUDE_CODE_PROCESS_WRAPPER` → `wicket-jail` | Yes (documented wrapper contract). | Medium: wrapper must keep stdin/stdout sockets and env; bridge state lives outside the box. | Documented. | **Adopt** for personal/Pro/Max use (`vendor_rc` mode, bridge flavour). |
| Self-hosted environment runner with `--exec-path` = wicket wrapper | Yes, Team/Enterprise only, public beta. Documented env (session JWT, 30-min OAuth token, `CLAUDE_CONFIG_DIR`), stdin and fd 3/4/5 contract. | Medium-high: documented, versioned, has a CI test recipe. | Documented. | **Adopt** as the org flavour of `vendor_rc`; it also lets wicket *dispatch* a task (`claude --environment ccpool_…`) that humans then watch in claude.ai. |
| Channels MCP server (wicket gateway declares `claude/channel` + `claude/channel/permission`) | Yes, research preview; custom channels need `--dangerously-load-development-channels` or an allowlist; Team/Enterprise must enable Channels. | Medium. | Documented. | **Adopt** to push wicket notices into a session and to *see* permission prompts; answering them is still agent-local consent (§7). |

### 1.8 Data flow and retention [verified]

- "While Remote Control is connected, the session transcript, including your messages, Claude's responses, and tool
  activity, is stored on Anthropic servers." Execution and files stay local, but **tool outputs are part of the
  transcript**, so anything Claude reads with a tool (file contents, command output, fetched pages) leaves.
- In addition: git diffs for the diff pane (the CLI computes and uploads them), files Claude sends to the user,
  attachments from the phone (downloaded into the box: an **ingress** of operator-supplied files), directory listings
  for `@` autocomplete, titles, push-notification text (delivered via Apple/Google push).
- Retention: consumer 30 days, or 5 years with the training setting on; commercial 30 days; ZDR not available with
  RC; a deleted session's event data is permanently removed. Consumer accounts with the training setting on may have
  the data used for training.
- Self-hosted environments: "The conversation itself, including prompts, responses, and tool results, goes to
  `api.anthropic.com`, and Anthropic stores the session transcript", even when inference goes to Bedrock/Vertex.
- Connector tools (claude.ai connectors) execute **from Anthropic's infrastructure**, not from the box, so in an RC
  session they are an egress path that wicket's proxy never sees as a provider call (it sees only an
  `api.anthropic.com` MCP path). Deny them in RC zones.

IFC consequence: in `vendor_rc` mode the transcript sink is a declared destination with labels
`dest:anthropic.session_store{retention: 30d|5y, training: bool, devices: account}`. A zone whose data labels are not
cleared for it cannot run in `vendor_rc` mode; the zone compiler rejects the combination. The model API already sees
the same content, so the *additional* exposure is storage, device fan-out, and push text, plus the new ingress.

### 1.9 New channels RC adds that bypass wicket's gates [verified + inferred]

1. **Instruction ingress**: anyone holding the claude.ai session (a phone, a stolen browser session) can steer the
   agent, switch its permission mode (a `set_permission_mode` control request), change the model, approve tool calls,
   upload files into the box, and reconnect MCP servers. wicket does not see these unless it taps the channel.
2. **Exfil egress**: the transcript, diffs and file uploads go to Anthropic and to every device on the account.
3. **Cross-zone path**: *cross-session messaging* carries messages between the account's sessions on different
   machines "through Anthropic servers", which would connect two wicket zones outside every gate. Settings
   `crossSessionInbound: "refuse"` plus a deny on cross-session `SendMessage` turn it off, but those are agent-side
   settings, so the egress proxy must also deny the corresponding paths. [verified for the settings; endpoints E-RC3]
4. **Account API reach from the box**: a box that holds the account's full-scope OAuth token can call every
   `/v1/code/*` API: create triggers (scheduled cloud agents), webhooks, cloud sessions, channels, memory. Even a
   session-scoped JWT can post events to the session the human is reading. The egress proxy must path-allowlist
   `api.anthropic.com` (inference + this session's `worker/*` + required flag/JWKS calls) and deny the rest. [inferred
   H; exact required set E-RC3]
5. **UI impersonation**: whatever the agent writes appears in the same transcript the human reads. It can draw text
   that looks like a wicket approval request. wicket approvals must therefore never be answerable in RC chat text.
6. Native prompt fidelity is imperfect: the changelog has fixes for "a reply sent from `claude agents` to a background
   session waiting on a permission prompt sometimes approving the pending command" and "the Edit permission prompt
   preview sometimes showing a different location than the approved edit". Channel-relayed prompts carry a
   **model-written** `description` and a truncated, sanitized `input_preview`; the docs say "treat both fields as
   untrusted".

---

## 2. Equivalents for other agents (brief)

| Agent | Remote surface | Mechanics | Fit for wicket |
|---|---|---|---|
| **OpenAI Codex** | ChatGPT mobile/desktop "Remote connections" (GA mid-2026 per secondary sources) | Host is the ChatGPT desktop app on macOS/Windows; QR pairing per phone×host; "a secure relay layer keeps trusted machines reachable"; phone can start/continue chats, steer, **approve commands**, review diffs, terminal output and screenshots, and get notifications; SSH hosts run the Codex app-server over SSH. "Sandboxing settings, security controls, and action approvals still apply." [verified, <https://developers.openai.com/codex/remote-connections>] Relay crypto (Noise) claims are secondary sources only [unverified]. | No headless Linux host, so not usable for wicket's boxes today. Codex **app-server** (JSON-RPC) and `codex-acp` remain the T2 path; wicket's UI mirrors. |
| **Codex cloud / Claude Code on the web / Cursor / Copilot cloud agents / Devin** | Vendor-hosted sessions | The agent runs in the vendor's VM; the UI is the vendor's. | Not inner agents of wicket; prior art for the UI (§3). |
| **Gemini CLI, goose, OpenCode** | No vendor phone UI found. goose desktop and OpenCode's server/TUI split are local. | ACP over stdio; the ACP **Streamable HTTP & WebSocket transport** RFD (Transports WG, April 2026; Rust crate `agent-client-protocol-http` 2.x) would let a remote UI attach to an ACP agent. [verified that the RFD and crate exist; status draft] | wicket's adapter speaks ACP to the agent; wicket's own UI is the remote client. An ACP-over-WebSocket *front* on wicketd (wicket as ACP proxy/conductor) would let Zed or JetBrains act as a remote operator UI. |
| **ACP clients as remote UIs** (Zed, JetBrains) | Editors attach to agents via ACP | The client is the permission host. | If wicket exposes a per-session ACP endpoint (via the `Proxy`/`Conductor` roles of the official crate), an editor becomes an operator surface, but its "Allow" is still only an agent-local answer unless wicket maps it to a typed grant (§7). |
| **Third-party mobile wrappers** (Happy Coder `slopus/happy`; others) | Phone app for Claude Code/Codex | A local CLI wrapper spawns the agent, encrypts its event stream client-side, relays via its own server (self-hostable), and switches the agent between local and remote modes. [unverified: search summaries of the README only, L-M] | Design prior art for an **end-to-end-encrypted relay**: wicket's admin UI can reach a home box without opening ports, with the relay unable to read or forge approvals. |
| **Agent dashboards** (agent view `claude agents`, Conductor, Vibe Kanban, Coder Tasks, `coder/agentapi`) | Local multi-session dashboards | Mostly terminal-scraping or SDK/stdio wrappers. | UI ideas only; none mediates authority. |

---

## 3. Prior art: operator and oversight UIs

Gathered by a web-research sub-agent on 2026-11-08 and spot-checked against the Claude Code pages above. Markers as
it reported them: **[verified]** primary source read today, **[likely]** primary-source snippet or well-established,
**[unverified]** secondary or memory.

| Product | What the operator gets | Notable for wicket |
|---|---|---|
| **Claude Code on the web / app** [verified] (<https://code.claude.com/docs/en/claude-code-on-the-web>, `/mobile`) | Session sidebar; Changes card with diff view, **line comments that go to Claude with the next message**, compare-against-branch; queued messages retractable until read; permission mode switchable live (bypass mode not selectable from mobile); share/archive/delete; "Rewind to here"; PR creation and **Auto-fix** (subscribe the session to CI/review events); `claude -p "msg" --cloud <id>` queues a message from any machine; credentials stay outside the VM (GitHub proxy, network secrets). | Diff comments as steering; retractable queue; vendor already ships the injecting-proxy pattern. |
| **Docker Sandboxes `sbx`** [verified] (<https://docs.docker.com/ai/governance/local/approvals/>) | `sbx policy approval ls/inspect/respond <ID> --option allow|dismiss`; each entry shows sandbox, destination:port, protocol, **method + path**, and why it was blocked; duplicates collapse; allow creates an exact-destination rule for that sandbox only; the request itself is not held (agents retry); approvals never expire. TUI with sandbox cards and a network panel. | Closest productised analogue of wicket's escalation queue. Gaps wicket fills: no expiry, no typed effects/risk, no binding to an `Op` digest. |
| **OpenHands** [verified] (<https://docs.openhands.dev/sdk/arch/security>) | Tabs: Chat, Changes, VS Code, shared Terminal, App, view-only Browser. Confirmation policies AlwaysConfirm / NeverConfirm / ConfirmRisky using an LLM-filled `security_risk` per tool call. | The risk label is the agent's self-assessment: exactly what wicket must not trust (principle 4). |
| **Devin** [verified] (<https://docs.devin.ai/work-with-devin/devin-session-tools>) | Progress timeline (shell, edits, browser), read-only **Side Chats** while it works, **pause before takeover** (terminals flip read-only → writable), Slack keywords (`sleep`, `archive`, `EXIT`, `(aside)`), per-user Slack identity linking. | "Ask without steering" and explicit takeover. |
| **Cursor cloud agents** [verified] (<https://cursor.com/docs/cloud-agent>) | Web PWA, desktop, iOS, Slack, Linear, API; teammates read-only by default, follow-ups opt-in; **take control of the remote desktop and release it**; artifacts (screenshots, video, logs); domain egress limits. | Role split viewer / steerer; artifacts as first-class outputs. |
| **GitHub Copilot cloud agent** [verified] (<https://docs.github.com/en/copilot/how-tos/copilot-on-github/use-copilot-agents/manage-and-track-agents>) | Session log with tools, tests, **token usage and duration**; steering applied **after the current tool call**; Stop keeps pushed commits; commits link to the session log and are signed; "Approve and run workflows" needed for Actions on agent PRs (admins may opt out, 2026-03); the requester cannot approve [likely]; firewall writes blocked address + command into the PR. | Steering at tool-call boundaries; commit↔session audit links; requester ≠ approver. |
| **Codex cloud / remote** [verified] (<https://learn.chatgpt.com/docs/cloud.md>, remote-connections) | Per-environment allowlist and network secrets; follow-ups in the same task; QR pairing per phone×host with MFA/SSO/passkey; phone can approve commands; host rules still apply. | Pairing per host; host-side rules authoritative. |
| **E2B / Daytona / Modal** [likely] | CLI list/kill/logs/metrics; Daytona dashboard with web terminal, file browser, VNC and SSH, warning that terminal URLs are as sensitive as SSH credentials; audit logs; Modal list/terminate + OTel export. | Fleet view; "a terminal link is a credential". |
| **Temporal** [verified] (<https://docs.temporal.io/web-ui>) | Web UI Cancel/Signal/Update/Reset/Terminate; approvals via signals or (better) validated Updates with timeouts. | Durable, validated decision messages. |
| **Argo Workflows** [verified] | `suspend` node with **typed inputs** (`enum: [YES, NO]`, `default: NO`) rendered as a form on resume. | Typed resume, default-deny. |
| **LangGraph / Agent Inbox** [verified]/[likely] | `interrupt(payload)` + `Command(resume=…)`; node re-runs (idempotency needed); response schemas rendered as typed forms; Agent Inbox actions accept / edit / respond / ignore. | "Edit" = approve a narrower variant: maps to RAR narrowing. |
| **Inngest / Trigger.dev** [likely]/[verified] | `waitForEvent` with match key and timeout (null on timeout), second wait with another reviewer as escalation; Trigger.dev wait tokens with scoped public completion tokens, never expiring without a timeout. | Escalate-on-timeout; beware capability URLs without expiry. |

---

## 4. What operators need

Derived from §3 and from wicket's own model.

1. **Fleet view**: every zone and session with status (running, waiting on human, parked, killed), isolation tier,
   labels, resources, age, budget used, attached operators and surfaces (wicket UI, RC).
2. **Live transcript** with tool calls expandable per step, subagent progress, compaction markers, **origin badges**
   on every human message (wicket operator, RC operator, parent agent, channel), and free text from the box rendered
   inert.
3. **Steer**: queued follow-ups retractable until read; delivery at tool-call boundaries; an "ask without steering"
   side question that never reaches the agent's context (answered by a separate quarantined reader over the
   transcript); interrupt.
4. **Approval inbox**: wicket's typed escalations (§5), plus, separately labelled, the agent's own permission prompts.
5. **Lifecycle**: pause (freeze / park), resume, interrupt, stop-keep-artifacts, kill, revoke a grant subtree.
6. **Diff review**: the `extract(Patch)` handle rendered as a diff, line comments fed back as steering, "promote" as an
   explicit gate (push / PR) rather than a side effect of chat.
7. **Network and gate log**: denied and pending requests with the command that caused them (Copilot firewall, sbx
   panel); grants listed with expiry and revocable.
8. **Cost**: tokens, dollars and wall time per session against the zone budget, from the LLM proxy (or the egress
   tap in `vendor_rc` mode).
9. **Zone view and blast radius** ([design §12]) from the same session page: "what can this session reach right now".
10. **Audit**: who decided what, on which surface and device, with which assertion.

---

## 5. Approval UX that resists approval phishing

The threat: a compromised agent (or an injected page it read) wants a human to approve something. Its tools are
persuasive prose in the transcript, look-alike requests, floods that cause fatigue, and timing.

1. **Render only the typed request** from wicket's ledger: provider, verb, resources, effects, derived risk, budget
   (uses, TTL), the delta against the current zone ceiling, and **field provenance** (which fields come from task
   text, the manifest or an existing grant, and which only from the agent: highlighted). The agent's justification is
   collapsed in an "untrusted, written by the agent" box ([design §10]). Prior art: RAR `authorization_details`,
   Argo typed inputs, sbx method + path, Google PAM's own warning that justifications are unvalidated.
2. **Binding code** (CIBA `binding_message`): a short code derived from the `Op` digest appears in the problem+json the
   agent sees and in the approval UI. It lets a human who saw a request mentioned in a transcript, Slack or a call
   confirm they are deciding *that* request. It is not authentication. For R3+ the approver types it back (Duo
   Verified Push / number matching, CISA guidance).
3. **Approve only on a surface wicket controls end to end**, with **per-action WebAuthn step-up** (`userVerification:
   required`, `challenge = H(canonical typed request ‖ decision ‖ narrowing ‖ nonce)`). The assertion is verified by
   `wicketd`, not by the web front end, so a compromised UI process cannot mint approvals. (Secure Payment
   Confirmation would let the browser render the bound fields itself, but is payments-only; WebAuthn `txAuthSimple` was
   dropped.)
4. **Narrow choices**: once / N uses / N minutes, exact resource; "edit" means approve a narrower variant (Agent
   Inbox), never wider. No "always". Default-deny on expiry; escalate to a second operator on timeout (Inngest).
5. **Requester ≠ approver**: an agent never approves its own request; a human who *started* a task can be barred from
   approving its R4 requests (GitHub "prevent self-review"); quorum (two-person) for configured classes (Teleport).
6. **Fatigue controls**: duplicate requests collapse (sbx); rate limits per zone (already in [design §11]); a request
   class denied repeatedly auto-mutes and alerts; a **"report unexpected"** button that freezes the session (Duo fraud
   report).
7. **Never approvable from free text**: not from RC chat, Slack text or email replies. The agent can write "reply YES
   to approve R-123" into any transcript; the reply would be agent-reachable text. Channels permission relay uses
   `yes <id>` replies only because the channel authenticates the sender, and its own docs call the displayed fields
   untrusted.
8. **Lock screen**: deny, snooze, open and report are safe; **approve is not** (no user verification, shoulder
   surfing, reflex taps). Only a future native companion app with an in-app signature over the request hash could
   offer approve from a notification.

---

## 6. Auth, push and multiple operators for wicket's admin surface

**Auth (single owner plus an occasional second operator)** [design recommendation from §3 sources]:

- Network: `wicketd` and the console listen on loopback or a Unix socket only. Remote reach via **Tailscale** (`tailscale
  serve`, which injects `Tailscale-User-Login` and strips spoofed copies; verify again via LocalAPI WhoIs; reject
  tagged devices for human actions), or via an end-to-end-encrypted relay in the Happy/Codex style when there is no
  tailnet. Never a public listener. Cloudflare Access (validate `Cf-Access-Jwt-Assertion` against team certs + AUD) only
  if public exposure is unavoidable, and still with passkeys behind it.
- Login: **passkeys** (WebAuthn, UV required), short sessions. Per-action step-up for approvals, kill, policy and
  operator management.
- Host CLI: Unix socket with `SO_PEERCRED`; the break-glass path that always works.
- Machine clients (parent agents are not operators; CI; scripts): mTLS or short-lived signed tokens with a
  `viewer`/`steerer` role at most.
- Roles: `viewer`, `steerer`, `approver(max_risk)`, `admin`. Each operator has their own passkeys; nothing is shared.
- OIDC for organisations later; the operator registry maps OIDC subjects and, for `vendor_rc`, the claude.ai account
  UUID (from the verified session JWT, see §7.3) to wicket operators.

**Push**:

- Primary: **Web Push (VAPID) to the wicket PWA**. Payload encrypted (RFC 8291), contains only request id, binding
  code, risk class and a one-line typed summary whose fields are cleared for `dest:push_provider` (default: no content
  at all). Tap opens the approval page with step-up. Do not rely on action buttons (inconsistent on iOS).
- Secondary: self-hosted **ntfy** (Android, desktop); actions limited to Open / Deny / Snooze; never embed an approval
  capability in an `http` action (not end-to-end encrypted; the URL is a bearer token). **Pushover** emergency priority
  for paging (ack ≠ approve).
- Presence suppression like `CLAUDE_CLIENT_PRESENCE_FILE`: no pushes while the owner is active in the console.
- On this box today the owner already gets RC pushes from the Claude app; wicket pushes should be distinguishable
  (separate app/PWA) so a wicket approval can never be confused with a Claude prompt.

**Multiple operators**:

- Decisions are compare-and-set ledger transitions (`PendingHuman → Granted|Denied`); first valid decision wins, the
  others see "decided by X on device D at T". Quorum classes collect N distinct operators.
- Steering is not locked (Claude RC lets everyone type), but the transcript shows who sent what. **Takeover** (direct
  shell into the box, Devin/Cursor style) requires pausing the agent and is logged as an operator session, with its
  own labels.
- Teleport-style **moderated sessions** for high-risk zones: a session runs only while a moderator is attached; on
  leave it pauses.
- Presence: the console shows who is watching; RC presence is invisible to wicket (only the vendor knows).
- A human who reads zone A's transcript and types into zone B is a human declassifier. wicket cannot prevent it, but
  it records which labelled views an operator opened recently and shows a warning when they steer a zone those labels
  are not cleared for.

---

## 7. Recommended design for wicket

### 7.1 One abstraction, two families

```rust
/// A surface through which humans observe and act on sessions.
pub trait OperatorChannel: Send + Sync {
    fn id(&self) -> ChannelId;
    fn family(&self) -> ChannelFamily;            // WicketNative | VendorNative
    fn authority(&self) -> ChannelAuthority;      // the most this surface may ever do
    fn label_clearance(&self) -> LabelSet;        // what data may be shown/sent here (a destination for IFC)
    async fn publish(&self, ev: &OperatorEvent) -> Result<()>;   // transcript deltas, escalations, state
    fn inbound(&mut self) -> BoxStream<'_, OperatorInput>;
}

pub enum ChannelKind { Api, Web, Cli, Push(PushKind), VendorRc(RcFlavour), AcpFront }
pub enum RcFlavour { Bridge, SelfHostedRunner }

pub struct ChannelAuthority {
    pub observe: bool,
    pub steer: bool,                     // send messages / interrupt
    pub answer_agent_prompts: bool,      // agent-local consent only
    pub decide_escalations: Option<RiskClass>, // None for every VendorNative channel
    pub lifecycle: LifecycleOps,         // pause/park/kill/revoke: WicketNative only
    pub amend_task: bool,                // typed task amendment: WicketNative only
}

pub struct OperatorInput {
    pub principal: Option<OperatorId>,   // None if wicket cannot authenticate the sender
    pub evidence: AuthEvidence,          // PasskeyAssertion{..} | PeerCred | Mtls | TailscaleIdentity
                                         // | VendorAttested{account, device_status} (observed, never verified by wicket)
    pub channel: ChannelId,
    pub payload: InputPayload,           // Steer(Untrusted<Text>) | Attach(Handle) | Decide{request, digest, code, decision, assertion}
                                         // | AnswerAgentPrompt{prompt_id, allow} | Lifecycle(op) | AmendTask(TypedAmendment)
}
```

| Capability | wicket web/PWA | wicket CLI (host) | push | vendor RC | ACP front (editor) |
|---|---|---|---|---|---|
| observe | yes (label-filtered) | yes | summary only | yes, **everything** (vendor shows the full transcript) | yes |
| steer | yes | yes | no | yes | yes |
| answer agent-local prompts | yes (marked) | yes | no | yes (first answer wins) | yes |
| decide wicket escalations | yes, up to role's max risk, with step-up | yes | deny/snooze only | **never** (§7.3) | never |
| pause / park / kill / revoke | yes, with step-up | yes | deny-and-freeze ("report unexpected") | interrupt and end session only (agent-level) | interrupt |
| amend task (typed) | yes | yes | no | no | no |

### 7.2 Per-zone operator mode, compiled like everything else

`operator_mode` is a zone property the zone compiler checks against the zone's labels and ceiling:

- **`wicket` (default).** T1 stdio launch exactly as [design §6]: LLM proxy via `ANTHROPIC_BASE_URL`, placeholder
  credential, nonessential traffic off. wicket is the SDK host; it answers `can_use_tool` itself (allow inside the
  ceiling, deny on mirrored deny rules) or forwards the prompt to operator channels as an **agent-local prompt** when
  the zone sets `agent_prompts: ask_operator`. Remote comfort comes from wicket's PWA + push over Tailscale. No RC.
- **`vendor_rc` (opt-in, Claude Code only).** Required, and checked by the compiler:
  1. The zone's data labels are cleared for `dest:anthropic.session_store` and `dest:account_devices` (transcript,
     diffs, files, push text), and for the account's retention/training setting. ZDR or confidential zones cannot use
     it.
  2. Subscription credential: a claude.ai login owned by a registered operator. The zone view shows a **vendor
     credential in the box** (bridge flavour: account-wide; self-hosted flavour: ~30-minute session-scoped token)
     until E-RC2 shows it can be swapped at the proxy.
  3. Model route: `ANTHROPIC_BASE_URL` unset; the LLM-proxy functions (budget, liveness, taint from server tools) move
     to the egress proxy's TLS-intercepted `api.anthropic.com` adapter ([01 §1.9] option B).
  4. Egress: `api.anthropic.com` path-allowlisted to inference, this session's `/v1/code/sessions/{id}/worker/*`, and
     the required flag/JWKS/refresh calls (E-RC3). Deny `/v1/code/triggers`, `webhook-triggers`, `channels`,
     `memory`, other sessions, `environments` (unless this is the bridge itself), and the connector MCP paths. SSE
     passes unbuffered.
  5. Agent-side settings (root-owned managed settings, telemetry only but cheap): `crossSessionInbound: "refuse"`,
     deny cross-session `SendMessage`, `disableClaudeAiConnectors`, `isolatePeerMachines: true`, deny rules mirroring
     the ceiling, permission mode `auto` or `acceptEdits` (real enforcement is at the gates; prompts that remain go to
     the phone).
  6. Process layout. *Bridge flavour* (Pro/Max/Ultra; works on this box): `claude remote-control --spawn session` runs
     on the **host** under wicket's supervision, with `CLAUDE_CODE_PROCESS_WRAPPER` pointing at `wicket-jail exec
     --zone <z>`, which builds the box and `exec`s the session binary inside it with stdin/stdout preserved. One bridge
     per zone keeps sessions and directories separate. *Self-hosted flavour* (Team/Enterprise): a self-hosted
     environment per trust class, an on-demand runner per session (environment secret stays on the orchestrator host),
     `--exec-path` = the same wicket wrapper, `--capacity 1`, `--confine-repo-settings enforce`. wicket can also
     **dispatch** a task into it (`claude --environment ccpool_…`) so the human watches a wicket-started task in
     claude.ai.
  7. wicket's own console mirrors the session from the egress tap (read-only parse of the SSE and POSTed events),
     shows RC-origin messages with an origin badge, and keeps every wicket control (escalations, pause, kill, grants).
     wicket → agent messages ("R-123 granted, retry") use the normal pending path (`wicket.await_grant` returns, or
     the HTTP retry succeeds), optionally a wicket **Channel** (`<channel source="wicket">`) once Channels allow it.

`vendor_rc` is a convenience, not a security feature: it adds a destination and an instruction ingress. The design
should make the comfortable default wicket's own PWA, and treat RC as "also watch it in the Claude app".

### 7.3 How approvals relate to escalation

Two kinds of decisions exist and must never be conflated:

| | Agent-local prompt | wicket escalation |
|---|---|---|
| Source | Claude Code `can_use_tool`, ACP `session/request_permission`, Codex approvals | A gate denied an `Op` and opened a typed request |
| Effect of "allow" | The agent may *attempt* the action inside the box | A ledger grant: the gate will let matching `Op`s through |
| Where answerable | Any channel with `answer_agent_prompts` (wicket UI, RC, editor) | wicket-native channels only, with step-up |
| Trust | Advisory, like all in-box controls ([design §2.1]) | TCB decision |

**Is an RC approval ever a wicket grant? Default: never.** Reasons: the answer reaches wicket only through the box
(hostile) or through a private vendor protocol; the prompt the human saw was rendered by Claude Code with a
model-written description and truncated preview; Anthropic and the claude.ai account security join the TCB; the agent
controls the surrounding transcript.

A fenced research option, **`rc_attested_approvals`**, off by default and limited to risk ≤ R1 without
`notify.external` or exfiltration effects, could accept one only if *all* hold:

1. The agent asked through wicket's `wicket.request_access` MCP tool, so the `can_use_tool` input contains the wicket
   request id, digest and binding code in fields short enough to appear untruncated in `input_preview`.
2. wicket's egress proxy observes, on the **server → box** SSE stream (TLS terminated by wicket, so the box cannot
   inject into it), the matching approval frame with `device_attestation_status` = `VERIFIED`, before the box acts.
3. The approving account maps to a wicket operator with approver role, verified through the session JWT against
   Anthropic's JWKS (documented for self-hosted sessions:
   <https://code.claude.com/docs/en/self-hosted-environments-identity>), and the org requires Trusted Devices.
4. The protocol version is one wicket's conformance suite has pinned.

Even then it is weaker than a wicket passkey approval and should be measured in shadow mode first, like the parent
tier. Every other RC answer is logged as telemetry ("operator allowed Bash `…` via RC") and changes nothing at the gates.

Conversely, wicket never answers a Claude Code prompt on the human's behalf in `vendor_rc` mode. If the human wants
the wicket view of a pending agent prompt, the console shows it read-only with "answer it in the Claude app".

### 7.4 Labelling human messages into an agent

Every inbound message gets an `Origin` that is stored, shown, and used by policy:

| Origin | Example | Integrity | May be provenance for escalation fields? |
|---|---|---|---|
| `operator(wicket, principal, assertion)` with `AmendTask` | "also update `docs/ci.md`" as a typed amendment | trusted | **Yes**: appended to the zone's trusted task-text chain (signed in the ledger), so a later request for that path passes the provenance check (it still needs a decision). |
| `operator(wicket, principal)` free-text steer | "try the other approach" | trusted author, untrusted as authority | No. Steers within the existing ceiling only (principle 6: free text doesn't widen authority). |
| `operator(vendor_rc, account)` | message typed in the Claude app | author vendor-attested, not wicket-verified | No. Logged with origin; the zone treats it like the steer row. |
| `operator_forwarded(…)` | an email, log or file the human pasted or attached | **untrusted content** carried by a trusted human | No. Labelled with the content's own labels (or the zone's default for unknown content) and taint, because a human forwarding a poisoned page is the classic injection path. The console offers two buttons: **Instruct** and **Attach as data**. |
| `agent(parent)` | `wicket.send` from the parent zone | typed fields only ([design principle 6]) | Only through typed fields. |
| `system(wicket)` | "R-123 granted; retry" | trusted | n/a |

The agent may be shown a short header (`[operator alex via wicket]`, `<channel source="wicket">`) to help its own
injection resistance, but enforcement never depends on what the agent believes about origins.

Confidentiality: operator messages carry the labels of anything they attach. RC attachments arrive via the session
channel into the box: the egress tap labels them `operator_forwarded(vendor_rc)`.

### 7.5 Consistency between surfaces

- **`wicketd` is the source of truth** for zone and session state, grants, pending escalations, budgets and labels.
  Channels are projections of one ordered event log (sequence numbers, resumable subscriptions), so the web UI, CLI
  and push never disagree about wicket state.
- **Transcript**: `wicket` mode: wicket's stdio copy is authoritative. `vendor_rc` mode: two copies, Anthropic's
  (feeds RC) and wicket's tap (feeds the console and the audit log). Divergence (tap parse failure) is shown as a gap,
  not hidden.
- **Agent-local prompts**: first answer wins on every surface (Claude Code's own rule, also for channel relay); wicket
  records which surface answered when it can see it.
- **Lifecycle across surfaces**: a wicket pause or park freezes the box; RC then shows "can't reach" and wicket's push
  explains why. A park longer than the RC resumability window (about 4 hours for bridge sessions; lease and requeue
  rules for runners) may lose the RC session: wicket must then re-serve it (`claude remote-control --session-id`) on
  restore (E-RC4). An RC "end session" or archive is fail-narrow and accepted; wicket records an operator-initiated
  finish and still runs the outcome gates.
- **Kill switch for RC alone**: denying the session-channel paths at the egress proxy disconnects RC while the agent
  keeps running under wicket (for example when a zone's labels change mid-task, or when an RC device is reported
  lost).

### 7.6 Security risks

**RC as an unmediated channel** (mitigations in brackets):

1. Exfiltration of everything tool output contains to Anthropic storage and to every device on the account [label
   clearance at compile time; `vendor_rc` only for cleared zones; ZDR-class zones excluded].
2. Instruction ingress from anyone holding the claude.ai account on any device, including permission-mode changes
   and file uploads into the box [Trusted Devices on; enforcement at gates makes in-box mode changes irrelevant to
   authority; attachments labelled and tainted; RC kill switch].
3. Account-API reach from the box with the subscription credential (cloud sessions, triggers, webhooks, memory,
   connectors executed on Anthropic's side) [path allowlist; prefer the self-hosted flavour's session-scoped token;
   E-RC2 placeholder swap].
4. Cross-zone messaging through Anthropic (cross-session `SendMessage`) [managed settings + path denies; E-RC3].
5. UI impersonation and approval phishing in the transcript [no approvals from free text; distinct wicket push/app;
   binding codes].
6. Protocol drift: the session protocol is private and changes near-daily; a tap that breaks silently blinds wicket's
   audit [conformance suite pins versions; tap failure flips the zone to "RC disconnected" by policy].
7. Terms: wicket must not emulate Claude Code's OAuth client or automate login/refresh; the owner signs Claude Code in
   on the host. RC for wicket-as-a-product means "your own Claude subscription, used by Claude Code itself", to be
   checked against the consumer/commercial terms before shipping.

**wicket's admin UI as the highest-value target** (it can widen authority up to the org ceiling):

1. Split it: `wicket-console` (HTTP, rendering, sessions) holds no ledger write access; `wicketd` verifies every
   decision's WebAuthn assertion against the operator's registered key with a challenge bound to the request digest.
   A compromised console can show wrong things but cannot mint grants.
2. No public listener; Tailscale identity + passkeys; per-action step-up; short sessions; strict CSP; `SameSite=Strict`;
   `frame-ancestors 'none'`.
3. Everything from the box is attacker-controlled: render as inert text; no markdown images or auto-links (image-URL
   exfiltration); strip bidi/invisible characters; show truncation explicitly; open diffs in a sandboxed frame.
4. Operator management (adding a passkey, a second operator, changing roles or quorum) needs step-up and is announced
   on every other registered device (Claude's "you will also get an email" pattern).
5. Rate limits and anomaly alerts on decisions (new device, burst approvals, approvals outside usual hours).
6. Append-only, hash-chained audit log of every operator action, exported off the box.
7. Break-glass: host CLI over `SO_PEERCRED`, works with the console down.
8. Push payloads carry no data by default; capability URLs never appear in notifications.

---

## 8. What this changes in the design doc

- §6: add `operator_mode: wicket | vendor_rc{bridge|self_hosted}`; record that RC is incompatible with the default T1
  launch and what `vendor_rc` changes (subscription credential, base URL, egress-side LLM adapter, path allowlist).
- §8.1: the egress proxy gets an `anthropic-session` adapter (observe-only parse of SSE + worker events; whole-channel
  cut) and must not buffer `text/event-stream`.
- §10 "Human channel": replace "CLI plus a push notification, later a web UI" with the `OperatorChannel` model: CLI,
  API, PWA with passkey step-up, Web Push/ntfy; RC answers are agent-local only.
- §12: the zone view shows operator channels as edges: RC as a destination + ingress, with its retention, and any
  vendor credential in the box.
- §13 crates: `wicket-operator` (channel trait, event log projection, push), `wicket-console` (untrusted web front end).
- §16: new open questions = the experiments below.

---

## 9. Experiments

| Id | Question | How | Decides |
|---|---|---|---|
| **E-RC1** | Does a jailed RC session work through wicket's TLS-intercepting egress proxy? | Host bridge with `CLAUDE_CODE_PROCESS_WRAPPER` → `wicket-jail`; box egress only via the proxy with wicket's CA; log every host and path for 30 minutes of normal use from the phone (messages, prompts, diff pane, attachments, model change). | Whether `vendor_rc` bridge flavour is viable; the required host/path set. |
| **E-RC2** | Can the box run without the account credential? | In the jail give the child a `CLAUDE_CONFIG_DIR` without the stored login and `CLAUDE_CODE_OAUTH_TOKEN` = placeholder; have the proxy inject the host's current access token for `/v1/messages`, and swap a placeholder `CLAUDE_CODE_SESSION_ACCESS_TOKEN` for the real one on the session paths. Check behaviour with Trusted Devices on (client-event signing key location). | Whether `vendor_rc` can keep principle 2, or must be shown as "vendor credential in box". |
| **E-RC3** | Minimum `api.anthropic.com` path set; does denying the rest break the session? | From E-RC1 logs, build the allowlist; deny triggers, webhooks, channels, memory, other sessions, cross-session messaging, connectors; replay the 30-minute script. | The adapter's path rules. |
| **E-RC4** | Parking and RC | Freeze for 5 min, 1 h, 5 h; gVisor checkpoint/restore; check whether the session re-registers (`worker_epoch`, lease) or needs `--session-id` re-serve. | Parking rules for `vendor_rc` zones. |
| **E-RC5** | Does the egress tap see enough to mirror the transcript and detect RC-origin messages and approvals reliably? | Parse SSE inbound frames and POSTed outbound events across three Claude Code releases. | Whether the console mirror and `rc_attested_approvals` research are possible at all. |
| **E-RC6** | Self-hosted flavour | If a Team/Enterprise org is available: on-demand runner with the wicket wrapper; verify session JWT via JWKS; dispatch with `--environment`. | Whether the org flavour is the better `vendor_rc` path. |
| **E-OP1** | Approval UX | Red-team: an injected agent tries to get a human to approve via transcript prose, look-alike requests and floods, against the §5 UI; measure wrong approvals. | Whether binding codes / typed-only rendering are enough, or R3+ needs quorum. |

---

## 10. Sources

Primary (read 2026-11-08):

- Remote Control: <https://code.claude.com/docs/en/remote-control>
- Self-hosted environments: <https://code.claude.com/docs/en/self-hosted-environments>, `…-deploy`,
  `…-configuration`, `…-reference`, `…-identity`, `…-testing`
- Channels: <https://code.claude.com/docs/en/channels>, <https://code.claude.com/docs/en/channels-reference>
- Cross-session messaging: <https://code.claude.com/docs/en/cross-session-messaging>
- Corporate launcher / `CLAUDE_CODE_PROCESS_WRAPPER`: <https://code.claude.com/docs/en/corporate-launcher>
- Data usage, ZDR, security, feature availability, env vars, settings reference:
  <https://code.claude.com/docs/en/data-usage>, `/zero-data-retention`, `/security`, `/feature-availability`,
  `/env-vars`, `/settings-reference` (`disableRemoteControl`, `remoteControlAtStartup`, `dialogExpiry`,
  `processWrapper`, `crossSessionInbound`)
- Claude Code on the web: <https://code.claude.com/docs/en/claude-code-on-the-web>
- Changelog: <https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md> (2.1.139 API key disables RC;
  2.1.196 non-Anthropic base URL disables RC; 2.1.238 403 tolerance; 2.1.281 confirmation debounce; permission-prompt
  fidelity fixes)
- `claude --help`, `claude remote-control --help`, `claude daemon --help` (2.1.319)
- Codex remote connections: <https://developers.openai.com/codex/remote-connections>
- ACP transports: <https://agentclientprotocol.com/rfds/streamable-http-websocket-transport>,
  <https://agentclientprotocol.com/announcements/transports-working-group>
- Prior art and approval/auth/push sources: as linked inline in §3, §5 and §6 (Docker `sbx`, OpenHands, Devin, Cursor,
  GitHub Copilot, Temporal, Argo, LangGraph, Trigger.dev, OpenID CIBA, Duo, CISA number matching, Teleport, GitHub
  Environments, Tailscale Serve, Cloudflare Access, W3C SPC, ntfy, Pushover, MDN Notification actions).

Observed on this box (read-only): `ps` process tree of the Remote Control service; `/proc/<pid>/environ` variable **names** for two
RC sessions (values printed only for `CLAUDE_CODE_ENVIRONMENT_KIND`, `CLAUDE_CODE_SESSION_KIND`,
`CLAUDE_CODE_ENTRYPOINT`, `CLAUDE_CODE_BRIDGE_*_ENTRYPOINT`, `CLAUDE_CODE_BRIDGE_MCP_CARRIER`); `ss -tnp`;
`strings` on `~/.local/share/claude/versions/2.1.319` (endpoint paths, `--sdk-url` origin check, transport class
names, attestation statuses).

Secondary, low confidence: Codex Remote GA date and relay crypto (codex.danielvaughan.com, mcp.directory); Happy Coder
architecture (github.com/slopus/happy via search summaries).
