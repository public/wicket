# 12 — OpenClaw: overlap, security lessons, and OpenClaw as an inner agent

*2026-11-08. Researched for the owner's note "OpenClaw has overlap with wicket and is worth researching". pi itself
is covered in [11 §1] and not repeated.*

**Confidence marks:** **[H]** = read in primary source (code or the project's own docs at the commit below, or
GitHub/npm data pulled directly); **[M]** = reputable secondary source, or inferred from primary source;
**[U]** = unverified.

**Sources collected (read only; nothing built, installed or run; in-repo `AGENTS.md`, `CLAUDE.md`, `.agents/skills`
treated as data):**

| Local path | Upstream | Commit / date | Licence |
|---|---|---|---|
| `refs/repos/openclaw` (sparse: `docs/`, `src/` without tests, `CHANGELOG/`, `security/`, top-level files, extension manifests) | `github.com/openclaw/openclaw` | `97fd50313ca6` (2026-11-08), `package.json` **2026.11.1** | MIT |
| `refs/repos/clawhub` (sparse: `docs/`, top-level) | `github.com/openclaw/clawhub` | `547b484e29fa` (2026-11-08) | MIT |

Ecosystem projects (NanoClaw, IronClaw, NVIDIA OpenShell/NemoClaw, OpenClaw Enterprise, OneCLI) were read on GitHub
and their docs sites, not cloned (§7).

---

## TL;DR

1. **What it is now.** OpenClaw is Peter Steinberger's self-hosted personal assistant. It started as "Clawd" /
   **Clawdbot** (Nov 2025), was renamed **Moltbot** on about 27 Jan 2026 after Anthropic's legal team asked, and
   became **OpenClaw** on 29–30 Jan 2026. Steinberger joined OpenAI in Feb 2026. Since Jul 2026 the project has been
   stewarded by the **OpenClaw Foundation** (US 501(c)(3); chair Dave Morin; donors include OpenAI, Amazon and Red
   Hat). It is MIT-licensed, has **394k GitHub stars**, sees **2.8M npm downloads a week**, and uses calendar
   versions: GitHub release **v2026.11.1** (5 Nov), npm `latest` 2026.11.2, extended-stable 2026.9.36. There is no
   hosted or paid tier. Microsoft's Copilot "Autopilot" is built on it. [H, §1]
2. **"Built on pi" is history.** In **2026.5.22** OpenClaw "internalize[d] the former Pi agent runtime" into its own
   `@openclaw/agent-core`, and `pi` is now only a config alias for the built-in `openclaw` runtime. Only
   `@earendil-works/pi-tui` remains as a dependency. Besides its own loop, OpenClaw now **hosts other harnesses**:
   Codex app-server, Claude Code (through its stdio protocol), Copilot, and ACP agents. In that respect it is itself
   a harness host. [H, §2.5]
3. **Architecture.** There is one long-lived Node **Gateway** per host (WS + HTTP on `127.0.0.1:18789`). It owns
   every channel connection (~25 chat networks), the agent loop, model calls, plugins, MCP clients and all
   credentials. Operators, nodes and workers connect over one JSON-Schema'd WebSocket protocol with roles, scopes
   and signed device pairing. **Nodes** (Mac/iOS/Android/headless) are paired devices that expose
   `system.run`, camera, screen and similar commands, i.e. remote execution. [H, §2]
4. **Security model, in its own words:** "one trust boundary per gateway". Anyone who can message a tool-enabled
   agent shares its delegated authority. Plugins are in-process TCB. Sandboxing is **off by default**, and when it
   is on, it moves **only tool execution** into Docker/Podman/SSH/OpenShell. The Gateway, the model key, plugins and
   MCP tools stay on the host. SECURITY.md lists **public internet exposure, prompt-injection-only chains, and
   attacker writes to `MEMORY.md`** as out of scope. [H, §3]
5. **It has rebuilt much of wicket inside the process.** Recent releases added:
   - typed delegation of config changes with human approval;
   - exec approvals bound to argv, cwd, env, executable real-path and content hash, re-checked at spawn;
   - durable first-answer-wins approval records across surfaces;
   - standing grants bound to an automation's definition;
   - an LLM exec reviewer;
   - per-session permission modes;
   - a **"secret egress proxy"** that gives subprocesses authenticated `oc-sent-v2…` sentinels and substitutes them
     only at bound HTTPS hosts (since about 2026.7–8);
   - Proxyline whole-process egress routing to an operator proxy.

   All of this is enforced **inside the same process as the agent**, and much of it is cooperative: their own docs
   say the egress allowlist "constrains only cooperating clients". [H, §3.7]
6. **Track record.** See §4. Notable incidents: CVE-2026-25253 (one-click RCE through gateway-token exfiltration),
   tens of thousands of internet-exposed gateways, the **ClawHavoc** campaign (341 malicious skills out of 2,857 in
   early Feb 2026, mostly infostealers), prompt injection through email and chat, and Moltbook's exposed database
   (over 1M agent API tokens). The project responded with a VirusTotal partnership, then ClawScan (Tencent A.I.G +
   NVIDIA SkillSpector + an LLM judge), a Trail of Bits audit, the security audit tooling, and the egress work. [§4]
7. **Operator-channel lesson.** OpenClaw lets people **approve exec from chat**: `/approve <id> allow-once|always`,
   native buttons on Slack/Discord/Telegram/Matrix, **emoji reactions** on WhatsApp/Signal/Matrix. The approver is
   whoever the chat platform says sent the message (numeric Telegram ID, phone number). The agent itself is told to
   relay `/approve` instructions into the chat. This is the opposite of wicket §13.1, and it is the case study for
   why wicket's rule should stay as it is. It also shows what wicket's chat-side *notices* need to do comfortably.
   [H, §5]
8. **Positioning.** The overlap is the gateway/control plane, sandbox placement, tool policy, approvals, channels and
   multi-agent routing. The difference is that OpenClaw is a **personal assistant with in-process policy**, while
   wicket is a **meta-harness with external enforcement**. OpenClaw's own enterprise track (OpenClaw Enterprise +
   NVIDIA OpenShell) is converging on wicket's architecture: a control-plane decision point, a supervisor
   enforcement point outside the sandbox, and a credential proxy that checks a grant before attaching a GitHub App
   token. [H/M, §6–7]
9. **Integration.** Two clean seams:
   - **(a) OpenClaw as an inner agent.** Box the whole Gateway. Point model providers at wicket-llm with a
     placeholder, and Proxyline at wicket-egress. wicket connects as an operator client and as the **exec-approval
     client** over the Gateway protocol, which makes it T1-like; `openclaw acp` is the T2 alternative.
   - **(b) wicket as an OpenClaw sandbox backend.** `registerSandboxBackend` in the plugin SDK, plus
     `createRemoteShellSandboxBackend`, make a wicket backend about one `buildCommand` function. It governs only the
     "hands".

   Both are feasible. Neither removes the end-to-end channel keys (WhatsApp, Signal, Matrix E2EE) from the box.
   The recommended pattern is **OpenClaw as a tainted "front-desk" zone with messaging-only tools, delegating work to
   wicket zones through `wicket.spawn`**: the reader/actor privilege separation that [05] found most effective
   (§6).
10. **Biggest design changes for wicket** (§8):
    1. an **Ingress** surface (inbound messages and webhooks as labelled, admitted `Op`s);
    2. **standing zones** for long-lived assistants whose memory persists;
    3. chat apps as announce-and-steer operator channels with origin labels per sender, never deciders;
    4. **credential placements** beyond headers (URL path, Basic auth, WebSocket frames, and E2E session keys that
       cannot be moved out of the box);
    5. an OpenClaw adapter and a backend plugin;
    6. approval-binding properties borrowed from OpenClaw;
    7. about 30 attack cases (§10).

---

## 1. What OpenClaw is (verified)

- **Identity.**
  - Repo `openclaw/openclaw`, created 2025-11-24. MIT. 394,177 stars and 82.8k forks on 2026-11-08. 3,765
    contributors. Homepage openclaw.ai, docs at docs.openclaw.ai, Foundation at openclaw.org. [H: `gh api`]
  - `package.json` version `2026.11.1`. `engines.node` `>=24.16.0 <25 || >=26.1.0`. [H]
- **History** [H: openclaw.ai/blog/introducing-openclaw; npm registry; M for press]:
  - "Clawd" was born in Nov 2025 as a WhatsApp relay. The npm package `clawdbot` was created 2026-01-04.
  - **Moltbot**, 2026-01-27: "Anthropic's legal team politely asked us to reconsider". The press calls it a trademark
    request. [M]
  - **OpenClaw**, 2026-01-29 (npm `openclaw` created that day): "trademark searches came back clear".
  - The old changelog directory `.clawdhub` was still read until July 2026 (`docs/tools/skills.md`). [H]
- **Founder and governance:**
  - Steinberger joined OpenAI around 14–15 Feb 2026 to lead "the next generation of personal agents". [M: Bloomberg]
  - The OpenClaw Foundation was announced on 2026-07-08 [H: openclaw.ai/blog/introducing-openclaw-foundation]:
    - 501(c)(3); chair Dave Morin; Steinberger is "Clawfather" and still makes the technical calls;
    - 10 full-time staff at launch;
    - councils on agent identity, profiles, evals and enterprise.
  - The README says the Foundation "employs the core team and signs releases" and that "OpenAI is a donor, not an
    owner". The `why-openclaw` page lists Amazon, Atlassian, GitHub, Microsoft, NVIDIA, OpenAI, Red Hat and Tencent
    among more than 30 partner organisations. [H: `README.md`, `docs/start/why-openclaw.md`]
- **Releases:**
  - Monthly `YYYY.M.patch`, with `latest`, `beta` and `extended-stable` channels (monthly from `.33` with backports).
    In October there were 17 stable releases. [H: releases API; openclaw.ai blog, 30 Jul 2026]
  - The split changelog has 139 files under `CHANGELOG/`. [H]
- **Adoption:**
  - npm: 2.80M downloads in the week of 1–7 Nov 2026; 14–15M a month since June. [H: api.npmjs.org]
  - Microsoft Autopilot (Copilot's persistent agent) "is built on OpenClaw" (25 Sep 2026). [H: openclaw.ai blog]
  - Kakao, Naver and Karrot restricted it on corporate networks (Feb 2026). [M: Korea Times]
- **Scale of the code.** 65.5k tracked files: 29k in `src/`, 12.9k in `extensions/` (184 bundled plugins), 1.5k
  docs pages. The repo is about 13.5 GB including history. [H]

**Correction to the brief.** "Built on pi" was true until May 2026. Since then pi is an ancestor, and OpenClaw
uses its own fork (§2.5). Everything else in the brief checks out: Gateway/control plane, many channels, multi-agent
routing, ClawHub skills, sandboxing, tool policies, exec approvals, nodes, remote access. It also understates how
much has been added: permission modes, typed delegation, the egress proxy, cloud workers, multi-user roles and an
enterprise control plane.

---

## 2. Architecture

### 2.1 The Gateway process

`docs/concepts/architecture.md`, `docs/gateway/protocol.md` [H]:

- **One Gateway per host.** It is "the only place that opens a WhatsApp session" and "owns all messaging
  surfaces". Default bind `127.0.0.1:18789`, serving both WebSocket and HTTP (Control UI, `/__openclaw__/canvas/`,
  optional OpenAI-compatible `/v1/chat/completions` and `/v1/responses`, `/tools/invoke`).
- **In the same process:**
  - the agent loop (`src/agents/embedded-agent-runner/`);
  - model transport (`src/llm/`);
  - plugins (channels, providers, memory, the Codex harness), "in-process with the Gateway", treated as trusted
    code;
  - MCP clients (`src/agents/agent-bundle-mcp-*.ts`);
  - cron;
  - the approval store;
  - every credential: per-agent `openclaw-agent.sqlite` auth profiles, `credentials/**`, shared
    `state/openclaw.sqlite`.
- **Supervision.** launchd or systemd. A Docker image exists. In containers the bind defaults to `lan`
  (`docs/install/docker.md:251`). Non-loopback binds refuse to start without auth
  (`docs/gateway/security/network-exposure.md:24`).
- **Workers.** Compute work (code mode, compaction, file-tool planning) runs in worker threads
  (`docs/agent-runtime-architecture.md` §Compute workers). That is a performance boundary, not a security one.

### 2.2 Control protocol, auth and pairing

[H: `docs/gateway/protocol/{transport,handshake,auth}.md`, `docs/gateway/operator-scopes.md`]

- **Wire format.** WebSocket text frames carrying JSON. The first frame must be `connect`, otherwise the socket is
  hard-closed. After that: `{type:"req",id,method,params}` → `{type:"res",id,ok,payload|error}`, and events
  `{type:"event",event,payload,seq?}`.
- **Schema.** TypeBox schemas in `packages/gateway-protocol/src/schema.ts` generate JSON Schema, and Swift models are
  generated from that. **Events are not replayed**; clients refresh on gaps.
- **Retries.** Side-effecting methods (`send`, `agent`) need idempotency keys.
- **Roles:**
  - `operator`: CLI, UI, automation. Scopes `operator.read|write|admin|approvals|pairing|talk.secrets`.
  - `node`: declares `caps`, `commands` and `permissions` at connect. These are treated as claims and filtered by
    a server-side allowlist.
  - `worker`: a closed protocol for cloud execution hosts.
- **Auth modes:**
  - shared secret (`token` / `password`), which gives **full operator scope, including admin**, on the
    HTTP-compatible endpoints;
  - Tailscale Serve identity headers, verified with `tailscale whois` on a dedicated listener;
  - `trusted-proxy` (identity from a reverse proxy, with a `trustedProxies` CIDR list);
  - `none` for private ingress.
- **Device identity and pairing.**
  - Every client has a keypair device identity and signs a `connect.challenge` nonce. Signature v3 binds
    `platform` and `deviceFamily`, and metadata changes force a re-pair.
  - New devices need approval, then get a **device token scoped to role and scopes**.
  - Direct loopback connects can be auto-approved. Tailnet, LAN and same-host-tailnet connects need explicit
    approval.
  - Node enrolment can be auto-approved by `autoApproveCidrs` (off by default) or `sshVerify`, which is **on by
    default** and reads the device key back over SSH with strict host keys.
- **Remote access** (`docs/gateway/remote.md`, `tailscale.md`):
  - preferred: Tailscale Serve (stays on loopback; identity headers) or an SSH tunnel;
  - Tailscale **Funnel** gives public HTTPS with a shared password;
  - LAN bind behind a firewall;
  - TLS fingerprint pinning for `wss://`.
- **Origin and locality.** The rules are intricate: forwarded-header evidence disqualifies loopback locality,
  Host/Origin checks apply to Control UI auto-pairing, and so on. Many past CVEs sit exactly here (§4). [H:
  `network-exposure.md:108–162`]

### 2.3 Agents, sessions and routing

[H: `docs/concepts/multi-agent.md`, `access-control.md`, `trust-model.md`]

- **What an agent is:**
  - workspace (cwd + `AGENTS.md`/`SOUL.md`/`USER.md`/`IDENTITY.md`/`MEMORY.md`/`memory/*.md`, `skills/`);
  - `agentDir`: auth profiles, model registry, session SQLite;
  - session store.
  - "Each agent's workspace is the default cwd, not a hard sandbox."
- **Bindings** route inbound traffic to an agent. A binding maps a channel account, guild or peer to an `agentId`.
- **Session keys:**
  - `agent:<id>:main`; group and channel sessions have their own keys.
  - `session.dmScope` defaults to `main`: **all DMs from all channels share one session**. Alternatives:
    `per-channel-peer`, `per-account-channel-peer`, `per-peer`.
  - "`sessionKey` is a routing selector, not an authorization token."
- **Cross-agent reach is on by default:**
  - `tools.sessions.visibility: all` and `tools.agentToAgent.enabled: true`;
  - so "any tool-enabled agent running unsandboxed can list, read, search, and message every agent's sessions,
    including other users' transcripts".
- **Sub-agents.** `sessions_spawn`, with a nesting and yield model.
- **Multi-user:**
  - named operator roles, session owner, creator and participants, guest invitations, public read links;
  - all "usability features, not security boundaries" (`docs/concepts/multi-user.md`).

### 2.4 Nodes (devices)

[H: `docs/nodes/index.md`, `tool-permissions.md` §Node execution]

- **What a node is.** A companion device (macOS menu-bar app, iOS, watchOS, Android, headless `openclaw node run`,
  Windows suite, ESP32) connected with `role: node`. It exposes `camera.*`, `screen.record`, `location.get`,
  `canvas.*`, `notifications.*`, `computer` (desktop control), SMS and `system.run`.
- **`system.run` on a paired Mac is remote code execution.** It is gated by:
  1. pairing;
  2. the gateway's coarse `gateway.nodes.commands.allow|deny`, which matches exact command names only;
  3. the node's own exec-approvals file.
- **Nodes can do more than execute:** host MCP servers and skills, publish tool descriptors
  (`node.pluginTools.update`), and host whole sessions.
- **Trust.** "Node pairing and node commands: operator-level remote execution on paired devices." A node with
  `security="full", ask="off"` is "expected behavior".

### 2.5 Runtimes: what happened to pi, and OpenClaw as a harness host

[H: `docs/agent-runtime-architecture.md`, `docs/concepts/agent-runtimes.md`, `docs/gateway/cli-backends.md`,
`CHANGELOG/2026.5.22.md`]

- **pi was internalised.** 2026.5.22: "Agents/runtime: internalize the former Pi agent runtime into OpenClaw,
  remove legacy package dependencies, and keep Pi-named SDK aliases only as deprecated plugin compatibility."
  - Built-in runtime id `openclaw`; the alias `pi` normalises to it. `packages/agent-core` (`@openclaw/agent-core`)
    holds the loop.
  - "No external agent framework packages remain." The only pi package left in `package.json` is
    `@earendil-works/pi-tui@1.4.0`.
- **Embedded harnesses.** Plugins can register runtimes:
  - `codex` drives Codex app-server: native threads, approvals, `/codex steer`; it can share threads with Codex
    Desktop;
  - `copilot`;
  - `muse`.
- **CLI backends.**
  - `claude-cli` runs Claude Code as a subprocess with an optional **loopback MCP bridge** carrying Gateway tools.
  - In `ask: "on-miss"` mode it checks Claude's native Bash calls against OpenClaw's exec allowlist
    (`cli-backends.md` §Native Bash and the exec allowlist).
- **ACP.** `openclaw acp` serves OpenClaw to editors (it is an ACP *server*), and `acpx` hosts external ACP harnesses
  (Claude Code, Gemini CLI, OpenCode, Cursor).
- **Also A2A 1.0, an MCP server, and an OpenAI-compatible HTTP API** (`docs/start/why-openclaw.md` §Open standards).

**Implication.** OpenClaw sits on the same layer as wicket's `wicket-agent` crate. It drives Codex app-server and
Claude Code's stdio protocol from a host process. It differs in that the host process is also the channel server
and credential holder, and in-process policy is its only enforcement.

### 2.6 Placement: sandboxes, cloud workers, OpenShell workers

[H: `docs/gateway/sandboxing/*.md`, `docs/gateway/cloud-workers.md`, `docs/gateway/openshell-workers.md`]

- **Tool sandbox.** `exec`, `read`, `write`, `edit`, `apply_patch`, `process` and the optional browser move into a
  backend. "The Gateway process always stays on the host."
  - Backends: `docker` (default), `podman`, `ssh`, `openshell` (NVIDIA OpenShell CLI over SSH), `crabbox` (leased
    cloud boxes).
  - **Plugin and MCP tools still execute on the Gateway side**, gated by a second sandbox tool policy.
- **Cloud workers:**
  - "worker-turn" moves a whole agent turn to a disposable machine; "remote-exec" moves only commands there;
  - transcript and accepted workspace changes stay with the Gateway;
  - setup secrets reach workers as **placeholders substituted at bound HTTPS hosts**.
- **OpenShell worker inference.** The native loop and tools run inside OpenShell, with inference credentials
  brokered by OpenShell. The Gateway keeps "session authority, transcripts, and placement".

This is the same "brain and hands" axis as [11 §3.1] `Placement`, but with the trust arrow reversed: OpenClaw
treats the *brain* (Gateway) as trusted and the hands as untrusted. wicket treats both as untrusted.

---

## 3. Security model as implemented

### 3.1 Trust model: "one trust boundary per gateway"

[H: `docs/gateway/security/trust-model.md`, `SECURITY.md`]

- **Supported:** one operator, or a mutually trusting team, per Gateway. **Not supported:** "one shared
  gateway/agent used by mutually untrusted or adversarial users".
- **"Everyone who can message a tool-enabled agent shares that agent's delegated tool authority."**
- **Defaults are trusted-operator:**
  - host exec is `security="full", ask="off"`;
  - `agents.defaults.sandbox.mode` is `off`;
  - `tools.exec.host` is `auto` (sandbox if one is active, otherwise the gateway host);
  - permission mode "Without those settings or sandboxing, the default is full access" (`permission-modes.md`).
- **Stated stance, in order:** "Identity first → Scope next → Model last".
- **Out of scope** (`SECURITY.md:171–194`), quoted selectively:
  - "Public Internet Exposure";
  - "Prompt-injection-only attacks (without a policy/auth/sandbox boundary bypass)";
  - "Reports that require write access to trusted local state (`~/.openclaw`, workspace files like `MEMORY.md` /
    `memory/*.md`)";
  - "a trusted-installed/enabled plugin can execute with gateway/host privileges";
  - env-var-driven executable behaviour;
  - "host-side exec when sandbox runtime is disabled".
- **Workspace memory** is "trusted local operator state. If someone can edit workspace memory files, they already
  crossed the trusted operator boundary." (`SECURITY.md` §Workspace Memory Trust Boundary). Yet the agent can write
  those files with its own tools, so **an injected agent is, by definition, inside the boundary**.
- **The shared secret is full admin.** Shared-secret bearer auth on `/v1/*` and `/tools/invoke` gets "the full
  default operator scope set (`operator.admin`, …)", and narrower `x-openclaw-scopes` headers are ignored
  (`SECURITY.md` §Operator Trust Model).

**For wicket.** This is a coherent personal-assistant threat model, and the project is unusually explicit about it.
But read beside §4, a large share of real incidents fall exactly into the excluded classes: exposure, injection,
memory poisoning, malicious installed extensions. wicket's Principle 1 ("the box is hostile") is the inverse
choice. wicket should publish an equally explicit **boundary matrix** (§8, §2).

### 3.2 Sandbox

[H: `docs/gateway/sandboxing/{modes-scope-and-backend,docker-backend,workspace-access,images-and-setup}.md`,
`src/agents/sandbox/container-allocation.ts`]

- **Modes** `off|non-main|all`. Default `off`. `non-main` sandboxes everything except `agent:<id>:main`, so group
  and channel sessions are sandboxed and owner DMs are not.
- **Scope** `agent` (default, one container per agent) | `session` | `shared`.
- **Docker defaults:**
  - `--network none`, `--read-only`, tmpfs `/tmp /var/tmp /run`, `--cap-drop ALL`, `no-new-privileges`, `--init`;
  - optional seccomp, AppArmor, pids and memory limits (`container-allocation.ts:74–142`);
  - `network: host` blocked; `container:<id>` blocked unless `dangerouslyAllowContainerNamespaceJoin`.
- **Workspace access:**
  - `none` (default): an isolated workspace under `~/.openclaw/sandboxes`;
  - `ro`: agent workspace at `/agent`;
  - `rw`: `/workspace`.
- **Bind mounts.** `docker.binds` default to **read-write** when the mode is omitted. They are validated after
  symlink resolution against a denylist (`/etc`, `/proc`, `/sys`, `/dev`, `/run`, `docker.sock`, `~/.ssh`,
  `~/.aws`, …).
- **Container user.** Unset means the uid of the workspace owner, so "a root-owned workspace can therefore run as
  root".
- **The gateway drives Docker through the host Docker CLI and socket.** In Docker-out-of-Docker setups the gateway
  container holds the host socket.
- **Environment into the box** (`src/agents/sandbox/sanitize-env-vars.ts`):
  - a **denylist by name pattern** (`AWS_SECRET_ACCESS_KEY`, `*_ADMIN_KEY`, `SECRET_ENV_NAME_RE`) plus a small
    allowlist (`PATH`, `HOME`, `LANG`, …);
  - other names pass. Strict mode exists.
- **Managed GitHub identity** is excluded from the sandbox by default. `allowInSandbox: true` mounts the token
  read-only at `/openclaw/github`, and the audit warns about it.
- **Escape hatches:**
  - `tools.elevated` runs exec on the gateway or node host;
  - `/elevated full` skips approvals for the session;
  - per-chat `sessions.patch {sandboxMode:"off"}` (admin);
  - "Continue for this session" with the native runtime's own permissions.
  - **A role with `sandbox: "required"` beats all of these**, and execution fails closed if the backend is
    unavailable.

**Self-assessment:** "not a perfect security boundary, but it materially limits filesystem and process access when
the model does something dumb" (`docs/gateway/sandboxing.md`).

### 3.3 Tool policy

[H: `docs/gateway/sandbox-vs-tool-policy-vs-elevated.md`, `tool-permissions.md`, `src/security/dangerous-tools.ts`]

- **Five layers:** tool profile, provider profile, global and per-agent `allow`/`deny`, per-provider `allow`/`deny`
  (`provider` or `provider/model`), and sandbox tool policy. Deny wins. A non-empty allow list makes it an
  allowlist.
- **Groups** (`group:runtime|fs|sessions|memory|web|ui|automation|messaging|nodes|agents|media|openclaw|plugins`).
- **Granularity is the tool name only.** "Tool policy filters tool availability by name; it does not inspect side
  effects inside `exec`. If `exec` is allowed, denying `write`… does not make shell commands read-only."
- **Requester-scoped tools:**
  - `tools.toolsBySender` and "owner-only tools" (`gateway`, `cron`, `openclaw`);
  - non-owner chat senders can never use `cron` or `gateway`;
  - these are **evaluated against the current turn's originating requester** and "do not authenticate or sanitize
    other content in that model prompt, including quoted text, prior shared-room history, forwarded content,
    fetched content, attachments, tool results" (`hardened-baseline.md` §Requester-scoped controls). This is the
    confused-deputy gap that wicket's labels exist to close.
- **Cross-provider messaging is open by default.** `tools.message.crossContext.allowAcrossProviders: true` and
  `allowWithinProvider: true`.
- **Typed config delegation.** The `gateway` tool has no config-write action. Agents request persistent config
  changes through the `openclaw` delegation tool, which maps them to **typed operations**:
  - Full Access applies them without a prompt;
  - restricted runs need human approval;
  - "free-text replies such as 'yes' never authorize the change" (`permission-modes.md` §Delegated setup).
- **HTTP default deny.** `DEFAULT_GATEWAY_HTTP_TOOL_DENY` lists the tools that are RCE-grade over HTTP: `exec`,
  `apply_patch`, `sessions_spawn`, `gateway`, `nodes`, `computer`, … (`src/security/dangerous-tools.ts`).

### 3.4 Exec approvals, permission modes and the LLM reviewer

[H: `docs/tools/exec-approvals.md`, `exec-approvals-advanced.md`, `exec.md`, `docs/gateway/permission-modes.md`]

- **`tools.exec.mode`** `deny|allowlist|ask|auto|full`. Approvals can only tighten config. `askFallback` defaults to
  `deny` when no approval UI is connected.
- **Session permission modes:**

  | Mode | Behaviour |
  |---|---|
  | `read-only` | Exec denied |
  | `guarded` ("Ask me") | Human reviews after the allowlist fast path |
  | `workspace` ("Auto-review") | An **LLM reviewer** returns allow, deny or ask |
  | `full` | Unrestricted; needs `operator.admin` |

- **Binding** (the strongest part, and worth borrowing):
  - approved runs bind cwd, exact argv, env and the pinned executable path;
  - every resolved command-segment executable is bound at review and **re-checked before launch**: real-path
    identity for protected executables, plus a **content hash for writable ones**;
  - a new executable earlier on `PATH` denies the run;
  - for scripts and interpreter files, OpenClaw binds **one concrete local file operand** and denies if it drifts.
    If it cannot identify exactly one, it refuses to mint an approval-backed run;
  - heredocs always need review;
  - `strictInlineEval` makes `python -c`, `node -e`, `find -exec`, `xargs` and similar need approval even in
    allowlist mode;
  - `bash -lc` and other login-shell wrappers skip auto-review and go to a human;
  - **Bash "allow always" is unavailable** for the claude-cli backend;
  - the committed policy is revalidated at the final spawn boundary.
- **The LLM reviewer:**
  - It "receives a bounded excerpt of the current conversation without secret masking: user requests, assistant
    text, tool calls, and tool results, labeled by origin". It treats this as "untrusted evidence, not
    instructions".
  - Three consecutive denials escalate to a human. Reviewer failure goes to a human.
  - "Commands containing reviewer-directed text are denied back to the agent."
  - **This is the design wicket Principle 4 rejects:** the decider sees agent-influenced context, including tool
    results.
- **Durable approvals** (2026.8.1):
  - one canonical record per approval; **the first valid answer settles it** across Control UI, CLI, mobile and
    chat;
  - aborting a run cancels its pending approvals; "a late approval cannot restart it";
  - a lost acknowledgement leads to a re-read, never an assumption;
  - pending IDs are bound to the issuing Gateway.
  - [H: `docs/releases/2026.8.1/security-and-privacy.md`, `exec-approvals-advanced.md` §Official mobile operator
    apps]
- **Standing grants for automations.** "Always allow" on a cron run mints a grant bound to agent, automation, job
  configuration and the exact operation (command, cwd, env). A substantive job edit invalidates it. It can expire
  (`tools.exec.grantExpiryDays`), is listed and revocable, and is "revalidated against the live approval row … on
  every use". [H: `exec-approvals.md` §Standing grants]
- **Self-assessment:** approvals "are guardrails for operator intent, not hostile multi-tenant isolation … they do
  not semantically model every runtime/interpreter loader path".

### 3.5 Elevated mode

`tools.elevated.enabled`, plus a per-provider sender allowlist `tools.elevated.allowFrom.<provider>`. `/elevated on`
runs exec on the host, and `/elevated full` also skips approvals. It is exec-only and cannot override tool deny or a
required sandbox. [H: `docs/tools/elevated.md`, `sandbox-vs-tool-policy-vs-elevated.md`]

### 3.6 Inbound admission: DM pairing, allowlists, groups, context visibility

[H: `docs/channels/pairing.md`, `docs/gateway/security/access-control.md`, `src/pairing/*`]

- **DM policy** `pairing` (default) | `allowlist` | `open` (needs an explicit `"*"`) | `disabled`.
- **Pairing codes:**
  - an unknown sender's message is **not processed**; the sender gets an 8-character code (uppercase, no
    `0O1I`);
  - **1 h TTL**; at most **3 pending per channel account**; one code message per sender per hour;
  - the operator approves with `openclaw pairing approve <channel> <code>` or in the Control UI queue;
  - state lives in `channel_pairing_requests` and `channel_pairing_allow_entries` in `state/openclaw.sqlite`.
- **Command ownership.** The first CLI pairing approval **bootstraps `commands.ownerAllowFrom`** (for example
  `telegram:123456789`) when no owner exists. Owners can `/update`, restart, change config and approve commands.
- **Groups:**
  - group allowlists plus `requireMention` and mention patterns;
  - `groupPolicy: open` is recommended for "a private room whose members you trust";
  - "replying to a bot message (implicit mention) does **not** bypass `groupAllowFrom`".
- **Context visibility vs trigger authorization.** `contextVisibility: all` is the default, so quoted replies,
  thread history and forwarded text from **non-allowlisted senders reach the model**. The `allowlist` and
  `allowlist_quote` options filter them. Reports that only show this are classed as hardening.
- **Identity linking.** `session.identityLinks` collapses one person's identities across channels. Linked
  identities can steer a session from another transport (`queue-steering.md:152`).

### 3.7 Credentials

[H: `docs/gateway/security/secrets-and-storage.md`, `docs/gateway/secrets/*.md`, `openclaw-agent-runtime.md`]

- **Where they live:**

  | What | Where |
  |---|---|
  | Model auth (API keys + OAuth) | `agents/<id>/agent/openclaw-agent.sqlite` |
  | WhatsApp session keys | `credentials/whatsapp/<acct>/creds.json` (Baileys) |
  | Telegram, Discord, Slack tokens | config, env, or SecretRef |
  | MCP OAuth tokens | `state/openclaw.sqlite` |
  | Codex account | `agents/<id>/agent/codex-home/**` |

  Transcripts sit in SQLite with tool output and pasted secrets unmasked. Permissions are 700/600; "Store values are
  not encrypted at rest".
- **SecretRefs** (`env`/`file`/`exec`/`store`, plus 1Password and Vault plugins) keep plaintext out of the config
  file. "Plaintext credentials remain agent-readable when they sit in files the agent can inspect, including
  `openclaw.json`."
- **Shared secret store.** Two kinds of entry:
  - **protected** `secret` entries are write-only;
  - **agent-readable** `env` entries are injected as plaintext into gateway-hosted exec.
  - The agent can ask the human to add a secret with the `secrets` tool. The human types it into a masked prompt
    and "the value never enters the chat … or the model's context".
- **Secret egress proxy** (default off; about 2026.7–8):
  - a Gateway-owned loopback MITM proxy, run in a dedicated worker;
  - gateway-hosted exec children get `HTTPS_PROXY` with **per-process Basic proxy credentials**, the CA variables,
    `NODE_USE_ENV_PROXY=1`, and **`oc-sent-v2…end` sentinels** in place of each protected secret;
  - the proxy substitutes sentinels in URLs, headers, streamed bodies and the origin `Authorization: Basic` header,
    **only at exact HTTPS hosts bound to that secret**;
  - unknown, tampered or unbound sentinels fail closed; no redirects are followed; the grant is revoked when the
    process exits;
  - `bypassHosts` give blind tunnels for pinned clients, and "a sentinel sent there is safe by construction because
    it is authenticated ciphertext";
  - an optional `allowedHosts` traffic allowlist exists.
  - **Stated limits:**
    - "constrains only cooperating clients … A subprocess can ignore those variables and open raw sockets";
    - WebSocket frames are not substituted;
    - HTTP/2 upstream is not supported;
    - **sandbox and node exec get neither proxy nor sentinels**;
    - reflection by an allowed host can still leak the value.
  - [H: `secret-store-and-egress.md:53–178`]
- **Proxyline.** `proxy.proxyUrl` routes the Gateway's own `fetch`, undici, `node:http(s)` and WebSocket traffic
  through an operator proxy. It "replaces caller-provided Node HTTP agents". OpenClaw "does not ship … or certify a
  proxy". [H: `docs/security/network-proxy.md`]
- **Workspace `.env` blocking.** Provider keys, every `OPENCLAW_*` name, `*_ENDPOINT` routing keys and `PATH`-like
  roots are blocked from untrusted workspace `.env` files, "so a cloned workspace cannot redirect bundled connector
  traffic". [H]

### 3.8 Prompt-injection mitigations

[H: `docs/gateway/security/prompt-injection.md`, `src/security/external-content.ts`]

- **Untrusted wrapping.** External content (web, email hooks, OpenResponses files, extracted documents) is wrapped
  in `<<<EXTERNAL_UNTRUSTED_CONTENT id="<random 8 bytes hex>">>>` markers with `Source:`, `From:` and `Subject:`
  metadata. The random ID stops spoofed boundaries (`wrapExternalContent`, `external-content.ts:323`).
- **Pattern logging.** `SUSPICIOUS_PATTERNS` regexes ("ignore previous instructions", `elevated=true`, `rm -rf`, …)
  are logged only.
- **Chat-template tokens.** ChatML, Llama, Gemma, Mistral and GPT-OSS special-token literals are stripped from
  wrapped content, for self-hosted backends.
- **Outbound sanitizer.** `<tool_call>`, `<system-reminder>` and similar are stripped from replies.
- **Bypass flags.** `allowUnsafeExternalContent` exists for hooks, Gmail and cron.
- **The main mitigation is model choice.** The docs cite an arena result (0.5% attack success for Opus 4.5 vs 8.5%
  for Gemini 2.5 Pro) and advise against tool-enabled weak models. They suggest a **reader agent** with no tools
  that summarises untrusted content for the main agent, connected by send-only delegation. The 2026-03 privsep
  paper [05] evaluated exactly this.

### 3.9 Skills and plugins supply chain

[H: `docs/tools/skills.md`, `docs/cli/skills.md`, `docs/gateway/security/tool-permissions.md` §Plugins,
`clawhub/docs/security-audits.md`, `moderation.md`]

- **Skill format and load order.**
  - Skills are AgentSkills-spec `SKILL.md` files with YAML frontmatter.
  - Load order, highest first: `<workspace>/skills`, `<workspace>/.agents/skills`, `~/.agents/skills`,
    `<state>/skills`, **Workshop skills (written by the agent itself)**, bundled, extra dirs and plugin skills.
  - **An execution workspace's `skills/` and `.agents/skills/` load too**, and the skills watcher hot-reloads a
    changed `SKILL.md` on the next turn.
- **Secret injection.** `skills.entries.*.env` / `apiKey` inject secrets into the **host** process for that turn.
- **ClawHub trust.** ClawHub returns a `clawhub.skill.verify.v1` envelope with scan state from VirusTotal, ClawScan
  and static analysis.
  - Malicious or blocked releases are refused.
  - A **pending scan can be bypassed** (`--force-install`), and "Official ClawHub skill publishers … bypass this
    release-trust check".
  - "`openclaw skills verify` … does not hash current local files" (`why-openclaw.md`).
  - Installs record digests (`.clawhub/origin.json`, `lock.json`).
  - **No publisher signing**: trust is a server verdict.
- **ClawScan pipeline** (ClawHub): Tencent A.I.G + NVIDIA SkillSpector + risk analysis, with an LLM judge (Codex)
  issuing the verdict.
  - Statuses: Pass, Review, Warn, Malicious, Pending, Error.
  - It judges "coherence": do name, metadata, requested authority and content line up.
  - ClawHub rejects `.pyc`/`.pyo`/`.pyd` because A.I.G cannot read bytecode (CVE-2026-84809 in A.I.G).
  - Platform vulnerabilities in ClawHub "are not publicly disclosed by default".
- **Plugins:**
  - "Plugins run in-process with the Gateway — treat them as trusted code."
  - ClawHub and the bundled catalogue count as trusted sources. Others warn and need `--force`.
  - "OpenClaw does not run built-in local dangerous-code blocking during install/update"; `security.installPolicy`
    lets an operator run a local allow/warn/block command.

### 3.10 Audit, doctor and formal models

- **`openclaw security audit [--deep|--fix|--json]`:**
  - about 125 `checkId`s (`fs.*`, `gateway.*`, `sandbox.*`, `tools.exec.*`, `plugins.*`, `skills.*`,
    `security.exposure.*`, `security.trust_model.*`);
  - it combines "open inbound × tool damage" findings and detects policy drift (sandbox settings with mode off;
    `nodes.commands.deny` entries that only match exact IDs);
  - `--fix` is deliberately narrow.
  - [H: `docs/gateway/security/running-the-audit.md`, `audit-checks.md`, `src/security/audit*.ts`]
- **`openclaw doctor`** migrates config, repairs provenance and checks bwrap/userns for the Codex sandbox.
- **`openclaw sandbox explain`** prints the effective mode, mounts, tool policy and the config keys to change.
- **Formal models.** TLA+/TLC models cover gateway exposure, the node exec pipeline, approval-token replay, the
  pairing store and mention gating. The repository holding them (`vignesh07/openclaw-formal-models`) is "currently
  unreachable", and there is no CI integration. [H: `docs/security/formal-verification.md`]
- **Threat model.** A MITRE-ATLAS-mapped threat model is in `docs/security/THREAT-MODEL-ATLAS*`. [H]

---

## 4. Security track record (2025–2026)

*Sources for this section:*
- GHSA data pulled with `gh api` on 2026-11-08 (`repos/openclaw/openclaw/security-advisories`, all pages, and
  `/advisories?ecosystem=npm&affects=openclaw`);
- the researchers' and vendors' posts linked inline.

I re-verified GHSA-g8p2-7wf7-98mq (CVE-2026-25253 in the global DB, patched in `v2026.1.29`) and GHSA-gv46-4xfq-jv58
(critical, node-invoke approval bypass) myself.

### 4.1 Volume and classes [H]

- **Repository advisories.** 722 published: **14 critical, 249 high, 390 medium, 69 low**. Only 39 carry a CVE in the
  repo record.
- **Global advisory DB.** Counting `clawdbot` and plugin packages too, there are **762 advisories, 453 with CVEs**.
- **By month:**

  | Month (2026) | Advisories published |
  |---|---|
  | Jan | 3 |
  | Feb | 220 |
  | Mar | 204 |
  | Apr | 108 |
  | May | 67 |
  | Jun | 45 |
  | Jul–Aug | 0 |
  | Sep | 75, all on 2026-09-11, for fixes that shipped in 2026.8.1 on 2026-08-31 |
  | Oct–Nov | 0 |

- **Top CWEs:** 863 incorrect authorization (164), 862 missing authorization (49), 78 command injection (46),
  22 path traversal (39), 284 (38), 918 SSRF (37), 269 (28), 184 incomplete denylist (27), 367 TOCTOU (24),
  59 symlink (22).
- **Rough root-cause classes** (keyword pass over titles):

  | Class | Approx. count |
  |---|---|
  | Exec allowlist, approval or command-injection bypass | 148 |
  | Channel sender authorization | 145 |
  | Gateway auth, scope, pairing, origin or proxy trust | 126 |
  | Path, file or symlink | 84 |
  | SSRF | 47 |
  | Sandbox escape or policy | 45 |
  | Credential exposure | 18 |
  | Untrusted metadata placed into prompts | 18 |

- **Reporters.** Most come from Chinese and other security labs: tdjackey (137), KeenSecurityLab (90), qclawer (60),
  zsxsoft (56), zpbrent (52), AntAISecurityLab (31).
- **No paid bug bounty** (`SECURITY.md`).

**Reading.** Almost all the volume is in OpenClaw's *own* in-process authorization logic: scopes, pairing, sender
allowlists, approval binding, shell parsing. The same classes recur: scope subsetting was re-found six times in
March, exec parsing in February and again in September, and the heartbeat owner-downgrade three times. **This is the
cost of putting the policy engine inside a large, fast-moving agent process.** It is the strongest empirical
argument for wicket's "small trusted core outside the box" (Principle 8).

### 4.2 Significant advisories [H unless marked]

| # | ID | Date | Severity | What failed | Fixed |
|---|---|---|---|---|---|
| 1 | GHSA-g8p2-7wf7-98mq / **CVE-2026-25253** | 01-31 | High 8.8 | **1-click RCE.** The Control UI accepted `?gatewayUrl=` and auto-connected *with the stored gateway token*, and the WS had no Origin check. It worked even against loopback-only gateways, because the victim's browser connects. Chain (depthfirst): token with `operator.admin` → `exec.approvals.set ask:"off"` → `config.patch tools.exec.host="gateway"` (out of the container) → `system.run`. https://depthfirst.com/post/1-click-rce-to-steal-your-moltbot-data-and-keys | 2026.1.29 |
| 2 | GHSA-g55j-c2v4-pjcg / CVE-2026-25593 | 02-04 | High | Unauthenticated local WS `config.apply` wrote `cliPath`, which later ran through a shell | 2026.1.20 |
| 3 | GHSA-gv46-4xfq-jv58 / CVE-2026-28466 | 02-14 | **Crit 9.9** | The Gateway forwarded caller `params` to nodes, and the node treated `params.approved===true` as approved → RCE on paired hosts | 2026.2.14 |
| 4 | #1795 (O'Reilly), GHSA-xc7w-v5x6-cc87, CVE-2026-26316 | Jan–Feb | Med/High | **Behind a reverse proxy every request came from loopback**, which counted as local/authenticated | 2026.1.24-3; webhooks 2026.2.12–13 |
| 5 | GHSA-5wcw-8jjv-m286 / CVE-2026-32302; GHSA-844j-xrrq-wgh4 | 03 | High | `trusted-proxy` mode skipped Origin for browser WS → `operator.admin`; X-Forwarded-For loopback spoofing | 2026.3.11 / 3.22 |
| 6 | GHSA-jmmg-jqc7-5qf4 "ClawJacked" (Oasis) | 02-26 | High | Web page → loopback WS: no Origin check for non-UI client IDs, no throttling of loopback password guesses, silent local pairing [M for the write-up] | 2026.2.25 |
| 7 | GHSA-4jpw-hj22-2xmc, -rqpp-rjj8-7wv8 (9.9), -hf68-49fm-59cq, -9hjh-fr4f-gxc4, -fqw4-mph7-2vr8, -hc5h-pmr3-3497 | 03-12 → 03-29 | **Crit** | **Minting without caller-scope subsetting:** `device.token.rotate`, `device.pair.approve` and `/pair approve` let `pairing`/`read` callers mint `operator.admin`; shared-secret clients self-declared scopes | 2026.3.11–3.28 |
| 8 | GHSA-h3f9-mjwj-w476 / CVE-2026-26325 | 02-15 | High | Approval checked `rawCommand` but executed `command` | 2026.2.14 |
| 9 | GHSA-65rx-fvh6-r4h2 / CVE-2026-27209; Sep batch GHSA-9f86-pvv5-rxfw, -ghpx-6xwq-2w4w, -74gc-hg2m-79p9, -3mq7-q27j-mq7q | 02, 09 | High | Allowlist analyser missed heredoc `$(…)`, escaped newlines, wrapper binaries; reusable approvals accepted changed args or cwd | 2026.2.21; 2026.8.1 |
| 10 | GHSA-w235-x559-36mg / CVE-2026-27002; GHSA-9p3r-hh9g-5cmg (crit); GHSA-xw4p-pw82-hqr7 | 02–03 | Med–Crit | **Sandbox config injection** (host binds incl. docker.sock, `network=host`, unconfined seccomp); TOCTOU in the remote fs bridge `readFile`; skill-mirror traversal | 2026.2.15 / 3.31 / 2.14 |
| 11 | GHSA-8rh7-6779-cjqq, -j7p2-qcwm-94v4 (9.6 each), -g8xp-qx39-9jq9 | 03 | **Crit** | A workspace `.env` loaded before trusted config; the env blocklist missed package-manager vars, `CC` and `CXX` | 2026.3.22–3.28 |
| 12 | GHSA-g5cg-8x5w-7jpm (crit) + -g2hm-779g-vm32, -g375-h3v6-4873 | 03–04 | Crit | **Heartbeat runs inherited `senderIsOwner`** and bypassed the sandbox; webhook wakes and async-exec completions too | 2026.3.31 / 4.10 / 4.14 |
| 13 | GHSA-62qm-6fjj-6g23 ("Dreaming"), -rrxp-5mx8-mvhh, -7cp7-87pj-p32v, -hpg5-cq3m-phqp | 09-11 | High | **Authority laundering through background paths:** memory from a restricted sender lost provenance, then an unattended "dreaming" agent with broader tools acted on it; voice calls inherited owner tools; skill dispatch skipped owner-only policy; agent cron reached operator jobs | 2026.8.1 |
| 14 | CVE-2026-24764, CVE-2026-27001, CVE-2026-27165, GHSA-g27f-9qjv-22pm | 01–03 | Med | **Untrusted metadata placed directly into prompts:** Slack channel metadata → system prompt; cwd name with newline/bidi; ACP `resource_link`; WS headers → logs the LLM later reads | various |
| 15 | GHSA-qrq5-wjgg-rvqw (9.3), GHSA-4rj2-gpmh-qq5x (9.4), CVE-2026-26324, -26322, -26327, -25474, -26319 | 02 | Crit/High | Plugin-install traversal; voice-call allowlist bypass (empty caller ID + suffix match); SSRF via full-form IPv4-mapped IPv6; gateway tool accepted arbitrary `gatewayUrl`; **unauthenticated mDNS TXT steering routing and TLS pins**; webhook secrets missing (Telegram, Telnyx) | 2026.2.x |

ClawHub itself had 5 medium advisories (2026-09-11) [H]:
- four ordinary accounts' reports could auto-hide any skill;
- former org publishers could take over org skills;
- changelog previews sent quarantined content to the AI provider;
- SSRF in profile-image fetch;
- spoofable forwarded-IP quotas.

### 4.3 Exposed gateways

- **O'Reilly (Dvuln), from 2026-01-23.**
  - A Shodan search for "Clawdbot Control" found hundreds of instances. Of those examined by hand, 8 had no auth
    (full exec and config) and 47 had auth.
  - Root cause: proxied requests came from loopback, and `trustedProxies` defaulted to empty. Fixed by PR #1795 in
    2026.1.24-3 [H changelog; M counts via The Register, 2026-01-27,
    https://www.theregister.com/2026/01/27/clawdbot_moltbot_security_concerns].
- **Pillar Security honeypot** on :18789 (2026-01-29) saw probes within minutes: direct exec JSON-RPC, forced
  `minProtocol: 1` downgrades, a spoofed `clawdbot-control-ui` client ID claiming operator scopes, `config.get` and
  `chat.history` harvesting, and `node.list` in 16% of requests. [H]
  https://www.pillar.security/blog/caught-in-the-wild-real-attack-traffic-targeting-exposed-clawdbot-gateways
- **Scan counts** (not comparable: different methods and dates):
  - Censys: 21,639 on 2026-01-31 (HTML title) and 63,070 on 2026-03-31 (fingerprint) [M];
  - SecurityScorecard STRIKE: more than 40,000 in 24 h, **35.4% of observed deployments vulnerable** [H]
    https://securityscorecard.com/blog/how-exposed-openclaw-deployments-turn-agentic-ai-into-an-attack-surface/;
  - The Register: more than 135k (2026-02-09) [M].
- **Infostealers.** Hudson Rock found a Vidar variant exfiltrating `openclaw.json` (gateway token), `device.json`
  (pairing private key), `soul.md` and memory files. The stealer was generic [M, BleepingComputer].

**Project stance.** "Public Internet Exposure" is out of scope (`SECURITY.md`). The audit flags it, and non-loopback
binds without auth refuse to start. Container images still default to a LAN bind.

### 4.4 Malicious skills (ClawHub)

- **O'Reilly's proof of concept** (2026-01-27): a benign skill whose download count he inflated to more than 4,000;
  it was installed in 7 countries. At the time ClawdHub "treats all downloaded code as trusted" [M].
- **Cisco AI Defense** (2026-01-28): the #1 skill "What Would Elon Do?" produced 9 findings (2 critical): silent
  `curl` exfiltration and an injection telling the agent to bypass safety. Cisco released `skill-scanner`. [H]
  https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare
- **Koi Security "ClawHavoc"** (about 2026-02-01) [M; Koi's URL now redirects to Palo Alto]:
  - **341 malicious of 2,857** skills, 335 from one campaign, later **824 of 10,700+**;
  - "fake prerequisites" leading to **AMOS**; reverse shells;
  - the only publishing gate was a GitHub account at least one week old.
- **1Password** (2026-02-02): the top "Twitter" skill required a fake `openclaw-core` dependency. The chain was
  staging page → obfuscated command → binary with the macOS quarantine attribute stripped. "Do not run OpenClaw on a
  company device." [H] https://1password.com/blog/from-magic-to-malware-how-openclaws-agent-skills-become-an-attack-surface
- **VirusTotal Part I and II** (2026-02-02 and 02-05) [H]:
  - publisher hightower6eu: **314 skills, all malicious**;
  - `better-polymarket`: `warmup()` runs before argument parsing → `/dev/tcp` reverse shell even on `--help`;
  - `wake-up`: a "semantic worm" that installs `HEARTBEAT.md` every 4 h, with an infection-referral API;
  - `evilweather`: appends to `authorized_keys`;
  - `rankaj`: `.env` → webhook.site;
  - `devinism`: a "cognitive rootkit" writing into `SOUL.md`/`AGENTS.md` that survives uninstall.
  - https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html, …-part-ii.html
- **Snyk ToxicSkills** (2026-02-05): of 3,984 skills, 36.8% have a flaw and 13.4% a critical one; 76 confirmed
  malicious; 91% of the malicious ones *also* use prompt injection. [H] https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub
- **JFrog**: a fake npm installer `@openclaw-ai/openclawai` (postinstall hook, fake Keychain prompt, GhostLoader RAT),
  March 2026 [M].
- **Response:**
  1. **VirusTotal partnership** (2026-02-07): deterministic ZIP + SHA-256 → Code Insight; malicious → "instantly
     blocked"; daily rescan; "not a silver bullet" for natural-language payloads; O'Reilly named lead security
     advisor [H] https://www.openclaw.ai/blog/virustotal-partnership.
  2. Later **ClawScan** (Tencent A.I.G + NVIDIA SkillSpector + LLM judge; claims 98.6% catch on its benchmark; the
     three scanners agree on only 0.69% of skills).
  3. Moderation holds and publisher-abuse scoring.
  4. `security.installPolicy`.
  5. **Still no publisher signing** [H, §3.9].

### 4.5 Prompt injection through channels, email and the web, and persistence

- **Zenity Labs** (2026-02-04) [H]
  https://labs.zenity.io/p/openclaw-or-opendoor-indirect-prompt-injection-makes-openclaw-vulnerable-to-backdoors-and-much-more:
  - zero-click, from a document processed in a Google Workspace task;
  - the agent **added an attacker-controlled Telegram integration** (attacker bot token, attacker allowlisted);
  - persistence was **a scheduled task rewriting `SOUL.md` every 2 minutes** from an attacker endpoint;
  - it ended with a Sliver C2 beacon;
  - "No software vulnerability is required."
- **Embrace The Red, "Agent Commander"** (2026-03-16) [H]
  https://embracethered.com/blog/posts/2026/agent-commander-your-agent-works-for-me-now:
  - a malicious **email** takes over the agent;
  - persistence via **`HEARTBEAT.md`**: the heartbeat runs every 30 min by default, often on a weaker model, and
    `HEARTBEAT_OK` suppresses output;
  - natural-language C2;
  - subagent → main-agent messages escape the sandbox.
- **PromptArmor** [H]: zero-click exfiltration through **chat link previews**. The agent emits
  `https://evil/?d=<secret>` and Telegram's or Discord's preview fetcher delivers it. Fixed by
  `channels.telegram.linkPreview: false`.
  https://www.promptarmor.com/resources/llm-data-exfiltration-via-url-previews-(with-openclaw-example-and-test)
- **HiddenLayer** [M]: a `web_fetch` page appended to `HEARTBEAT.md`.
- **Imperva** (Jun 2026) [M]: instructions in WhatsApp **contact names, vCard FN and location labels** were inlined
  into the prompt; hardened in 2026.4.23.
- **Kukuy** (Jan 2026) [M]: an email extracted a private key in "5 minutes".
- **Moltbook** [H]:
  - joining means installing `moltbook.com/skill.md`, which adds a heartbeat: "Fetch https://moltbook.com/heartbeat.md
    and follow it" every 4 h. That is a **remote instruction channel built into every participating agent**
    (Willison, https://simonwillison.net/2026/Jan/30/moltbook/).
  - Wiz (2026-02-02) found a Supabase key in client JS with no RLS, giving **read/write** access to 1.5M agent API
    tokens, about 35k emails and 4,060 DM threads (some with OpenAI keys). Write access to `posts` meant injection
    into every agent reading the feed. https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys

### 4.6 Warnings and the project's response

- **Warnings:**
  - Gartner (2026-01-29) called it "Unacceptable Cybersecurity Risk" and on 02-09 advised "Block Personal AI
    Assistants" [M, abstract];
  - China's CNCERT warned about "extremely weak default security configuration" (about 2026-03-10), and notices to
    state agencies, SOEs and banks followed [M];
  - Kakao, Naver and Karrot imposed corporate bans [M].
- **Response** [H]:
  - security audit tooling from 2026.1.14 onward; SECURITY.md with private GHSA reporting and security@openclaw.ai;
  - the MITRE ATLAS threat model (2026-02-08); incident-response docs (05-03);
  - VirusTotal, then ClawScan; a Trail of Bits audit (21 Sep, per the project blog [M]);
  - in 2026.8.1, durable approvals, run-bound authority and the secret egress proxy.
  - Fix cadence: high-profile issues same day to one day; big batches (54 advisories in 2026.3.31, 48 in 2026.8.1);
    disclosure lagging release by about 11 days for the September batch.
  - Default posture deliberately unchanged: sandbox off, host exec, a trusted operator.

---

## 5. Operator-channel lessons (vs wicket §13.1)

### 5.1 What OpenClaw does

| Concern | OpenClaw | Source |
|---|---|---|
| Steering | Any admitted sender's message is a user turn. Mid-run messages steer the active run: tool calls are skipped with "Skipped to process an incoming message". Linked identities can steer from another channel. | `docs/concepts/queue-steering.md` [H] |
| Origin | Inbound content is wrapped with `From:`/`Source:` metadata. Requester-scoped tools key off the *triggering* sender only. There are no labels on content from other senders in the same prompt. | §3.3, §3.8 |
| Approvals in chat | `/approve <id> allow-once\|allow-always\|deny`. Native buttons on Discord, Slack, Telegram, Matrix, QQ, Google Chat. **Emoji reactions** on WhatsApp, Signal and Matrix (`✅`, `♾️`, `❌`). Same-chat approval is on by default for deliverable chats. | `exec-approvals-advanced.md:236–420` [H] |
| Who may approve | The channel's resolved approver list: `execApprovals.approvers` or `commands.ownerAllowFrom`, i.e. **platform sender IDs** (numeric Telegram ID, phone number, Slack user ID). "Session delivery only controls where the prompt appears. It does not by itself authorize every participant." Generic same-chat `/approve` accepts any command-authorized sender. | `commands-approve.ts:31–85`, FAQ [H] |
| Who renders the prompt | **The agent is told to relay** `/approve` instructions "only from an actual pending approval, using the exact request ID". A bare or invented ID cannot approve. | `exec-approvals-advanced.md:241` [H] |
| Approval content | Native prompts "include the command text". Previews are sanitised and truncated, but binding uses the full command. Google Chat buttons carry opaque action tokens with server-side state. | [H] |
| Strong surfaces | Control UI and the iOS, Android and Apple Watch apps read a durable sanitised record. The Watch offers allow-once and deny. Approvals can be opened "from a secure standalone link" (#103698). PWA push alerts re-check device, person, role and scopes before delivery. | `releases/2026.8.1/security-and-privacy.md` [H] |
| Free text | "Free-text replies such as 'yes' never authorize the change." | `permission-modes.md` [H] |
| Automations | Never posted to chat ("would repeat a card on every occurrence"). They go to connected approval clients, otherwise deny. | `exec-approvals.md` [H] |
| Owner routing | Owner-only group commands send their approval to the owner's *private* route, possibly on another network. The group only sees an acknowledgement. | [H] |
| Notifications | Approver DMs, origin-chat fan-out, PWA push, iPhone notifications for plugin approvals. | [H] |
| Multi-user | Named operator roles, session owners and participants, but "usability features, not security boundaries". | `multi-user.md` [H] |

### 5.2 What works

- **Binding every decision to an exact typed request** (argv, cwd, env, executable hash), with first-answer-wins,
  cancel-on-abort and no late revival. This matches wicket's ledger semantics, and OpenClaw's implementation
  details are good conformance cases.
- **Never posting automation approvals to chat.** A repeating card trains people to approve without reading.
- **Owner-private routing:** the approval leaves the group and goes to the owner's private surface.
- **Server-side state behind opaque button tokens** (Google Chat): the callback carries no authority.
- **The "secure standalone link" approval**: a chat notice that opens an authenticated surface. This is the shape
  wicket already wants (announce in a chat, decide in wicket).

### 5.3 What is weak or abused

1. **The approver's identity is only as strong as the chat account.** Phone-number identities are exposed to SIM
   swap, WhatsApp linked-device takeover, and iMessage handles reached by email. Slack and Discord accounts can be
   phished, and bot tokens leak.
2. **The agent writes into the same channel as the approval.** The model is instructed to relay approval commands.
   An injected agent can request an approval for a dangerous command and describe it misleadingly in the
   surrounding chat text ("approve the cleanup, id …"). It can also flood benign requests to train reflexive
   approval. The approval card shows the real command, but in the same visual stream as model text.
3. **Emoji reactions as approvals.** A one-tap ✅ in a group conversation is a very low-friction authorisation of
   RCE. Signal and WhatsApp reaction approvals need an explicit approver list, but the gesture is still trivial.
4. **Group visibility.** "A Telegram forum-topic approval prompt can be visible to everyone in the topic." The
   command text and paths leak to every member.
5. **Requester-scoped authority vs mixed content.** An owner-triggered turn whose prompt includes a stranger's
   quoted message or a forwarded email runs with owner-only tools. OpenClaw names this and sends users to
   `contextVisibility` and sandboxing.
6. **Steering is unauthenticated free text.** It has the same authority as the original request; there is no
   typed amendment.
7. **Approval and pairing of new senders** are themselves chat-borne. The first pairing approval in the CLI makes
   that sender **owner**, which bootstraps admin over chat.

### 5.4 Compared with wicket §13.1

| wicket §13.1 rule | OpenClaw | Verdict for wicket |
|---|---|---|
| Authority only in the ledger; vendor UIs announce, never decide | Chat apps decide | **Keep the rule.** OpenClaw is the case study. Add chat apps as `ChannelKind::Chat` with `observe/message/announce` caps only (§8). |
| Passkey step-up over the request digest | Channel sender ID; mobile apps use device tokens; no per-approval step-up | Keep. Optionally borrow OpenClaw's Watch / mobile durable-record flow as a *companion* that still asserts a passkey. |
| Typed `AmendTask` vs free-text steer | Only free text, plus typed config delegation for config changes | Keep. OpenClaw's `openclaw` delegation tool (typed op plus human approval, "yes" never counts) is the same idea applied to config. |
| Origin labels per message | `From:` metadata inside wrapped text; tool choice by triggering requester | Strengthen: **label per sender and per quoted span**, and compute the turn's taint from *all* senders in the context, not only the trigger (§8, A-CH-3). |
| Approval-phishing defences: typed card, untrusted fold, burst alerts | Command text in the card; model text around it | Add: never let the agent emit text that *looks like* an approval instruction in a channel wicket announces into. Notices carry a binding code plus a link, rendered by wicket, never by the agent. |
| First answer wins; same state everywhere | Implemented (2026.8.1) | Borrow the conformance details: lost-ack re-read, cancel on abort, no late revival, pending bound to the issuing control plane. |

---

## 6. Overlap and positioning

### 6.1 Where they overlap and where they differ

| Area | OpenClaw | wicket | Note |
|---|---|---|---|
| Purpose | Personal or team assistant across chats and devices | Meta-harness for black-box agents doing tasks | Different products, same substrate problems |
| Control plane | Gateway: one Node process, in-process TCB with plugins | `wicketd` + small Rust TCB; inner agents are hostile | OpenClaw trusts the brain; wicket trusts neither brain nor hands |
| Model key | In the Gateway (SQLite auth profiles); OpenShell worker inference can broker it | LLM proxy only | |
| Sandbox | Tools only; off by default; Docker/Podman/SSH/OpenShell/Crabbox | Whole agent in a box; netns with no route; gVisor/Firecracker | OpenClaw's backend interface is a clean seam (§6.3) |
| Egress | Proxyline (cooperative), secret egress proxy (cooperative, gateway-exec only), host-based | Mandatory interception; adapters judge method, path and args | OpenClaw's sentinel design is worth borrowing (§6.4) |
| Tool policy | By name; requester-scoped; profiles; groups | By `Op` (provider, verb, resource, args, effects, risk) at the proxies | |
| Approvals | Exec / plugin / config; durable; chat-decidable; LLM reviewer | Typed escalation + ledger; passkey; no LLM tier in v1 | |
| Channels | ~25 chat networks as inbound *and* operator UI | Operator channels only; no inbound user channels | Gap in wicket: **ingress** (§8) |
| Multi-agent | Bindings, per-agent workspace/auth/session, `sessions_spawn`, agent-to-agent on by default | Zones + gates + handles; child ⊆ parent | wicket is stricter |
| Memory | Persistent workspace files (SOUL/MEMORY/skills); agent writes them; "trusted" | Task-scoped, labelled, deleted; Declassify to persist | Gap in wicket: **standing zones** (§8) |
| Devices | Nodes: camera, screen, `system.run`, computer use | None | Out of scope for v1; any node is a separate zone |
| Enterprise | OCE + OpenShell: IAM, credential proxy, network-policy ceiling, prover | Ledger, Cedar + symcc, zones | Closest prior art for wicket's architecture (§7) |

### 6.2 OpenClaw as an inner agent under wicket

**Fit.** Technically good. OpenClaw already supports every route wicket needs:
- provider `baseUrl` overrides with SecretRef keys;
- a process-wide proxy (`proxy.proxyUrl`) and `NODE_EXTRA_CA_CERTS`;
- immutable externally managed config (`OPENCLAW_CONFIG_PATH` + `OPENCLAW_CONFIG_READONLY=1`);
- update checks and helper downloads that can be switched off;
- loopback-only binding;
- a JSON-Schema'd operator protocol, with **exec approvals routed to connected approval clients**.

**Misfit:**
1. **It is a daemon, not a task.** wicket's model is a manifest that runs to completion.
2. **Its value is long-lived memory and channels.** wicket deletes memory at task end.
3. **End-to-end chat identities hold keys that cannot be externalised.** WhatsApp/Baileys Noise and Signal keys,
   signal-cli, and Matrix E2EE keys must live in the box.
4. **Some channels need inbound webhooks:** Google Chat, Teams, LINE, Gmail Pub/Sub hooks, A2A.

**Tier.** Two protocol options:
- **T1 (Gateway WS protocol).** The adapter connects as an `operator` client with
  `operator.write|approvals|read` (not `admin`). It sends turns with `agent` / `chat.send` and reads `agent` events.
  It declares the `exec-approvals` capability, so the Gateway routes pending exec and plugin approvals to wicket,
  which answers `exec.approval.resolve` / `approval.resolve`. These answers are advisory (§13.1.2), the same as
  Codex's. **Typed output:** none native; use a terminating plugin tool or the outbox. The protocol is
  closed-but-schema'd: generate Rust types from `packages/gateway-protocol` JSON Schema, pinned per version, the way
  [11] does for Codex.
- **T2 (`openclaw acp`).** Loses approvals routing and the channel surface.

**Placement:**
- `Whole`: Gateway, loop and tool exec in one wicket box, with OpenClaw `sandbox.mode: off`. No Docker socket in
  the box.
- `Split`: the Gateway in a brain box; tools in a wicket hands box through the backend plugin of §6.3, using
  OpenClaw's own seam.

**Recommended deployment pattern: "front desk + workers".**
1. OpenClaw runs in a **standing zone** `frontdesk`:
   - channels on;
   - `tools.profile: "messaging"`, no `exec`, no fs writes outside memory, no nodes, no browser;
   - taint `chat:*`, `web` if it fetches;
   - `send` limited to its own channels.
2. Its only route to real work is the wicket MCP gateway, configured in OpenClaw's `mcp.servers` with
   `wicket.spawn(template, task_text, inputs: [handle…])` and typed fields.
3. Work runs in ordinary wicket task zones, joined by gates (`TypedFields`, `HandlesOnly`). The spawned task text
   inherits `frontdesk`'s label (§5.1), so a stranger's DM can at most request a pre-approved task template whose
   escalations are judged against trusted text.

This is reader/actor privsep [05] with wicket's mechanics, and it keeps OpenClaw's channel UX.

**OpenClaw security features under wicket:**

| Feature | Under wicket | Why |
|---|---|---|
| DM pairing, allowlists, mention gating, `dmScope: per-channel-peer` | **Keep** (defence in depth) | First filter on strangers; wicket can't see inside E2E channels |
| `contextVisibility: allowlist_quote` | Keep | Reduces cross-sender injection |
| External-content wrapping, special-token stripping | Keep | Cheap |
| Tool profile `messaging`, deny `gateway`/`cron`/`openclaw`/`nodes`/`sessions_*`, `agentToAgent.enabled: false`, `tools.sessions.visibility: self` | Keep, and **mirror into the zone ceiling** | Early denials; same idea as Claude's managed deny rules |
| `crossContext.allowAcrossProviders/WithinProvider: false` | Keep, and **enforce at egress** for HTTP-API channels (Slack `chat.postMessage` channel = resource) | Destination control becomes a real `Op` |
| Exec approvals (`mode: ask`) with wicket as the approval client | Keep as advisory early-typed-request channel | Like Codex `requestApproval` |
| LLM exec reviewer (`mode: auto`) | **Disable** | An agent-context decider (Principle 4), and it spends model budget |
| OpenClaw sandbox (Docker backend) | **Disable** in `Whole`; replace with the wicket backend in `Split` | Needs the Docker socket; tools-only |
| `tools.elevated`, `/elevated`, per-chat sandbox opt-out | **Disable** | Escape hatches |
| Secret egress proxy, Proxyline allowlists | **Disable** the secret proxy; keep Proxyline pointed at wicket-egress | Avoid two MITMs; wicket injects |
| Shared secret store, SecretRef `exec` providers, 1Password/Vault plugins | **Disable** | No secrets in box; `exec` providers run commands |
| Nodes, `sshVerify`, `autoApproveCidrs`, Bonjour, Tailscale Serve/Funnel | **Disable** | Remote execution and exposure outside the box |
| ClawHub installs, Skill Workshop, workspace `skills/` | Disable installs; **pin skills in the image**; Workshop writes are memory | Supply chain + self-modification |
| Plugins | `plugins.allow` exact pinned list, in-image | In-process code |
| Codex / claude-cli runtimes | Off (or routed through wicket-llm only) | Subscription OAuth in box |
| `openclaw security audit --json` | **Run in preflight** and fail the launch on any `critical` | Free config linting |

### 6.3 wicket as OpenClaw's sandbox backend

**The seam is public** [H: `src/plugin-sdk/sandbox.ts`, `src/agents/sandbox/backend-handle.types.ts`,
`remote-shell-backend.ts`]:
- `registerSandboxBackend(id, {factory, manager, resolveWorkdir, capabilities})`;
- the handle provides `buildExecSpec`, `runShellCommand` and an optional `createFsBridge`;
- `createRemoteShellSandboxBackend(params, { createSession })` with `createRemoteShellSandboxSession({ buildCommand })`
  builds an SSH-like backend from one command builder. OpenShell and Crabbox use these.

**A `@wicket/openclaw-sandbox` plugin would be about 200 lines:**
- `buildCommand({remoteCommand, tty})` → `["wicket", "box", "exec", "--lease", <lease>, "--", "/bin/sh", "-c", remoteCommand]`,
  talking to `wicketd` over its UDS;
- `factory` asks wicketd to claim a zone instance per OpenClaw `scopeKey` (session or agent), from a manifest
  template named in plugin config;
- `manager.removeRuntime` releases it;
- the filesystem bridge goes through the remote-shell fs bridge (or `wicket box extract`).

**What it gives:**
- OpenClaw users get a box with no network route except wicket's proxies, credentials injected at egress, git
  store-and-forward, typed escalation for tool-side network actions, and `wicket explain` for what the hands can
  reach.

**What it doesn't:**
- The brain (Gateway, model key, plugins, MCP tools, channels) stays outside wicket. wicket sees only commands and
  their egress. This is `Placement::Split` **with a foreign brain**: wicket governs the hands workload as a zone
  whose task text it has never seen.
  - So escalations from it have **no trusted task text**. Every field is agent-supplied and fails provenance, which
    means human-or-deny unless the template's ceiling covers it.
  - That is correct, but it should be an explicit mode: `zone.origin: ForeignBrain{product: "openclaw"}`.

This is a good adoption path: OpenClaw users are many, and the plugin is small. It is not wicket's core.

### 6.4 What to borrow, and what to avoid

**Borrow:**
1. **Authenticated, destination-bound placeholders** (`oc-sent-v2`):
   - placeholders as authenticated ciphertext bound to (zone, secret, allowed hosts);
   - the proxy refuses an unregistered, tampered or wrong-host placeholder before forwarding;
   - placeholders survive in Basic-auth userinfo and request bodies;
   - wicket can then *detect* a placeholder sent to a wrong host (an exfiltration attempt) and leak nothing.
   - Add to §9.1 and §2 principle 2. wicket keeps "strip all client auth" as the default for adapter-mapped hosts,
     and uses body substitution only where an adapter declares the field.
2. **Per-process proxy credentials** (Basic proxy auth per exec process, revoked at exit). That gives wicket
   sub-zone attribution for processes within one box, where the transport identity is per box.
3. **Approval binding:** executable real-path plus content hash, one file operand, heredoc and inline-eval
   detection, login-shell wrappers to a human, re-check at spawn. These go in the advisory exec-prompt mapping
   ([11 §3.6.5]) and the `AnswerAgentPrompt` path.
4. **Durable approval lifecycle conformance:** first answer wins, cancel on abort, no late revival, re-read on lost
   ack, pending bound to the issuer.
5. **Standing grants bound to a job definition digest**, invalidated on substantive edit, with expiry and use
   count. This maps directly to ledger grants bound to a manifest digest for recurring tasks.
6. **Typed config delegation** with "free-text yes never authorizes". It confirms wicket's `AmendTask` design.
7. **Trust-boundary matrix plus "not vulnerabilities by design" list**, and an audit with `checkId`s and narrow
   `--fix`. Use these for `wicket doctor` and for the docs.
8. **`sandbox explain`-style "why is this blocked, and which key changes it"** for denials. The 403
   problem+json should name the manifest path that would grant the request.
9. **DM-pairing mechanics** (8 characters, no ambiguous characters, 1 h TTL, cap 3 pending, message not processed
   until approved) for wicket's Ingress admission and for console device enrolment.
10. **Workspace `.env` blocklist and chat-template token stripping** in preflight and in wicket-llm (open-weights
    upstreams).
11. **AgentSkills format compatibility** for any wicket "task template" library. Do not adopt ClawHub trust.

**Avoid:**
1. Decisions made in chat apps on platform sender IDs; emoji-reaction approvals; the agent relaying approval
   commands.
2. An LLM decider fed transcript and tool results.
3. Env-var **denylists** by name (wicket allowlists; no secrets at all).
4. In-process plugins as TCB; registry verdicts without signatures; "official publisher bypasses checks".
5. Defaults of host exec with full access, sandbox off, cross-agent session visibility on, cross-provider sends on.
6. A shared secret that equals admin and ignores narrower scopes.
7. Declaring agent-writable memory "trusted local state". In wicket, anything the agent wrote is labelled with the
   agent's taint.
8. Hostname-only destination policy without IP pinning (OpenClaw states this limit; wicket already resolves once
   and dials the vetted IP).

---

## 7. Related "claw" ecosystem (brief)

Source: the ecosystem survey, `gh api` and the projects' docs, 2026-11-08. All stars are from `gh api` [H] unless
marked.

| Project | What | Isolation / credentials | Relevance |
|---|---|---|---|
| **OpenClaw Enterprise (OCE)** `openclaw/openclaw-enterprise` (454★, MIT, created 2026-08-29, pre-1.0) | "Kubernetes for agents": Go `occ` + TS controller + Postgres; started at OpenAI, donated to the Foundation; Red Hat and NVIDIA collaborate | OpenShell sandboxes; a **Credential Proxy**: the supervisor's `EvaluateHttpRequest` asks the OCE worker whether caller + credential version has a grant, and only then attaches a GitHub App installation token minted outside; network-policy additions versioned under an installation ceiling and frozen per deployment; per-agent ServicePrincipals that "do not inherit creator's permissions" [H: repo docs] | **Closest architecture to wicket.** Read before building §9.4 and §8.3. Different: no IFC, labels, typed gates or handles. |
| **NVIDIA OpenShell** (21.3k★, Apache-2.0, Rust, 0.1.x) | Agent sandbox runtime | Landlock + seccomp user-notify for connect/DNS → trusted supervisor injects credentials for policy-allowed endpoints; outer network fence per runtime; a **prover** flags policy changes that add new reach and blocks auto-approval [H: docs.nvidia.com/openshell] | Prior art for wicket-jail + egress + symcc "does this widen?" |
| **NVIDIA NemoClaw** (23.0k★, alpha) | Reference stack: OpenClaw/Hermes/Deep Agents in OpenShell | Digest-pinned YAML blueprints; `inference.local` keeps model keys out; TUI approvals for blocked hosts, per instance, not persisted | Same shape as wicket manifests + LLM proxy |
| **NanoClaw** `nanocoai/nanoclaw` (31.1k★, MIT) | Minimal OpenClaw alternative on the Claude Agent SDK | One container per agent group; host↔container via two single-writer SQLite mailboxes; credentials via the **OneCLI** HTTPS-MITM gateway; Docker Sandboxes microVMs [H] | Validates whole-agent-in-box + external credential injection for a chat assistant |
| **OneCLI** (3.6k★, Apache-2.0, Rust) | Credential gateway ("Agent Vault"), now a harness | Per-host/path injection, `Proxy-Authorization` agent tokens [H] | Already in `refs/repos/onecli` [07] |
| **IronClaw** `nearai/ironclaw` (12.7k★, Apache-2.0, Rust) | OpenClaw re-implementation from NEAR AI | WASM capability tools; allowlist → **leak scan (request)** → inject → execute → **leak scan (response)**; Docker for heavy work; TEE hosting [H/M] | Bidirectional leak scanning at the boundary |
| **ZeroClaw** (33.3k★, Apache-2.0, Rust) | Re-implementation | Landlock/bwrap/Seatbelt/Docker; "tool receipts" [H] | Minor |
| nanobot (49.9k★), PicoClaw (30.1k★), TinyClaw | Lightweight clones | Pairing/allowlists only | None |
| Cloudflare **moltworker** (9.9k★), DigitalOcean/Hostinger 1-click, **Kimi Claw** | Hosted variants | Provider-held credentials | No official hosted OpenClaw [H: README] |
| Cisco skill-scanner (2.7k★), Prompt Security clawsec (1.1k★, AGPL), Adversa SecureClaw (dormant), `openclaw-ansible` (605★) | Scanners and hardening | — | Cisco scanner already in refs (`cisco-mcp-scanner`, sibling project) |
| **Moltbook** | Social network for OpenClaw agents; acquired by Meta around Mar 2026 [M] | Wiz found an exposed DB: over 1M agent API tokens, about 35k emails and DMs [M] | Long-lived bearer tokens held by agents |

---

## 8. Changes to design.md (section by section)

Ranked overall importance: **(1)** §13.1 chat channels and origin labels; **(2)** a new Ingress surface (§3, §9);
**(3)** standing zones (§4.3, §5, §12); **(4)** credential placements and authenticated placeholders (§9.1, §2);
**(5)** OpenClaw adapter and backend plugin (§6, §7); **(6)** approval binding (§11); **(7)** conformance and
red-team cases (§6.1, §15); **(8)** a published boundary matrix (§2, §13).

**§1 "What the research changed"** — add rows:
- "OpenClaw (394k★) rebuilt typed delegation, approval binding and a sentinel-substituting egress proxy, *in the
  agent's own process and cooperative*. Its incident record (exposure, ClawHavoc, injection via chat and email,
  token exfiltration) is the strongest public evidence for external enforcement." [12 §3–4]
- "pi no longer powers OpenClaw directly; OpenClaw forked pi's runtime in 2026.5.22 and now hosts Codex
  app-server, Claude Code and ACP agents itself." [12 §2.5]

**§2 Principles:**
- Principle 2 gains a clause: placeholders are **authenticated and destination-bound**, so a placeholder seen at the
  wrong destination is evidence of an exfiltration attempt, logged and denied.
- New Principle 10, **"State the boundary"**: wicket publishes which mechanisms are security boundaries (proxies,
  jail, ledger) and which are UX (in-box settings, agent prompts, chat notices). Agent-writable state is never
  "trusted local state".

**§3 Architecture:**
- Add **`Surface::Ingress`** to `Op`: inbound user messages and webhooks entering a zone. It is admitted by policy
  (sender allowlist or pairing, rate limit), labelled with an origin `SourceTag::Chat{network, sender}` /
  `Webhook{source}`, and size-bounded.
- In the diagram, "human ── CLI/TUI" becomes "operators ── console/CLI/chat notices" and "users ── Ingress".

**§4.2 Labels:**
- Add `SourceTag::Chat{network, sender_class}` with `sender_class ∈ {owner, allowlisted, stranger}`.
- A turn's taint is the join over **every** sender whose content is in context: quotes, history, forwards. The
  triggering sender alone is not enough. That closes OpenClaw's requester-scoped gap (A-CH-3).

**§4.3 Zones:**
- Add `lifetime: Task | Standing{lease, review_every}` to `Zone`.
- Standing zones keep declared stores across inbound events, but every store write is labelled. The store's label
  only grows until a `Declassify` review, and reaching `review_every` forces a human review of accumulated memory
  diffs.

**§5 Tasks:**
- Add **service manifests**: a standing zone plus the inbound bindings it accepts plus the task templates it may
  `spawn`.
- Inbound events are not task text. A spawned child's task text is the *template's* trusted text plus typed
  parameters. Free text from the event travels as a handle with `chat` taint.

**§6 Inner agents:**
- Add **OpenClaw** to the adapter list: T1 over the Gateway WS protocol, with wicket as the operator client and the
  `exec-approvals` client; T2 via `openclaw acp`.
- `Placement::Whole` with OpenClaw's sandbox off, or `Split` via the wicket backend plugin.
- Draft LaunchPlan in §9 below.
- **`AgentCaps` additions:**
  - `daemon: bool`: the agent is a long-running service, not run-to-completion;
  - `ingress: Vec<IngressKind>`;
  - `in_box_credentials: Vec<CredentialClass>` for E2E chat keys that cannot leave the box;
  - `approval_client: Option<ProtocolRef>`;
  - `config_lockdown: ManagedFile{OPENCLAW_CONFIG_PATH, readonly_env}`;
  - `self_modifying: Vec<Path>` (Skill Workshop, `SOUL.md`, `MEMORY.md`), which wicket treats as memory.

**§6.1 Conformance** — add:
- (12) `openclaw security audit --json` reports no `critical` in the shipped LaunchPlan;
- (13) no inbound listener reachable except wicket's ingress bridge;
- (14) no `node`-role connection is accepted;
- (15) skills and plugins load only from the read-only image paths (a planted `<workspace>/skills/x/SKILL.md` and
  `.agents/skills` are ignored or labelled);
- (16) agent writes to `SOUL.md`, `MEMORY.md` or workshop skills are captured as labelled store writes.

**§7 Sandboxes:**
- Add "**foreign-brain hands zones**": a `Sandbox` instance claimed by an external harness's backend plugin (OpenClaw
  `registerSandboxBackend`), with `zone.origin: ForeignBrain`.
- Its escalations have no trusted task text, so the ceiling is the whole authority, and anything outside it goes to
  a human.

**§9.1 Egress proxy** — add **credential placement** to adapters, so the proxy can inject into each:
- `Header` (current);
- `UrlPath{template}`: Telegram `/bot<token>/`;
- `BasicUserinfo`;
- `BodyField{json_pointer}`;
- `WsFrame{match}`: Discord gateway `IDENTIFY`. Deferred; until then marked "credential in box";
- `NotExternalisable`: WhatsApp/Signal/Matrix E2EE session keys, which the zone view lists as **"identity keys in
  box"**.

Also add authenticated placeholders (§2), per-process proxy credentials for attribution inside a box, and destination
control for chat sends: Slack `chat.postMessage` with `channel` and Discord `POST /channels/{id}/messages` become
adapter `Op`s with a `notify.external` effect.

**§9.2 MCP gateway:**
- Note that OpenClaw (an MCP client) can be the *caller* of `wicket.spawn`. Expose task templates as tools whose
  parameters are typed fields. That is the front-desk pattern.

**§11 Escalation:**
- For exec-shaped agent prompts, the advisory mapping binds executable real-path plus content hash, one script
  operand, heredoc and inline-eval detection, and sends login-shell wrappers to a human, re-checked at spawn.
- Recurring tasks (standing zones, cron-like templates) get **standing grants bound to the template digest**,
  invalidated on substantive edit, with expiry, use counts and listing.
- Add "late approvals never revive a cancelled request" and "lost acknowledgement means re-read" to the state
  machine's notes.

**§12 Memory:**
- Personal-assistant memory (`SOUL.md`, `MEMORY.md`, `USER.md`, workshop skills, cron jobs) is memory the agent
  writes itself. In a standing zone it is a labelled store.
- Its *reads* at the start of each session are a taint ingress. A write that contains `chat:stranger` content
  taints every later session (A-MEM-1).
- Scheduled jobs the agent creates are persistent authority. They are `Op`s (`wicket.schedule`) that need a grant,
  never in-box cron.

**§13.1 Operator channels:**
- Add `ChannelKind::Chat{network}` with caps `observe` (opt-in, data-class-gated), `message` (steer, origin-labelled),
  `announce` (escalation notices), and **never** `decide_escalations` or `answer_agent_prompts` by default.
- Notices are rendered by wicket's bot identity, never by the agent. They carry the binding code and a link to the
  console approval (OpenClaw's "secure standalone link" shape). They go to the owner's *private* route, never to a
  group.
- Automation and recurring requests are never announced per occurrence. Instead there is a digest, plus a standing
  grant offer in the console.
- Add the OpenClaw failure modes to E-OP1's red-team list (§10 A-AP-*).

**§13.2 Showing boundaries:**
- `wicket explain` adds "identity keys in box" and "ingress senders admitted", and lists standing-zone memory with
  its label.

**§14 Crates:**
- `wicket-agent` gains `openclaw`: T1 over the Gateway protocol; types generated from the pinned JSON Schema in
  `packages/gateway-protocol`.
- New small asset `adapters/openclaw/wicket-sandbox-plugin/` (TS, the backend plugin; outside the TCB).
- `wicket-ingress`: admission, labels and the webhook bridge. It sits beside `wicket-egress`.

**§15 Milestones:**
- **M3d (after M3b): OpenClaw front-desk.** OpenClaw in a standing zone with Telegram or Slack (header- or
  path-injectable credentials), messaging-only tools, `wicket.spawn` to the fix-flaky-sync template.
- **Done when:**
  - a stranger's DM is not processed (pairing);
  - an allowlisted sender's injected message can spawn only the template, with typed fields;
  - no model or channel credential is findable in the box for these two channels;
  - the A-* cases marked M3d pass.
- Also schedule the backend plugin as a "later" item.

**§16 Decisions** — add:
- "Chat apps announce and steer; they never decide";
- "Ingress is an enforcement surface";
- "Standing zones exist, but memory in them is labelled and reviewed";
- "OpenClaw is supported as an inner agent through its operator protocol, not by patching it".

**§17 Open questions** — add:
- How should a standing zone's accumulated taint be reset without losing the assistant's usefulness? Periodic
  reviewed `Declassify` of a memory diff? Fork-at-clean-ancestor of memory?
- Can wicket mediate end-to-end chat channels at all, or must those channels stay "identity keys in box"?
- WebSocket-frame credential injection for Discord-style gateways: worth building?

---

## 9. Draft LaunchPlan: OpenClaw as an inner agent

Style follows design §6 and [11 §5]. Hostnames are illustrative. There are no secrets: only placeholders and
routes. Unverified keys are marked **[U]**.

**Zone shape:** `frontdesk`, `lifetime: Standing{lease: 24h renewable, review_every: 7d}`,
`sandbox: {isolation: gvisor}` (Node + SQLite + channel WebSockets; `process` acceptable for development),
`operator_mode: wicket`, `ingress: [telegram:bot, slack:socket]`.

**Root-owned, read-only `/etc/wicket/openclaw/openclaw.json`** (`OPENCLAW_CONFIG_PATH`, `OPENCLAW_CONFIG_READONLY=1`):
```json5
{
  gateway: {
    mode: "local", bind: "loopback", port: 18789,
    auth: { mode: "token", token: { source: "env", provider: "default", id: "WICKET_OC_GATEWAY_TOKEN" } }, // [U] SecretRef shape for gateway.auth.token
    nodes: { pairing: { autoApproveLocal: false, sshVerify: false }, commands: { deny: ["system.run", "*"] } },  // [U] glob support
    tailscale: { mode: "off" },
  },
  update: { checkOnStart: false },
  proxy: { proxyUrl: "http://wicket-egress.zone.internal:3128", loopbackMode: "gateway-only" },
  models: { providers: {
    anthropic: { baseUrl: "http://wicket-llm.zone.internal:8080", apiKey: { source: "env", provider: "default", id: "WICKET_LLM_TOKEN" } },
    openai:    { baseUrl: "http://wicket-llm.zone.internal:8080/v1", apiKey: { source: "env", provider: "default", id: "WICKET_LLM_TOKEN" } } } },
  agents: {
    defaults: {
      model: "anthropic/<zone-allowed model>",
      sandbox: { mode: "off" },                 // wicket is the box; Split placement uses backend: "wicket" instead
      skipBootstrap: true,                       // workspace files are seeded by wicket from the standing store
    },
  },
  session: { dmScope: "per-channel-peer" },
  channels: {
    telegram: { dmPolicy: "pairing", botToken: { source: "env", provider: "default", id: "WICKET_TG_TOKEN" },
                groups: { "*": { requireMention: true } }, contextVisibility: "allowlist_quote", execApprovals: { enabled: false } },
    slack:    { dmPolicy: "allowlist", allowFrom: ["<owner slack id>"], contextVisibility: "allowlist_quote", execApprovals: { enabled: false } },
  },
  tools: {
    profile: "messaging",
    deny: ["group:runtime", "group:nodes", "group:automation", "group:ui", "gateway", "openclaw", "plugins",
           "sessions_spawn", "sessions_send", "conversations_send", "secrets", "skill_workshop", "web_fetch", "web_search"],
    elevated: { enabled: false },
    exec: { mode: "deny" },                      // front desk never execs; Split/worker variants use "ask" with wicket as approval client
    sessions: { visibility: "self" },
    agentToAgent: { enabled: false },
    message: { crossContext: { allowAcrossProviders: false, allowWithinProvider: false } },
  },
  approvals: { exec: { enabled: false }, plugin: { enabled: false } },   // nothing forwarded into chats
  mcp: { servers: { wicket: { url: "http://wicket-mcp.zone.internal:8081/mcp",
                              headers: { Authorization: "Bearer ${WICKET_MCP_TOKEN}" } } } },   // [U] exact mcp.servers shape
  plugins: { allow: ["telegram", "slack", "anthropic", "openai", "memory-core", "wicket-sandbox"] },
  skills: { install: { allowUploadedArchives: false }, load: { extraDirs: [] } },
  secrets: { egressProxy: { enabled: false } },
  security: { installPolicy: { command: ["/usr/bin/false"] } },          // [U] shape; blocks any runtime install
}
```

**Env:**
```
OPENCLAW_CONFIG_PATH=/etc/wicket/openclaw/openclaw.json   OPENCLAW_CONFIG_READONLY=1
OPENCLAW_STATE_DIR=/wicket/state/openclaw                 # labelled standing store: sqlite, transcripts, memory
OPENCLAW_WORKSPACE_DIR=/wicket/state/openclaw/workspace   # SOUL/MEMORY/USER files = labelled store
OPENCLAW_NO_AUTO_UPDATE=1  OPENCLAW_OFFLINE=1  OPENCLAW_DISABLE_BONJOUR=1  OPENCLAW_LOAD_SHELL_ENV=0 [U]
WICKET_LLM_TOKEN=wkt_cap_<zone,session>  WICKET_MCP_TOKEN=wkt_mcp_<zone,session>
WICKET_OC_GATEWAY_TOKEN=<random, per box; known to the adapter only via the box's control channel>
WICKET_TG_TOKEN=wkt_ph_<zone,telegram>   # placeholder; egress adapter rewrites /bot<ph>/ → real token (UrlPath placement)
SLACK_BOT_TOKEN=wkt_ph_<zone,slack-bot>  SLACK_APP_TOKEN=wkt_ph_<zone,slack-app>   # header placement [U] env names
HTTPS_PROXY=http://wicket-egress.zone.internal:3128  HTTP_PROXY=…  NO_PROXY=wicket-llm.zone.internal,wicket-mcp.zone.internal,localhost,127.0.0.1,::1
NODE_EXTRA_CA_CERTS=/etc/wicket/ca.pem  SSL_CERT_FILE=/etc/wicket/ca-bundle.pem
# deliberately absent: ANTHROPIC_*, OPENAI_*, CODEX_HOME, ~/.codex, ~/.claude, any auth-profile rows, credentials/whatsapp/**
```

**argv:** `node /opt/openclaw/openclaw.mjs gateway run` (image-pinned, no `npm install` at runtime). Preflight runs
`openclaw security audit --json` and `openclaw config validate` with the same env, and fails on `critical`.

**Adapter session (wicket → Gateway over the box's loopback, bridged to a UDS):**
```
connect {role:"operator", scopes:["operator.read","operator.write","operator.approvals"],
         auth:{token:$WICKET_OC_GATEWAY_TOKEN}, device:<wicket adapter keypair>, caps:["exec-approvals"]}   [U] cap name/shape
subscribe agent/chat/presence events → normalised AgentEvents (each inbound user turn tagged with channel+sender → SourceTag::Chat)
exec.approval.requested / plugin.approval.requested → advisory AgentPrompt (typed), answered via approval.resolve   [U] event names
```
Inbound messages enter through the channels themselves (outbound long-poll or WebSocket through wicket-egress), so
wicket sees them as **responses** on the Telegram/Slack adapters. `getUpdates` and Socket Mode envelopes are parsed
there to apply `SourceTag::Chat` labels, and the Ingress policy runs as a response filter. Webhook channels are not
supported in v1.

**Credential routes:**
- `LlmProxy{base: models.providers.*.baseUrl, token: WICKET_LLM_TOKEN}`;
- `EgressInject{api.telegram.org, placement: UrlPath("/bot{token}/")}`;
- `EgressInject{slack.com, placement: Header(Authorization)}` (Socket Mode: `apps.connections.open` with the app
  token; the returned `wss://` ticket URL is single-use);
- `GatewayOnly{wicket.spawn, wicket.await_grant, wicket.read_handle}`.

**Egress needs:** `api.telegram.org` (`getUpdates`, `sendMessage`, `getFile`, path-allowlisted), `slack.com` +
`wss-primary.slack.com` [U], wicket-llm, wicket-mcp. Nothing else: no `openclaw.ai` update or telemetry, no
`clawhub.ai`, no npm.

**Preflight taint:** the seeded workspace (`AGENTS.md`, `SOUL.md`, `USER.md`, `MEMORY.md`, `memory/**`, `skills/**`,
`.agents/skills/**`, workshop skills) carries the standing store's current label. Repo content is never mounted into
`frontdesk`.

**Pending path:** none in the front desk, which has no exec. Work happens in spawned zones, and `wicket.spawn`
returns a handle plus status. The front desk polls `wicket.await_grant` / `read_handle` and reports in chat. The
report text is rendered from typed fields.

**Operator mode:** `wicket`. Chat apps reach the owner only as wicket notices from wicket's own bot (§8 §13.1),
never through the agent.

**Unsupported in this plan (zone view says so):** WhatsApp, Signal, Matrix E2EE (identity keys in box), iMessage
(macOS host), webhook-only channels, nodes, browser, computer use, voice.

**Split variant (OpenClaw users who want wicket hands):** keep OpenClaw on the user's host and install
`@wicket/openclaw-sandbox` with `agents.defaults.sandbox: {mode:"all", backend:"wicket", scope:"session"}`. Each
OpenClaw session claims a `ForeignBrain` hands zone from a template, and exec goes over
`wicket box exec --lease <id>`.

---

## 10. Attack cases for wicket's red-team and conformance suites

<!-- SECTION 10 FILLED FROM INCIDENT RESEARCH -->

---

## 11. Unverified items and experiments

- **E-OC1:** OpenClaw runs with `OPENCLAW_CONFIG_READONLY=1`, a root-owned config and a read-only `/opt/openclaw`,
  with state confined to `OPENCLAW_STATE_DIR` (does anything write to `$HOME`?).
- **E-OC2:** placeholder model keys through `models.providers.*.baseUrl`. No catalogue or auth-discovery call goes
  around wicket-llm. Check `/model status` reporting and discovery calls to provider hosts.
- **E-OC3:** Proxyline routes *all* channel transports (Telegram's own undici dispatcher, Slack Socket Mode
  WebSocket) through wicket-egress. Tested by the netns having no route; any bypass shows as a connection failure.
- **E-OC4:** the operator-protocol `exec-approvals` capability and the event and method names for routing approvals
  to wicket [U]. Generate types from `packages/gateway-protocol` at the pinned tag.
- **E-OC5:** Telegram `UrlPath` injection and Slack Socket Mode through the egress proxy; long-poll liveness versus
  wicket-llm's liveness sensor (a daemon is never "idle").
- **E-OC6:** the backend plugin (`registerSandboxBackend`) against OpenClaw 2026.11.x: session-scope runtime claim
  and release, fs bridge, recreate.
- **[U]** Several config key shapes in §9 (marked). `docs/gateway/configuration-reference.md` and the generated
  config schema at the pinned tag decide them.

---

## 12. Sources

Primary (local clones at the commits above) [H]:
- `openclaw/README.md`, `SECURITY.md`, `VISION.md`, `package.json`, `CHANGELOG/2026.5.22.md`, `2026.7.1.md`,
  `2026.9.5.md`, `2026.10.8.md`
- `docs/concepts/{architecture,multi-agent,multi-user,agent-runtimes,agent-workspace,memory-provenance,queue-steering}.md`
- `docs/agent-runtime-architecture.md`, `docs/openclaw-agent-runtime.md`
- `docs/gateway/{protocol,protocol/auth,protocol/handshake,remote,tailscale,cli-backends,permission-modes,openshell,openshell-workers,cloud-workers,config-cloud-workers,telemetry}.md`
- `docs/gateway/sandboxing/*.md`, `docs/gateway/sandbox-vs-tool-policy-vs-elevated.md`
- `docs/gateway/security/{index,trust-model,access-control,prompt-injection,tool-permissions,secrets-and-storage,network-exposure,hardened-baseline,running-the-audit,audit-checks}.md`
- `docs/gateway/secrets/secret-store-and-egress.md`, `docs/security/{network-proxy,formal-verification,THREAT-MODEL-ATLAS}.md`
- `docs/tools/{exec,exec-approvals,exec-approvals-advanced,elevated,skills}.md`, `docs/cli/skills.md`,
  `docs/channels/pairing.md`, `docs/nodes/index.md`, `docs/start/why-openclaw.md`,
  `docs/releases/2026.8.1/security-and-privacy.md`, `docs/install/docker.md`, `docs/help/environment.md`
- `src/agents/sandbox/{backend.ts,backend.types.ts,backend-handle.types.ts,container-allocation.ts,sanitize-env-vars.ts,remote-shell-backend.ts,remote-shell-transport.ts}`,
  `src/plugin-sdk/sandbox.ts`, `src/security/{external-content.ts,dangerous-tools.ts}`,
  `src/auto-reply/reply/commands-approve.ts`, `src/plugin-sdk/approval-approvers.ts`
- `clawhub/docs/{security,security-audits,moderation}.md`

Web (from the ecosystem survey; marks as given in §1 and §7):
- https://openclaw.ai/blog/introducing-openclaw [H]
- https://openclaw.ai/blog/introducing-openclaw-foundation [H]
- https://openclaw.ai/blog/openclaw-enterprise [H]
- https://openclaw.ai/blog/microsoft-autopilot-openclaw [H]
- https://openclaw.ai/blog/where-openclaw-security-is-heading [H]
- https://openclaw.ai/blog/tencent-aig-joins-clawscan [H]
- https://openclaw.ai/blog/openclaw-nvidia-skill-security [H]
- https://steipete.me/posts/2026/openclaw [H]
- https://api.npmjs.org/downloads/point/last-week/openclaw [H]
- https://www.bloomberg.com/news/articles/2026-02-15/openai-hires-openclaw-ai-agent-developer-peter-steinberg [M]
- https://www.koreatimes.co.kr/amp/business/tech-science/20260208/top-tech-firms-ban-openclaw-over-security-breach-fears [M]
- https://github.com/openclaw/openclaw-enterprise (docs/guides/concepts.md, docs/design/credential-proxy-architecture.md) [H]
- https://docs.nvidia.com/openshell/latest/about/architecture [H]
- https://docs.nvidia.com/nemoclaw/latest/user-guide/openclaw/about/how-it-works [H]
- https://github.com/nanocoai/nanoclaw (docs/isolation-model.md) [H]
- https://nanoclaw.dev/blog/nanoclaw-docker-sandboxes [H]
- https://github.com/nearai/ironclaw [H]
- https://github.com/onecli/onecli [H]
- https://www.techradar.com/pro/everything-you-need-to-know-about-moltbook [M]
- Incident sources: §4.
