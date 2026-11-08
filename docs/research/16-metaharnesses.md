# 16 — Meta-harnesses: projects that run, swap or orchestrate other agents

Research date: 2026-11-08. Scope: open-source projects that call themselves a "meta-harness", or that run
Claude Code, Codex, Gemini CLI, OpenCode, pi and similar CLIs behind one interface (session managers, fleet
orchestrators, sandboxed runners, harness optimisers). Starting point: [metaharness.tools](https://metaharness.tools)
(`nrwl/metaharness.tools`) and everything it lists, then GitHub search (`topic:meta-harness`, "metaharness" in
name or description) and the `andyrewlee/awesome-agent-orchestrators` list.

Hosted sandbox platforms (Docker Sandboxes, E2B, Daytona, Modal, Vercel, Claude Code cloud, Codex cloud) are in
[01 §3]; sandbox runtimes and gateways in [07] and [08]; NVIDIA OpenShell, NemoClaw and OpenClaw Enterprise in
[12]. They are referred to here, not repeated.

Confidence tags, as in [14] and [15]:
- **[H]** read in the project's code or primary docs in this session;
- **[M]** from the README, a vendor post or a secondary source, not checked in code;
- **[L]** metadata only (GitHub description, stars, licence), or a guess.

Local study copies are under `refs/repos/<name>` (not committed; see `refs/README.md`). Nothing was installed,
built or run. Several clones ship `AGENTS.md`/`CLAUDE.md` files; they were read as data only.

> **Status of this note.** Read at source level in this session: Omnigent, leash, sandcastle, the two
> harness-optimisation projects, metaharness.tools, and (by a parallel pass, §2.13) Rivet Agents/Sandbox
> Agent, xum, Sculptor, agent-safehouse, Harbor, inspect_swe + inspect_ai, OpenAI Symphony and fullsend.
> Also read at source level by parallel passes: the fleet orchestrators (§2.10), session managers (§2.11),
> small meta-harnesses (§2.12), and Google AX + Agent Substrate, Scion, Centaur, CLI Agent Orchestrator and
> docker-agent (§2.9). vibekit and Polygraph are README/doc level. Rows still tagged [L] were not read.

---

## 0. Summary

- **"Meta-harness" means two different things.** metaharness.tools separates *harness orchestration* (a
  layer above many harnesses: cross-repo work, session memory, swapping harnesses, policy) from *harness
  optimisation* (the Stanford Meta-Harness paper, arXiv 2603.28052: an outer loop that rewrites one harness
  around a frozen model and keeps the best variant) [H]. wicket uses the word in a third sense: the layer that
  *builds the box* other agents run in and brokers every crossing (design.md preamble, §2). None of the
  projects listed on metaharness.tools has that as its centre.
- **Omnigent (Databricks, Apache-2.0, ~11k stars, alpha, created 2026-06) is the only listed meta-harness
  with real enforcement outside the agent.** It wraps agent terminals in bubblewrap/seatbelt plus seccomp, can
  put the box in its own network namespace with a MITM egress proxy on a unix socket, and injects host-bound
  credentials into the `Authorization` header only, so the sandbox can hold nothing or a host-bound
  placeholder [H]. But its defaults favour availability (network on, top-level-only dotfile masking, overflow
  = warn), its tool policies run through the agent's own permission hooks, a policy that abstains means ALLOW,
  and the model credential normally reaches Claude Code inside the box via `apiKeyHelper` [H].
- **Almost everything else is worktrees plus the agent's own permission mode, usually switched off.**
  Every fleet orchestrator read (Gas Town/City, Paperclip, Multica, Agent Orchestrator, Paradev, ruflo) and
  most session managers default the agent to skip-permissions or bypass-approvals; several "approve" by
  pressing Enter when the screen matches a prompt (claude-squad, uzi, ccmanager) [H]. Sandboxed runners
  (sandcastle, leash, Rivet Sandbox Agent, Harbor, agent-of-empires, Nimbalyst) box the agent but put the
  model key or the subscription OAuth file inside, often mounting or copying host `~/.claude` files [H].
- **Several less-advertised projects are closer to wicket than anything on metaharness.tools.**
  *Centaur* (Paradigm) gives each sandbox only placeholders, including a **dummy Claude credentials file whose
  bearer is injected by iron-proxy from a central token broker**, behind a default-deny NetworkPolicy [H].
  *Agent Substrate* (under Google AX) runs every actor under gVisor or a microVM with default-deny egress,
  placeholder-discarding header injection, and wake-on-request with request parking [H]. *inspect_ai*'s
  agent bridge (used by inspect_swe to run Claude Code, Codex, Gemini CLI, OpenCode) gives the agent a
  `network_mode: none` container, a model-API proxy reached over a file-based RPC channel, and a dummy key;
  the real key stays on the host, provider-side web search and remote MCP are withheld, and an approval chain
  reviews tool calls *in model responses* at that proxy, with host tools run only under a single-use grant
  bound to the model's proposal [H]. *branchyard* (Rust, tiny) confines local harnesses in a user+network
  namespace whose only exit is a listener handed to the engine, and gives them a per-turn JWT instead of a
  model key [H]. *fullsend* runs agents in OpenShell sandboxes behind an L7 gateway with a
  four-tier credential policy whose default is "no credential in the run" and whose second tier is proxy-side
  placeholder swap [H].
- **Nobody ships wicket's full set**: typed escalation bound to a request digest, single-use grants in a
  ledger, and approvals that cannot be answered from inside the box. The closest pieces are inspect_ai's
  proposal-bound grants, Rivet's approve-then-consume approval actor, Omnigent's ASK verdict (in-memory
  future, answered from web UI *or* the agent's own terminal), leash's Cedar policies compiled to eBPF LSM + a
  MITM proxy, and OpenShell's prover-gated policy changes [12].
- **What to borrow** (ranked in §3): inspect_ai's approval of tool calls at the LLM proxy and its default
  withholding of provider-side tools; Paperclip's 409 `approval_required` + argument-hash Action Request;
  Omnigent's host-bound placeholder rules; fullsend's credential tiers; branchyard's handed-listener netns;
  loom's at-most-once ticket relay and its refusal to merge agent-config changes unreviewed. **What to avoid**:
  approvals answerable in the agent's terminal or by keystroke on scraped text, shell-command parsing as
  policy, fail-open defaults and switches reachable from the box, and host OAuth files in the box.

---

## 1. Comparison table

Activity: last push to the default branch as of 2026-11-08; stars rounded. "In box" means inside the
agent's sandbox or process environment.

| Project | What it orchestrates | Isolation model | Credential handling | Policy / approval model | Licence | Activity |
|---|---|---|---|---|---|---|
| **Omnigent** `omnigent-ai/omnigent` [H] | ~20 harnesses: Claude Code (SDK and native TUI via tmux), Codex (exec, app-server, native), Cursor, OpenCode, Goose, pi, Hermes, Kiro, Devin, ACP agents, YAML agents | bwrap + seccomp (Linux), seatbelt (macOS), Job Object (Windows, no FS/net isolation); optional `--unshare-net` with MITM egress proxy on a unix socket; or remote sandboxes (Modal, Daytona, E2B, k8s, microsandbox, OpenShell, …) | Host-bound credential rules in the egress proxy: inject `Authorization` on access, or swap an `oa_cred_*` placeholder; replay to another host → 403. Model key usually in box via `apiKeyHelper` or CLI login; a "model signer" relay keeps it out for Databricks gateway routes | Python policy functions (ALLOW/DENY/ASK) at request, response, tool_call, tool_result phases; three levels (session → agent → server); budgets, risk score, GitHub/Google policies; ASK shown as approval card in web UI and in the native terminal | Apache-2.0 | very active; v0.21.0 2026-11-05 |
| **Polygraph** (Nx) [M] | "Agent-agnostic meta-harness": cross-repo graph, durable sessions, memory; Claude Code, Codex, OpenCode | Not described | Not described | Not described | Hosted, no licence stated; free early access | announced 2026-06-26 |
| **Stanford Meta-Harness** `stanford-iris-lab/meta-harness` [H] | Harness *optimisation*: Claude Code proposes harness edits, candidates scored on benchmarks (Terminal-Bench 2 via Harbor) | Proposer runs on the host; evaluation in Runloop or Modal sandboxes | `claude` CLI login on host | Proposer runs with `--dangerously-skip-permissions`, MCP and skills disabled | MIT | active (2026-11-05) |
| **SuperagenticAI metaharness** [H] | Harness optimisation, Codex primary; Gemini CLI and Omnigent experimental | Codex `workspace-write` sandbox; candidates in separate workspaces | Codex login/env | `allowed_write_paths` checked after each proposal; off-target edits rejected | **FSL-1.1-ALv2** (source-available, Apache-2.0 after two years) | 2026-09-02 |
| **leash** `strongdm/leash` [H] | claude, codex, gemini, qwen, opencode in a `coder` image | Agent container + privileged manager container: eBPF LSM (file open, exec, connect) + iptables redirect to MITM proxy; macOS via Network Extension | Header injection at the proxy (`rewrite.conf`), but by default forwards `ANTHROPIC_API_KEY` etc. and offers to mount `~/.claude` into the box | Cedar policies transpiled to eBPF/proxy rules; Record/Shadow then Enforce; MCP observer; web Control UI | Apache-2.0 | slowing (2026-04-06) |
| **sandcastle** `mattpocock/sandcastle` [H] | `sandcastle.run()` TS library: Claude Code, Codex, others; branch strategies | bwrap / seatbelt native sandboxes, Docker/Podman, E2B, Modal, Sprites | Model key passed as env (`ANTHROPIC_API_KEY`) into the box; fresh private `$HOME` so host logins are not visible | Agents run with permission checks skipped; the sandbox is the containment. Native sandbox network is **open, including host localhost** (its own docs say so) | MIT | active |
| **vibekit** `superagent-ai/vibekit` [M] | Claude Code, Codex, Gemini, Grok, OpenCode, Cursor | Docker locally; Daytona, E2B, Modal, Northflank, Cloudflare, Dagger, Blaxel adapters | Keys in box; "redaction" of secrets in output; optional `--proxy` sets `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` | Observability and redaction, no per-action policy found | MIT | quiet (2026-01) |
| **docker-agent** harnesses [H] | Delegates to Claude Code, Codex, opencode, pi CLIs (drivers in an external `rumpl/harness` library) | Host process by default; `--worktree`; `--sandbox` uses a Docker Sandboxes VM with a default-deny proxy, but does not carry the harness CLI or its login, so harness agents are not isolated | CLI's own login on host; in `--sandbox`, known model keys are proxy-managed, other env forwarded | Claude Code runs with `--dangerously-skip-permissions`; questions/plan approvals via a per-turn loopback MCP `--permission-prompt-tool` with a per-turn bearer; native approval hooks do not gate harness tools | Apache-2.0 | active |
| **Rivet Agents / Sandbox Agent** `rivet-dev/agents` [H] | Sandbox Agent: Rust daemon *inside* the sandbox with HTTP+SSE, driving Claude, Codex, Amp, Pi, Cursor through ACP adapters. Rivet Agents: pi loop in a backend actor, only tools in the sandbox | None of its own: E2B, Daytona, Modal, Docker, Cloudflare | Sandbox Agent: model key in box env and scrapes host `~/.claude/.credentials.json`, `~/.codex/auth.json`. Rivet Agents: logins held in an outside `credentials` actor | ACP permission requests relayed to the client (once/always/reject); example approval actor whose `consume(version)` makes one approval allow exactly one deploy | Apache-2.0 | active |
| **inspect_swe + inspect_ai agent bridge** `meridianlabs-ai/inspect_swe`, `UKGovernmentBEIS/inspect_ai` [H] | Claude Code, Codex CLI, Gemini CLI, OpenCode, Kimi, Antigravity, mini-swe-agent, ACP agents, headless in Inspect sandboxes | Docker or k8s; generated compose uses `network_mode: none` | In-box model proxy on a local port, bridged to the host by file-based RPC (no network); agent gets a dummy key; real key in the host model provider; client auth headers never forwarded; provider-side tools withheld | Agent runs with permissions skipped, but an approval chain reviews tool calls in model responses at the bridge; host tools need a single-use grant bound to the proposal | MIT | active |
| **fullsend** `fullsend-ai/fullsend` [H] | claude (default), pi, codex, opencode, headless, dispatched from GitHub Actions / GitLab CI; one sandbox per agent role | OpenShell sandboxes (container + Landlock + FS/process policy); L7 gateway with per-endpoint, method+path and per-binary allowlists | Four tiers (ADR 0025): prefetch/post-process with no credential in run (default); OpenShell placeholder swap at proxy; host-side capability-reducer API; host files (real secrets in box). Gateway route keeps provider key out, box gets endpoint-bound OIDC placeholder | In-box hooks (tool allowlist, SSRF, canary, redaction) + outside L7 proxy and schema-validated post-scripts; humans gate by role minimums and merge labels | Apache-2.0 | active |
| **agent-safehouse** `eugene1g/agent-safehouse` [H] | Launcher wrapper for ~14 agent CLIs (not an orchestrator) | macOS Seatbelt, deny-first composable SBPL profiles; **network deliberately open**; docker.sock and ssh-agent denied | `env -i` + allowlist without API keys, but agent keeps `~/.claude` and keychain | FS/IPC policy only, kernel-enforced; `explain` tool | Apache-2.0 | active |
| **Google AX** `google/ax` + **Agent Substrate** `agent-substrate/substrate` [H] | Declarative immutable `Task` (workspace: repos, MCP servers, skills; model); runner is PID 1 and runs one-shot `claude --print` | Every actor in **gVisor or a Cloud Hypervisor microVM** (no plain containers); default-deny egress: all TCP to an egress gateway, DNS relay answers NXDOMAIN off-policy, other UDP dropped. AX itself creates no `EgressPolicy` yet | AX puts `spec.env` (e.g. `ANTHROPIC_API_KEY`) in plaintext env and task YAML. Substrate: `replaceHeaders` rule with `credentialUri`; gateway terminates TLS, discards the placeholder, inserts the real value; separate credential provider; fail-closed 403/500/503 matrix; per-actor JWTs and SPIFFE certs | `EgressPolicy` as external PEP; API authorised with OpenFGA; human approvals only on the roadmap | Apache-2.0 | active; 14.6k stars |
| **Scion** `GoogleCloudPlatform/scion` [H] | Named agents (harness + template) dispatched by a Hub to runtime brokers; tmux keystroke delivery; agents delegate via a CLI; A2A bridge | Container per agent (Docker/Podman/Apple), k8s pod with optional runtimeClass, Cloud Run, or Substrate actor (gVisor); per-agent worktrees; on Substrate a validated per-actor `EgressPolicy` | All in the box: Hub secrets as env/files, host `~/.claude/.credentials.json` copied in, Hub JWT in env, GCP tokens from an in-container metadata server | Hub RBAC, tiered agent roles, frozen permission ceilings per delegation edge; Claude runs with skip-permissions; no typed approval gate | Apache-2.0 | active |
| **Centaur** `paradigmxyz/centaur` [H] | Thread (Slack/Teams/API) → one sandbox; in-pod Rust `harness-server` (JSON-RPC, Codex app-server events) spawns Claude stream-json with `bypassPermissions`, also codex, pi, amp, hermes | k8s pod per thread (agent-sandbox CRDs), optional gVisor; default-deny NetworkPolicy: only the API and a per-sandbox **iron-proxy** (TLS MITM, own DNS, header allowlist, metadata/pod CIDRs denied); default domain allowlist `"*"` | **Placeholders only**: typed tool credentials bound to hosts and a header/query/path slot; model key as stub env; subscription login as a **dummy `.credentials.json` with a fake refresh token**, real bearer injected from a central token broker that serialises refresh-token rotation | Principal → roles/grants → secrets → request rules (host, method, path) at proxy and API; no tool-level policy; Slack-button workflow gates | Apache-2.0 OR MIT | active; 1.4k stars |
| **Gas Town** `gastownhall/gastown` [H] | Claude, Codex, Gemini, Copilot, OpenCode, pi, … in tmux with verified-submit typed input; optional ACP proxy; unit = bead (Dolt issue) | Worktree per worker; optional Docker image (cap_drop ALL, no network limit); for container/Daytona workers an **mTLS proxy** with per-command/subcommand exec allowlist and git smart-HTTP to a host bare repo, short-TTL client certs + serial deny-list | Model logins in agent env/keychain; quota rotation swaps keychain tokens between accounts; git push credentials stay host-side in proxy mode | Agents run with skip-permissions/yolo flags; PreToolUse guard hooks (in box); ESTOP sentinel freezes all agents | MIT | active; 18.7k stars |
| **Gas City** `gastownhall/gascity` [H] | Successor SDK: tmux, subprocess, ACP, k8s, ssh runtimes; beads + formulas | Worktrees, k8s pods (no NetworkPolicy, root or nil SecurityContext), ssh hosts; controller/box split with per-box HMAC bearers | Model keys in agent env; secrets to 0600 files not argv; credential-provider helper protocol with audience + scopes | Default `unrestricted` = skip-permissions; ACP permission requests become approve/approve_always/deny/deny_always interactions; `internal/clientgrant`: single-use, request-bound grants (digest of method, path, query, body hash; ed25519-signed) | MIT | very active |
| **Paperclip** `paperclipai/paperclip` [H] | claude-local (stream-json), codex, gemini, opencode, pi, cursor-cloud, HTTP gateways; issues run on heartbeat wakeups in an org-chart model | Worktrees or sandbox plugins (E2B, Daytona, Modal, Cloudflare, k8s); k8s plugin: deny-all ingress, Cilium FQDN egress, optional kata-fc | Model keys from a secrets vault **injected into the run env**; third-party tool credentials brokered by the server tool gateway, never in the run | Skip-permissions by default; real gate is the server MCP tool gateway: profiles, allow/block/require_approval/rate_limit/trust_rule; **Action Request** with canonical-args hash, `signedArguments`, expiry; agent gets HTTP 409 `approval_required`, retries with the request id; budget reservations with dispatch recheck. Native Bash/file tools not gated | MIT | very active; 112k stars |
| **Multica** `multica-ai/multica` [H] | Local daemon claims tasks; Claude via stream-json with `bypassPermissions` (not overridable), Codex app-server, ACP for others | Per-task directory; Codex sandbox forced to danger-full-access; no network limit | Host CLI logins; a `MULTICA_TOKEN` minted per (agent, task) at claim time, fail closed | None at runtime; `AskUserQuestion` disallowed | **"Multica License"**: Apache-2.0 plus commercial-use and branding conditions (not OSI) | very active; 55k stars |
| **Agent Orchestrator** `OrchestratorInc/agent-orchestrator` (was `ComposioHQ/agent-orchestrator`) [H] | ~45 agent adapters; tmux/PTY/ConPTY; ACP and Codex app-server chat drivers; orchestrator agent spawns workers from issues/PRs | Worktree only | CLI logins in per-account config folders; GitHub token from env or `gh auth token` | Agent's own permission mode; `sessionguard` refuses typed input while the agent shows a permission dialog | Apache-2.0 | very active; 14k stars |
| **Paradev** `ParadevAI/Paradev` (was `superset-sh/superset`) [H] | Desktop PTY presets (`claude --dangerously-skip-permissions`, `codex --dangerously-bypass-approvals-and-sandbox`); chat runtime via Agent SDK, Codex app-server, ACP | Local worktree; cloud workspaces on Vercel Sandbox with allow-all or a `"*"` catch-all network policy | **Placeholders only in the box**: Vercel firewall swaps the header when it equals the placeholder, per host (Anthropic, ChatGPT, repo-scoped GitHub installation token re-minted on keepalive, HMAC for its own API) | Local: bypass; chat mode: SDK `canUseTool` and Codex approvals in the UI (in-process) | MIT + CLA | very active; 16k stars |
| **ruflo** `ruvnet/ruflo` (was claude-flow) [H] | One Claude Code "queen" with a generated `--mcp-config` and a large MCP tool surface; many "agents" are records, not processes | None by default; optional Docker pool (project read-only, `--network` only if configured) | `-e ANTHROPIC_API_KEY=…` on docker argv | Skip-permissions defaults to true; `AgenticPolicyEngine` (legacy/observe/enforce, default legacy) with `PolicyApproval{maxUses, uses, expiresAt, revokedAt}` and hash-chained receipts, but state in an agent-writable project file and wired to few tools | MIT | active; 81k stars |
| **OpenAI Symphony** `openai/symphony` [H] | Spec + Elixir reference: polls trackers, one `codex app-server` per issue workspace | Per-issue directory (optionally over SSH); relies on Codex `workspaceWrite` with `networkAccess: false` | Codex host login; tracker credentials stay host-side as host-executed dynamic tools, env names unset in the child | Codex approval policy; an unanswerable approval **fails the run** ("MUST NOT stall") | Apache-2.0 | 2026-09-15 |
| **Harbor** `harbor-framework/harbor` [H] | Eval framework running ~40 agent CLIs (Claude Code headless with `bypassPermissions` by default) in task environments | Docker compose or ~30 remote providers; per-phase network policy (agent vs verifier): public / none / allowlist via an egress sidecar (gost + nftables) sharing the agent netns | `ANTHROPIC_API_KEY`/`CLAUDE_CODE_OAUTH_TOKEN` in container env; copies host `~/.codex/auth.json`; inference host auto-allowlisted | None beyond network policy; verifier scores afterwards | Apache-2.0 | active |
| **xum** `coder/xum` (was `coder/mux`) [H] | Own agent loop (Vercel AI SDK), itself an ACP server; imports Claude Code/Cursor plugins and skills | Local, worktree, SSH, Docker/Podman, devcontainer, Coder runtimes; cgroup limits; no network restriction found | Model loop and keys on the host, tools run in the runtime; "project secrets" injected as env into every bash call; SSH agent and `GH_TOKEN` forwarded | Per-mode tool policy, `tool_pre`/`tool_post` hook scripts (trusted projects only) | AGPL-3.0 | active |
| **Sculptor** `imbue-ai/sculptor` [H] | Claude Code via stream-json + stdio control protocol; pi in RPC mode; others in a PTY | Worktree by default; experimental container backend. "Sandboxed" in docs means `IS_SANDBOX=1` + `--dangerously-skip-permissions` | Host Claude login; Docker recipe forwards key and OAuth token as env | All tool permissions auto-approved; questions/plan approvals via harness-owned MCP tools | MIT | active |
| **CLI Agent Orchestrator** `awslabs/cli-agent-orchestrator` [H] | Supervisor delegating via an MCP server (assign, handoff, inbox) to ~15 CLIs in tmux; regex screen status | None; agents on the host | Host logins / env keys | Role → `allowedTools` translated to native flags (advisory for Codex/Kimi, none for Cursor); `delegateTools` caps children; scraped permission prompts become exactly-once interrupt records answered by typing | Apache-2.0 | active |
| **Session managers** [H]: claude-squad (AGPL-3.0, tmux scraping, AutoYes presses Enter on prompt text), ccmanager (MIT, PTY; host-side auto-approval = regex blocklist then a Haiku judge of scraped screen text, then writes `\r`), agent-of-empires (MIT, Rust; tmux or ACP structured view; optional Docker/Podman/Apple Container sandbox), vibe-kanban (Apache-2.0, stream-json control protocol; sunsetting), emdash (Apache-2.0, PTY or ACP; SSH remotes), Nimbalyst (MIT, formerly Crystal; optional Cloudflare sandbox), Toad (AGPL-3.0, ACP client), uzi (MIT, stale), agentapi (MIT, deprecated/archived) | Several CLI agents side by side | Worktrees + tmux/PTY. agent-of-empires: container with bridge network by default, `none` allowed but no proxy provided. Nimbalyst Cloudflare sandbox: `enableInternet=false`, HTTPS interception, concrete-host allowlist | Host logins. agent-of-empires mounts **one shared read-write `.credentials.json` into every Claude sandbox**; Nimbalyst copies the Claude OAuth file into its sandbox; emdash keeps git tokens out of the env via a nonce-authenticated credential helper | Mostly the agent's own prompts or auto-accept. agent-of-empires: single-use server approval nonces and ACP `fs/*` brokered with a root check (outside the agent). vibe-kanban and Nimbalyst: PreToolUse hooks to a human approval UI (in box) | various | mostly active |
| **branchyard** `vamsiramakrishnan/branchyard` [H] | Rust engine: Claude Code via stream-json + `--permission-prompt-tool stdio`, Codex app-server, ACP | Tiers: worktree; `--isolated` private HOME with ANTHROPIC*/OPENAI* stripped; Landlock write guard; **unprivileged user+net namespace whose only exit is a listener handed to the engine over a socketpair**; microsandbox, Substrate, GKE Agent Sandbox (egress "not applied" on those) | **Model gateway**: the harness's "API key" is a per-turn Ed25519 JWT; gateway verifies, adds the real key, meters, enforces budget (subscription-login harnesses bypass it); connector gateway holds upstream credentials | Presets matched against ACP/stream-json requests; `--ask` to a console deck; a branchyard approval never overrides a native deny and vice versa; child scope capped at parent's | Apache-2.0 | active; 10 stars |
| **loom** `cosmix/loom` [H] | Interactive Claude Code (Codex optional) in tmux; daemon over a unix socket | Worktrees + Claude Code's own sandbox settings (Bash only) + PreToolUse guards for file tools; plan check commands in loom's own bwrap `--unshare-all` | Host Claude login; token files read-denied to Bash | Refuses `bypassPermissions` at preflight; sessions cannot write `.loom/`, `.claude/`, hooks; privileged actions via **one-shot tickets applied at most once through a ledger** by a daemon outside the sandbox; branches touching `.claude/` or `.mcp.json` go to human review | MIT | active |
| **Herd** `NickGuAI/Herd` [H] | Claude stream-json, Codex app-server, Gemini ACP on local/SSH/Tailscale machines | None | Credential pools: selected account's OAuth installed into the native credentials file | Per-category policy (MCP, bash regex, skills) = auto/review/block; standing approvals with expiry; PreToolUse hook POSTs with an HMAC session-bound token and polls; fails closed, but `HERD_APPROVAL_FAIL_OPEN=1` flips it from inside the agent env | AGPL-3.0 | 2026-07 |
| **zeroshot** `the-open-engine/zeroshot` [H] | Rust graph engine (step/verifier/par/loop/map); agents emit typed signals, cannot add edges; Claude, Codex, Copilot, pi | Local same-user plus subreaper; hosted/Docker "capsule" container, no egress policy found | Keys injected as env; GitHub delivery token kept controller-only | Hosted workers always skip permissions; "independent approval" = LLM verifier nodes | MIT | active; 2.1k stars |
| **Other small meta-harnesses** (StateRoot, Hive, aegis, Circus Chief, keel, ruvnet/metaharness, …) [L] | Shared memory across harnesses, folder-as-state pipelines, kanban control planes | Mostly worktrees | Vendor logins | Mostly none | mostly MIT/Apache | 5–740 stars |

---

## 2. Per-project notes

### 2.1 metaharness.tools (`nrwl/metaharness.tools`) [H]

- An Astro site by Nx, MIT, last commit 2026-08-24 (`refs/repos/metaharness`). It is an explainer, not
  software. Its "landscape" section lists three projects: **Polygraph** (Nx's own product), **Omnigent**
  (Databricks) and **SuperagenticAI/metaharness**; the FAQ adds the Stanford reference code
  (`apps/website/src/components/sections/v3/LandscapeV3.astro`, `FaqV3.astro`).
- Capabilities it attributes to a meta-harness: swappable harnesses, repository knowledge, provisioning into
  isolated worktrees, cross-repo PRs, session durability, multiplayer sessions, distilled memory
  ("dreaming"), organisational policy "in code", feedback loops (`WhatMetaHarnessV3.astro`).
- Security appears once, as "policy lives at the meta-harness layer, checking prompts, tools and actions".
  There is nothing about where enforcement runs, credentials, or memory poisoning. The memory page treats
  shared memory purely as a productivity feature (`pages/memory.astro`); compare design.md §12, which treats
  every persisted write as a smuggling channel.
- Note the site is written by a vendor (Nx) that also lists its own product first.

### 2.2 Omnigent (`omnigent-ai/omnigent`) [H]

Python (+ a TS web UI), Apache-2.0, status alpha, created 2026-06-11, announced by Databricks on 2026-06-13
(Zaharia, Uhlenhuth, Zumar). ~11.3k stars; releases weekly (v0.21.0 on 2026-11-05). Clone at
`refs/repos/omnigent`, commit `2a9cbe2c`.

**Architecture.** A *server* (sessions, policies, sharing, web/mobile UI, REST) and *runners/hosts* that wrap
each agent in a session behind one executor API (`omnigent/inner/*_executor.py`). Harnesses are driven three
ways: SDKs (`claude_sdk_executor.py`, `openai_agents_sdk_executor.py`), native control protocols (Codex
app-server, ACP for Grok/Jcode/Devin/OpenClaw), and native TUIs in tmux with keystroke injection and screen
reading (`harnesses/claude_native/bridge.py`, >11k lines). Sessions can be shared, co-driven and forked.

**Isolation.**
- Linux: bubblewrap with a hermetic mount view, `$HOME` never mounted, cwd read-only unless granted,
  top-level dotfiles tmpfs-masked, then `PR_SET_NO_NEW_PRIVS` and a seccomp profile (k8s-derived denylist,
  `clone` with `CLONE_NEW*` → EPERM, `clone3` → ENOSYS, socket families limited to UNIX/INET/INET6)
  (`omnigent/inner/bwrap_sandbox.py` header). `--unshare-net` only when `allow_network` is false
  (`bwrap_sandbox.py:608-612`).
- Network: an asyncio MITM proxy on a **unix socket** for "hard enforcement via network namespace isolation",
  or TCP for "soft enforcement" (`inner/egress/proxy.py` header; `inner/egress/controller.py`). Rules are
  `METHODS host/path-glob`, default deny (`inner/egress/rules.py`). Host names are restricted to
  `[A-Za-z0-9.-]`, explicitly citing the sandbox-runtime 0.0.43 parser-differential fix (NUL, `%`, CRLF).
- Defaults lean to availability: `allow_network: bool = True`; dotfile masking scans only the top level by
  default and on overflow of a 50,000-entry cap it **warns and leaves the rest unmasked**
  (`inner/datamodel.py:600-720`, with the trade-off spelled out in comments).
- macOS seatbelt; Windows Job Object only (no FS or network isolation). Remote backends: Modal, Daytona, E2B,
  Blaxel, Islo, CoreWeave, Kubernetes, OpenShell, Boxlite, microsandbox, Databricks.
- `enforce_sandbox` is a policy that *transforms* the launch probe; a DENY on `sys_agent_start` is logged
  and ignored: "there is no agent-start policy phase today" (`docs/POLICIES.md`, `enforce_sandbox`).

**Credentials.**
- Agent CLIs get a deny-by-default environment: base vars plus the harness's own variable family; other
  providers' keys are not inherited; extra names need `env_passthrough` (`docs/POLICIES.md`).
- The egress proxy holds host-bound `CredentialRewriteRule`s. Default is *swap-on-access*: a request to the
  bound host with no `Authorization` header gets the real one. Opt-in *placeholder swap*: an `oa_cred_*`
  value in `Authorization` (Basic/Bearer/token) is replaced; an unknown placeholder or one bound to another
  host gets 403. A client-set non-placeholder `Authorization` is left alone. No injection on TRACE or OPTIONS
  (`inner/credential_proxy.py` header; `inner/egress/proxy.py:1380-1460`). Credential sources include
  commands and a unix-socket broker with a 5 s deadline.
- Git over SSH is mediated by exact repository-scoped bindings (`inner/git_ssh_policy.py`).
- **The model credential is usually in the box.** For native Claude Code, a static key becomes
  `apiKeyHelper: "printf %s <key>"` passed via `--settings`, because the env allowlist excludes
  `ANTHROPIC_API_KEY` (`harnesses/claude_native/main.py:3316-3325`); the managed "connect broker" path vends
  ~1 h OAuth tokens through the helper (`main.py:3546-3560`). Subscription logins come from the CLI's own
  config. Only the Codex-on-Databricks-gateway route uses a separate signer relay that keeps the credential
  outside and gives the box a placeholder for exact method/host/path routes (`inner/model_signer.py`,
  `inner/model_egress.py`, `inner/model_signer_service.py`).

**Policy and approvals.**
- Policies are Python callables returning ALLOW / DENY / ASK at `request`, `response`, `tool_call`,
  `tool_result`; DENY short-circuits; session policies run first, then agent spec, then server
  (`docs/POLICIES.md`). Returning `None` abstains, and any non-result, non-dict return is coerced to ALLOW
  (`inner/policies.py:340-380`). LLM-judged `PromptPolicy` fails closed when misconfigured (`policies.py:405-435`).
- Built-ins: tool-call caps, `ask_on_os_tools`, spend caps with soft thresholds, per-user daily budget, PII
  scan of LLM requests, `github_policy` (parses `git`/`gh` shell commands; unparseable syntax → ASK),
  Google Workspace policies, `risk_score_policy` (accumulates points per tool and per sensitivity label and
  escalates guarded tools past a threshold), model-routing rules.
- Enforcement point for tool policies is the harness's own permission path: Claude SDK `can_use_tool` and
  `PreToolUse` hooks (`inner/claude_sdk_executor.py:2506-2862`), Claude native `PermissionRequest` hook
  forwarded to the server (`harnesses/claude_native/hook.py:1047-1120`), Codex app-server approvals
  (`server/routes/_codex_elicitation.py`), plus policy hooks for Cursor and Hermes. That is outside the
  agent's *reasoning* but relies on the agent calling its permission path; the OS sandbox and egress proxy
  are the only layers that hold if it does not.
- ASK becomes an approval card. Pending approvals are in-process `asyncio.Future`s keyed by a
  workspace-namespaced elicitation id with an owner check and a request fingerprint
  (`server/_elicitation_registry.py`). Approvals can also be answered in the embedded native terminal; the
  server then infers the answer from the mirrored tool result. No signature, no use count, no ledger.

**For wicket.** The closest existing system. It validates wicket's §9.0/§9.4 rules (inject only into a
declared slot, bind to host, reject placeholder replay) and §6's adapter split (SDK / control protocol / TUI).
It differs on principle 1 (the box is hostile): policy runs through in-box permission hooks, approvals can be
answered from the box's terminal, the model key sits in the box, and defaults fail open.

### 2.3 Polygraph (Nx) [M]

Announced 2026-06-26 on the Nx blog as an "agent-agnostic meta-harness": a dependency graph across an
organisation's repos, resumable shared sessions, institutional memory, a TUI. trypolygraph.com shows a hosted
product, free during early access, with an enterprise tier; no licence or source. Nothing published on
sandboxing, credentials, permissions or policy. It lets agents "read and write across every repo a user can
access", the opposite of per-task least privilege. Not reusable; useful only as the "cross-repo" use case
wicket's §5 manifests should be able to express.

### 2.4 Stanford Meta-Harness and its implementations [H]

- `stanford-iris-lab/meta-harness` (MIT, 1.8k stars, active) is the paper's framework; the optimised
  Terminal-Bench 2 harness is in `meta-harness-tbench2-artifact` (76.4% on TB2 with Claude Opus 4.6, per its
  description). The proposer is Claude Code run as
  `claude --dangerously-skip-permissions -p … --output-format stream-json --setting-sources ""` with MCP and
  skills disabled (`reference_examples/*/claude_wrapper.py:115-150`). Evaluation runs in Runloop or Modal
  sandboxes through Harbor (`reference_examples/terminal_bench_2/SETUP.md`).
- `SuperagenticAI/metaharness` (177 stars): Codex-first; per-candidate workspaces, environment snapshot,
  `allowed_write_paths` enforced after the fact; all candidates kept on disk. **Licence is FSL-1.1-ALv2**
  (GitHub reports NOASSERTION): not open source until the two-year Apache conversion. Ideas only.
- Others in the optimisation sense: `001TMF/harness-forge` (Claude Code skill), `raphaelchristi/harness-evolver`,
  `china-qijizhifeng/agentic-harness-engineering` (965 stars), `zozo123/meta-harness-on-islo` [L].
- **Relevance.** These loops are agents writing code that other agents then execute, i.e. exactly wicket's
  §17 promotion problem. They run the proposer with permissions off on the host. In wicket the proposer is a
  zone with a write-scoped workdir, candidates are programs under §17, and the scoring harness is trusted
  code outside the box.

### 2.5 leash (`strongdm/leash`) [H]

Go, Apache-2.0, ~600 stars, last commit 2026-04-06 (`refs/repos/leash`).
- Two containers: the agent ("target") and a privileged manager that attaches eBPF LSM programs
  (`file_open`, `bprm_check_security`, `socket_connect`) scoped by cgroup, and runs a MITM proxy that
  iptables redirects to; the CA key stays in a private dir the target cannot see
  (`docs/design/SECURITY-MODEL.md`, `ARCHITECTURE.md:200-240`).
- **Cedar** is the policy language. Because eBPF cannot evaluate Cedar, leash transpiles Cedar into its own IR
  and lints at authoring time for constructs it cannot enforce (`docs/design/CEDAR.md`). Policies start
  permissive; the docs recommend **Record/Shadow** first, then enforce. MCP observer correlates tool calls
  with file and network telemetry.
- Credentials: header injection is designed (`rewrite.conf`) but the README defaults forward
  `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`/`GEMINI_API_KEY` into the container and prompt to mount `~/.claude`
  (README "Key Concepts"); `docs/design/PROXY.md` still lists header injection as TODO in places. No
  approval flow; policy is edited live through the Control UI or `POST /api/policies`.
- For wicket: confirms Cedar for agent policy (design.md §3) and shows the value of a *transpile-and-lint*
  step when the enforcement point is weaker than the policy language. Avoid its credential defaults and the
  privileged manager container sharing a kernel with the agent (gVisor is wicket's floor, §7).

### 2.6 sandcastle (`mattpocock/sandcastle`) [H]

TypeScript, MIT, ~8.9k stars, active. `sandcastle.run()` creates a sandbox, a branch strategy and an agent
session, then merges commits back.
- Providers: bwrap/seatbelt "native", Docker/Podman, E2B (Firecracker), Modal, Fly Sprites
  (`docs/guide/sandbox-providers.md`).
- Native sandbox: fresh private `$HOME` per sandbox, so host logins (`~/.claude`, `~/.codex`, `~/.config/gh`)
  are not visible; env limited to what sandcastle passes; **network open, including host localhost**, stated
  plainly in its threat section ("built for accidents and prompt-injection attacks", not determined attackers).
- Agents run with permission checks skipped (`--dangerously-skip-permissions` unless `permissionMode` is set);
  it tells users to switch off the agent's own sandbox. Model key goes in as `env: { ANTHROPIC_API_KEY }`
  (`docs/guide/agent-providers.md`).
- For wicket: a clear statement of what a "native" sandbox does *not* cover is good practice (§14.2). Its
  rule that agent-provider env and sandbox-provider env must not overlap is a small, cheap check worth having.

### 2.7 vibekit (`superagent-ai/vibekit`) [M]

MIT, ~1.9k stars, quiet since 2026-01. CLI `vibekit claude|codex|gemini|…` runs the agent in Docker or one of
eight hosted sandbox adapters (`packages/`), with "redaction" of secrets in output and local observability.
Proxy support only sets `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` to a user-supplied URL (`packages/cli/src/cli.js`).
Output redaction is the weakest of the credential strategies ([01 §3.12]): the secret is already in the box.

### 2.8 docker-agent harness delegation [M]

Docker's agent runtime (`docker/docker-agent`, Apache-2.0) lets an agent hand work to Claude Code, Codex,
opencode, pi or command-code via a `harness:` block. The CLI runs on the host as the same user with its own
login; Claude Code runs with `--dangerously-skip-permissions`; its `AskUserQuestion`/`ExitPlanMode` are relayed
through a per-turn loopback MCP server registered as `--permission-prompt-tool`; Docker Agent's own approval
hooks and budgets do not apply to harness tools ("approval is external"). `--sandbox` does not carry the CLI
login, so it cannot box the harness without separate provisioning. Source:
docker.github.io/docker-agent/features/harnesses/ (read 2026-11-08). The `--permission-prompt-tool` relay is
the same hook wicket's Claude adapter can use for *advisory* prompts (§14.1.2), never for grants.

### 2.9 Cluster-scale runtimes: Agent Substrate + AX, Centaur, Scion, CAO [H]

- **Agent Substrate** (`agent-substrate/substrate`, Apache-2.0) is the sandbox layer under Google AX and an
  optional Scion backend. Every actor runs under gVisor or a Cloud Hypervisor microVM; egress is default-deny
  with all TCP tunnelled to an egress gateway and a DNS relay that answers NXDOMAIN for hosts outside the
  actor's `EgressPolicy` (`docs/guides/egress-traffic.md`). Credential injection
  (`docs/guides/egress-credential-injection.md`): an `https` rule's `effects.replaceHeaders` names a header,
  prefix and `credentialUri`; the gateway terminates TLS, **discards whatever placeholder the actor sent** and
  inserts the real value; only a separate credential-provider reads secrets; failures are closed with a
  documented 403/500/503 matrix; per-actor JWTs (audience, 300-3600 s) and SPIFFE certs are available.
  Lifecycle: tasks start suspended, suspend/resume snapshots RAM and filesystem to object storage, templates
  have golden snapshots, warm pools, and the router **wakes a suspended actor on request and parks requests**
  while workers are saturated (`docs/concepts/request-parking.md`). Closest existing analogue to design.md
  §7.1, §8.3 and §13.2.
- **Google AX** (`google/ax`) on top of it is weaker than its substrate: the task's `spec.env` (the Claude
  example passes `ANTHROPIC_API_KEY`) goes in plaintext into the actor env and into `AX_TASK_YAML`
  (`internal/controller/reconciler.go:180-200`); it creates no `EgressPolicy` yet; least-privilege egress and
  approval policies are roadmap items (`docs/roadmap.md`).
- **Centaur** (`paradigmxyz/centaur`, Rust) is the closest *deployed* design to wicket's credential model.
  One pod per thread behind a default-deny NetworkPolicy that reaches only the API and a per-sandbox
  iron-proxy. Tools declare typed credentials (`http` with `match_headers` and `hosts`, `oauth_token`,
  `gcp_auth`, `pg_dsn` giving the box a local DSN to the proxy); the box env holds only placeholders
  (`docs/pages/extend/tools.mdx:50-95`). For Claude subscription logins the box gets a **dummy
  `~/.claude/.credentials.json` with a fake JWT and refresh token** (`services/sandbox/claude-credentials.json`);
  iron-proxy injects the current bearer from a central token broker that refreshes rotating tokens under a
  Postgres row lock so many proxies don't trip reuse detection (`crates/centaur-token-broker/src/broker.rs`).
  GitHub uses a placeholder sent as the Basic password by `gh auth setup-git`. Authority chain: principal →
  roles/grants → secrets → request rules (host, method, path). Gaps: default domain allowlist `"*"`, Claude
  runs with `bypassPermissions`, and human approval exists only as Slack-button workflow gates. Durable
  workflows (sleep, wait-for-event, child workflows), warm pool, idle suspend that keeps a state PVC.
- **Scion** (`GoogleCloudPlatform/scion`): teams of agents, frozen permission ceilings per delegation edge,
  secrets pushed *after* boot so golden snapshots stay secret-free (`.design/kubernetes/substrate-runtime.md`
  :126-131). But all credentials are in the box (env, files, a copied host `.credentials.json`, an
  in-container metadata server for GCP tokens), it does not use Substrate's header injection, and Claude runs
  with skip-permissions.
- **CLI Agent Orchestrator** (AWS Labs): host processes in tmux; role-based `allowedTools` translated to
  native flags (advisory where the CLI has none); `delegateTools` caps what a child can receive; scraped
  permission prompts become exactly-once interrupt records answered by typing.
- **agenttier** (pod + PVC per agent, default-deny NetworkPolicy, gVisor; 49 stars) [L].

### 2.10 Fleet orchestrators [H]

Read at source level by a parallel pass; paths are relative to each clone under `refs/repos/`.

- **None of the seven runs agents in a no-network box reached only through proxies, and every one defaults
  the agent CLI to a bypass mode** (skip permissions / bypass approvals).
- **Paperclip** has the most wicket-like *escalation contract*. Its server-side MCP tool gateway
  (`server/src/services/tool-gateway.ts`, ~11.9k lines; `doc/MCP-ACCESS-GOVERNANCE.md`) answers a gated call
  with HTTP 409 `approval_required` and an **Action Request** carrying a canonical-arguments hash,
  `signedArguments` and an expiry; the agent retries with `approvedActionRequestId`, and changed arguments
  fail with `signed_arguments_mismatch`. Trust rules pin catalog and schema hashes; budgets use reservations
  re-checked at dispatch (`budget-reservations.ts`). Gaps: native Bash and file tools are not gated, the model
  key is injected into the run env (`ai-connection-runtime.ts`), and `dangerouslySkipPermissions` defaults to
  true (`packages/adapters/claude-local/src/index.ts:71`). Compare design.md §9.5 and §11.
- **Gas City** `internal/clientgrant`: single-use grants bound to a digest of method, path, raw query and
  body hash, ed25519-signed out of tree and never cached. Close to wicket's grant shape (§11); its health
  patrol (config-fingerprint drift, crash-loop quarantine) is relevant to §13.6. k8s pods have no
  NetworkPolicy (`internal/runtime/k8s/pod.go:449-460`).
- **Gas Town** `gt-proxy-server`: mTLS proxy giving container workers an exec allowlist per command and
  subcommand plus git smart-HTTP to a host bare repo, with short-TTL client certs and a serial deny-list
  (`internal/proxy/*`, `docs/proxy-server.md`). The witness protocol verbs (`POLECAT_DONE`, `HELP:`,
  `MERGE_READY`, `HANDOFF`) are a typed mailbox. Its quota rotation swaps keychain tokens between accounts.
- **Paradev** keeps credentials out of its Vercel cloud boxes: the CLIs see placeholder env vars and auth
  files, and the Vercel firewall swaps the header only when it equals the placeholder, per host, including a
  repo-scoped GitHub installation token re-minted on keepalive (`packages/trpc/src/lib/sandbox/credentials.ts`).
  But the network policy is allow-all or ends in a `"*"` catch-all, and the GitHub rules attach the token
  unconditionally.
- **Multica** mints a `MULTICA_TOKEN` per (agent, task) at claim time and refuses to start rather than fall
  back to the daemon's own credential (`server/internal/daemon/daemon.go`). It forces Codex to
  `danger-full-access` because Seatbelt blocks its own API (`execenv/codex_sandbox.go`). Licence is the
  "Multica License" (Apache-2.0 plus commercial and branding conditions): not open source.
- **Agent Orchestrator** `internal/sessionguard`: every pane write takes an input lease, re-reads the
  screen and refuses while a permission dialog is showing, so typed input cannot approve on the user's behalf.
- **ruflo** defines `PolicyApproval {maxUses, uses, expiresAt, revokedAt}` and hash-chained `PolicyReceipt`s
  (`v3/@claude-flow/security/src/policy/types.ts`), but the engine defaults to `legacy`, is wired to a few of
  its own MCP tools, and stores state in an agent-writable project file; the Docker pool passes
  `ANTHROPIC_API_KEY` on argv (`cli/src/services/container-worker-pool.ts:420-433`).

### 2.11 Session managers and desktop ADEs [H]

[09] classed agent dashboards as "UI ideas only; none mediates authority". The source pass mostly confirms
it, with a few useful exceptions:
- **Approval by keystroke on scraped screen text** is common: claude-squad AutoYes (`session/tmux/tmux.go:246-259`),
  uzi `auto` (`cmd/watch/auto.go`), and ccmanager, which runs a regex blocklist and then asks Claude Haiku to
  judge the scraped terminal before writing `\r` into the PTY (`src/services/autoApprovalVerifier.ts`).
- **agent-of-empires** (Rust, MIT) has an ACP structured view where it brokers `fs/*` itself with a
  sandbox-root check and uses **single-use server-generated approval nonces**, and does not forward its own
  token to the agent (`src/acp/approvals.rs`, `docs/development/internals/structured-view.md`). Its container
  sandbox defaults to bridge networking; `none` is allowed but no proxy is provided, and one shared read-write
  `.credentials.json` is mounted into every Claude sandbox (`docs/guides/sandbox.md`).
- **vibe-kanban** drives Claude Code over stream-json with `--permission-prompt-tool=stdio` and answers
  `can_use_tool` itself (`crates/executors/src/executors/claude.rs:157-258`); default is bypass; the README says
  the project is sunsetting.
- **emdash** keeps git tokens out of the session env with a credential helper that calls back to the
  desktop over loopback with a per-session nonce (`packages/core/src/primitives/git-credentials/api/env.ts`);
  the token still reaches the agent through the helper's stdout.
- **Nimbalyst**: optional Cloudflare sandbox with `enableInternet=false`, HTTPS interception and a
  concrete-host allowlist, but it copies the host's Claude OAuth file into the container
  (`services/cloudflareSandbox/claudeCredentialExport.ts`). Its loopback `ANTHROPIC_BASE_URL` proxy only tees
  the stream for transcripts.
- **Toad** (ACP client): `fs/write_text_file` joins `project_root / path`, so an absolute path escapes
  (`src/toad/acp/agent.py:445-451`).
- **agentapi** (deprecated in favour of Coder Agents): screen-diffing HTTP wrapper; Host-header allowlist only.

### 2.12 Small self-described meta-harnesses [H]

- **branchyard** (Rust, Apache-2.0, 10 stars, created 2026-09) is the closest small project to wicket's
  design. Local Linux harnesses run in an unprivileged user + network namespace whose only exit is a listener
  handed back to the engine over a socketpair (`crates/branchyard-runtime/src/netns.rs`), with a host-side
  allowlisting proxy and optional per-branch CA for method/path rules (`egress.rs`, `docs/egress.md`);
  `enforce=required` refuses to start where confinement is unavailable. The harness's "API key" is a per-turn
  Ed25519 JWT that a model gateway swaps for the real key while metering budget (`docs/model-gateway.md`,
  `crates/branchyard/src/models/gateway.rs:262-291`); child scopes are capped at the parent's. Caveats from its
  own docs: egress is "not applied" on the microsandbox/Substrate/recipe backends, subscription-login
  harnesses bypass the gateway, and as of 2026-10-10 no real harness had run under a policy. It vendors
  httpjail, boundary, agentapi and emdash.
- **loom** (Rust, MIT) refuses `bypassPermissions` at preflight, makes `.loom/`, `.claude/` and hooks
  unwritable to sessions, and routes privileged actions through **one-shot tickets** relayed by a PostToolUse
  hook to a daemon that applies each at most once through a ledger; commits are made by the daemon so signing
  keys stay out of the box; branches touching `.claude/` or `.mcp.json` need human review. Its network limit is
  Claude Code's own sandbox (Bash only) plus in-box hooks.
- **Herd** (AGPL-3.0): category policies (MCP, bash regex, skills) as auto/review/block with expiring
  standing approvals; a PreToolUse hook posts to the server with an HMAC session-bound token and polls. It
  fails closed, but an env var in the agent's own environment (`HERD_APPROVAL_FAIL_OPEN=1`) flips it.
- **zeroshot** (Rust, MIT, 2.1k stars): agents emit typed signals into a graph they cannot extend;
  "independent approval" is LLM verifier nodes; hosted workers always skip permissions.
- Not read: StateRoot, Hive, aegis, Circus Chief, keel, ruvnet/metaharness, kyber-weave and others from
  `topic:meta-harness` [L]. T3MP3ST (AGPL-3.0) uses the term for an offensive-security platform; out of scope.

### 2.13 Sandboxed runners and eval harnesses [H]

- **inspect_ai agent bridge** (used by `inspect_swe`; MIT). The auto-generated compose file sets
  `network_mode: none` (`inspect_ai/src/inspect_ai/util/_sandbox/docker/config.py:119,131`). A model-API proxy
  runs inside the container on a local port and speaks OpenAI Completions/Responses, Anthropic and Google
  (`agent/_bridge/sandbox/bridge.py:54-120`); it reaches the host through `sandbox_service`, a file-based RPC
  over a private 0700 directory polled via sandbox exec (`util/_sandbox/service.py:184-230`). Claude Code gets
  `ANTHROPIC_BASE_URL=http://localhost:<port>` and a hard-coded dummy token (`inspect_swe/_claude_code/env.py:96-110`);
  credential headers are never forwarded, and provider-side web search, code execution and remote MCP are
  withheld because they would bypass the sandbox (`bridge.py:215-222`). An **approval chain reviews tool calls
  inside model responses at the bridge** and turns a rejection into a synthetic tool result
  (`agent/_bridge/_approval.py`); host-side bridged tools run only under a single-use grant tied to the model's
  proposal (`agent/_bridge/sandbox/host_tool.py:57-177`). This is wicket's §9.3 LLM proxy and taint ingress in
  miniature. Weakness: polling exec as the transport (0.2-2 s).
- **fullsend** (Go, Apache-2.0). OpenShell sandboxes, one per agent role, behind an L7 gateway with
  per-endpoint, method+path and per-binary allowlists (ADRs 0017, 0020, 0025). A four-tier credential decision
  tree (`docs/ADRs/0025-provider-credential-delivery-for-sandboxed-agents.md`): prefetch inputs and
  post-process outputs so no credential is in the run (default); OpenShell placeholder swap; a host-side
  capability-reducing REST API with a per-run bearer; real files in the box (last resort). The gateway route
  keeps the provider key out and gives Claude an endpoint-bound OIDC placeholder via `apiKeyHelper`
  (ADR 0137); the default Vertex route puts a workload-identity file and token in the box. In-box hooks add
  SSRF, canary and redaction checks; host post-scripts validate output against a JSON schema; humans gate by
  role minimums and merge labels. It checksums runner-written config dirs before each launch.
- **Harbor** (Apache-2.0): per-phase network policy (agent vs verifier) of public / none / allowlist, the
  allowlist enforced by a gost + nftables sidecar sharing the agent's netns (`environments/docker/docker-compose-egress-control.yaml`,
  `trial/network_policy.py`); exact hosts, no inferred wildcards. The model key is in the container env, which
  is why the inference host is auto-allowlisted.
- **OpenAI Symphony** (Elixir + `SPEC.md`): one `codex app-server` per issue workspace; tracker operations are
  host-executed dynamic tools and the tracker env names are unset in the child (`SPEC.md:1093-1112`); an
  approval request with no auto-approve **fails the run rather than stall** (`app_server.ex:505-536`). It relies on
  Codex's own `workspaceWrite` sandbox with `networkAccess: false` and declines to mandate more.
- **Rivet**: Sandbox Agent (Rust daemon inside the box, ACP adapters) puts the model key in the box env and
  copies host `~/.claude/.credentials.json` and `~/.codex/auth.json` into it
  (`server/packages/agent-credentials/src/lib.rs`); its docs say "everything inside the sandbox has access to
  the token". Rivet Agents instead runs the pi loop in a backend actor with logins in a `credentials` actor
  outside the sandbox, and its human-in-the-loop example uses an approval actor whose `consume(version)` lets
  one approval allow exactly one deploy (`examples/docs/human-in-the-loop/deploy.ts`).
- **xum** (AGPL-3.0) runs its own agent loop and the model key on the host and executes tools through a
  Runtime interface (local, SSH, Docker, Coder); it replaces Claude's provider-side web fetch with a local,
  hookable tool. Project secrets go into every bash call's env.
- **Sculptor** (MIT): stream-json + stdio control protocol, with `AskUserQuestion`/`ExitPlanMode` replaced by
  harness-owned MCP tools; "sandboxed" in its docs means `IS_SANDBOX=1` plus skip-permissions
  (`process_manager_utils.py:84-88`).
- **agent-safehouse** (Apache-2.0): deny-first composable Seatbelt profiles for ~14 CLIs with an `explain`
  tool; network deliberately open ("blocking exfiltration/C2 is explicitly NOT a goal"); `~/.claude` stays
  readable.

---

## 3. What wicket should borrow / avoid (ranked)

### Borrow

1. **Review tool calls at the LLM proxy, and withhold provider-side tools by default** (inspect_ai
   `agent/_bridge/_approval.py`, `bridge.py:215-222`). A tool call that appears in a model response can be
   judged, or turned into a synthetic refusal, *before* the agent sees it. That gives wicket a second
   enforcement point for agents whose tools never cross a proxy (local file edits), and confirms §9.3's
   rewrite of server-side tool definitions. Proposal-bound single-use host tools (`host_tool.py`) are the
   same shape as §11 grants.
2. **Subscription login as a dummy credentials file plus a brokered bearer** (Centaur
   `services/sandbox/claude-credentials.json`, `crates/centaur-token-broker`). This is the concrete recipe for
   §9.3's "owner's Claude subscription token, never an API key": the box sees a syntactically valid but fake
   OAuth file, `wicket-llm` injects the real bearer, and one broker serialises refresh-token rotation for all
   zones. Check against Claude Code's current refresh behaviour before relying on it.
3. **Placeholder-discard injection, NXDOMAIN DNS gating and wake-on-request parking** (Agent Substrate
   egress and request-parking docs). The gateway ignores whatever the box sent in the slot (stronger than a
   match-and-swap), fails closed with a documented status matrix (a good template for §9.5), and parks a request
   that arrives for a hibernated agent while it restores (§13.2, §13.8 wake budgets). Scion's "push secrets
   after restore" rule keeps snapshots clean (§7.1 parking).
4. **A typed "approval required" response the agent can retry against** (Paperclip tool gateway: HTTP 409
   `approval_required`, Action Request with canonical-args hash, `signedArguments`, expiry, retry with
   `approvedActionRequestId`, `signed_arguments_mismatch` on change). It is the closest shipped analogue of
   §9.5 and §11's digest binding; use its error codes as conformance cases. Gas City's `clientgrant` (digest of
   method, path, query, body hash; never cached) and Rivet's `consume(version)` approval actor are the same
   idea in smaller form.
5. **Host-bound placeholder rules, header slot only, with replay refusal** (Omnigent
   `inner/egress/proxy.py:1380-1460`). Matches §9.0 and §9.4; adopt its test cases directly: placeholder sent
   to another host → 403; client-set real `Authorization` left untouched *and suppresses injection*; no
   injection on TRACE/OPTIONS. wicket goes further by rebuilding the request from the `Op` (§1 table), but these
   are good negative tests for `wicket-egress` (§9.1).
6. **A credential decision tree with "no credential in the run" as the default** (fullsend ADR 0025:
   prefetch/post-process → proxy placeholder → host capability-reducer API → files in the box). Make the
   tier explicit per provider in the zone manifest (§5, §9.4) and show it in the zone view (§14.2); wicket
   simply never offers the last tier.
7. **Network namespace whose only exit is a listener handed to the control plane** (branchyard
   `branchyard-runtime/src/netns.rs`), and refuse to start where confinement is unavailable
   (`enforce=required`). The same pattern as wicket's bridged proxy sockets (§3) and Codex's listener-fd
   handoff [08]; a second, small Rust reference for `wicket-jail`.
8. **At-most-once privileged actions and agent-config review** (loom: one-shot tickets relayed to a
   daemon outside the box and applied through a ledger; commits signed by the daemon; branches touching
   `.claude/` or `.mcp.json` held for human review). Matches §12's "repo state is a smuggling channel" and
   should be a default gate on promotion (§13.4, §17).
9. **Typed input that cannot approve by accident** (Agent Orchestrator `sessionguard`: input lease,
   re-read the screen, refuse while a permission dialog shows). Needed for any T3 adapter that types into a
   TUI (§6).
10. **Deny-by-default child environment with a named passthrough list** (Omnigent `env_passthrough`). Same
   shape as §6's `LaunchPlan` ("no secrets, only placeholders + routes"); the passthrough list should be part of
   the zone manifest (§5) and shown in the zone view (§14.2).
11. **Shadow mode before enforce, and transpile-time lint when the enforcement point is weaker than the
   policy language** (leash `docs/design/CEDAR.md`). wicket already plans shadow mode for
   `rc_attested_approvals` (§14.1.2); apply it to new manifests too, and make the zone compiler (§3, §5.2)
   reject Cedar it cannot enforce at a given surface rather than silently approximating.
12. **Accumulating session risk that escalates guarded tools** (Omnigent `risk_score_policy`). A cheap
   approximation of §4.2 labels for surfaces that have no label yet; as a *tighten-only* input to the decision
   engine, never a loosening one.
13. **Harness-optimisation discipline for adapters** (Stanford Meta-Harness, SuperagenticAI): every candidate
   stored, scored on a fixed suite, with a write-scope check. That is what the per-agent-version conformance
   suite (§6.1) needs when Claude Code, Codex and pi ship weekly; and §17 already gives the boundary for running
   agent-written candidates.
14. **Explicit "what this boundary does not protect" text** (sandcastle's threat section). §14.2 should
   generate the equivalent from the enforcement config (principle 7).
15. **Exact-route model credential relay** (Omnigent `model_egress.py` `FrozenModelRoute`: one method, one
   host, one queryless path). A minimal form of §9.3 that can be checked by `wicket-llm` tests.

### Avoid

1. **Approvals answerable from the agent's terminal or through its permission hook as if they were grants**
   (Omnigent native terminals, docker-agent relay), and approval by keystroke on scraped screen text (claude-squad AutoYes, uzi `auto`, ccmanager's Haiku judge of the terminal). §14.1.2 rule 1 already forbids this: agent-local prompts are
   advisory; grants come only from wicket-native channels with passkey step-up.
2. **Fail-open policy semantics.** Omnigent coerces an unrecognised policy return to ALLOW, starts with network
   on, and warns-and-continues when dotfile masking overflows. Principle 3 (fail narrow): unmapped means deny,
   and an overflowing mask is an error. The same goes for fail-open switches the box can reach (Herd `HERD_APPROVAL_FAIL_OPEN=1` in the agent env) and policy state the agent can write (ruflo `.claude-flow/policy/state.json`).
3. **Classifying shell command text as policy** (Omnigent `github_policy`). It has to give up on heredocs,
   substitutions and comments and fall back to ASK, which trains approval fatigue. wicket judges the request at
   the git/HTTP boundary (§3 "every crossing becomes one `Op`", §9.1).
4. **Model key or subscription login in the box** (Omnigent `apiKeyHelper printf`, leash env forwarding and
   `~/.claude` mount, sandcastle `env`, Paperclip run env, Harbor, agent-of-empires' shared read-write `.credentials.json` in every sandbox, Nimbalyst, Rivet and Scion copying host OAuth files in, AX writing keys into task YAML). Violates principle 2; the LLM proxy holds it (§9.3).
5. **Permissions off plus an open network** (sandcastle native, Stanford proposer, docker-agent). Skipping the
   agent's prompts is fine *only* when the outer box has no route out (§3 diagram).
6. **Shared, ever-growing memory across sessions and harnesses as a feature** (metaharness.tools "distilled
   memory", Polygraph, StateRoot). Without §12's promotion gate and labels this is the smuggling channel
   design.md warns about.
7. **Privileged helper sharing the agent's kernel** (leash manager container with eBPF). wicket's jail helper is
   small and separate (§3.1), and the agent sits under gVisor (§7).
8. **Placeholder swap with an open catch-all network** (Paradev on Vercel). Hiding the key is not enough if
   the box can reach any host with the data; injection must sit behind a default-deny policy (§9.1).
9. **Turning a sandbox off because it blocks the harness's own API** (Multica forcing Codex to
   `danger-full-access`). Give the agent a socket to the control plane instead (§3).

---

## 4. Follow-ups

- Verify the Centaur dummy-credentials + brokered-bearer recipe against the pinned Claude Code version
  (refresh behaviour, `claude auth status`) before adopting it for `wicket-llm` (§9.3).
- Read Agent Substrate's gVisor integration and snapshot path against §7 and §13.5 (it is Go; ideas, not code).
- Add Omnigent, Centaur, Agent Substrate, inspect_ai's agent bridge, Paperclip's tool gateway, fullsend,
  branchyard and leash to
  `prior-art.md` (relevance 2–3).
- Licence checks before any code reuse: SuperagenticAI metaharness (FSL-1.1-ALv2) and Multica (Multica
  License) are not open source; claude-squad, xum, Toad and Herd are AGPL-3.0 (ideas only); Paradev needs a CLA
  for contributions.

## 5. Sources (read 2026-11-08)

- https://metaharness.tools and https://github.com/nrwl/metaharness.tools
- https://github.com/omnigent-ai/omnigent (README, `docs/POLICIES.md`, `omnigent/inner/*`, `omnigent/server/*`)
- https://www.databricks.com/blog/introducing-omnigent-meta-harness-combine-control-and-share-your-agents
- https://nx.dev/blog/announcing-polygraph, https://trypolygraph.com
- https://github.com/stanford-iris-lab/meta-harness, https://arxiv.org/abs/2603.28052
- https://github.com/SuperagenticAI/metaharness
- https://github.com/strongdm/leash
- https://github.com/mattpocock/sandcastle
- https://github.com/superagent-ai/vibekit
- https://docker.github.io/docker-agent/features/harnesses/
- https://github.com/UKGovernmentBEIS/inspect_ai, https://github.com/meridianlabs-ai/inspect_swe
- https://github.com/fullsend-ai/fullsend, https://github.com/harbor-framework/harbor, https://github.com/openai/symphony
- https://github.com/rivet-dev/agents, https://github.com/coder/xum, https://github.com/imbue-ai/sculptor, https://github.com/eugene1g/agent-safehouse
- https://github.com/gastownhall/gastown, https://github.com/gastownhall/gascity, https://github.com/paperclipai/paperclip,
  https://github.com/multica-ai/multica, https://github.com/OrchestratorInc/agent-orchestrator, https://github.com/ParadevAI/Paradev,
  https://github.com/ruvnet/ruflo
- https://github.com/vamsiramakrishnan/branchyard, https://github.com/cosmix/loom, https://github.com/NickGuAI/Herd,
  https://github.com/the-open-engine/zeroshot
- claude-squad, ccmanager, agent-of-empires, vibe-kanban, emdash, nimbalyst, toad, uzi, coder/agentapi (GitHub)
- https://github.com/google/ax, https://github.com/agent-substrate/substrate, https://github.com/GoogleCloudPlatform/scion,
  https://github.com/paradigmxyz/centaur, https://github.com/awslabs/cli-agent-orchestrator, https://github.com/docker/docker-agent
- https://github.com/andyrewlee/awesome-agent-orchestrators, GitHub search `topic:meta-harness`
- GitHub repository metadata (stars, licence, last push) via the GitHub API for every project in §1
