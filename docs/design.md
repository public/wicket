# wicket — design v0.2

*v0.2, 2026-11-08. Draft for discussion: research 01–17 folded in. Nothing is built yet.*

A **meta-harness**: it does not run an agent loop. It builds the environment that other agent processes
run in, gives each the least access its task needs, brokers every crossing of a boundary, and shows humans
what those boundaries are. Claude Code is the primary inner agent; the harness itself is agent-agnostic and
model-agnostic.

"Meta-harness" has two meanings in 2026 [17 §2.3, §1.1]. wicket uses it in the sense of Anthropic's
Managed Agents post: a platform that is unopinionated about the agent loop and virtualises session, harness
and sandbox. It adds enforcement on top. It is *not* the optimiser sense of Lee et al.'s *Meta-Harness*
(arXiv 2603.28052), which searches over harness code. In de Macedo's four-condition definition of a harness
(loop, tools, context, control), wicket supplies the fourth, control and containment, from outside the box
for agents that already have the other three. That is why §6 can stay agent-agnostic.

Sources:
- [`00-origin-conversation.md`](00-origin-conversation.md) — the concept brief (zones and gates, the
  confused deputy, handles, generated adapters).
- [`research/01-inner-agents.md`](research/01-inner-agents.md) — driving and boxing Claude Code, ACP, other
  CLIs, prior-art orchestrators.
- [`research/02-isolation.md`](research/02-isolation.md) — sandbox backends, networking, filesystem, what this
  box supports.
- [`research/03-policy-authority-ifc.md`](research/03-policy-authority-ifc.md) — Cedar, tokens, escalation,
  labels, research papers.
- [`research/04-enforcement-plane.md`](research/04-enforcement-plane.md) — MCP spec, gateways, egress proxy,
  git, adapter DSL.
- [`research/05-papers-agent-security.md`](research/05-papers-agent-security.md) — 44 agent-security papers
  read in full (CaMeL, FIDES, APPA, ceLLMate, MiniScope, …).
- [`research/06-papers-mcp-and-foundations.md`](research/06-papers-mcp-and-foundations.md) — 64 items: MCP
  and tool-ecosystem attacks, benchmarks, and the foundations (reference monitor, capabilities, DIFC,
  Cedar, Zanzibar, Firecracker, warning fatigue, RAR/GNAP).
- [`research/07-oss-sandboxes-runtimes.md`](research/07-oss-sandboxes-runtimes.md) — 31 sandbox and runtime
  projects read at source level.
- [`research/08-oss-gateways-policy.md`](research/08-oss-gateways-policy.md) — about 50 gateway, proxy,
  policy and token projects read at source level.
- [`research/09-operator-channels.md`](research/09-operator-channels.md) — Remote Control mechanics and
  oversight UIs.
- [`research/10-infrastructure.md`](research/10-infrastructure.md) — providers, Kubernetes, startup and
  efficiency.
- [`research/11-pi-and-codex.md`](research/11-pi-and-codex.md) — pi and Codex as inner agents.
- [`research/12-openclaw.md`](research/12-openclaw.md) — OpenClaw.
- [`research/13-hermes.md`](research/13-hermes.md) — Hermes Agent.
- [`research/14-multi-tenancy.md`](research/14-multi-tenancy.md) — platform mode and tenant isolation.
- [`research/15-mandates-user-delegation.md`](research/15-mandates-user-delegation.md) — user mandates, agentic commerce.
- [`research/16-metaharnesses.md`](research/16-metaharnesses.md) — about 40 meta-harnesses, orchestrators and
  sandboxed runners compared (Omnigent, Agent Substrate, Centaur, inspect_ai, Paperclip, Harbor, …).
- [`research/17-metaharness-literature.md`](research/17-metaharness-literature.md) — essays, papers and vendor
  docs on harnesses, harness search, evaluation harnesses and harness safety.
- [`research/18-authorization-landscape.md`](research/18-authorization-landscape.md) — authorization
  engines, relationship stores, capability tokens and policy distribution, against wicket's requirements.
- [`research/22-pause-resume-hibernate.md`](research/22-pause-resume-hibernate.md) — pausing, resuming and
  hibernating boxes: snapshot mechanisms, storage options, correctness, a layered plan.
- [`prior-art.md`](prior-art.md) — the consolidated catalogue of papers and projects.
- Components, processes and dependencies: Claude Doc https://claude.ai/artifact/XDhPxV33xb5G7QG4FpkS2L

Section numbers like `[03 §7.5]` point into those files.

---

## 1. What the research changed

Things the brief assumed or left open, and what we now know (2026-11-08):

| Brief | Now |
|---|---|
| "Most agents handle *permission pending, retry later* fine" | **Unverified for every agent.** It is the first experiment (§19, M3). The cooperative paths are better than expected, though: Claude Code has a `PreToolUse` → `defer` hook and an indefinitely pending `can_use_tool` control request; ACP `session/request_permission` can be held open; MCP 2026-07-28 adds `input_required` + retry and Tasks. [01 §1.10, 04 §1.1] |
| Enforcement lives outside the box | Confirmed as the industry consensus (Docker Sandboxes, `srt`, Codex, E2B BYOP, Claude Code on the web). Nobody ships typed escalation, attenuation, labels or handles: that remains wicket's gap. [01 §3.12] |
| Allowlist the model API host | **Not enough.** Anthropic's May 2026 containment post: allowlisting `api.anthropic.com` let an attacker exfiltrate files with *their own* API key. Every credential-bearing host needs TLS interception, and the proxy must strip client auth and inject its own. [02 §7.2] |
| Two enforcement surfaces (MCP gateway, egress proxy) | **Three.** The model API is its own surface: an **LLM proxy** (via `ANTHROPIC_BASE_URL`) holds the model key, is the best liveness sensor, and is a taint ingress (Claude's WebSearch runs server-side and is invisible to the egress proxy). [01 §4.5–4.6] |
| microVMs for speed and lightness | This box (Vultr VC2) has **no KVM**. v1 Linux tiers are a native process jail and gVisor (which also gives checkpoint/restore for parking). Firecracker comes later on bare metal. [02 §1, §10] |
| Typed escalation à la RFC 9396 | Kept. MCP's own spec now says single-use must be enforced server-side, so use counts and approvals live in a **ledger**, not in tokens. [03 §2.6] |
| Macaroon/Biscuit attenuation | Adopted: zone ceilings, grants and leases are Biscuit tokens, checked on the node by a vendored, patched `biscuit-auth` (§2.1). The PoC still uses a capability algebra with a syntactic subset check, stored in the ledger. [03 §7.2] |
| Claude-style Remote Control and wicket's own UI side by side (owner, 2026-11-08) | Remote Control needs a claude.ai subscription login and Anthropic's own base URL, and its control protocol runs through Anthropic's session service (`--sdk-url`, Anthropic hosts only). So it can't share wicket's default launch. It becomes an opt-in `vendor_rc` zone mode: the RC bridge stays on the host, and its sessions are jailed via `CLAUDE_CODE_PROCESS_WRAPPER`. An observe-only tap at the egress proxy feeds wicket's console, and RC answers are never wicket grants. [09] |
| Claude Code is the only inner agent that matters | **Codex app-server and pi are T1 too**: native control protocols with host-answered approvals, steering and typed output. pi has no permission layer by design ("the sandbox is your job"). Codex has its own Remote Control. [11] |
| Hash-pin tool descriptions; label per agent | Tool descriptions poisoned from the start defeat pinning, and the highest-success real attacks tamper with *values inside* allowed calls (MCPTox, MSB). So descriptions are taint, sink arguments need provenance on every R2+ `Op`, and handles can be passed as arguments. [05, 06] |
| The process jail is a reasonable first tier | Frontier models escape misconfigured containers (SandboxEscapeBench). gVisor is the floor for anything valuable, every hardening layer fails closed, and VMMs are jailed too. [05, 07] |
| Credential injection at the proxy | Substituting placeholders anywhere in a request (srt's mask, iron-proxy, tokenizer) reflects the real secret back. Inject only into the declared header slot, rebuild requests from the `Op`, never forward client headers. [07, 08] |
| Adapters generated from OpenAPI | Better sources exist: GitHub's docs repo maps permissions to 1,075 endpoints, GitHub OpenAPI flags `triggersNotification`, AWS publishes per-action `IsWrite`/`IsPermissionManagement`, Cloudflare tags token groups. These set **risk floors** the generator cannot go below. [04 §4.1] |
| Nothing like wicket exists | Still true after surveying ~40 self-described meta-harnesses and orchestrators. The norm is worktrees plus skip-permissions, with the model key or a copied `~/.claude` login in the box. The closest designs (Agent Substrate, Centaur, inspect_ai's agent bridge, Omnigent) keep keys out and default-deny egress, but none ships typed escalation bound to a digest with grants that can't be answered from inside the box. [16 §0, §3] |
| Evaluation harnesses already "box any agent" | They do, but they write the model key into the box and allowlist the model host (Harbor), and guard against cheating rather than exfiltration. Cheating is real (agents reading future commits, patching scorers), so scorers belong outside the proposer's reach: the verifier-zone pattern (§17). [17 §1.4, §2.5] |
| The harness matters less than the model | It moves both. Changing only the edit format moved 14 of 16 models by about 15 points; swapping the harness with the model fixed moved a containment score from 39 to 62 (HarnessSafe). wicket's denial bodies are part of the agent's interface, and the boundary's utility cost has to be measured (§9.5, §19 M1/M3). [17 §2.2, §2.6] |

---

## 2. Principles

*Scaffolding versus boundaries.* "Every component in a harness encodes an assumption about what the model
can't do" is right for prompts, loops and adapters, which should be deleted as models improve; that is why
wicket's adapters, `AgentCaps` and LaunchPlans are data with per-version conformance (§6.1). It is wrong for
authority: the enforcement plane assumes nothing about model weakness. Anthropic made the same call when it
chose structural isolation over narrow token scoping [17 §1.1]. Policy enforced at the proxies also never
enters the context window, so compaction can't erode it.

1. **The box is hostile.** Assume the inner agent is compromised from its first token. Nothing inside the
   box is in the trusted computing base, including the adapter's own config, hooks and the agent's own
   sandbox. Those are telemetry and UX only.
2. **No secrets in the box by default.** Sandbox identity is the transport (its netns, UDS or vsock), not a
   bearer token. Tools get placeholders; real credentials are injected on the way out. A workload that must
   hold a secret itself (e.g. a webhook receiver's HMAC key) gets it only as an explicit, human-granted,
   visible exception, never the model or injection credentials (owner, 2026-11-09; #36).
3. **Fail narrow.** Every mistake should cost the agent access (it stalls, someone notices) rather than
   leak access. Unmapped means deny. Undeclared parameter means deny. Unknown risk means R4.
4. **Judge the request, not the reasoning.** Escalation deciders see a typed request and the trusted task
   text, never the agent's justification or context.
5. **Authority only narrows downward.** A child's ceiling is a subset of its parent's, checked mechanically.
6. **Data carries labels; free text does not cross gates into wider authority.** Parents get typed
   low-capacity fields and opaque handles.
7. **The picture is generated from the enforcement config.** The zone view and the blast-radius answer are
   computed from the same objects the proxies enforce. No hand-drawn diagrams.
8. **Small trusted core.** The decision engine, proxies, jail helper and adapter interpreter are the TCB.
   Keep them small, fuzzed and boring. Generated artifacts (adapters, manifests) are data checked by that
   core, not code.
9. **Cheap boundaries get used; expensive ones get bypassed.** Startup latency and per-instance overhead
   are requirements on a par with isolation level (owner, 2026-11-08). wicket will start many short-lived
   sandboxes: one per zone, plus an instance per task of every third-party MCP server. If a boundary costs
   seconds or hundreds of MB, people will merge zones and share servers, and the security model erodes.
   Every backend and milestone has a latency and density budget (§7.1), measured in CI.
10. **A platform, not just a tool.** The same model serves one developer and an agentic SaaS with
    thousands of tenants (owner, 2026-11-08). Tenants are the outermost isolation boundary. By default
    nothing that can carry data or authority is shared between them; sharing happens only through
    policy-controlled cross-tenant gates (§15).
11. **Agents are long-lived by default** (owner, 2026-11-08). An agent is a durable identity that wakes,
    works, sleeps, hibernates, and is eventually garbage-collected by policy. Processes are disposable;
    authority is per work item; what persists across sleep passes a promotion gate (§13).
12. **Users can delegate, narrowly** (owner, 2026-11-08). An agent can act on a user's behalf, shopping
    online for example, only under a mandate: purpose-, time- and money-bound, revocable, with
    checkout-style approval points the user signs. The user's credentials never reach the agent (§16).
13. **Reusable programs run without an agent, never without a boundary** (owner, 2026-11-08). Code an
    agent writes becomes a program only through a reviewed, signed promotion, and every run gets the same
    sandbox, egress control and audit as an agent (§17).

### 2.1 Build versus reuse (owner, 2026-11-10)

wicket shouldn't rebuild what identity and access management systems already do well. Cloud IAM, though,
doesn't do wicket's core job:
- **IAM governs calls to one provider's APIs.** wicket governs every crossing out of an agent's box: any
  website or API (most have no IAM), the model API, MCP tools, git pushes, new sandboxes. It judges per
  request (method, path, risky patterns).
- **IAM gives credentials *to* the workload.** wicket keeps them out of the box and adds them outside.
- **IAM's delegation is static and managed by admins.** wicket's is made by agents at runtime: sub-agents
  with narrowed authority, and requests and grants in-band. Letting an agent create IAM roles would itself
  be a high-risk permission change.
- **IAM has no isolation,** no in-band "wait for a human, then retry", and no taint.

So wicket is the **enforcement point and broker in front of the agent**: the sandbox, the proxies,
keeping credentials out, the request → approval → retry loop, and runtime delegation between agents.
Everything around that uses standard components:

| Need | Reuse | Status |
|---|---|---|
| Workload identity, rotation, attestation | **SPIFFE** IDs and SVID formats; a real **SPIRE** deployment can be the issuer | the PoC has its own small issuer with SPIFFE-shaped IDs (#52) |
| Org rules: images, hosts, escalation and inspection rights, operator roles | **Cedar** (the `cedar-policy` crate, embedded), static and reviewed; **SymCC** in CI to diff policy changes (#50, #34, #11) | the PoC's checks are hand-written (#51) |
| Delegated authority: zone ceilings, grants and leases | **capability chains in the Biscuit format**, checked by a vendored, patched `biscuit-auth`: narrowing by construction, signed, checked offline, revocable by subtree; intersected with the org rules at decision time | the PoC's `subset.rs` is hand-written and conservative (#57) |
| Distributing policy and grants to nodes | wicket's own **signed snapshot-and-delta feed with a freshness lease** (TUF-style), so nodes know when they're stale and fail narrow; no product signs increments or fails narrow | central checks on the control host (#57) |
| Relationship data: spawn trees, tenants, roles | Cedar entities materialised from wicket's ledger; **OpenFGA** as an optional source in platform mode | the ledger (#11) |
| Human identity and groups | the organisation's **identity provider** (OIDC), passkeys at the IdP | passkeys enrolled in wicket's console (#53) |
| Downstream credentials | providers' **scoped native credentials** (AWS STS session policies, GCP downscoped tokens, GitHub App installation tokens; §9.4) | whole tokens injected from the vault (#54) |
| Human just-in-time access workflows | Teleport access requests, AWS Identity Center, Entra PIM, as optional **approval channels** | wicket's own ledger and console |
| Clusters and scheduling | Kubernetes behind the placement interface (#45) | Vultr + SSH first (#37) |

The rule: if a mature, standard component does it, wicket integrates with it, and keeps its own code for
what only an in-path broker can do. Where the best fit is weakly maintained, wicket may fork or vendor it.

**Identity is JWT; authority is Biscuit** (owner, 2026-11-10; confirmed after experiments #59 and its
follow-up, 2026-11-11).
- **Identity:** who a box is. It stays JWT, as SPIFFE JWT-SVIDs (#52): standard, and readable by anything
  outside wicket.
- **Authority:** what a box may do, i.e. zone ceilings, grants and leases. It's a Biscuit token held by the
  node, never by the box.
- **Why not JWT for authority:**
  - A JWT can't be narrowed. Delegating means someone with a signing key mints a new token: either a round
    trip to the control plane for every spawn or grant (against local decisions, #57), or signing keys on
    every node, where a compromised node could mint *any* authority.
  - "The child is within its parent" would be hand-written checks over claims, which have to be right
    everywhere.
- **Why Biscuit:**
  - The holder appends blocks offline, with no issuer key, and blocks can only add checks. The decision
    must pass the checks of *every* block. So a child can't exceed its parent by construction, and a
    compromised node can only narrow what it already holds.
  - Approvals are third-party blocks signed by the approving principal: the human approval service, or a
    parent box's grantor key that a zone block trusts.
  - Each block has a revocation id, so revoking one revokes the subtree under it.
  - Leases lapse on their own, without invalidating the token.
  - It's a published format with several implementations, so parties outside wicket can verify a token.
- **How it's checked fast** (`experiments/biscuit-fast/RESULTS.md`). Stock biscuit-auth 6.0.0 takes about
  1 ms per request at spawn depth 5 (#59), because it rebuilds the token's rules for every request, and
  its wall-clock time limit makes denials depend on load. wicket vendors upstream main with three
  patches:
  1. load a token once, then add each request's facts on top;
  2. a step budget instead of the wall-clock limit, so decisions are deterministic;
  3. a compiled evaluator shared between threads. Anything it can't compile, and any run-time error, goes
     to the stock engine.

  Result at depth 5: 7–11 µs median and under 30 µs p99 per request. Loading a token costs about 3 ms,
  once per token.
- **The rules that come with it:**
  - A **structural check** runs before a token is loaded:
    - first-party blocks hold only checks from wicket's fixed vocabulary: no rules, no `check all`;
    - `.matches` only as `$p.matches("<literal>")` on the request path. Path globs become globset's own
      regex, so tokens match exactly as wicket's matcher does. Patterns are capped at 256 bytes and must
      compile under a size limit;
    - third-party blocks hold only `approved(...)` rules, from keys a zone block trusts;
    - blocks (16), token size and checks per block are capped.

    Without it, a hostile block can burn CPU inside the step budget.
  - A **differential test in CI** compares the compiled evaluator with the stock engine on random tokens
    and requests. It runs on every change to the fork and every rebase onto upstream.
  - Patches 1 and 2 are small and general, and should go upstream. Patch 3 is wicket's to maintain.
  - The format sits behind wicket's own chain interface.
- **What it costs:**
  - About 20k vendored lines and a 1.9k-line fork in the trusted computing base.
  - The work of rebasing onto upstream.
  - Tokens are 10 KB at depth 5. That's fine held on the node, but too big for a request header.
  - Its rule language (Datalog) takes learning, although wicket generates every block, so nobody writes it
    by hand.

The survey behind these choices, with the options ruled out and why, is research 18
(`research/18-authorization-landscape.md`). In short:
- Cedar is healthy and right for static org rules. Its analyser can't reason about authority stored as data
  or about template-linked policies, so it can't be what guarantees delegation.
- Every system that reliably stops a child exceeding its parent does it by intersection at decision time:
  AWS session policies, Biscuit attenuation, Kubernetes' escalate/bind rule.
- Biscuit is the one moderately maintained capability-token library (Apache-2.0, Eclipse Foundation). Stock,
  it's too slow for the request path (about 1 ms at depth 5), so wicket vendors and patches it (7–11 µs).
- The local-agent and distribution projects (cedar-local-agent, OPAL, avp-local-agent, Cedarling and
  Lock) are inactive, AWS-only, or immature for this.

---

## 3. Architecture

```
                         ┌──────────────────────────── wicketd (control plane) ───────────────────────────┐
  human ── CLI / TUI ──► │ task runner · zone compiler · escalation broker · ledger · handle & label store │
  (approvals, views)     │ audit log · credential vault · view/blast-radius · adapter registry             │
                         └───────┬────────────────────────────┬───────────────────────────┬───────────────┘
                                 │ Decision engine (library, in-process in every enforcement point)
                                 │ Op → Cedar(org ∧ zone ∧ forbids) ∧ ∃grant ⊇ op ∧ label rules ∧ ledger
              ┌──────────────────┼────────────────────┬───────────────────────┐
              ▼                  ▼                    ▼                       ▼
     ┌────────────────┐ ┌──────────────────┐ ┌──────────────────┐ ┌───────────────────────┐
     │ LLM proxy      │ │ MCP gateway      │ │ Egress proxy     │ │ Sandbox backends      │
     │ model key held │ │ rmcp, tools from │ │ rama, per-box CA │ │ process jail · gVisor │
     │ liveness,taint │ │ adapters, pinned │ │ strip+inject,    │ │ firecracker · seatbelt│
     │ budget, models │ │ 3rd-party, handle│ │ git S&F, decider │ │ e2b · wasm (codemode) │
     └───────▲────────┘ └────────▲─────────┘ └────────▲─────────┘ └──────────┬────────────┘
             │ ANTHROPIC_BASE_URL │ MCP over UDS         │ HTTPS_PROXY        │ creates, owns
     ┌───────┴────────────────────┴──────────────────────┴────────────────────▼──────────────┐
     │ sandbox: no network route except the bridged proxy sockets                             │
     │   inner agent (Claude Code / ACP agent / any process)   gh · git · curl · SDKs          │
     │   /wicket/out (outbox)   workdir overlay   placeholders only                            │
     └─────────────────────────────────────────────────────────────────────────────────────────┘
```

**Every request crossing the box boundary becomes one `Op`**, whichever surface it arrives on:

```rust
pub struct Op {
    pub agent: AgentId,                 // from transport identity, never from the request
    pub surface: Surface,               // Llm | Mcp | Egress | Git | Spawn | Store
    pub provider: ProviderId,           // "github", "anthropic", "fs", "net", "wicket"
    pub verb: Verb,                     // adapter-canonical, e.g. contents.write
    pub resources: Vec<Resource>,       // ALL must be allowed
    pub effects: EffectSet,             // read.scoped, notify.external, exec.ci, ...
    pub risk: RiskClass,                // max(floor(effects)), raised by dangerous patterns
    pub args: BTreeMap<SmolStr, Value>, // declared args only
    pub digest: [u8; 32],               // canonical hash; escalation requests bind to it
}
```

One engine, one resource model: a gateway-native MCP tool is *defined by* an adapter endpoint and executes
through the same upstream client, so an MCP call and a `gh api` call to the same endpoint get the same
decision by construction. [04 §7.1]

### 3.1 Process layout

`wicketd` is one daemon per host. In v1 the proxies run as tasks inside it, sharing the decision engine in
memory. They are separate crates with narrow interfaces so they can be split into their own processes (and
privilege-separated) later. The **jail helper** (`wicket-jail`) is a separate small binary started with
the privileges needed to build namespaces, because Ubuntu 24.04's AppArmor blocks unprivileged user
namespaces on this box [02 §1].

The proxy↔engine seam follows the **`srt` decider protocol** semantics (framed strict JSON: allow with
header set/remove and credential, deny, need-body; fail closed; per-request timeout). That keeps the data
plane swappable and lets us test the decider offline from recorded frames, and run Anthropic's `srt-proxy`
as a differential reference. [04 §7.1]

### 3.1.1 wicket inside the box: its own name, not localhost (owner, 2026-11-09)

wicket's endpoints in the box (egress proxy, LLM route, MCP gateway) live at **`wicket.internal`**, on
their own address, so the agent keeps all of `127.0.0.0/8` for its own servers.
- **The address is `198.18.0.1`,** from a block reserved for benchmarking and never routed on a real
  network, added to the box's loopback. `.internal` is the top-level domain reserved for private use;
  `.local` would send tools looking for it with multicast DNS.
- **The name comes from the box's hosts file**, written by the runtime at creation. The box has no resolver
  (§9.1, DNS).
- **wicket-entry starts as root** with only `NET_ADMIN`, `SETUID`, `SETGID` and `SETPCAP`, adds the address,
  then starts the forwarders and the agent through `setpriv` as the agent's user. By then every capability
  set is empty, including the bounding set, and `no-new-privileges` holds throughout.
- **Those capabilities act on gVisor's own network stack**, never the host's.
- **Verified live:** the agent ran its own servers on 127.0.0.1:8080 and :3128 (wicket's old ports), its
  capability sets were all zero, and `ip addr add` failed.

### 3.2 Identity: proving an agent is one of ours (owner, 2026-11-08)

The owner's requirement: there must be cryptographic proof that an agent in a given zone is one of wicket's.
The proof must not depend on agents registering themselves at startup.

**Launch is registration.** An agent never enrols itself. wicket creates the identity record *before* the
box starts, from facts it chose and can hash:
- tenant, zone, agent id (§13) and activation;
- manifest digest, policy epoch, image digest, adapter and agent version;
- the node it runs on.

It then binds that record to the channels it creates for that box: the unix sockets that only that box
gets. A self-registration handshake would be weaker in every way. It would put a bearer secret in the box,
where any code there can read it. It would prove only that *something* in the box knew a bootstrap token,
and a leaked token could be replayed.

**No identity key ever enters the box.** Anything in the box can read anything else in it, so a key
there identifies the box at best, and only until something copies it. Instead the enforcement points
assert identity *on the box's behalf*:

| Who needs the proof | Mechanism |
|---|---|
| wicket's own proxies | The socket a request arrives on *is* the box (no token; already the PoC's model). On remote nodes, the forwarded socket rides an SSH or mTLS channel to a node wicket enrolled, with the host key pinned at provisioning. The PoC pins it at `wicket node enrol` (#16), and both ends then authenticate each other on the channel itself (node certificate and node key one way, the issuer key the other; below); targets that aren't enrolled are still trusted on first use, with a warning. |
| Other zones, other tenants (§15 sharing), the console | Every gate message, handle and output is wrapped by the gateway in a **signed envelope**: issuer, identity record digest, content digest, labels. A receiver verifies wicket's signature, never the sender's claim. |
| External services | `wicket-egress` signs outbound requests with **HTTP Message Signatures** (RFC 9421), as Web Bot Auth does. It is opt-in per reach rule, and carries a `Signature-Agent` that resolves to the zone's identity. |
| Anyone auditing a result later | A **launch attestation** signed at start (the identity record) and a **result attestation** signed at end (output digests, the egress decisions, grants used). This is in-toto/SLSA-style provenance, chained into the audit log. |
| wicket, about its own nodes | Node enrolment with a one-time join token leads to a node key, held in a TPM where there is one, and short-lived node identity certificates (built: JWT-SVID-style, `spiffe://<install>/node/<name>`; see "Node identity" below). Later, a hardware attestation (SEV-SNP/TDX quote, TPM quote) that the node runs the expected runtime. Until then a node is trusted because wicket created it through the provider API and pinned its host key. |

**Naming.** wicket is the issuer for its trust domain, in the way SPIRE is for SPIFFE. Identities look like
`spiffe://<install>/t/<tenant>/z/<zone>/a/<agent>`, with the activation and run as claims. Signing keys
live in the vault, or a KMS/HSM in production, and are rotated. Short-lived certificates and signatures
carry the policy epoch, so a revocation is visible to verifiers.

**Short-lived keys, rotation and revocation** (owner, 2026-11-08: keys must be short-lived and
refreshed, in case an agent's environment is compromised or a key is exfiltrated).
- **Agent identities live 10 minutes.** At half-life the runner issues a new document with a brand-new
  key and discards the old key. A copied key or document is useless within minutes.
- **Validity is checked at a trusted time.** The verifier checks the identity at a time *it* trusts,
  never one the sender claims: the ledger's record time for messages, and its own clock for anything
  presented live. So an expired key can't be used to backdate a message.
- **Every document issued is kept** (`identity_history`), so the audit verifies each one at its own
  issue time.
- **`wicket identity revoke <run>` is the kill switch.** Within seconds:
  - the run's box is stopped;
  - its undelivered messages are dropped;
  - it can't send;
  - its pending requests can't be approved.

  Revocation cascades to everything the run started, because children act on its authority.
- **The installation's root key is the remaining long-lived secret.** In the PoC it's a 0600 file
  readable by the operator's user. Production splits it: the root stays offline or in a TPM/KMS and only
  certifies short-lived *issuing* keys, rotated daily or faster. `wicket run` never sees the root.
- **Agent keys never enter the box,** so compromising the box itself doesn't expose a key. Rotation
  covers the other paths: memory of the runner process, logs, a compromised host.

**Back to the human** (owner, 2026-11-08: identities must be tied to the initiator, all the way back to
the human user if there is one).
- **Every identity names its `principal`:** the human or trigger at the root of the chain, and how wicket
  knew it was them. A run started from the PoC CLI is `{type: human, id: <unix user>, via: cli,
  assurance: unix-user}`. A run started from the console carries the passkey-authenticated operator.
  A schedule or webhook carries itself and the human who created it (§13.2).
- **Delegation through agents is recorded in `act`** (RFC 8693 actor chain). A child's `act` is its
  parent, whose `act` is its own parent, and so on down to the principal.
- **The child's runner builds the chain from the parent's verified identity,** not from anything the
  parent agent said. Neither the principal nor the chain can be widened along the way.
- **It's shown wherever a human decides,** e.g. "Acting for: alice (cli, unix-user) → lead → fetcher".
  The passkey signs it with the decision, and recipients of messages see it too.
- Mandates (§16) will hang off the same principal.

**Agent-to-agent messages** go only through wicket (boxes have no network to reach each other). A
sender calls `send_message(to, body)` on its gateway. wicket sets the sender from the socket (an agent
can't name itself), checks policy and signs the envelope with the sender's agent key. The recipient's
gateway verifies the envelope against the issuer before delivering it. The policy:
- parent and child may always talk;
- otherwise the recipient's zone must list the sender's zone in `accept_from`;
- never across tenants (in v1; §15 sharing policy later).

A message is therefore delivered only if:
1. its sender is an agent this installation launched;
2. its zone is the zone wicket put it in;
3. it was addressed to this recipient.

Bodies are the sender's data, shown to the recipient as such. Typed gates (§4.3) narrow them further.

**PoC status (2026-11-08).** Built: the issuer (`wicket identity issuer`), per-run identity documents
(EdDSA JWS) with keys held by `wicket run`, `whoami`, `send_message`, `await_message`, `spawn_agent`
(a child `wicket run` with its own sandbox, sockets and identity, reach narrowed only), and signed
`run_finished` reports. Also:
- verified identities are shown with every pending request, and the console refuses approval when the
  identity doesn't verify (enforced on the server, not just in the page);
- the passkey signs the identity digest together with the decision;
- `audit --verify` re-checks every identity and envelope offline;
- `in_box_subagents: false` removes Claude Code's own Agent tool, so every subagent is a wicket child.

Also built since then:
- 10-minute identities re-issued every 5 minutes with fresh keys, with history and audit;
- delivery checks at the ledger's record time;
- revocation that cascades to children and stops boxes;
- the principal and delegation chain in every identity, shown with every request.

Built since: minimal node enrolment (#16): a join token, a pinned host key, a node key and a short-lived,
name-constrained node CA (see [nodes.md](nodes.md)). Not built: signed result attestations, RFC 9421 egress signatures, X.509 node certificates
for an mTLS transport, the separate system user, root and issuing key separation, and federation with other installations.

**Node identity (#16, built).** Nodes get short-lived identity certificates, and the control channel
authenticates both ends whatever carries it:
- **Certificate.** The issuer signs a JWS (`typ: wicket-node+jwt`, the shape of a SPIFFE JWT-SVID): subject
  `spiffe://<install>/node/<name>`, a serial, 24 h by default, and a `cnf` binding the node's Ed25519 key.
  The key is made on the node at enrolment and never leaves it, so the issuer can renew the certificate
  without the node sending anything but its proof. The ledger records every serial (`node_certs`).
- **Handshake.** The control host's hello carries a nonce. The node answers with its own nonce, its
  certificate and a proof signed with the node key. The control host answers with a proof signed with the
  issuer key, and only then does the node welcome it. Each proof is a JWS (`typ: wicket-node-auth+jwt`)
  over the role, the node name, both nonces, the certificate's digest and a channel binding. The control
  host checks the certificate against its issuer key and the ledger: unexpired by its own clock, binding
  the enrolled key, recorded, and neither it nor the node revoked. The node checks the control host's
  proof against the issuer public key installed at enrolment. Before both checks pass, neither end acts
  on the other: the control host sends no feed or box, and the node keeps its current control connection.
- **Transport independence.** The handshake (`wicket_identity::node`) takes the channel binding as input
  and knows nothing about ssh. Over ssh (0.0.1) the binding is empty, because ssh with the pinned host key
  already keeps a third party off the stream. A QUIC or mTLS transport passes its TLS exporter
  (RFC 9266), so a proof can't be relayed onto another connection. Its X.509 certificate would bind the
  same node key.
- **Renewal and revocation.** A run renews the certificate over the channel at half-life, and the node
  checks it and swaps it in atomically. Earlier certificates stay valid until they expire, so a lost
  renewal doesn't lock a node out. A node unreachable past expiry is renewed over its pinned ssh
  (`wicket node renew-ca`). `wicket node revoke` revokes the node's certificates. A run connected to the
  node rechecks every second, then stops its box and drops the node, which is not reconnected.
- **Limits.** In the PoC the control host proves the issuer key itself, which is the long-lived key. With
  root and issuing keys split, it would present a short-lived control-host certificate from the issuer
  instead, and the handshake would gain a chain. `wicket dev node-feed-probe` connects as an observer and
  skips the handshake: it can only send feed frames, which the node verifies against the feed root, and it
  never takes over the control connection.

Built since (#24): the console starts runs (from allowlisted manifest directories, the manifest's digest
signed), sends follow-ups, revokes identities and answers prefix asks, each with a passkey assertion over
exactly that action. A console-started run's principal is the passkey-authenticated operator
(`{type: human, id: passkey:<name>, via: console, assurance: passkey (user verification)}`), handed to
the detached `wicket run` in `WICKET_PRINCIPAL`; the signed audit record binds operator, run id and
principal.

**Granularity is the sandbox.** Subagents inside one box share a process and a uid, so per-subagent
*cryptographic* identity is impossible there. Per-subagent attribution is reported, not proven (§11.1).
An agent whose identity must be provable on its own runs in its own sandbox, as a wicket child or team
member, and gets its own record, sockets and signatures.

---

## 4. Core model

These types live in `wicket-core`. It has no I/O and is the most heavily property-tested crate. Detail and
rationale: [03 §7.5].

### 4.1 Resources and capabilities

```rust
pub struct ResourcePath(Vec<SmolStr>);       // ["repo","acme/api","ref","main","path","infra","ci.yml"]
pub enum ResourcePattern { Exact(ResourcePath), Prefix(ResourcePath), OneLevel(ResourcePath) }
#[derive(PartialOrd, Ord)]
pub enum RiskClass { R0Read, R1ReadScoped, R2WriteReversible, R3ExternalOrIrreversible, R4ExecOrPrivilege }

pub struct Capability {
    pub provider: ProviderId,
    pub resources: ResourcePattern,
    pub verbs: BTreeSet<Verb>,
    pub max_risk: RiskClass,
    pub args: BTreeMap<SmolStr, Constraint>,  // closed world: unlisted args are denied
}
pub struct Budget { pub expires_at: Timestamp, pub max_uses: Option<u32>, pub egress_bytes: Option<u64> }
```

`Constraint` is a closed vocabulary:
- `Exact`, `OneOf`, `NotOneOf`, `Range`, `Prefix`, `Any`;
- `IfPresent { then, otherwise }`, for optional arguments and resources (Fly's `resset.IfPresent`).

Numbers are strict: NaN, ±∞, and booleans passed as numbers are rejected [05 §10.2-12].

**Enforcement evaluates the whole chain on every `Op`** (Fly macaroon style) [08 §6 a2-2]:

  `decide(op) = org ∧ every ancestor zone's reach ∧ live grant ∧ label rules ∧ ledger(uses, epoch, revocation)`

`is_subset_of` (a syntactic, per-field check) is used only for **admission and explanation**: refusing
over-wide spawns and asks, and rendering diffs. A bug in it then costs usability, never authority.

**Cedar** expresses the human-authored layers (org ceiling, zone policy, dangerous-pattern `forbid`s). The
algebra→Cedar compiler is in the TCB. It is differentially tested: Cedar `is_authorized` against
`wicket-core`'s `decide`. Templates are linked before analysis (SymCC rejects templates, open attributes and
`AnyEntity`), and `OneLevel(p)` compiles to `like "p/*" && !like "p/*/*"`, because `*` crosses `/`.

**`cedar-policy-symcc`** (pinned together with `cedar-policy`, with a cvc5 sidecar; a timeout means fail)
proves the slow properties off the hot path:
- child ⊆ parent at zone creation;
- whether a policy change narrows (automatic) or widens (needs a decision);
- whether a generated adapter is narrower than the conservative default and disjoint from the dangerous
  list.

### 4.2 Labels

```rust
pub struct Label { pub conf: BTreeSet<DataClass>, pub taint: BTreeSet<SourceTag> }  // join = (∪, ∪); ∅ taint = trusted
pub enum Capacity { Bool, Enum(u16), Int { min: i64, max: i64 }, BoundedStr(u32), Handle }
```

- **Unknown is not trusted.** Ingress that no adapter labels gets the explicit taint `unknown`, never ∅.
  Assigning provenance is itself part of the TCB. [05 §10.2-9]
- **Third-party tool descriptions are taint** for the zone that sees them, as are agent context files
  (`CLAUDE.md`, `AGENTS.md`, `AGENTS.override.md`, `.agents/skills`, per adapter). [05 §10.2-10, 11 §3.7]
- **Server-asserted metadata is never a policy input.** MCP annotations, an upstream's `_meta.ifc`, and
  classification fields the caller supplies may only *raise* labels, never lower them or grant anything
  [08 §6 a2-8]. GitHub's MCP server `pkg/ifc` label table seeds the GitHub adapter's default labels.

- An agent's label **floats up** as it reads (the gateway and proxies join each response's label into the
  agent), capped by its zone's `clearance` and `taint_admit`.
- **No writing down:** an `Op` to a destination is denied unless the destination's clearance covers the
  agent's `conf`.
- **Integrity per risk:** a zone says which taint may be present when it performs an action of a given
  risk (`action_taint_allow`). For example, a zone tainted with `web` may comment (R3) but not push (R2 with
  `exec.ci`, which is R4).
- **Per-argument stance, not only per-agent** [05 §10.2-1, 10.2-2]. Adapters mark each parameter as
  *content* (a body, a message, file contents) or *sink* (recipient, target repo or ref, URL host,
  @mention, amount).
  - A content argument may carry untrusted data. Better still, it can be a **handle** the gateway
    substitutes at dispatch, after checking the handle's label against the destination's clearance.
  - A sink argument on any R2+ `Op` must trace to the trusted task text, the manifest, a typed gate field
    or a live grant, *and* the agent's taint must be inside `action_taint_allow`. Otherwise the `Op`
    becomes pending.

  This makes "the PR body may be untrusted, the target repo must be trusted" expressible, and it is the
  main lever against label creep. Strict per-agent IFC alone cost SPA about half its utility.
- **Provider-side state is memory.** The gateway records a label for every resource it allowed a write to,
  and applies it to later reads. Adapters give pessimistic default labels for resources wicket has never
  seen written. [03 §5.3]

### 4.3 Zones, gates, handles

```rust
pub struct Zone {
    pub id: ZoneId, pub name: String, pub parent: Option<ZoneId>,
    pub reach: CapabilitySet,                 // ⊆ parent.reach
    pub clearance: BTreeSet<DataClass>,       // what it may see
    pub taint_admit: BTreeSet<SourceTag>,     // what untrusted input it may ingest at all
    pub action_taint_allow: BTreeMap<RiskClass, BTreeSet<SourceTag>>,
    pub send: Vec<Destination>,               // where it may send
    pub stores: Vec<StoreId>,                 // task-scoped memory, deleted at task end
    pub auto_max_risk: RiskClass,             // ceiling of the auto tier
    pub ratchet_budget: u32,                  // cumulative-grant budget before forced human review
    pub sandbox: SandboxRequirement,          // isolation floor, snapshot need
}
pub enum GateRule {
    TypedFields { schema: Vec<(SmolStr, Capacity)>, endorse: BTreeMap<SmolStr, Endorsement> },
    HandlesOnly,
    QuarantinedReader { output: Vec<(SmolStr, Capacity)> },   // capability-less LLM extracts typed fields
    Declassify { by: Decider, to: Label },
    HumanApproval,
}
pub struct Gate { pub from: ZoneId, pub to: ZoneId, pub rules: Vec<GateRule> }
pub enum Endorsement {
    Validator(ValidatorRef),   // trusted check against trusted state, e.g. "names a file in the repo tree"
    CleanRerun,                // a fresh child admitting only trusted inputs must produce the same value
}
pub struct Handle { pub id: HandleId, pub origin: AgentId, pub label: Label, pub schema: Option<SchemaRef>,
                    pub expires_at: Timestamp, pub entry: Option<(SessionRef, EntryId)> }  // transcript-entry handles
```

**Gates carry typed fields and handles only, on every edge**, including `wicket.spawn` inputs, child status
and **errors** (enums plus labelled handles). The reason: a forged "error" relayed by a child got
arbitrary code run 58–90% of the time [05, MAS hijacking].
- Any free text an adapter forwards joins the child's taint into the parent.
- A `BoundedStr` from a tainted zone longer than a small N must pass a trusted validator; otherwise it
  becomes a handle.
- Endorsement always needs a validator or a clean re-run, never just a low-capacity type. That is stricter
  than FIDES, which described endorsement but didn't evaluate it; SPA forbids it outright.
- The quarantined reader returns typed fields plus `enough_information: Bool`, with no free-text error
  channel.

A **handle** is an opaque reference to content in the store (transcript, diff, report). A parent can pass
it to another child or to the final output without reading it. Dereferencing a handle joins its label into
the reader: that is how creep is made explicit rather than avoided.

**Agents live in zones.** An agent is a durable identity (§13) with a *home zone*: its standing ceiling.
A zone can hold many agents, which can collaborate on one work item, in separate sandboxes or as a crew
in one sandbox (§13.7). Uniform swarms are one zone; non-uniform swarms are several zones joined by
gates.

---

## 5. Tasks and the manifest

A task is a **manifest**: trusted task text plus a zone/gate graph. It is the human-facing artifact and
what humans approve. Example, the split from the brief:

```yaml
# tasks/fix-flaky-sync.yaml
task: fix-flaky-sync
text: |                                   # TRUSTED. The only input to policy derivation.
  tests/test_sync.py::test_reconnect in acme/api is flaky. Find the cause, fix it,
  and open a PR against main. Upstream docs for the websocket library may help.
org: acme                                 # org ceiling + data classes + who may approve what
data_classes: [acme.source]

zones:
  research:
    agent: claude-code
    sandbox: { isolation: process }
    reach:
      - { provider: github, resources: "repo/acme/api/**", verbs: [read] }
      - { provider: net, resources: "host/websockets.readthedocs.io/**", verbs: [read] }
    clearance: [acme.source]
    taint_admit: [web, repo-content]
    send: []                              # can't write anywhere external
  fix:
    agent: claude-code
    sandbox: { isolation: process }
    reach:
      - { provider: github, resources: "repo/acme/api/**", verbs: [read] }
      - { provider: github, resources: "repo/acme/api/ref/wicket/fix-*/**", verbs: [contents.write] }
      - { provider: github, resources: "repo/acme/api/pulls", verbs: [create] }
    clearance: [acme.source]
    taint_admit: [repo-content]           # no web: a poisoned docs page can't reach a push
    action_taint_allow: { R2: [repo-content] }
    send: [{ id: github-acme-api, clearance: [acme.source] }]

gates:
  - from: research
    to: fix
    rules:
      - typed:
          cause: { enum: [race, timeout, ordering, env, unknown] }
          file:  { bounded_str: 200 }      # endorsed only if it names a file in the repo
          line:  { int: [1, 100000] }
          notes: handle                    # free text stays behind a handle
```

`wicket explain tasks/fix-flaky-sync.yaml` answers the human question mechanically: *"If `research` is
compromised: it can read acme/api and the docs host and send nowhere. It can influence `fix` only via
{cause: 5 values, file: ≤200 chars endorsed against the repo tree, line}. `notes` is unread unless `fix`
dereferences it, which taints `fix` with `web` and blocks its pushes."*

### 5.1 Static and dynamic topology

- **Static:** wicketd runs the manifest's graph directly. Zones run in dependency order, and outputs flow
  through gates.
- **Dynamic** (PoC: `spawn`, with `max_children` in the agent spec): a zone may be granted the
  `wicket.spawn` tool in its MCP gateway. A parent calls
  `spawn(zone_template, task_text, inputs: [handle…])`. wicketd checks child ⊆ parent and admits only
  handles and typed values as inputs. **The child's task text inherits the parent's label.** It is only as
  trusted as the parent, and re-derivation for the child's escalations runs against the chain of task texts
  back to the root, each with its label.

**Agents construct zones** (owner, 2026-11-09: as long as the new zone's permissions are a subset of the
agent's own; a human with that much access can approve an extension). Built:
- **`spawn` starts an agent (task) or a program (command, possibly a long-running service)** in a zone the
  caller writes.
- **`wicket_core::subset` proves the zone is within the caller's,** conservatively; anything it can't prove
  is a violation, and every violation is listed. It checks:
  - reach: host, method and path, each covered by a parent rule;
  - credential injections: only the parent's own;
  - model budget: at most what's left, and then carved out of the parent's;
  - memory, CPU, PIDs and time;
  - isolation: at least as strong;
  - images: from the parent's allowlist;
  - `accept_from` and child slots.
- **Inherited without asking:** the parent's `forbid` rules, `unlisted_hosts: hide`, and defaults no wider
  than the parent's.
- **With `ask_human`, a wider zone becomes a pending request** bound to the request as the agent stated it.
  A human approves, and the agent's identical retry starts exactly that zone. It's audited as
  `spawn.beyond_parent`.
- **Every box gets an identity,** programs included, chained to its creator and the human. Programs report
  back with a signed `run_finished` carrying their output tail.

**Humans are principals under the same rules** (owner, 2026-11-09): an identity, an authority (by default
everything) and audited, signed actions. An approval is a principal delegating part of its own authority,
accepted only within it (#11).

Also recorded as issues:
- MCP servers per zone, granted by the creator within its own access (#9);
- agent-built MCP servers as reusable tools (#10);
- `expose`/`connect` (#6);
- `request_capacity` (#7);
- moving a running agent to a bigger box by checkpoint and restore, or a provider resize (#8).

### 5.2 Policy derivation

The proposer is an LLM, so it **chooses among vetted templates; it never writes policy** [05 §10.2-6:
MiniScope, AutoCedar, ceLLMate, Conseca]:
1. **The proposer instantiates adapter-defined capability templates**, one rationale per line. It never
   writes raw capabilities or Cedar.
2. **A deterministic solver** computes the minimal capability set covering those templates, and the
   minimal *native* scopes (GitHub App permissions from endpoint coverage, never from scope names or an
   LLM). Generation runs in two phases: sufficiency first, then a tightness audit.
3. **Humans approve floors and ceilings per task class × agent kind**, and symcc certifies
   *floor ⊆ manifest ⊆ ceiling*. Inside that band the manifest needs no fresh human review.
4. **The proposer's view is an explicit, labelled manifest field.** By default it holds the task text, the
   org's data classes and the adapter catalog, and **nothing fetched** (CaMeL's rule). It may opt in to
   repo file names and similar context, labelled as attacker-influenced. ActPlane found 74% of policies
   needed some repo context to be concrete, so the utility cost of the strict default is measured, not
   assumed. The proposer never sees third-party tool descriptions.
5. **Hand-off detection.** Tasks that delegate control to data ("do what issue #12 says") are flagged.
   They get an R1-capped tainted zone or human review. The proposer also emits a **data-minimisation set**:
   what gets mounted or exposed at all.
6. **Learning.** Each manifest a human approves (and each approved escalation) feeds that task class's
   defaults. Approved deviations never write themselves back into standing policy (DRIFT does that).
   The diff between proposed and approved manifests is logged, which is the brief's 20-task
   over/under-grant experiment run continuously.

---

## 6. Inner agents

Detail: [01 §4] (Claude Code, ACP), [11] (Codex, pi), [12] (OpenClaw), [13] (Hermes), [16] (how ~40
orchestrators drive these agents).

**Adapter settings** (`agent.adapter_settings`) pass harmless configuration to the agent's own adapter: for
Claude Code, its `settings.json`. Only allowlisted keys are accepted: commit attribution, output style and
similar. Hooks, permissions, MCP servers, environment and credential helpers stay under wicket's control.
`agent.env` likewise refuses wicket's reserved variables (proxies, CA, model routes, placeholders).

**Hermes Agent** [13] is a T1 candidate through its `hermes-gateway-v1` JSON-RPC (host-answered approvals,
steer/interrupt, resume, replay of pending requests on reconnect), with ACP as the T2 fallback. Its own
security policy says the OS is the only boundary and recommends wrapping the whole process, which is
`Placement::Whole`. Its risk is self-modification: by default it writes memory and skills (including a
background fork that replays the transcript into them), schedules its own cron jobs, edits its own
`config.yaml`, installs and hot-reloads MCP servers, and imports any Python in `hooks/`. Under wicket its
config is regenerated on every wake, memory and skill writes are staged to `pending/` for the §13.4
promotion gate, prompts are answered only `once` or `deny`, and library mode is never used (it auto-approves
dangerous commands when no callback is attached). Hermes has no unix-socket transport, so it uses the
loopback forwarders like Claude Code.

**Claude Code adapter details from the Agent SDK hosting guide** [17 §3]: auto-memory loads regardless of
`settingSources`, so the LaunchPlan sets `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`; each zone gets its own
`CLAUDE_CONFIG_DIR`; there is no session timeout, so §13.8 budgets must cover it; and
`CLAUDE_ASYNC_AGENT_STALL_TIMEOUT_MS` is a usable stall signal.

```rust
pub trait InnerAgent: Send + Sync {
    fn kind(&self) -> AgentKind;
    fn tier(&self) -> Tier;                                   // T1 | T2 | T3: protocol class
    fn placement(&self) -> Vec<PlacementSupport>;             // Whole | Split{hands}
    fn caps(&self) -> AgentCaps;
    fn supported_versions(&self) -> semver::VersionReq;
    fn plan(&self, task: &TaskSpec, zone: &ZoneEnv) -> Result<LaunchPlan>;   // pure; no secrets, only placeholders + routes
    fn attach(&self, io: BoxIo, plan: &LaunchPlan) -> Result<Box<dyn AgentSession>>;
}
#[async_trait]
pub trait AgentSession: Send {
    async fn start(&mut self, prompt: TaskPrompt) -> Result<()>;
    fn events(&mut self) -> BoxStream<'_, AgentEvent>;        // normalised, size-bounded, free text as handles; AgentState::Settled
    async fn answer(&mut self, req: PermissionReqId, d: AgentDecision) -> Result<()>;
    async fn send(&mut self, msg: HostMessage) -> Result<()>; // steer / follow-up, e.g. "R-123 granted; retry"
    async fn checkpoint(&mut self) -> Result<ResumeToken>;
    async fn finish(self: Box<Self>) -> Result<AgentOutcome>; // typed fields (schema-validated) + labelled handles
}
```

**Tier = protocol class** [11 §3.1]:

| Tier | Agents | How wicket drives it | Pending path |
|---|---|---|---|
| **T1: native control protocol** | **Claude Code** (stream-json control protocol, spoken natively from Rust); **Codex app-server** (JSON-RPC: host-answered `requestApproval`, `turn/steer`, per-turn `outputSchema`, `thread/resume`/`fork`, `dynamicTools`); **pi** RPC mode plus a small in-box wicket extension | the agent's own permission prompts are answered by wicket; steering; native typed output (pi: a terminating `wicket_result` tool) | hold the prompt open + pause/snapshot; Claude `defer` + `--resume`; Codex replays pending approvals on reconnect |
| **T2: ACP** | Gemini CLI, goose, OpenCode, Cline…, and fallbacks `codex-acp`, Claude's ACP adapter (official `agent-client-protocol` crate, protocol v1) | JSON-RPC over stdio; MCP servers passed per session | hold `session/request_permission`; follow-up prompt after grant |
| **T3: process** | anything; optionally with a structured event stream (`codex exec --json`, `pi --mode json`) | enforcement only at the proxies; `/wicket/out/result.json` outbox validated outside | structured 403 / MCP error with `request_id`; restart with checkpointed workdir |

**Placement is a separate axis:**
- `Whole`: the agent process runs in the box.
- `Split { brain, hands }`: the agent's loop runs outside the box, and only its tool execution runs
  inside. Examples: Codex `exec-server`, pi's remote tool operations, Claude Managed Agents with a wicket
  worker (formerly "T1b"), or wicket's own `wicket-guest` exec.

`AgentCaps` grew from the agent survey [11 §3.2]:
- `typed_output` (native schema per turn | terminating tool | outbox);
- `steer`;
- `host_tools` (gateway tools served over the agent's own pipe: Codex `dynamicTools`, ACP MCP-over-ACP, pi
  extension tools);
- `model_wire`;
- `server_side_tools` (taint ingress the egress proxy can't see);
- `config_lockdown` (managed file | file ownership only);
- `config_exec_vectors` (config keys that run commands, e.g. pi `!cmd` values) — always rejected;
- `context_files` (preflight taint list);
- `persistent_policy_writes` (in-box state an approval could persist, e.g. Codex rules amendments) —
  never sent;
- `session_store`, `fork_at`, `settled_signal`, `native_remote`, `background_traffic`.

**Launches.** Common to all three: no model credential in the box, only a zone- and session-bound
placeholder. The model base URL points at the LLM proxy, and `HTTPS_PROXY` plus the CA env vars point at
the egress proxy. The only MCP server is the wicket gateway. Repo context files are labelled as taint. The
agent's state dir sits inside the zone's labelled state.
- **Claude Code** ([01 §4.4]):
  - `ANTHROPIC_BASE_URL` plus a placeholder `ANTHROPIC_AUTH_TOKEN`;
  - nonessential traffic, auto-update, telemetry and claude.ai connectors off, so it needs **no internet
    hosts**;
  - `--strict-mcp-config`;
  - root-owned managed settings (`allowManagedHooksOnly`, `allowManagedMcpServersOnly`, deny rules
    mirroring the ceiling);
  - `CLAUDE_CONFIG_DIR` in labelled state, auto-memory off.
- **Codex** ([11 §5.1]):
  - root-owned `/etc/codex/requirements.toml` pins `model_provider = "wicket"` (Responses wire, base URL =
    LLM proxy, websockets off), allows only the gateway MCP server, disables remote control, web search,
    update checks and browser use, and allows managed hooks only;
  - `codex app-server --listen stdio://`;
  - approvals are answered `accept`, `decline` or `cancel`, **never with the policy-amending variants**;
    `item/permissions/requestApproval` is declined (wicket owns permissions).
- **pi** ([11 §5.2]):
  - a root-owned agent dir (`PI_CODING_AGENT_DIR`), with `models.json` pointing providers at the LLM proxy
    and **no `!command` values**;
  - the gateway in `mcp.json` with `exposure: "direct"` (pi's default codemode exposure would hide
    `wicket.await_grant` from the model);
  - `cacheWarming: off` (it would fool liveness detection);
  - `pi --mode rpc --no-approve --session-dir … --no-skills`;
  - a hash-pinned wicket extension turns `tool_call`s into held-open dialogs and registers
    `wicket_result`.

Each launch above is advisory: the box boundary and the proxies enforce.

**Model credentials: the owner's Claude subscription, never an API key** (owner, 2026-11-08: "you must
never use the anthropic API key. This is just Claude Code cli with my subscription").
- The inner Claude Code authenticates with a subscription token from `claude setup-token`, which the owner
  runs and stores in wicket's vault (`wicket secret set claude-oauth`).
- The box gets a same-shaped placeholder in `CLAUDE_CODE_OAUTH_TOKEN`. The LLM proxy strips it and injects
  `Authorization: Bearer <token>` on the way out. Verified in the PoC: Claude Code switches to subscription
  mode, sends every model call through `ANTHROPIC_BASE_URL`, and makes no other outbound calls.
- Alternatively the vault holds a *reference* to the host's existing Claude Code login (`wicket secret link`):
  wicket reads the current access token at injection time, never the refresh token, never writes the
  credentials file, and never copies it. wicket never emulates Claude Code's OAuth flow.
- API-key injection was removed from the code entirely.

**Anthropic's rules on subscription credentials** (owner, 2026-11-08: "whatever Anthropic say is ok"). The
Claude Code legal and compliance page (read 2026-11-08) says subscription OAuth "is designed to support
ordinary use of Claude Code and other native Anthropic applications". Developers building products,
including on the Agent SDK, "should use API key authentication". Third parties may not "route requests
through Free, Pro, Max, or Ultra plan credentials on behalf of their users". They also may not "collect,
store, or intermediate Claude.ai credentials or session tokens". A platform hosting Claude Code may not
"remove, disable, or restrict any authentication method built into it", and each end user signs in with
their own credentials. So:
- **Subscription tokens are for the unmodified Claude Code binary only.** Hermes, pi, OpenCode and other
  inner agents never get the owner's Claude subscription. They use their own vendors' terms, or models the
  owner holds API access to elsewhere (not an Anthropic API key, by the owner's rule).
- **Single-owner mode** is the owner running their own Claude Code on their own hosts with their own
  subscription, at individual scale. That is the case the PoC covers, and it is ordinary use of Claude Code
  (owner, 2026-11-08: "It's just Claude code"): the client is the unmodified binary, and the proxy only keeps
  the token out of the box. Keep it to the owner's own use.
- **Platform mode (§15) never brokers subscription credentials.** Each end user signs in to Claude Code
  through Anthropic's own flow, or the tenant brings an API key or cloud-provider credential billed to
  itself. wicket doesn't pay for, resell or intermediate Claude usage. Centaur's token broker [16 §3-2] is
  therefore a single-owner pattern only.

Other agents' vendor logins (ChatGPT for Codex) would follow the same placeholder-and-inject pattern, if
the owner chooses them and the vendor's terms allow it.

**Model agnosticism** lives in the LLM proxy, not the adapters. It speaks the **Anthropic Messages** API,
then **OpenAI Responses** (Codex is Responses-only), then Google, then Chat (only for open-weights servers).
It:
- upstreams to any of them with the vault's credential;
- enforces per-zone model and budget limits;
- **rewrites** server-side tool definitions (e.g. Anthropic `web_search`/`web_fetch`
  `allowed_domains`/`max_uses`) from the zone's reach, as GitHub's AWF does [08 §6 a2-10];
- marks a session tainted when a response contains server-side tool results (Claude `web_search`, Codex
  hosted `web_search_call`);
- classifies cache-warm and model-refresh requests as not proving liveness.

**wicket's own LLM calls are different.** These are the manifest proposer, the parent-tier re-derivation,
quarantined readers and the adapter generator. They go through a small Rust `Model` trait implemented over
the LLM proxy's upstream module, Claude by default, and each gets a fresh context containing only the
trusted inputs its role allows. No third-party LLM library sits in the TCB; pi-ai's context and compat
design is borrowed, not its Node code [11 §3.5].

### 6.1 Conformance suite (per adapter, per pinned agent version)

The suite runs in CI inside a real zone:
1. The agent reaches only the LLM proxy and the gateway.
2. No real credential is findable in env, files or `/proc`.
3. A denied request produces the expected event, and the agent does not route around it.
4. A pending round-trip resumes.
5. Typed output validates.
6. Repo-supplied hooks, MCP config and env blocks are ignored.
7. The protocol version matches.
8. A pending request survives a host-side restart or reconnect (Codex replay; pi re-dialog).
9. The model's declared tool list includes the `wicket.*` tools (pi exposure).
10. No background model traffic while parked (pi cache warming, Codex refresh).
11. No in-box policy persists after approvals (e.g. Codex `rules/` unchanged).
12. **Reflection:** a placeholder echoed back by an upstream (comment body, error message) never comes back
    as the real secret, and a zone placeholder seen anywhere except its own injection slot trips an
    anomaly.
13. Each SandboxEscapeBench misconfiguration class is negated in the box.

Per-agent experiments:
- **E-PI1:** pi runs with a read-only agent dir.
- **E-PI2:** `--no-approve` ignores the repo's `.pi/`.
- **E-CX1:** `requirements.toml` pins the provider against `-c`, `thread/start.config` and config writes.
- **E-CX2:** `workspace-write` nests under each backend.
- **E-CX3:** approvals replay across an app-server restart.

Claude Code ships near-daily, so this suite is how adapters stay honest. [01 §4.7, 11 §4]

---

## 7. Sandboxes

Detail and trait sketch: [02 §11].

```rust
#[async_trait]
pub trait Sandbox: Send + Sync {
    fn capabilities(&self) -> &Capabilities;          // isolation level, snapshot kind, egress modes, host requirements
    async fn prepare(&self, spec: &SandboxSpec) -> Result<Prepared>;
    async fn start(&self, p: Prepared) -> Result<Box<dyn Instance>>;
    async fn restore(&self, s: &SnapshotRef, o: RestoreOverrides) -> Result<Box<dyn Instance>>;
}
#[async_trait]
pub trait Instance: Send + Sync {
    async fn exec(&self, req: ExecRequest) -> Result<Process>;     // harness-only control channel
    async fn attach(&self, pid: ProcessId) -> Result<IoStreams>;
    async fn pause(&self) -> Result<()>;  async fn resume(&self) -> Result<()>;
    async fn snapshot(&self, o: SnapshotOpts) -> Result<SnapshotRef>;  // only after quiescence
    async fn extract(&self, what: Extract) -> Result<Output>;      // Patch{base} | File | Tar — parsed host-side
    async fn destroy(self: Box<Self>) -> Result<Teardown>;         // includes violation log
}
```

The zone declares an isolation floor and whether it needs snapshots, and the scheduler picks the cheapest
backend whose capabilities satisfy both (§7.1). `EgressMode` deliberately has no "direct" variant.

**Isolation floor.** The `process` tier shares the host kernel the way containers do, and frontier models
escape misconfigured containers (SandboxEscapeBench [05]). So:
- **gVisor (or a microVM) is the default floor** for any zone with valuable reach, clearance or labels,
  and for every third-party MCP server.
- `process` is for development, M1, and low-value zones.
- On production hosts the vault and `wicketd` never share a kernel with process-tier boxes.
- A sandbox crash is logged as a security event.

| Order | Backend | Notes |
|---|---|---|
| 1 | **`process`** (Linux) | `wicket-jail`: user/mount/pid/ipc/uts/net namespaces, per-box UID, overlay rootfs, cgroup v2 limits and freeze. **Network: Codex's listener-fd handoff.** The jail binds `127.0.0.1:0` inside an interface-less netns and passes the listening fd to wicketd by `SCM_RIGHTS`. That listener *is* the box's identity: no socket file, no in-box forwarder, and seccomp denies every new `AF_UNIX`/`AF_VSOCK`/`AF_NETLINK`/`AF_PACKET` socket and `io_uring`. **The mount view is locked:** mounts are built fd-relatively; then all caps and the bounding set are dropped, `max_user_namespaces=1` is set, and the agent runs in a nested userns. srt's namespace-escape seccomp rules are a second layer (`clone3`→ENOSYS). Landlock must report `FullyEnforced`. [07 a.2-1,2] |
| 2 | **`gvisor`** | `runsc --platform=systrap --network=none --host-uds=open` with a bind-mounted UDS and an in-box forwarder: gVisor sockets aren't host fds, so the fd handoff doesn't apply. Needs no KVM. **Checkpoint/restore for parking.** The default floor on VPSes. |
| 3 | **`seatbelt`** (macOS) | Generated SBPL from Codex's base policy. Developer machines. |
| 4 | **`firecracker`** | KVM hosts. Official jailer, vsock-only networking (`<uds>_<port>`), ext4 workdir image + `wicket-guest` PID-1 shim, diff snapshots with UFFD restore, VMGenID. libkrun has no snapshot on Linux, so it parks by freeze only. |
| 5 | **`e2b`** | **E2B Cloud/BYOC only:** bring-your-own-proxy and MITM exist only there, while the open-source runtime ships a no-op egress hook. Its direct DNS is a **bidirectional C2 channel**, not a small leak, so the zone view shows it as such and valuable zones can't use it. |
| 6 | **`wasm`** | Codemode for **tool-only zones** (wasmtime components whose imports are gateway functions). It can't host a POSIX agent. For Claude Code, Bash + curl through the proxy already *is* codemode. |

**Rules that apply to every backend** [07 a.2-3,4]:
- **Fail closed on every hardening layer.** The jail refuses to start unless each declared layer is
  confirmed: userns lock, seccomp, Landlock `FullyEnforced`, cgroup, netns. (srt warns and carries on;
  Codex accepts partial Landlock.) The layers actually applied are reported in `Capabilities` and the
  zone view. Seccomp filters are table-tested over (family, type) pairs and clone flags.
- **Every VMM and `runsc` runs inside `wicket-jail`.** microsandbox, E2B and sandstorm-on-Firecracker
  don't do this. Never enable libkrun TSI `HIJACK_UNIX`.
- On Ubuntu, ship an **AppArmor profile granting `userns` to `wicket-jail`** instead of flipping the
  sysctl.
- **DNS:** in proxy mode the box has no resolver. In transparent and VM modes, synthetic DNS maps every
  name to one sinkhole IP and the proxy decides on SNI/Host. A **DNS-canary test is a blocking release
  gate** for every backend and proxy build: Claude's own sandbox shipped a DNS leak twice [06].

**Workdir and output:** the base repo is a read-only lower layer, and the agent writes to an upper layer.
`extract(Patch)` computes the diff host-side, in user space; we never mount a guest-written image with the
host kernel. Host-side git runs with `core.hooksPath=/dev/null`, so the workdir's `.git` is never
executed on the host. Launch-time path scans are not protection. The diff becomes a labelled handle, and
its taint survives `extract` up to any push or merge, because code is delayed execution. Its *summary*
(files touched, test result) crosses gates as typed fields. After an approved file escalation, a later
`Instance::grant_fd` can inject the opened file via `SECCOMP_IOCTL_NOTIF_ADDFD` without a restart (nono).

**Parking** follows sandstorm's tier ladder [07 a.2-7]:
1. Snapshots drop open connections on every substrate. So first the gateway answers *pending* and the
   agent goes quiet (watched via the LLM proxy; Codex replays pending approvals on reconnect).
2. Freeze: `cgroup.freeze`, confirmed via `cgroup.events`, about 10 ms.
3. `runsc checkpoint` (about 84 ms uncompressed). The in-box `--save-restore-exec-argv` hook can veto a
   checkpoint that isn't quiescent, and re-dials bridges after restore.
4. For long waits, detach the upper layer.

Each snapshot is **restored at most once**, and the source is never resumed. Lower layers are pinned by
digest, and restore is refused on mismatch. RNGs are reseeded after any restore. Snapshot images carry the
zone's `conf` label and count against a disk budget. Resume uses the agent's own resume path.

### 7.1 Startup and efficiency

*Budgets from [10 §4]: published numbers (most are vendor claims or old) plus a first measurement on this
box. The `wicket-bench` measurements in M1 and I1 replace the weak rows.*

**Selection rule:** the scheduler picks the **cheapest backend that meets the workload's isolation
floor**. Isolation is a hard filter; cost and latency are the score, never the other way round.

**Techniques, in the order they're built:**
1. **Shared read-only base layers.** One rootfs or image per agent version and MCP server version, cached
   on the node and mounted read-only. Per-sandbox state is a thin overlay or copy-on-write upper layer.
   Lazy image pulling (stargz, SOCI or nydus) for big images on cluster nodes.
2. **Warm pools, claim-then-bind.** Pristine sandboxes are pre-created with nothing identifying in them.
   On claim, wicket binds the identity: listener fd / socket, per-zone CA, placeholders, mounts and
   labels. So a pooled sandbox can't carry one task's identity or state into another. [07]
3. **Snapshot clones.** Boot an MCP server, or an agent up to "ready", once; snapshot it; restore clones
   from that snapshot. Firecracker restores in milliseconds with copy-on-write memory shared across clones,
   and gVisor checkpoint/restore plays the same role without KVM. After restore, reseed RNGs and rotate
   anything identity-bearing. One snapshot is never restored into two different trust contexts without
   reseeding.
4. **Right-sized enforcement.** The proxies and gateway are per node, not per sandbox, so a sandbox adds a
   listener and some ledger rows, not a process. Codemode (Wasm or V8 isolates) serves tool-only zones in
   microseconds to milliseconds.
5. **Direct launch on the hot path** (§8.3). The Kubernetes pod path promises only a 5 s p99 *before*
   image pull, and CNI setup alone can double that under concurrency. A bare namespace jail took about 3 ms
   on this box. So agent sandboxes and per-task MCP instances are launched directly by `wicket-node`.
6. **No cross-tenant memory dedup.** KSM across zones with different labels is a timing side channel, so
   it is allowed only within a trust class. Explicit snapshot copy-on-write sharing is preferred.

**Reference numbers** [10 §4.1]:
- process jail ≈ 3 ms (measured here);
- gVisor restore 65–160 ms (an unmerged PR) or about 1 s (Modal in production), idle ≈ 31 MiB;
- Firecracker ≤ 125 ms boot and ≤ 5 MiB VMM overhead, snapshot load ≈ 50 ms plus page faults;
- Kata 130–320 MiB fixed overhead;
- Wasm ≈ 5 µs, V8 isolates ≈ 5 ms;
- GKE agent-sandbox warm-pool claims 200 ms p90;
- Claude Code's own start is about 1–2 s (bare `node -e 0` alone took 0.6 s on this loaded box).

**Budgets** (p95, warm node):

| Workload | Ready time | Overhead per instance (beyond the workload itself) | Mechanism |
|---|---|---|---|
| Agent sandbox | ≤ 300 ms box-ready from the warm pool, ≤ 1 s cold, plus the agent's own start | ≤ 40 MiB | process jail or gVisor, direct launch |
| Per-task MCP server | ≤ 250 ms to `tools/list`-ready from a pristine snapshot or unbound warm instance, ≤ 2 s cold | ≤ 30 MiB | gVisor/Firecracker snapshot clone, direct launch |
| Shared, vetted MCP service | long-lived | pod overhead acceptable | gVisor pod |
| Codemode call | ≤ 5 ms | ≤ 5 MB | wasmtime pooling allocator, in the gateway |
| Parked agent resume | ≤ 2 s after approval | disk only while parked | freeze; runsc checkpoint; Firecracker snapshot |
| A whole new host | ~60–80 s on Vultr; seconds from a paid-time pool | — | provisioner |

**Measured, not assumed.** A `wicket-bench` suite reports ready time, RSS, PSS and CPU per workload kind and
backend, plus density (instances per GB per node). It runs in CI on every backend change, and each
milestone's done-when includes staying within budget. The agent itself (Node-based Claude Code, a few
hundred MB) usually dominates; wicket's own overhead is what the budget controls.

---

### 7.2 Isolation tiers, and how one is chosen (owner, 2026-11-10)

From weakest to strongest boundary between a workload and its host:

| Tier | Examples | Boundary | Needs |
|---|---|---|---|
| process sandbox | seccomp + namespaces + Landlock (bubblewrap, nsjail; Claude Code's and Codex's own sandboxes); Seatbelt on macOS | the host kernel, with the calls a process may make restricted | nothing |
| container | `runc` | the host kernel with namespaces and resource limits; packaging more than a security boundary | nothing |
| user-space kernel | **gVisor** | a kernel in Go intercepts system calls; the host kernel sees a small fixed set | nothing special: runs on any VPS |
| microVM / VM | **Firecracker**, Cloud Hypervisor, QEMU, libkrun; Apple Virtualization.framework; Hyper-V | the workload's own kernel behind hardware virtualization | hardware virtualization (KVM on Linux) |
| confidential VM | SEV-SNP, TDX | also protects the guest from the host; not part of wicket's threat model | specific CPUs and clouds |

**Kata Containers** isn't a separate tier. It's a container runtime that runs each container or pod in a
microVM using one of those hypervisors, so Kubernetes and Docker treat VMs as containers (a Kubernetes
RuntimeClass). It's the natural VM tier for the Kubernetes backend (#45).

**Why not Firecracker for everything:**
- **It needs KVM.** Most cheap cloud VMs (this Vultr VPS, Hetzner Cloud) don't expose it. Only bare metal or
  the few instance types with nested virtualization (some GCP, Azure and newer AWS types) do, at higher cost,
  and bare metal often bills monthly.
- **It's Linux only.** Macs use Virtualization.framework (#48), Windows uses Hyper-V.
- **No GPU passthrough.** GPU work needs Cloud Hypervisor or QEMU.
- **More machinery than containers:** root filesystems and kernels instead of OCI images, the jailer,
  snapshot management.
- **Its own kernel per box** costs memory, so fewer boxes per machine than gVisor, though snapshot restores
  make starting cheap.

**Ranking for the subset rule:** `process ≈ runc ≈ seatbelt < gvisor < vm`. A zone states its minimum.
Placement picks **the strongest tier the machine supports, never below the zone's minimum**:
- Firecracker on Linux hosts with KVM (#64);
- Virtualization.framework on Macs (#48);
- gVisor everywhere else.

A zone that requires `vm` where no KVM host exists becomes a `request_capacity` for one (#7). Seatbelt is
only for macOS-native work (#49), and ranks lowest.

### 7.3 Network modes (owner, 2026-11-10)

Full mediation is the default, but some zones need raw speed. `zone.network` takes one of three values (#63):

| Mode | The box's network | What wicket controls |
|---|---|---|
| **`mediated`** (default; built for gVisor and runc) | no interface; its only way out is wicket's endpoints at `wicket.internal` | every request: reach, approvals, credential injection, audit. DNS isn't an exfiltration route |
| **`filtered`** | a real interface; the host filters by IP and DNS name | allowlisted destinations only; requests themselves aren't inspected |
| **`direct`** (fast path) | a real interface with open internet | only **steered domains**, the ones with credential injection or request-level rules |

**How steering works in `direct`:**
- wicket's resolver answers steered domains with `wicket.internal`, so connections to them land at the proxy,
  which decrypts, checks and injects as usual.
- Every other name resolves normally and leaves through NAT on the host, UDP and HTTP/3 included.
- A box that bypasses the resolver reaches steered domains without credentials, which grants nothing.
- **Credentials never enter the box in any mode.**

**Per tier:**

| Tier | `mediated` | `filtered` / `direct` |
|---|---|---|
| gVisor, runc | `--network none`, unix sockets (built) | a veth pair with host-side nftables, NAT and wicket's resolver. gVisor can't run nftables inside, and doesn't need to |
| Firecracker, Cloud Hypervisor | no network device; vsock to wicket's endpoints | virtio-net on a host TAP with host nftables and NAT; Firecracker's bandwidth limits |
| Kata | vsock forwarding for wicket's endpoints (to verify) | Kubernetes network policy (e.g. Cilium DNS-aware rules) plus steering |
| Virtualization.framework | no network device; vsock | a file-handle network device with wicket as the NAT in user space (controlled, slower), or Apple's NAT with `pf` rules |
| Seatbelt | the profile allows only wicket's forwarders | general outbound, with steering only by proxy environment variables, which programs can ignore. The weakest |

**Policy:**
- `filtered` and `direct` give up per-request control and audit for unsteered traffic, and `direct` makes DNS an
  exfiltration route again. They're only for zones with nothing confidential to leak (no private
  repositories, confidential volumes or tenant data), and only a human grants them.
- By the subset rule a zone can't give a child a more open mode than its own.
- The zone view and approval cards say "open internet".
- With taint tracking (#27), a `direct` zone counts as an untrusted source.

**Performance.** Most of the cost of mediation is avoidable without giving it up (#62):
- deciding on the node, not the control host (#57);
- splicing encrypted bytes straight through for hosts wicket doesn't inspect;
- a zero-copy data path;
- read-through package caches on each node.

Measure before reaching for `direct`.

## 8. Infrastructure: hosts, placement and isolated services

*Draft. Owner requirement 2026-11-08. Kubernetes, provider and billing research is in
[`research/10-infrastructure.md`](research/10-infrastructure.md); the details here firm up once it lands.*

**Requirement.** wicket provisions and manages what code runs on:
- hosts: this machine, cloud VMs, bare metal, hosted sandbox services;
- the sandboxes on those hosts;
- long-running **isolated services**, for example third-party MCP servers, each in its own container or
  VM, isolated from each other.

Provisioning costs money and adds attack surface, so it is an authority domain like any other: it goes
through `Op`s, policy, budgets and escalation.

### 8.1 Everything that runs is a workload

```rust
pub enum WorkloadKind {
    AgentSandbox { zone: ZoneId },
    McpServer   { server: McpServerRef, scope: InstanceScope },   // third-party server, pinned image + tool hashes
    Codemode    { zone: ZoneId },
    NodeService (NodeService),                                     // per-host egress/LLM proxy, gateway shard
    Fixture     { purpose: SmolStr },                              // e.g. adapter test org runners
}
pub enum InstanceScope { PerTask, PerZone, Shared }
pub struct Workload {
    pub id: WorkloadId, pub kind: WorkloadKind,
    pub sandbox: SandboxRequirement,           // isolation floor, snapshot need (§7)
    pub reach: CapabilitySet,                  // its OWN egress, via the proxy and adapters
    pub placement: Vec<PlacementConstraint>,   // §8.3
    pub lease: Lease,                          // TTL; nothing runs without one
    pub label: Label,                          // join of everything it has served
}
```

Agent sandboxes from §7 are one kind of workload. Every kind is placed the same way, through Kubernetes (§8.3).

### 8.2 Isolated MCP servers (service zones)

No surveyed project combines all four of: a server with no network route of its own, egress only through
an inspecting proxy, credentials injected only at that proxy, and a gateway-owned non-TCP transport.
ToolHive comes closest, and secrets go in environment variables everywhere [07 a.4, 08 §6 a3]. wicket's
contract for a third-party MCP server:
1. **One sandbox per (server, task, zone)**, under the same `Sandbox` trait as agents, with gVisor as the
   floor. Its own UID, netns, mount view and cgroup; default limits 1 CPU and 512 MiB. Its own *server
   zone*, whose reach is the server's manifest ∩ the calling zone's reach. It is pinned by image digest
   next to its tool-description hashes. It is never shared across tasks or zones.
2. **An empty netns.** The only route out is the egress proxy, with the sandbox's own CA. There is no
   path to other servers, the agent, the host, the API server, metadata services or DNS.
3. **Placeholders only.** The server is launched with an explicit minimal env; nothing is inherited.
   Credential→host bindings come only from the vault and adapter, never from a caller (microsandbox-mcp
   lets the calling agent choose which secret goes to which host: a confused deputy). A non-HTTP server
   that must hold a secret gets a short-lived, narrowest-scope one, and the zone view marks it.
4. **A gateway-owned transport, never TCP.**
   - For stdio servers, `wicket-jail` hands the server's stdin/stdout fds to the gateway.
   - For HTTP-only servers, streamable HTTP runs over a UDS bind-mounted out of the sandbox, or vsock on
     Firecracker.

   The gateway terminates MCP on both sides and forwards re-encoded messages.
5. **The server's own egress is an `Op` of its server zone, carrying the invoking agent's label.**
   Otherwise the server becomes a label-laundering deputy. With concurrent calls, the labels of all
   in-flight callers are joined, which is another reason for per-task instances.
6. **No runtime additions.** The server set is part of the approved manifest. Adding a server is an
   escalation.

Instance state is memory (§12). `PerTask` is the default. `PerZone` is for servers with expensive
startup. `Shared` is only for servers declared stateless *and* restored from a clean template per task.
Warm pools and snapshot clones (§7.1) make per-task instances cheap.

**Links between boxes (PoC, #6).** Boxes reach each other's ports only through links wicket relays:
`expose(port)`, `connect(box, port)` (which returns `<name>.wicket.internal:<port>`), and `link(from, to,
port)` for a caller that controls both ends. A box's own children are connectable by default; any other
box must have exposed the port and accept the connector's zone (`accept_from`), or a human approves. A link
lends the connector the target's authority, so the target's reach must be within the connector's
(`subset::reach_within`), or a human approves. Each linked name gets an address from 198.18.1.1–32, added
at box start, and a line in a hosts file wicket owns. Under gVisor the box can't offer a socket to the host,
so wicket reaches into the target with `docker exec` per connection. Every link is audited and closes when
cut, revoked at either end, or when either run ends. Labels don't cross links yet (no label mechanism).
See `examples/links/`.

### 8.3 Substrate: Kubernetes for capacity, direct launch for the hot path

*Owner direction (2026-11-08): use Kubernetes rather than build our own scheduler. Research 10 refines this
into a hybrid, because the pod path is too slow and too limited for per-zone and per-task churn (§7.1).*

| Kubernetes does | `wicket-node` does (direct launch, inside reserved capacity) | wicket keeps |
|---|---|---|
| Nodes, node pools, autoscaling (cluster-autoscaler or Karpenter), node lifecycle and upgrades | Agent sandboxes and per-task MCP instances on the hot path: process jail, `runsc` or Firecracker launched directly, in under 300 ms | `Op`s, policy, ledger, escalation, labels, handles |
| wicket's own services, and long-lived shared MCP services as gVisor pods | gVisor checkpoint/restore and Firecracker snapshots for parking, which the pod API can't do | Placement *compilation and verification*: which isolation, separation and region each workload requires |
| L3/L4 policy for pods (Cilium default-deny) | Interface-less netns for direct-launched boxes, so there is no CNI to bypass | The money envelope, leases and billing-aligned release |

- **How capacity is held.** `wicket-node` asks Kubernetes for capacity as **reservation pods**: pause pods
  requesting the CPU and memory of N sandbox slots, including each tier's fixed overhead. The scheduler
  and autoscaler then see the real load and add nodes. Inside a reservation, `wicket-node` launches and
  recycles sandboxes freely.
- **wicket is a `kube-rs` operator** for its CRDs (`NodePool`, `Workload`, `WarmPool`). The CRDs are desired
  state, **never authority**: admission accepts only specs whose digest the ledger has approved, so editing
  a CR can't skip human approval. The operator can't read Secrets cluster-wide.
- **Untrusted pods**, where the pod path is used at all, run under a sandboxed `RuntimeClass` (gVisor, or
  Kata on KVM pools), enforced by a `ValidatingAdmissionPolicy`. They get no service-account token, no
  Kubernetes Secrets and no host mounts. Their only egress is the node-local proxy under Cilium
  default-deny (`policyEnforcementMode=always`); `toFQDNs` rules would bypass TLS inspection. Payloads start
  only after the endpoint's policy is realised. MCP pods get per-namespace deny-all, with ingress only from
  the gateway.
- **`kubernetes-sigs/agent-sandbox`** is an optional `Sandbox` backend: v1.0.10 but a `v1beta1` API with
  near-weekly breaking changes, and default egress to the whole public internet. It runs with its network
  policy unmanaged and Cilium in charge, for clusters where pod-path latency is acceptable (GKE warm pools
  claim in about 200 ms).
- Kubernetes adds a large TCB (API server, kubelet, CNI, runc; there were runc escape CVEs in November
  2025). The privileged `wicket-node` DaemonSet is TCB too, as `wicket-jail` already is.

### 8.4 Many clouds

wicket must run on **anything from Vultr or Hetzner to GCP or AWS** (owner, 2026-11-08). Clouds differ in
exactly the ways that matter to wicket [10 §3]:

| | Vultr | Hetzner | AWS | GCP | Azure | Fly | E2B |
|---|---|---|---|---|---|---|---|
| Billing granule | per started hour | hourly | per second (60 s min) | per second (1 min min) | per second | per second | per second |
| KVM | no | dedicated only | nested (Intel C7i/M7i/…) | nested (N4D and others) | nested (Dsv5/6, …) | no | — |
| Idempotent create | no (tag + list) | no | `ClientToken` | `requestId` | named PUT | — | — |
| Signed node identity | no | no | IID document, NitroTPM | identity JWT | attested data | no | — |
| Confidential VMs | no | no | SEV-SNP (limited regions) | SEV-SNP/TDX (not London) | SEV-SNP, TDX | no | — |
| Managed Kubernetes | VKE (no scale to zero) | — | EKS | GKE | AKS | — | — |

So providers are **plugins behind one trait**, and their differences are **data** the rest of wicket
reasons about:

```rust
#[async_trait]
pub trait HostProvider: Send + Sync {             // wicket-provisioner: the ONLY holder of cloud credentials
    fn id(&self) -> ProviderId;
    fn catalog(&self) -> &[HostClass];           // plan, region, $/h, features {kvm, arch, gpu}, attestation level
    fn billing(&self, class: &HostClass) -> BillingModel;   // granule, rounding, monthly cap, stopped-bills, min lease
    async fn create(&self, intent: &Intent, class: &HostClass, boot: &BootConfig) -> Result<HostRef>; // idempotent by intent
    async fn get(&self, h: &HostRef) -> Result<Option<ObservedHost>>;
    async fn list_owned(&self) -> Result<Vec<ObservedHost>>;   // by owner tag only
    async fn destroy(&self, h: &HostRef) -> Result<()>;        // refuses unowned or protected resources
    async fn attest(&self, h: &HostRef, ev: &NodeEvidence) -> Result<AttestationLevel>;
    async fn charges_since(&self, t: Timestamp) -> Result<Vec<ChargeLine>>;   // daily money reconcile
}
// impls, in order: Local (this host / a Mac), Vultr (via the provisioning broker on the control host), AWS, GCP, Hetzner,
// then Azure, OVH, Scaleway, Latitude; Fly and E2B as "hosts of one" / hosted Sandbox backends
```

- **Idempotency** uses the provider's token where one exists (`ClientToken`, `requestId`). Otherwise it is
  tag-then-list-before-create.
- **Cluster modes are per pool**, not per installation:
  - *managed* Kubernetes (GKE, EKS, AKS, VKE) where its pools fit;
  - *k3s self-managed* on VMs from any provider. That is the default on Vultr and Hetzner, and wherever
    pools must scale to zero.
  - One wicket installation can span several clouds. Nodes join over **WireGuard + mTLS**, so wicket
    doesn't depend on any provider's VPC.
- **Node trust is graded.** Bootstrap uses cloud-init with a single-use, CA-pinned join token. The node
  dials out (no inbound port) and refuses to register if any preflight probe fails (Landlock ABI,
  seccomp, KVM, runsc). Trust is then graded by `AttestationLevel`:
  - `ProviderApi`: Vultr and Hetzner, trust on first use, checked against the provider API;
  - `InstanceIdentity`: signed documents on AWS, GCP and Azure;
  - `Tpm`, `SevSnp`, `Tdx`: hardware attestation, later.

  Whatever the level, a node then proves itself on every control connection with its node key and a
  short-lived identity certificate from the issuer, and the control host proves the issuer key back
  (§3.2 "Node identity"). That handshake is the same on every cloud and transport, so a stronger level
  changes how the first certificate is earned, not how it is used.

  Measured boot of `wicket-node`'s own image is the first hardware attestation worth building, because
  it is what lets the vault release credentials to a node. High-sensitivity zones can demand
  `AttestationAtLeast(SevSnp)`, which today means Azure, or AWS outside London.
- **Credentials to nodes.** Nodes hold no cloud credentials and no long-lived upstream credentials.
  Per-task native credentials are delivered only to that task's node, audience-bound to the node's
  identity and held in memory. In v1 multi-host, the **LLM proxy is central**, so the model key isn't on
  every node.
- **Placement vocabulary** gains `Provider{allow, deny}`, `Region`, `Residency(jurisdiction)`,
  `AttestationAtLeast`, `MaxCostPerHour` and `MaxLifetime`. Each constraint carries its provenance (org
  policy, manifest, derived from labels, grant), so `explain` can say *why* a workload landed where it did.
  Labels derive constraints automatically: for example, `customer.pii` ⇒ `Residency(UK)`.
- **Upstream native credentials** use each cloud's narrowing mechanism: AWS STS session policies, GCP
  credential access boundaries, Azure scoped role assignments (§9.4).

### 8.5 Capacity, leases and money

- **The provisioner is the only holder of cloud credentials.** It is a reconciler over desired state
  (`NodePool` CRDs, or SQLite in local mode) with idempotent creates and owner-tagged resources.
  Garbage collection only ever touches resources that carry wicket's owner tag.
- **Leases snap to the billing granule.** Under per-started-hour billing (Vultr), a host's
  `granted_until` stops at the paid-hour boundary ("minute 50" rule). Hosts are pooled within the paid
  hour and released before the next one, unless a task or a parked snapshot is pinned to them. Under
  per-second billing, hosts are released as soon as they are idle.
- **Money is reserved at the worst case.** A provisioning `Op` reserves `BillingModel::worst_case(rate,
  lifetime)` in the ledger before creating anything. A pool's `max × rate × 672 h` must fit the budget.
  A daily reconcile matches the ledger against `charges_since` from every provider, to the cent.
- **The money envelope:**
  - the auto tier applies only inside the pre-approved envelope (plans, providers, max $/h, max lifetime,
    monthly cap);
  - anything beyond it goes to a human, with the cost on the approval card;
  - the monthly cap is a hard stop in the ledger.
- **Agents can ask for capacity, never for credentials.** A cloud key would be an egress bypass,
  persistence and money all at once. `wicket.request_capacity{isolation, kvm, gpu, duration}` is a typed
  escalation; a grant is a *lease on capacity* inside the requesting zone.
- **On the control host during development**, the Vultr provider goes through provisioning-broker grants. wicket
  automates what the broker script does by hand, inside the existing $20/month cap.

### 8.6 Modes and v1 scope

| Mode | Where | Backends |
|---|---|---|
| **Single host, no Kubernetes** | laptops, this box, M1 | `process`, `gvisor` (Linux), `seatbelt` (macOS); same reconcilers on SQLite |
| **Single-node k3s** | this box on demand (about 1.6 GB with gVisor and Cilium; agree with the host's operator, stop when idle) | direct launch + gVisor pods |
| **Multi-cloud clusters** | production | per-pool managed or k3s; gVisor everywhere, Kata/Firecracker on KVM pools |

v1 steps [10 §13]:

| Step | Build | Where | Spend |
|---|---|---|---|
| I0 | placement vocabulary, compiler and verifier for local mode; `BillingModel` data for Vultr, AWS, GCP, Hetzner and Fly; leases; ledger `money` effect | this box | $0 |
| I1 | `wicket-node` local: direct launch, unbound warm pools with claim-then-bind, per-task MCP instances; **measure every tier** | this box via the host's job-slot limits | $0 |
| I2 | Vultr provider through the provisioning broker, host reconciler (adopt-or-destroy after a crash), WireGuard + mTLS join of a second node | Vultr London | ~$1–3/month |
| I3 | operator, reservation pods, Cilium default-deny, gVisor RuntimeClass, optional agent-sandbox backend | k3s on this box, on demand | $0 |
| I4 | Firecracker tier, snapshot clones with RNG reseeding | a Mac (M3 or later, macOS 15+) or an AWS `c7i-flex.large` with nested virtualization in London (~$0.10/h) | $0–1 |

Later: GCP and Hetzner providers, managed Kubernetes pools, hosted Fly and E2B capacity, hardware
attestation. Vultr bare metal waits until its billing is confirmed: the API says monthly ($185), the docs
say hourly ($0.25).

---

## 9. Enforcement plane

Detail: [04 §7].

### 9.0 Rules shared by every surface

- **One strict pre-parser in front of every parser** [08 §6 a2-1]. It rejects:
  - duplicate keys, and keys that differ only in case, at any level;
  - number overflow (`1e1000`);
  - JSON-RPC batches;
  - non-UTF-8 and oversized bodies.

  Then it forwards the **re-encoded canonical bytes the decision saw**, never the original bytes. The
  dangerous parser mismatch is with the upstream server or provider: four Go gateways independently
  shipped Go's case-insensitive, last-duplicate-wins JSON matching. This applies to MCP JSON-RPC, adapter
  REST bodies and LLM requests.
- **Never forward a client header** [08 §6 a2-3]. Upstream requests are built from the `Op` and the
  adapter: declared headers only, with the auth slot set by the vault. Responses get a header allowlist,
  and any injected credential value is scrubbed from them.
- **Reads can be writes** [06]. Every outbound request carries data out in its URL, query, headers and DNS
  name. So no-write-down is applied to reads too: a host's `send` clearance must cover the agent's `conf`
  before even a GET goes out. This covers markdown-image exfiltration, DNS exfiltration and
  fetch-on-behalf endpoints.
- **Acquired authority is quarantined** [05 §10.2-5]. Adapters declare the effects `mint.credential` and
  `create.principal`, with the response-field paths that carry authority: deploy keys, PATs, GitHub App
  creation, Actions secrets, IAM keys. The proxy or gateway moves those fields into the vault and returns a
  placeholder or handle. Activating one is a separate ledger grant.
- **Denials carry no tainted content** and list remedies (§9.5).

### 9.1 Egress proxy (`wicket-egress`)
- **Data plane:**
  - Built from `rama` 0.4 parts (`rama-net`, `rama-tls-rustls`, `rama-tcp`), pinned exactly. rama's MITM
    relay is BoringSSL-only, and Codex actually pins `=0.3.0-alpha.4`, so the rustls termination is
    assembled ourselves.
  - **One upstream connection per CONNECT**, dialled at CONNECT time to the vetted IP through a custom
    connector that applies the SSRF classifier (smokescreen's, ported to Rust; it covers CGNAT, NAT64,
    6to4, Teredo, metadata IPs and the proxy's own addresses).
  - Authority pinning (Host/`:authority` forced to the CONNECT target, `@` refused) is lifted from Codex
    `mitm.rs`.
- **Per-box CA:** `rcgen`, **name-constrained to the zone's ceiling**, not its current reach, because Node
  reads `NODE_EXTRA_CA_CERTS` once at start and would reject hosts granted later. The key lives only in
  `wicketd` memory. It is injected along with `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `CODEX_CA_CERTIFICATE`
  and the `REQUESTS_`, `CURL_` and `GIT_SSL_` variables.
- **Flow:**
  1. CONNECT → host gate → TLS terminate.
  2. **Canonicalize-or-reject:** dot segments (Codex `authorization_path.rs`), encoded slashes, duplicate
     query/JSON keys, method-override headers, `@` in the authority, Host ≠ SNI ≠ CONNECT target, unknown
     protocols after CONNECT, TRACE/TRACK, bodies on GET/HEAD. A truncated body gets the strict outcome.
  3. Adapter match → `Op` → decision.
  4. Rebuild the request from the `Op` and inject the credential, or SigV4 re-sign.
  5. Upstream; redirects are not followed.
- **Credentials are bound when minted** [08 §6 a2-4]:
  - Each vault record carries `(provider, hosts, header slot, format)`, sealed with the credential.
  - Placeholders keep the token's **shape** (same prefix and length, Codex `shaped_dummy_value`) so CLIs
    accept them. Each is a unique **honeytoken** registered with the proxies.
  - A placeholder is swapped only on exact match **in its declared header slot**, never in bodies, queries
    or arbitrary headers. Substituting anywhere else (srt's mask, iron-proxy, tokenizer's `inject_body`)
    reflects the real secret into whatever the provider stores.
  - A placeholder seen anywhere else trips a ledger anomaly.
  - The proxy mints short-lived tokens itself, for example GitHub App installation tokens, so plaintext
    never leaves it (Fly's tokenizer).
- **Pinned/mTLS clients** get SNI-only tunnels, with no inspection and no credentials. Each such tunnel
  appears in the zone view as an unmediated channel.
- **Git:** smart HTTP only; SSH is denied. Branch and tag rules come from the receive-pack command list.
  Path rules (`.github/workflows/**`) need **store-and-forward**: receive the push into a quarantined local
  mirror, check the diff with the adapter rules, then push upstream with expected old OIDs. `gix` for the
  mirror.
- **Proxy↔decider seam:** srt's decider protocol strictness rules — no nulls, duplicate keys or empty
  optionals; one `need_body`; ids increase; any violation kills the link; one 5 s timer. `srt proxy` and
  httpjail are differential test references only.

### 9.2 MCP gateway (`wicket-gateway`)
- **`rmcp` 3.9, pinned**, with:
  - a message-level relay over rmcp model types for third-party servers (agentgateway's pattern);
  - `ServerHandler` for gateway-native tools.
- **Version bridge** for MCP 2025-11-25 and 2026-07-28 [08 §6 a2-6]:
  - detect the protocol era, and reject legacy-only methods on 2026-07-28 requests;
  - enforce that `Mcp-Method`/`Mcp-Name`/`Mcp-Param-*` headers agree with the body;
  - mark every result uncacheable;
  - namespace server-initiated request ids per upstream;
  - reject server names containing the namespace delimiter, and case-insensitive collisions;
  - seal MRTR `requestState` with rmcp's codec, bound to the `Op` digest, with single use enforced by the
    ledger.

  Claude Code's 2026-07-28 support is undocumented, so both versions are bridged.
- **Discovery and execution share one filter:** the function that hides a tool from `tools/list` is the
  one that blocks `tools/call`, applied in the same order. Meta-tools re-authorize the *inner* call (every
  `wicket.*` tool, codemode, any `call_tool`). Codemode gets step and call budgets.
- **Four kinds of tools:**
  1. **Gateway-native tools generated from adapters** (preferred; wicket writes the descriptions).
  2. **Third-party MCP servers as isolated service workloads (§8.2).** Their descriptions are pinned by
     hash *and* treated as taint: hash pinning doesn't catch descriptions that were poisoned from the start
     (MCPTox). A changed definition is a policy change — automatic if it narrows, a decision if it widens.
     Admission is by mechanism (sandbox, egress, no secrets), not by scanner verdict.
  3. **Remote MCP servers** with wicket-held, audience-bound OAuth tokens keyed by agent × route × upstream.
     Gateway sessions are bound to agent identity and route.
  4. **CLI-wrapping tools** (from nono): for example `gh pr create`, run in a **fresh tool sandbox per
     call** that holds the real token at *its* egress. The agent's box holds nothing, and each call is a
     gateway `Op`. [07 a.2-14]
- **Host-tool transports:** besides MCP over the sandbox's socket, the gateway can serve tools over the
  agent's own control pipe where supported (Codex `dynamicTools`, ACP MCP-over-ACP, pi extension tools).
  The box then needs no network path to the gateway.
- **`wicket.*` tools:**
  - `spawn`, `await_grant(request_id)`, `read_handle`, `request_access(typed)`, `request_capacity(typed)`
    (§8.5);
  - `check_send(dest)` (a dry run);
  - `restrict(...)`, a zero-risk tool that lets the agent narrow its own policy, applied automatically.

  Sink tools accept **handles as arguments**, and the gateway substitutes the content at dispatch (§4.2).

### 9.3 LLM proxy (`wicket-llm`)
- Holds the model credential (the owner's Claude subscription token, never an API key) and routes per zone (model allowlist, token and cost budget).
- Wire APIs: Anthropic Messages, OpenAI Responses, Google, Chat (§6). `codex responses-api-proxy` is
  differential prior art.
- **Rewrites server-side tool definitions** to the zone's reach, and taints sessions on server-side tool
  results.
- **Subscription logins without the login in the box** [16 §3-2]: the box gets a syntactically valid but
  fake credentials file (or the placeholder `CLAUDE_CODE_OAUTH_TOKEN`), `wicket-llm` injects the real bearer,
  and a single token broker serialises refresh-token rotation for every zone (Centaur's recipe). The PoC
  injects the access token by reference and never touches the refresh token.
- **Can review tool calls in model responses** before the agent sees them, and turn a forbidden call into a
  synthetic refusal (inspect_ai's agent bridge) [16 §3-1]. This is a second enforcement point for actions that
  never cross a proxy, such as local file edits; it is advisory for those, since the box can act without the
  model's say-so.
- Is the liveness sensor: no model request for N seconds after a denial means the agent is waiting.
  Cache-warm and model-refresh requests don't count.
- Does **not** forward client auth headers, ever (the containment-post lesson). It applies the §9.0
  pre-parser to request bodies.

### 9.4 Upstream credentials
- The vault mints the **narrowest native credential** per task, so a gateway bug is capped by provider
  scope:
  - GitHub App installation tokens limited to the repo IDs and the permission subset, without `workflows`
    or `administration` unless granted;
  - AWS STS session policies;
  - Stripe restricted keys;
  - Cloudflare scoped tokens.
- Native scopes are computed by the solver from endpoint coverage (§5.2).
- Vault-to-provider auth uses workload identity federation where the provider offers it.
- No token passthrough (MCP spec).

### 9.5 Denial and pending on the wire

```http
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json
X-Wicket-Request-Id: req_01JC...
Retry-After: 30

{"type":"https://wicket.dev/e/pending-approval","status":"pending_approval","request_id":"req_01JC...",
 "retry_after":30,"typed_request":{"provider":"github","verb":"contents.write",
 "resource":"repo/acme/api/ref/main/path/infra/ci.yml","budget":{"uses":1,"ttl":"10m"}},
 "hint":"Call wicket.await_grant with this request_id, or retry after 30s."}
```

MCP returns the same body as an `isError` result, or `input_required` / a task handle when the client
negotiated them. Connections are never held open while a human decides.

**Agents must not spin at the edge** (owner, 2026-11-09: the goal is that agents don't spin endlessly
when they hit isolation limits, and instead ask for more reach when they need it).
- **Every refusal says which case it is in the status line**, because many tools show nothing else:
  `Blocked by wicket sandbox: never allowed`, `… needs human approval (r-…)`, `… denied by a human`, or,
  in hiding zones, `unknown host`. The body says the sandbox has no other route, and what to do.
- **Repeats are counted.** From the third block of the same request, the refusal says to stop. After every
  ten blocks in a run, the operator sees "agent may be stuck".
- **`request_access`** lets the agent ask ahead, once, for a URL or a path prefix, with a reason shown to the
  human as the agent's own claim. It then waits with `await_grant`.
- **Every agent gets the same sandbox notice:** batch runs and wrapped sessions alike.

In a live check, an agent blocked on two hosts waited with `await_grant` and retried each once after
approval. It didn't probe.

**DNS.** The box has no resolver and no network. Names are resolved only on the host, and only for requests
a rule allows. So DNS isn't an exfiltration route, and blocked or pending names are never looked up.
- **Wildcard reach rules are the residual channel:** any name under them is resolved on the host. Prefer
  exact hosts in sensitive zones.
- **Showing "no such domain" in `escalate` mode needs an existence check.** A safe one asks only whether the
  *registered* domain exists (public suffix list), so agent-chosen subdomains are never queried. It's not
  built; `unlisted_hosts: hide` is the strict alternative.
- **An in-box resolver, when one is needed,** is wicket's own synthetic one: zone names only, "no such
  domain" otherwise, and never forwarding an agent-chosen name (§7).

**Denials are recoverable** [05 §10.2-7]. The body lists the remedies policy allows: request this narrower
grant, spawn a child zone, meet a prerequisite. In APPA, removing remedies dropped utility from 88% to
35%. Bodies never echo tainted content. E1 also measures retry loops (CapScope's runs took about 2× as long
because of retries after refusals).

**The wording is interface, and the retry contract is typed** [16 §3-4, 17 §4-2]. Paperclip's tool gateway
is the closest shipped analogue: HTTP 409 `approval_required` with a canonical-arguments hash and expiry,
and a retry carrying the approved request id that is rejected if the arguments changed. Its error codes
become conformance cases for §9.5. Bodies stay short with remedies first, body wording is an arm of E1, and
the §6.1 suite checks that an agent's next action after a denial is the offered remedy or a wait, not a
reroute.

---

## 10. Provider adapters

Detail, schema and six worked GitHub endpoints: [04 §4].

- **Data, not code.** A strict YAML subset (no anchors, aliases or tags), validated by a JSON Schema
  generated from the Rust types, and canonicalized to RFC 8785 JSON for hashing and signing. One
  interpreter in `wicket-adapter`.
- **Total over inputs.** Every path, query, header and body parameter the provider interprets is
  declared, typed and either bound into a resource or explicitly rejected. Anything undeclared is denied.
- **Effects are a set; risk is derived** as the maximum of the effects' floors. The adapter may raise risk,
  never lower it. Generated rules start at `unknown` (R4).
- **Resolvers** handle opaque IDs (declared lookups with a TTL, re-verified against the response).
  **Query rewrite** narrows over-broad reads; post-filtering is a marked fallback.
- **Sink parameters are marked** (recipient, repo/ref, URL host, @mention, amount) for the per-argument
  provenance check (§4.2). A `triggers` effect declares provider-side reactions (CI runs, notifications,
  ChatOps), so `explain` can compute *authority*, not just permission.
- **Examples are tests.** Every endpoint rule and dangerous pattern ships `examples.allow` and
  `examples.deny` requests, checked at load time and in CI (from Codex execpolicy).
- **Strictest decision wins** when several rules match.
- **Risk floors** are the maximum over the provider's metadata *and* community corrections (policy_sentry
  and iam-dataset keep corrections for AWS access levels AWS got wrong). A spec can never lower risk.
- **The dangerous-patterns file** is hand-maintained and provider-scoped. It is applied after
  classification and can only raise risk or force deny. The generator can't remove entries. For GitHub it
  covers workflow paths, agent-config files (`CLAUDE.md`, `.mcp.json`: cross-agent smuggling via repo
  state), @mentions, ChatOps, markdown image exfiltration, alias routes, GraphQL outside an allowlist, and
  more.

**Self-building loop** (the brief's §4):
1. The proxy denies an unmapped endpoint with a `request_id`.
2. The generator, with no agent context, sees the OpenAPI operation, the docs' permission entry, the
   provider's risk metadata, and the *shape* of the request (field names, not values).
3. It emits an R4 rule. Floor check: the request that triggered generation must end up allowed, or the
   generation failed.
4. Static checks: schema; coverage of every OpenAPI parameter; risk floors from provider metadata; symcc
   "narrower than previous ∪ approved delta".
5. Dynamic checks in the test org:
   - an allow/deny matrix over in-scope and out-of-scope resources × canonicalization attacks × alias
     routes;
   - executing the allows and confirming the touched resource;
   - webhook, notification and email sinks for undeclared effects;
   - an oracle cross-check against `X-Accepted-GitHub-Permissions`.
6. The rule lands at the lowest risk class the evidence supports. Downgrades below R3 need a human
   sign-off on a small diff.
7. The normal escalation path decides whether this agent gets it now.

---

## 11. Escalation

Detail and state machine: [03 §7.4].

```
Received → Validated (typed, canonical, bound to Op digest) → Narrowed (narrowest grant covering the call) → Classify
  ├ forbidden by org/dangerous list ─────────────────────────────────► Denied{reason, narrower_alt?}
  ├ ⊆ zone ceiling ∧ risk ≤ auto_max ∧ provenance OK ∧ ratchet OK ───► Granted(Auto)
  ├ ⊆ parent authority ∧ re-derivation(trusted task text) says yes ──► Granted(Parent)      [off in v1]
  ├ outside parent authority ────────────────────────────────────────► PendingUp(grandparent … Human)
  └ else ────────────────────────────────────────────────────────────► PendingHuman{binding_code, expires_at}
PendingHuman → Granted | Denied | Expired          Granted → Active → Closed (uses | expiry | task end | revoke subtree)
```

- **Field provenance:** each field of the request must trace to the task text, the manifest, a typed gate
  field or an existing grant. A field that only the agent supplied (say, a repo name that appears nowhere
  upstream) cannot be auto- or parent-granted. The same check applies to sink arguments on *every* R2+
  `Op`, not just escalations (§4.2). The highest-success real attacks tamper with a value inside an allowed
  capability: MCPTox parameter tampering at 72.8%, an out-of-scope parameter in MSB at 76.5% [05, 06].
- **The justification is `Untrusted<String>`.** It is stored and shown to humans, clearly marked, and never
  given to an LLM decider.
- **Grants are narrower than or equal to the ask** (RAR semantics): one file, not the repo; one use, not
  standing access. Everything expires at task end at the latest.
- **Ledger semantics** [05 §10.2-8, 06]:
  - The ratchet and use counts are keyed by (task root, policy epoch), not grant id. Past
    `ratchet_budget`, everything goes to a human with the full diff.
  - A single-use grant is consumed in the same transaction that forwards the request, after re-checking
    revocation and the epoch. Every policy change bumps the epoch, and decisions carry a Zanzibar-style
    consistency token against revoke and relabel races.
  - Relational limits the per-capability check can't express live here: co-possession ("read secret XOR
    publish") and cardinality.
  - No standing grants for R3+. Children never inherit live grants or pending requests.
  - A pre-approved request type is auto-granted only while the agent's taint is ∅.
  - **Fresh per use** is a grant property (from Codex's `prompt-user` rules), default for R4 and `money`.
    Such request types never count towards ratchet credit or fatigue promotion.
- **Fatigue, carefully.** High approval rates measure habituation, not safety. Chrome's SSL warnings were
  clicked through 70% of the time, and users attended to permission prompts 17% of the time and
  understood 3% [06]. So a request type humans approve more than 95% of the time becomes a *candidate*
  auto rule only if all of these hold:
  - a second reviewer approves the promotion;
  - it is not R3+ and matches no dangerous pattern;
  - a shadow metric of seeded bad requests shows humans still catch them.

  A type humans mostly deny becomes an auto-deny.
- **Human channel:** CIBA-shaped, so approval is asynchronous and can happen on another device. Decisions
  come only from wicket-native operator channels (CLI, API, console) with a passkey assertion over the
  request digest (§14.1). Vendor UIs such as Remote Control can announce a request but never decide it.
- **v1 starts with the parent tier off** (auto or human only), and measures in shadow mode what it would
  have decided. The evidence is DRIFT's ablation: letting an LLM validator widen policy raised attack
  success from 2.14% to 5.41%, for about 15 points of utility [05]. Adaptive attacks break LLM-based
  defences generally (*The Attacker Moves Second*). (Progent's 3.9% ASB figure, cited in v0.1, measures
  something else and is inflated by ASB's forced attack-tool injection [06].) If the parent tier is ever
  turned on, it gets a mechanically checked limit on what it may approve (no endorsement, at most R2),
  with each ruling bound single-use to the exact call.

### 11.1 Who a request is for (owner, 2026-11-08: "a user can't approve a grant if it doesn't know who it's for")

Every pending request names who asked, and the human sees it before deciding.
- **Across sandboxes** this is exact: the identity is the socket (§3.2).
- **Inside one sandbox** (Claude Code's subagents and agent teams, Codex threads, a crew) it is reported,
  not proven. wicket reads the agent's own event stream outside the box. For Claude Code, every subagent
  tool call carries `parent_tool_use_id`, which points at the `Agent` call that started the subagent, with
  its type and description. wicket matches a blocked request to the calls in flight: exactly one call
  naming the host or git operation, else the only call in flight, else every candidate. It never picks
  one silently.
- The console card shows "For: subagent general-purpose: Fetch example page — Bash: curl …", the
  candidates when it's ambiguous, and a warning when more than one agent asked for the same thing (one
  grant would serve them all). It always adds a note that the attribution is reported, and that anything
  in the box could use the grant.
- The passkey signs `requested_by` together with the decision, so the record says who the human was told
  it was for.
- When a grant is used, the user is attributed too. A grant used by an agent other than the one it was
  approved for is flagged in the audit log. A later policy could revoke it, or require approval per agent.
- A request no in-flight call explains is shown as "unknown". That itself is a signal: a background
  process, or something the agent didn't announce.

Built in the PoC and verified with two concurrent Claude Code subagents ([poc-results](poc-results.md)).

---

## 12. Memory, stores and smuggling

- **Memory is any state that outlives a write.** That covers:
  - stores the zone declares;
  - the agent's own config directory (`CLAUDE_CONFIG_DIR`, transcripts);
  - the workdir;
  - caches and logs;
  - provider-side state (the gateway's label store);
  - wicket's own learned artifacts.
- Default: everything an activation writes is **staged**. What persists across sleep is decided by the
  agent's promotion gate (§13.4), and the label stays attached. One-shot agents (`delete_when_done`) keep
  nothing.
- **wicket's learned artifacts** (adapters, default manifests, approval history) are produced only from
  trusted inputs or human decisions. The adapter generator never sees agent context; a manifest default
  only changes from a human-approved manifest or grant.
- **Repo state is a smuggling channel.** A child writing `CLAUDE.md` or `.mcp.json` instructs the next
  agent, which is why those paths are dangerous patterns. Labelling them as taint is necessary but not
  sufficient, because the agent still obeys them: config-file injection worked against every provider
  tested [06]. So for refs that aren't trusted, preflight **removes** agent context files from the agent's
  view (or exposes them only as handles), per each adapter's `context_files` list.
- **The agent's own policy stores are memory:** Codex `$CODEX_HOME/rules/*.rules` and config writes, pi
  `trust.json`. They are read-only or discarded, and never fed from approvals.
- **Taint recovery by forking.** Transcript entries carry labels (`(session, entry)` handles). When an
  agent gets tainted, wicket can fork its session at the last clean entry (pi, Codex fork/rollback) instead
  of discarding the run.
- **Covert channels** (timing, sizes, file names, escalation request contents) are not closed. Escalation
  requests are rate- and size-limited, and anomalies are logged.

---

## 13. Agent lifecycle: long-lived by default

*Owner direction (2026-11-08): long-lived agents are the default. Agents are active for a while, go to
sleep, hibernate, and are woken later. Agent garbage collection permanently removes agents and state no
longer deemed useful. Refined by research 12 (OpenClaw) and 13 (Hermes), the two long-lived assistants
studied.*

### 13.1 Agent ≠ process ≠ task

```rust
pub struct Agent {                       // the durable identity: outlives every process
    pub id: AgentId, pub tenant: TenantId, pub owner: PrincipalId,
    pub home_zone: ZoneId,               // standing ceiling: reach, clearance, send
    pub charter: Versioned<TrustedText>, // standing instructions, operator-signed
    pub kind: AgentKind, pub adapter_pin: semver::Version,
    pub memory: Vec<MemoryStoreId>,      // versioned, labelled (§13.4)
    pub subscriptions: Vec<Subscription>,// what may wake it (§13.2)
    pub retention: RetentionPolicy,      // §13.6
    pub key: AgentKeyRef,                // per-agent data key, wrapped by the tenant key
    pub state: LifecycleState,
}
pub struct Activation {                  // one period of activity in one sandbox
    pub id: ActivationId, pub agents: Vec<AgentId> /* one, or a crew (§13.7) */, pub woke_by: Wake,
    pub work: Vec<WorkItemId>, pub sandbox: InstanceRef, pub lease: Lease,
}
pub struct WorkItem {                    // what used to be a "task": a unit of work delivered to an agent
    pub id: WorkItemId, pub assignees: Vec<AgentId>,   // collaboration on one work item is first-class
    pub text: TrustedText,               // from an authenticated operator or an operator-created subscription
    pub payload: Vec<Handle>,            // event data: untrusted, labelled
    pub deadline: Option<Timestamp>,
}
pub enum Wake { OperatorMessage, Schedule(CronSpec), Event(SubscriptionId), AgentMessage(GateId), GrantDecided(RequestId) }
pub enum LifecycleState { Active, Idle, Sleeping, Hibernated, Archived, Deleted(Tombstone) }
```

The old one-shot task is the special case: an agent whose retention is `delete_when_done`, with one work
item. Manifests (§5) now describe an agent's home zone and its gates, or a team of long-lived agents; a
work item runs inside that standing structure.

### 13.2 Lifecycle

```
            message / schedule / event / grant decided
   ┌────────────────────────────────────────────────────────────────┐
   ▼                                                                │
 Active ──no activity N s──► Idle ──M min──► Sleeping ──H h──► Hibernated ──D days──► Archived ──policy──► Deleted
 sandbox running             freeze; RAM      checkpoint or      snapshot, workdir,      snapshot dropped;   crypto-shred;
 model calls flowing         held; ~ms wake   snapshot on node   session, staged memory  charter, memory and  tombstone in
                                              disk; ~s wake      pushed to object store; transcript handles  ledger + audit
                                                                 node released           kept; cold rebuild
```

- **Each step down frees resources and costs more to wake.** The thresholds are per plan and per agent,
  and billing-aware (§8.5): a sleeping agent pins its node, a hibernated one pins only storage.
- **Wake = restore or rebuild.** A snapshot is restored when it is compatible (same runtime version, CPU
  features and lower-layer digests, §7). Otherwise the agent is **rebuilt**: a fresh sandbox from the base
  image, plus the durable workdir, the approved memory version, and the agent's own session resume (Claude
  `--resume`, Codex `thread/resume`, pi `--session-id`). Rebuild must always work; snapshots are an
  optimisation. Every wake re-binds identity (claim-then-bind, §7.1). A **rebuild** gets new placeholders,
  a new listener and a CA from the ceiling. A **memory restore** re-binds the old placeholders, and the
  run's CA must outlive the snapshot, because the restored process already trusts it (research 22).
- **Wake sources are explicit and authenticated:**
  - an operator message (any operator channel, origin-labelled, §14.1.2);
  - a schedule;
  - an event subscription (a GitHub webhook received through the gateway, a queue);
  - a message from another agent through a gate;
  - a pending grant being decided.

  Subscriptions are created by operators or granted like any capability. An agent can't subscribe itself
  to arbitrary inputs.
- **Vendor remote UIs:** an RC session past its resumability window is re-served on wake (§14.1.4).

### 13.3 Authority across a long life

- **Living long doesn't widen reach.** The home zone is a standing *ceiling*. What an agent can actually
  do is still decided per `Op`.
- **Grants are scoped to a work item, not to the agent's lifetime.**
  - Standing grants exist only up to the auto tier, within the ceiling, and are listed in the manifest.
  - R3+ is always fresh per use (§11).
  - There are two ratchets: one per work item, and a lifetime ratchet per agent. The lifetime ratchet
    counts cumulative escalations since a human last reviewed the charter, and forces that review when
    exceeded.
- **Trusted text** is the charter (operator-signed, versioned) plus the current work item's text. For
  event-triggered work only the *subscription* is trusted, never the event. "Wake on a new issue and triage
  it" is trusted; the issue's content is a labelled handle.
- **Sleep is a declassification checkpoint, on rebuild only.** A memory restore keeps the agent's full label;
  a rebuild or a forked session declassifies (research 22). Across a rebuilding sleep, the agent's floating
  label resets to the join
  of what it *keeps*: approved memory versions, the workdir and its session handles. Ephemeral context is
  discarded at sleep unless it is promoted (§13.4). So a long life doesn't mean unbounded taint creep, and
  a run tainted by one bad page can be ended by sleeping past it, or by forking the session at the last
  clean entry.

### 13.4 What an agent keeps

| State | Kept across sleep? | How |
|---|---|---|
| Charter | yes | Operator-signed versions; changing it is a policy change (narrowing is automatic, widening needs a decision) |
| Memory stores: facts, notes, preferences, **skills** | yes, versioned | Writes during an activation land in a **staging layer**. A **promotion gate** decides what joins the next version: automatic for typed, low-risk facts within the label ceiling; quarantined-reader or human review for anything instruction-like (skills, procedures, "remember to…"). Every version is labelled, can be forked and rolled back, and each activation starts from a fork, so poison is undoable. |
| Session and transcript | yes, as labelled handles; resumed on wake | Compaction is allowed; entries keep their labels |
| Workdir | yes | Copy-on-write upper layer made durable; git-backed where it's a repo |
| Process and RAM state | only in the Idle and Sleeping tiers, and in hibernated snapshots | Dropped at archive |
| Caches | no | Rebuilt |
| The agent's own config and policy files | no | Regenerated from the LaunchPlan on every wake |
| Live grants, pending requests | no | Work-item-scoped; a pending request survives sleep only as a ledger entry that can wake the agent when decided |

Self-improving agents that write their own skills (Hermes, OpenClaw) are exactly the case the promotion
gate exists for. A skill is an instruction to every future activation, so it is never auto-promoted, and
its label is the join of everything that shaped it.

### 13.5 Durability

- **Control-plane state** (ledger, audit, agent registry, memory versions):
  - single host: SQLite in WAL mode, continuously replicated to object storage (litestream-style), with
    point-in-time recovery;
  - cluster and platform mode: Postgres, partitioned per tenant.
- **Agent state** (snapshots, workdirs, sessions, memory blobs) goes to **S3-compatible object storage**:
  a local directory or Garage/SeaweedFS (MinIO's community repository is archived), then Vultr Object
  Storage, R2, S3 or GCS. Volumes become durable trees with a single-writer lease. Every blob is encrypted with the agent's data
  key, which is wrapped by the tenant key (BYOK for high tiers). Residency follows the tenant's placement
  rules.
- **Node loss:** while an agent is active, wicket pushes incremental checkpoints of the workdir, session and
  staged memory (default RPO 60 s). An agent on a dead node is rebuilt elsewhere from its last durable
  checkpoint. Hibernated agents are unaffected.

**PoC (2026-11-09).** Built so far:
- **Named volumes per tenant and zone** (`zone.volumes`, under `/volumes/` in the box). They live on whichever
  host runs the box and persist across runs.
- **An in-place workspace** (`--workspace-dir`): a host directory mounted read-write, with the run's outbox
  mounted over its `out/`.
- **Follow-up messages to a running agent** (`wicket say <run> …`), carried over Claude Code's stream-json
  input. The session stays open for `agent.idle_timeout` after each turn and closes after that. Operator
  text is trusted task text from the principal, unlike anything an agent or a page says.

**Hibernate and wake (#70, 2026-11-12).** Built as experiment #70 recommended: rebuild plus `claude --resume` (H0), with `docker pause` for Idle.
- The ledger has an agent row for each long-lived agent: its state, generation, session, manifest and head
  bundle.
  - A wake is a compare-and-set claim that bumps the generation.
  - The LLM, egress and gateway proxies refuse a stale generation.
  - A push commits only under the current generation, and from the head it started from.
- The bundle is the box's whole writable state:
  - the workspace (or the in-place directory);
  - all of `/wicket/state`;
  - `/tmp`, now a per-box host directory;
  - `durable` volumes. `node` and `cache` volumes stay out of the bundle; on one node they behave the same.
- Trees are tar + zstd -3, content-addressed in an `ObjectStore` (a directory now). Each is verified by its
  tree digest on restore.
- The zone's model budget and `limits.timeout` are the agent's over all its activations. Spend is
  recorded on the agent row, and a wake starts from what is left. A spent agent is never woken, so peer
  messages can't buy it a fresh budget.
- Hibernation by rebuild happens only at a quiet point, checked against the box's process list. Otherwise the
  box stays Idle.
- Not built:
  - encryption and signing (the agent data key, a signed `StateManifest`);
  - S3-compatible backends;
  - the Sleeping tier (a stopped box with its state cached on the node);
  - the gVisor checkpoint (H2);
  - garbage collection;
  - hibernation for node and wrapped boxes.

Volumes inherit the zone's taint like any store (§12): whatever one run leaves there, the next one reads.

### 13.6 Garbage collection

- **Policy decides; the agent never does.** `RetentionPolicy` sets each tier's threshold (`idle_to_sleep` …
  `archive_to_delete`), a storage cap, and whether the agent is `delete_when_done`. It comes from the plan,
  the tenant and the agent, narrowest wins. Quota pressure can push agents down the ladder early.
- **"No longer useful"** is computed from signals:
  - no wake in N days;
  - no inbound references: subscriptions, schedules, other agents' gates, handles shared with others;
  - the owner is gone;
  - the charter has expired;
  - an explicit delete.
- **Reversible until the last step.** Hibernate → archive (drops the snapshot) → delete. Before delete,
  the owner is notified with a grace period, and inbound references are listed. A legal hold, or a live
  cross-tenant gate that promised retention (§15), blocks deletion.
- **Delete is crypto-shredding:**
  - destroy the agent's data key, so every durable blob becomes unreadable, then delete the blobs;
  - revoke grants, cancel schedules and subscriptions;
  - write a tombstone into the ledger and audit log, keeping the hash chain intact without the content.

  GDPR erasure uses the same path. Shared derived copies follow their gate's terms.

### 13.7 Several agents in one zone: teams and crews

A zone can hold any number of agents, and **several agents collaborating on one work item is a normal
case** (owner, 2026-11-08), including several Claudes on one machine. Two layouts, chosen per zone:

| Layout | What's shared | When |
|---|---|---|
| **Team:** one sandbox per agent | A zone-scoped shared workdir (copy-on-write branches merged by wicket, or a shared volume), a zone message channel through wicket, the work item's grants | Default where members need separate attribution, different agent kinds, or independent sleep and wake |
| **Crew:** several agents in **one sandbox** | Filesystem, processes and the network listener; each agent keeps its own adapter session | Cheapest and closest collaboration: pair programming, an agent and its reviewer, Claude Code agent teams |

Rules for both:
- **One ceiling.** Members share the zone's reach and the work item's grants. Members who need different
  ceilings belong in different zones joined by gates, as before.
- **Free flow inside the zone** means plain messages between members are fine. That is the definition of a
  zone. It also means **taint is shared**: one member reading a poisoned page taints whatever state the
  others read. In a crew that's the whole sandbox; in a team, the shared workdir and channel. Containing
  taint is done by splitting the agents into separate zones, not by trusting them to keep it to themselves.
- **Attribution.** In a team, each agent has its own transport identity. In a crew, members can impersonate
  each other inside the box, so authority and labels are per crew (the join of its members). Per-agent
  attribution is best effort: per-agent placeholders and listener fds, tagged in the audit log.
- **Escalations** are judged per zone and work item. A grant made for the work item serves every assignee.
- **Lifecycle.** A crew is one activation: it sleeps and wakes as one. Team members sleep and wake
  independently.
- **An agent's own sub-agents** (Claude Code's subagents and agent teams, Codex threads) are processes
  inside its sandbox. To wicket they are part of that agent; it doesn't need to know about them.
- **Budgets:** §7.1's per-instance overhead is per sandbox, so a crew of N agents costs one sandbox plus N
  agent processes.

### 13.8 Lifecycle budgets

These extend §7.1:

| Transition | Budget (p95) |
|---|---|
| Wake from Idle | ≤ 50 ms |
| Wake from Sleeping | ≤ 2 s |
| Wake from Hibernated | ≤ 10 s by restore, or a rebuild |
| Active checkpoint RPO | 60 s by default |

---

## 14. Humans in the loop

### 14.1 Operator channels: Remote Control and the admin interface

*Owner requirement 2026-11-08. Remote Control mechanics, prior-art oversight UIs and the risk analysis are in
[`research/09-operator-channels.md`](research/09-operator-channels.md).*

**Requirement.** People must be able to watch, steer, approve and stop inner agents comfortably from two
places, and see the same state in both:
1. **the agent vendor's own remote UI**, today Claude Code Remote Control (claude.ai, the desktop app, the
   phone);
2. **wicket's own remote admin interface**: web UI (usable on a phone), CLI and API.

Both must be comfortable to use. They are not equal in authority, though. wicket's own surfaces are
authoritative: grants, pause and kill, zone state. Vendor surfaces observe and steer only. The reasons are in
§14.1.2 and §14.1.4.

#### 14.1.1 One event bus, many channels

wicketd publishes everything humans care about on one ordered event stream per task:
- agent events (normalised `AgentEvent`s from §6);
- escalations and their state changes;
- the grant timeline;
- gate crossings;
- sandbox state (running, paused, parked, exited);
- cost.

Each **operator channel** subscribes to that stream and can send operator actions back.

```rust
pub enum ChannelKind { NativeRemote(NativeRemoteKind) /* ClaudeRemoteControl, ... */, WicketWeb, WicketCli, Push }
pub struct ChannelCaps {
    pub observe: bool,                 // live transcript, state
    pub message: bool,                 // steer: send a user message into the agent
    pub control: bool,                 // pause / resume / interrupt / kill
    pub answer_agent_prompts: bool,    // the agent's OWN permission prompts (advisory layer)
    pub decide_escalations: bool,      // wicket escalations (authority layer)
}
pub enum OperatorAction {
    Message { agent: AgentId, text: String },
    Control { agent: AgentId, op: ControlOp },
    AnswerAgentPrompt { agent: AgentId, prompt: PermissionReqId, allow: bool },
    Decide { request: RequestId, decision: HumanDecision, proof: ApprovalProof },
}
```

Adapters declare whether their agent has a native remote UI (`AgentCaps::native_remote`). The Claude Code
T1 adapter has one. ACP agents can be driven from an ACP client such as Zed. T3 agents only get wicket's
own channels.

#### 14.1.2 Rules that hold whatever the channel

1. **Authority lives only in wicket's ledger.** There are two kinds of decision, and they are never
   conflated:

   | | Agent-local prompt | wicket escalation |
   |---|---|---|
   | Source | Claude `can_use_tool`, ACP `request_permission`, Codex approvals | A gate denied an `Op` and opened a typed request |
   | "Allow" means | The agent may *attempt* it inside the box | A ledger grant the gates honour |
   | Answerable from | Any channel with `answer_agent_prompts`, including RC | wicket-native channels only, with passkey step-up |
   | Trust | Advisory (§2, principle 1) | TCB decision |

   **An RC approval is never a wicket grant** (default). The reasons:
   - it reaches wicket only through the hostile box or a private vendor protocol;
   - the prompt was rendered with a model-written description and a truncated preview;
   - the agent controls the transcript around it.

   Pending wicket escalations are *announced* in every channel. In RC that is a notice carrying the typed
   request and a binding code that says "approve in wicket". They are never answerable by RC chat text,
   because the agent can draw look-alike requests in the same transcript. A fenced research option,
   `rc_attested_approvals`, is off by default, limited to ≤R1, and requires a device-attested approval frame
   observed on the server→box stream plus account→operator mapping via JWKS. It runs in shadow mode first.
   [09 §7.3]
2. **Every inbound message gets an origin, and only typed amendments carry authority.** [09 §7.4]

   | Origin | Becomes trusted task text? |
   |---|---|
   | wicket operator, typed `AmendTask` ("also update `docs/ci.md`") | **Yes.** Signed into the trusted text chain (§5.1), so a later request for that path passes the provenance check. It still needs a decision. |
   | wicket operator, free-text steer | No. Steers within the existing ceiling only. |
   | RC message (vendor-attested author, not wicket-verified) | No. Same as a steer, shown with an RC badge. |
   | Pasted or attached content, from any channel | No. **Untrusted data** with its own labels and taint: a human forwarding a poisoned page is the classic injection path. The UI offers *Instruct* vs *Attach as data*. |
   | wicket system ("R-123 granted, retry") | n/a (trusted notice) |
3. **A native remote UI is a destination and an ingress, so it is mediated.** Remote Control sends the
   transcript, which includes tool outputs, to Anthropic's session service, and brings instructions back.
   So it:
   - is declared in the zone (`operator_mode: vendor_rc`), and the destination
     `anthropic.session_store{retention, training, devices}` must be cleared for the zone's labels;
   - is allowed **only** through the egress proxy, path-allowlisted to this session's endpoints;
   - is refused for zones holding data classes the destination isn't cleared for (wicket's own channels
     still work there).

   It carries the transcript (tool outputs included), diffs, file uploads in both directions and push text,
   all retained by Anthropic for 30 days, or 5 years on consumer accounts with training enabled.

   `wicket explain` lists it like any other channel.
4. **Same state everywhere.** An action taken in one channel shows up in all the others: a message typed in
   the Claude app appears in wicket's transcript view (via the tap, §14.1.4), and a wicket pause shows in
   RC as "can't reach", with wicket's push explaining why. Each event carries a channel tag, so the audit log
   shows who did what where. `wicketd` is the single source of truth. Channels are projections of one ordered,
   resumable event log, and a transcript gap (a tap parse failure) is shown as a gap, not hidden. For agent-local
   prompts, the first answer on any surface wins.

#### 14.1.3 wicket's admin interface

- **API first:** HTTP + JSON with an SSE or WebSocket event stream. The CLI and the web UI are both clients
  of it; nothing is UI-only.
- **Web UI (mobile-first)** has these views:
  - tasks and zones (§14.2 view, blast radius);
  - per-agent live transcript, with handles dereferenced for cleared humans and each view logged;
  - steer box;
  - pause, interrupt, kill, snapshot;
  - diff review for extracted patches;
  - the escalation queue;
  - the grant timeline;
  - cost.
- **Approvals resist approval-phishing and fatigue:**
  - The approval card shows the **typed request** (provider, verb, resource, budget), the zone's
    blast-radius delta and the binding code.
  - The agent's justification sits behind a clearly marked "untrusted" fold.
  - Approving requires a **fresh WebAuthn (passkey) assertion over the request digest**, so the ledger
    records a non-repudiable approval tied to exactly that request.
  - "Narrow and approve" is one tap: one file instead of the directory, one use instead of standing access.
  - *PoC status:* implemented. The challenge is `sha256(nonce || canonical decision JSON)`; each record
    stores (clientDataJSON, authenticatorData, signature) and is re-verified by `wicket audit --verify`.
    Revoked passkeys keep their public keys for that check (`docs/poc-results.md`).
- **Auth and exposure:**
  - passkeys (WebAuthn) as the primary login, OIDC optional;
  - listens on localhost by default and is published through a tailnet or an authenticating reverse proxy,
    never bare on the internet;
  - **split trust:** `wicket-console` (HTTP, rendering, sessions) is an *untrusted* front end with no
    ledger write access. `wicketd` itself verifies every decision's WebAuthn assertion against the
    operator's registered key, with the challenge bound to the request digest. A compromised console can
    show wrong things but cannot mint grants.

  It is still the highest-value target after the proxies. Everything from the box renders as inert text: no
  markdown images or auto-links (image-URL exfiltration), bidi and invisible characters stripped, truncation
  shown, diffs in a sandboxed frame. Adding a passkey, operator or role needs step-up and is announced on the
  other devices. Bursts of approvals and approvals from new devices raise alerts. The audit log is
  append-only, hash-chained and exported off the box. A break-glass host CLI over `SO_PEERCRED` works with
  the console down. Push payloads carry no data by default. [09 §7.6]
- **Push notifications** for pending escalations, finished tasks and stalled agents, through Web Push or
  ntfy. When the operator already uses Claude Remote Control, they can also go through that session.
- **Multiple operators:** org policy says who may approve what (data class, risk). Two-person approval is
  an option for R4.

#### 14.1.4 Coexisting with vendor remote UIs (Claude Remote Control, Codex Remote Control)

**Facts** (Claude Code 2.1.319, [09 §1]):
- RC needs a **claude.ai subscription login**. It is disabled by API keys and auth tokens, by any
  non-Anthropic `ANTHROPIC_BASE_URL`, by `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, and in ZDR orgs. So it is
  **incompatible with wicket's default T1 launch** (§6).
- Under RC the whole SDK control protocol (user messages, `can_use_tool`, interrupts, mode changes) runs
  over `--sdk-url https://api.anthropic.com/v1/code/sessions/<id>`, with Anthropic's service as the SDK host.
  `--sdk-url` only accepts Anthropic hosts, so a wicket relay is impossible.
- No certificate pinning was found, so the TLS-intercepting egress proxy can see the channel.
- Documented hook points:
  - `CLAUDE_CODE_PROCESS_WRAPPER`, which wraps the session processes RC spawns;
  - the self-hosted environment runner's `--exec-path` (Team/Enterprise);
  - Channels (an MCP server pushing events into a session).

**Design: a per-zone `operator_mode`, checked by the zone compiler.**

- **`wicket` (default).** The T1 stdio launch from §6: LLM proxy, placeholder credential, wicket as the SDK
  host. Remote comfort comes from wicket's console (installable mobile web app) plus push over a tailnet.
  This is the comfortable default and the only mode for sensitive zones.
- **`vendor_rc` (opt-in, Claude Code only).** "Also watch and steer it in the Claude app." It adds a
  destination and an instruction ingress; it is a convenience, not a security feature.
  - *Bridge flavour* (Pro/Max, works on this box): `claude remote-control --spawn session` runs on the
    **host** under wicket's supervision, one bridge per zone. `CLAUDE_CODE_PROCESS_WRAPPER` points at
    `wicket-jail exec --zone <z>`, which builds the box and runs the session process inside it with
    stdin/stdout preserved.
  - *Self-hosted flavour* (Team/Enterprise): a self-hosted environment per trust class, with an on-demand
    runner whose `--exec-path` is the same wrapper. It also lets wicket *dispatch* a task that humans then
    watch in claude.ai.
  - Model route: no `ANTHROPIC_BASE_URL`. The LLM proxy's jobs (budget, liveness, server-tool taint) move to an
    `anthropic` adapter on the TLS-intercepted egress path.
  - Egress: `api.anthropic.com` is path-allowlisted to inference, this session's `worker/*` paths and the
    required flag and JWKS calls. Triggers, webhooks, channels, memory, other sessions, cross-session
    messaging and connector paths are all denied. SSE passes unbuffered.
  - In-box managed settings (cheap, advisory): refuse cross-session inbound messages, disable claude.ai
    connectors, deny rules mirroring the ceiling.
  - **The tap is observe-only:** the egress proxy parses the session stream leniently to mirror the
    transcript into wicket's console, detect RC-origin messages and feed the audit log. wicket never
    rewrites or injects frames: that is fragile against a private, near-daily-changing protocol, and likely
    against the terms. The one exception is **cutting the whole channel**, a kill switch that disconnects RC
    while the agent keeps running under wicket.
  - wicket → agent notices use the normal pending path (`await_grant` returns, retries succeed), or a wicket
    Channel once Channels allow it.
  - **Credential caveat:** in the bridge flavour the box likely holds the account-wide subscription
    credential. Until experiment E-RC2 shows the proxy can swap a placeholder for it, the zone view shows
    **"vendor credential in box"**, and the path allowlist is what keeps that credential from reaching account
    APIs. wicket never emulates Claude Code's OAuth login or refresh: the owner signs Claude Code in on the
    host.

**Codex** has an equivalent: Remote Control relayed through chatgpt.com, disabled by default in wicket's
`requirements.toml`. `vendor_rc{codex}` flips `allow_remote_control`, supplies ChatGPT access tokens via
`account/login/start {chatgptAuthTokens}` (refresh held on the host), and path-allowlists the remote-control
endpoints [11 §2.9]. So the mode is `vendor_rc{claude | codex}`, with the same rules. Approval answers that
would amend the agent's in-box policy are never forwarded, and `ChannelCaps` gains
`answers_are_policy_writes`.

**PoC results (2026-11-09).** Built as `wicket wrap` plus `examples/remote-control`:
- **The bridge runs on the host.** `CLAUDE_CODE_PROCESS_WRAPPER` puts each session process in a gVisor box,
  with its stdio connected through.
- **E-RC1: yes.** A session ran entirely through the egress proxy: the worker registered, the event
  stream (SSE) worked, model calls worked, and the owner chatted with it live from the Claude desktop app.
- **E-RC2: yes, with no account credential in the box.**
  - The box gets a placeholder `.credentials.json` (only the non-secret scope and subscription fields are
    copied) and a placeholder in place of the bridge's session token.
  - The egress proxy swaps each placeholder for the real value, in `Authorization` only and only toward
    `api.anthropic.com`. The login is read by reference, as in §6.
  - The bridge's messaging socket and its other host paths never enter the box.
- **E-RC3: a first allowlist from a real session.**
  - Allowed: `/v1/messages`, `/v1/messages/count_tokens`, `/v1/code/sessions/*/worker/**`, and four profile
    and bootstrap reads.
  - Forbidden (zone `forbid` rules): the account's connectors (`mcp-proxy.anthropic.com`, `/v1/mcp_servers`,
    `/mcp-registry/**`). Wrapped sessions also get wicket's gateway as their only MCP server.
- **Two layers of approval were visible in the app:** Claude Code's own prompt (advisory, in the box) and
  wicket's block (decided only in wicket).

**Experiments** [09 §9]:
- **E-RC1:** does a jailed RC session work through the egress proxy?
- **E-RC2:** can the box run without the account credential?
- **E-RC3:** what is the minimal path allowlist?
- **E-RC4:** does RC survive parking (freeze, checkpoint)?
- **E-RC5:** is the tap reliable across releases?
- **E-RC6:** the self-hosted flavour.
- **E-OP1:** red-team approval phishing against the console.

### 14.2 Showing humans the boundaries

- **The zone view** is generated from compiled zones, gates, live grants and the gateway's provider-side
  label store. Two zones that write to the same GitHub issue get an edge. Nested zones collapse by default
  to about 7 or fewer at the top.
- **The blast-radius query:** `wicket explain --compromised <zone>` returns
  - reach and send;
  - what can cross each outgoing gate on its behalf (capacity in bits for typed fields);
  - unmediated channels (SNI-only hosts, DNS on hosted backends, vendor remote UIs);
  - **authority, not just permission**: what provider-side `triggers` (CI on push, ChatOps, notifications)
    turn its allowed actions into (Miller's distinction) [06];
  - Cedar witness requests from symcc for "can X cause Y" questions.

  The zone compiler also refuses any zone with an uncontrolled channel to a destination not cleared for
  its `conf`, and every label raise is explicit and logged.
- **The timeline** of grant diffs, for example "fix gained `contents.write` on `ci.yml` at 14:02, granted
  by human, expires 14:12".
- **Everything untrusted shown to humans is sanitised:** ANSI and control characters stripped, bidi and
  invisible characters removed, URLs defanged, truncation shown. This applies in `wicket approve`, the
  console, the TUI and the timeline. Real cases include terminal-escape and exfiltration-link attacks on
  the screen a human reads [05, 06].
- **Audit log** in Tracekit's format: RFC 8785 canonical records, parsed strictly; salted HMAC commitments
  over arguments, so the log can be shared without content; a hash chain per task plus a global chain with
  checkpoints; OTel `gen_ai.*` export [08].
- **Reference-monitor invariants are tested** (Anderson: complete mediation, tamper-proof, verifiable):
  each is a conformance check, and `wicket-core` is developed verification-guided, with differential random
  testing against a reference model, as Cedar's team did [06].
- v1 is CLI text plus Graphviz/Mermaid export, with a TUI later. The brief's three-engineer test (zone view
  vs raw policy, five blast-radius questions) decides whether the abstraction is right.

---

## 15. Platform mode: multi-tenant agentic SaaS

*Owner requirement (2026-11-08): wicket is not only a developer tool. An agentic SaaS product must be able
to run on it as a platform, with strong multi-tenant support and isolation. Owner direction for now: build
single-tenant first, but leave room for multi-tenancy. Detail and prior art are in
[`research/14-multi-tenancy.md`](research/14-multi-tenancy.md).*

**The hierarchy gains two levels:** platform → tenant → org/workspace → task → zone.
- The **platform operator** (the SaaS company) defines **plans**. Each plan is a tenant ceiling: allowed
  providers and adapters, data classes, isolation floor, dedicated or shared capacity, quotas and money.
- **Tenant admins** can only *narrow* within their plan (delegated administration, proven like child ⊆
  parent).
- **End users** of the SaaS product trigger tasks. They connect their own accounts (GitHub, Google…), and
  they approve their own agents' escalations.

**Isolation is the default; sharing is an explicit, policy-governed exception** (owner, 2026-11-08).
Unless a cross-tenant gate says otherwise, tenants share nothing that can carry data or authority:

| Layer | Rule |
|---|---|
| Kernel | Every tenant workload runs under gVisor or a microVM. Tenants never share a kernel, so the `process` tier is excluded in platform mode. |
| Nodes and pools | Shared pools for low tiers, with host anti-affinity where the plan says so; dedicated pools or hosts for high tiers. KSM and cross-tenant memory dedup are off. |
| Warm pools and snapshots | Identity-less warm sandboxes may be shared, since they hold nothing. Snapshot templates that contain tenant data are per tenant. A claimed sandbox is never reused. |
| Credentials | The vault is partitioned by tenant, with per-tenant encryption keys (BYOK for high tiers). End-user OAuth tokens are held per (tenant, user), used only by that user's tasks, and consented per connection. |
| Labels and handles | Data classes are namespaced per tenant. Handles and label stores never resolve across tenants. |
| MCP servers | Instances are per task, so never shared across tenants; third-party server images are pinned per tenant's approval. |
| LLM proxy | Per-tenant keys or BYOK, spend caps and rate limits. Prompt caching is scoped per tenant, so a cache can't leak across tenants. |
| Egress | Per-tenant CA. Optional per-tenant static egress IPs, which enterprise customers allowlist. |
| Ledger and audit | Partitioned per tenant, with per-tenant export, retention and erasure. |
| Control plane | Every API call is tenant-scoped; control-plane authorization is itself policy (Cedar), with platform-admin, tenant-admin and end-user roles. |

**Cross-tenant sharing goes through cross-tenant gates.** A tenant gate is the zone gate lifted one
level, with stricter rules:
- **Bilateral consent.** It needs both tenants' admins *and* platform policy (does the plan allow sharing
  of this kind, with tenants of that kind?). It is time-bounded, revocable by either side, and recorded in
  both tenants' ledgers.
- **What it can carry:**
  - **data:** handles and typed fields, relabelled into the receiver's label namespace by an explicit
    declassification;
  - **published artifacts:** manifest templates, adapters, skills, MCP server images. These are read-only,
    pinned by digest, and reviewed by the receiver before use; artifacts count as taint like any
    third-party description.
  - **service calls:** tenant A operates an MCP service or agent that B's agents call through the gateway.
    It runs in A's server zone with A's credentials, carries B's caller label, and bills to whoever the
    gate names.
  - **shared zones:** a joint workspace both tenants' agents work in. Its ceiling must be ⊆ what *both*
    tenants granted it, and its data carries both tenants' data classes.
  - **delegation:** B grants A's agent a narrow capability on B's resources. It is an ordinary grant held
    in B's ledger, with a confused-deputy defence like AWS's external ID.
  - **capacity:** opt-in shared pools, by plan.
- **The same machinery as everything else.** Typed fields and handles only, label rules, sink provenance,
  the per-call decision. A gate never shares credentials, ledgers or keys themselves: shared data is
  re-encrypted under the receiver's key, or under a key the gate holds.
- **Both sides see it.** Each tenant's `explain` and blast-radius views show its tenant gates as edges:
  what the other tenant can reach or receive through them.
- **Erasure and residency still apply.** Shared copies follow the sharer's residency rules unless the
  gate says otherwise. When a tenant leaves or revokes, the receiver's derived copies are deleted or kept
  according to what the gate specified at consent time.

**Refinements from research 14** ([`research/14-multi-tenancy.md`](research/14-multi-tenancy.md)):
- **One code path from day one.** `TenantId` is in every id, store key, label class and audit chain from M0.
  Single-tenant mode is tenant `t0`; the PoC already works this way. The authority check becomes
  platform ∧ plan ∧ tenant ∧ workspace ∧ zones ∧ grant ∧ labels ∧ ledger, and tenant admins can only narrow.
  The prover checks that on save, and evaluation enforces it anyway.
- **Pooled nodes hold no credentials.** On nodes that run several tenants' code, sandbox nodes run a plain
  forwarder and hold no tokens, CA keys or model keys. Per-tenant enforcement runs on separate enforcement
  nodes, which also own each tenant's static egress IPs. The PoC's remote node already has this shape: its
  sockets are forwarded to proxies on the control host.
- **End-user credentials** are keyed by (tenant, user, provider, connection). Consent is per purpose, on a
  wicket-owned connect page that checks the consenting user is the one who started the request. Tokens are
  minted at the narrowest scope per task and wrapped by tenant keys (BYOK for high tiers).
- **Approvals inside the product** use an embeddable passkey approval served from wicket's own domain. The
  SaaS backend can start tasks but can't approve anything above R2.
- **Model keys per tenant:** an Anthropic workspace or OpenAI project each. Through a shared one, tenants
  share a prompt cache and can probe each other's prompts by timing. Self-hosted models get a per-tenant
  cache salt. Anthropic's default limit of 100 workspaces per organization needs raising for large
  platforms.
- **Sharing by owner label.** Data labels name an owner tenant. A share needs both tenants' admins and the
  target's opt-in in its own ledger, and works by reference. Revocation takes effect on the next request,
  every share expires, and shared data keeps its owner's label: B can use A's data but can't send it where A
  didn't allow.
- **Isolation tiers by plan:**

  | Tier | What it adds |
  |---|---|
  | Pooled | gVisor on shared nodes, at most K tenants per node, credentials only on enforcement nodes |
  | PooledHardened | A proxy process per tenant, dedicated CPU cores, dedicated egress IPs |
  | Dedicated | Reserved node pools, microVMs, a per-tenant key |
  | Silo/BYOC | The tenant's own deployment or cloud account |

  Never shared by any policy: vault credentials, prompt caches, memory dedup, running MCP server instances.
- **Open risks:**
  - the extra network hop to enforcement nodes;
  - who vouches for end-user identity unless the tenant federates its login provider;
  - cache side channels below the Dedicated tier;
  - passkeys inside iframes;
  - whether crypto-shredding counts as GDPR erasure (needs legal sign-off).

  Research 14 lists 23 cross-tenant tests and milestones T0–T9; T0 (tenant ids everywhere) ships with M0.

**Embedding.** The SaaS backend drives wicket through a tenant-scoped API: start a task for tenant T and
user U from a manifest template; receive webhooks for state, pending escalations and results. End users
approve escalations **inside the SaaS product**, through an embeddable approval component and API. It is
CIBA-shaped, carries the same typed request and binding code, and needs a passkey or the product's own
step-up. White-labelling is supported.

**Noisy neighbours and money.** Per-tenant quotas (concurrent sandboxes, tokens, compute seconds,
egress), fair-share scheduling, and metering records for cost attribution, so the SaaS can bill its
customers.

**Blast radius.** `wicket explain` gains a tenant view: what one tenant's compromise can reach (nothing of
another tenant's, by construction), and what a compromised node or control-plane component exposes (only
the tenants scheduled on it, and only their short-lived credentials).

---

## 16. Mandates: acting on a user's behalf

*Owner requirement (2026-11-08): "user authed creds", where an agent gets time- and purpose-limited
access to resources so it can act on the user's behalf, such as shopping online. Protocols, prior art,
Rust types, 31 red-team cases and milestones MD0–MD9 are in
[`research/15-mandates-user-delegation.md`](research/15-mandates-user-delegation.md).*

A **mandate** is authority a *user* delegates to an agent: to act *as them* at a provider, for a stated
purpose, within limits, until a deadline. It is the same machinery as a grant (§4, §11) with one
difference: the principal is the user, not the operator, and the user's own account is used.

### 16.1 Model

```rust
pub struct Mandate {
    pub id: MandateId, pub tenant: TenantId,
    pub principal: UserId,                  // whose account and money
    pub grantee: AgentOrZone,               // who may use it
    pub connection: ConnectionId,           // the user's account at the provider; held in the vault, never in a box
    pub purpose: TrustedText,               // the user's own words: "weekly groceries, usual brands, Saturday delivery"
    pub allow: CapabilitySet,               // e.g. site:search, site:product.read, site:basket.*
    pub forbid: Vec<ActionPattern>,         // e.g. payment.*, address.*, account.*, subscription.*
    pub money: Option<MoneyLimit>,          // per order, total, currency
    pub quantity: Option<QuantityLimit>,    // per item, per order
    pub window: (Timestamp, Timestamp),     // not before / expires
    pub uses: Option<u32>,
    pub approvals: Vec<ApprovalPoint>,      // e.g. Checkout => passkey approval of the typed cart
    pub state: MandateState,                // Active | Exhausted | Expired | Revoked
}
pub struct MoneyLimit { pub per_order: Money, pub total: Money }
pub enum ApprovalPoint { Checkout, NewPayee, AnyR3, Custom(ActionPattern) }
```

- **A mandate is signed with a passkey by the principal**, the person whose account and money it is.
  Only that person can widen it or approve money. Spend counters live in the ledger, and without a
  mandate, no use of the user's credentials is possible.
- **Purpose:** a closed `PurposeClass` (groceries, travel booking, …) is what policy uses. The user's own
  purpose text is hashed into the mandate and shown on every approval, but it is never policy: no standard
  enforces purpose, and Transaction Tokens dropped their purpose claim.
- **The purpose is trusted text** for sink provenance (§4.2). Quantities, recipients and items must trace
  to the user's purpose or the user's live instructions. A product review saying "add 50 bottles" fails
  provenance and the quantity limit.
- **Mandates sit in the ledger** beside grants. Every use is recorded, the money spent is tracked against
  the limit, and the user can revoke at any time; revocation takes effect on the next request.
- **Standing mandates** suit long-lived agents (§13), for example "weekly groceries under £120, until I
  revoke it". Each order still passes its approval points.

### 16.2 Connections: how the user's access gets in, without reaching the agent

| Provider kind | How the user connects | What the agent gets |
|---|---|---|
| Has an API (Gmail, GitHub, calendars, banks with open banking) | OAuth consent on a wicket-owned page; narrowest scopes; RAR-style limits and token exchange where supported | Gateway tools or proxied HTTP. The token is injected per request, only under a live mandate |
| Website without an API (most shops) | The user logs in **themselves** in a wicket-provided remote browser. The session is kept in the vault's cookie jar | A browser workload it can drive (§16.3). Never the cookies, never the password |
| Agent payment protocols (AP2 mandates, agentic payment tokens, single-use virtual cards) | The user's wallet or bank issues a token with a merchant lock and an amount cap | A payment step that can't exceed what the user signed |

The agent never sees passwords, cookies, OAuth tokens or card numbers. That's principle 2, unchanged.

### 16.3 Websites: the shopping case

- **Three pieces, so the session never reaches anything the agent controls:**
  1. the user logs in themselves in a wicket-provided remote browser, and the session cookies go to the
     vault;
  2. the agent drives a separate, sandboxed browser that holds **no** session;
  3. the egress proxy injects the cookies only into requests that the mandate allows for that site, and
     captures any `Set-Cookie` back into the vault.

  A device-bound session (Chrome DBSC) would break step 3; no UK grocer uses one yet.
- **Site adapters** classify actions by risk, from URL and form-action patterns and page structure:
  - browsing and search: R0;
  - basket add and remove: R2, within the money and quantity limits;
  - checkout, placing an order, payment, delivery address, account and subscription changes: R4 with the
    `money` or `perm.manage` effect. These are always approval points, and are forbidden outright unless
    the mandate allows them.
- **"Never pay without the human" is seven layers, not one check:**
  1. Payment, wallet and 3-D Secure hosts are denied at egress.
  2. The site adapter makes checkout endpoints approval points, and unknown POSTs wait for review.
  3. A checkout-page detector freezes the session.
  4. The cart is locked. The user's passkey signs a **typed cart that wicket read itself** (items,
     quantities, unit prices, total, delivery slot, address, card last four). It is re-read just before the
     one allowed submit; any change voids the approval.
  5. The final charge is reconciled after delivery. At UK grocers checkout commits the order but the charge
     comes later, and substitutions and weighed items change it.
  6. The user can take over and press Pay themselves.
  7. Optionally, a capped virtual card or a bank-side limit.

  This is the rule this box already follows by hand: build the basket, notify the owner, wait.
- **Payment protocols** are used where available, but none of the live rails checks *what* is bought, so
  layers 1–6 stay:
  - AP2 v0.2 and Mastercard Verifiable Intent have user-signed, line-item constraints but few live
    merchants;
  - Visa Intelligent Commerce has been live with UK issuers since July 2026, using passkeys;
  - ACP and Stripe Shared Payment Tokens cap amount, merchant and expiry, but the user signs nothing.
- **Wire shapes:** RFC 9396 authorization details plus the `insufficient_authorization` remediation draft;
  Open Banking VRP control parameters for money limits; CIBA for approval delivery; ISO 27560 consent
  receipts.
- **Known risks:**
  - injected or manipulated items that stay within limits (dark patterns steer agents in over 70% of tasks);
  - address or card swaps, vouchers and loyalty points;
  - leaks of order history and other personal data;
  - sites that block agents (Tesco and Asda blocked ChatGPT agent);
  - terms that make the user liable for every order on their account (Ocado);
  - approval fatigue on weekly shops.

### 16.4 Lifecycle and UX

- **Grant:** a consent screen shows the purpose in the user's own words, the scope, the limits, the expiry
  and the approval points.
- **While it runs:** live view and receipts. After each action that matters (basket changed, order placed)
  the user gets a short receipt.
- **Revoke** at any time, from the console or a push notification. **Expiry** is automatic.
- **In platform mode,** a SaaS product's end users grant mandates inside the product through an embeddable
  consent and approval flow (§15). Tenant policy caps what mandates may allow at all.

---

## 17. Programs: deterministic workloads without an agent

*Owner requirement (2026-11-08): wicket also runs ordinary, deterministic workloads. An agent might write
a reusable program; running it again shouldn't need an agent each time, but it must get the same isolation.*

A **program** is code plus a run contract:
- **Code:** a source tree, content-addressed by digest; the digest is the program's identity.
- **Runtime:** a pinned image, plus a lockfile where relevant.
- **Entrypoint and typed I/O:** inputs as handles or typed fields; outputs in the outbox, as typed fields plus
  labelled handles.
- **Declared reach:** the hosts and adapter endpoints it needs, closed-world.
- **Labels:** inherited from how it was made (below).

```rust
pub struct Program {
    pub id: ProgramId, pub tenant: TenantId,
    pub digest: Digest,                     // of the source tree: the identity a run pins
    pub runtime: ImageRef,                  // pinned by digest
    pub entrypoint: Vec<String>,
    pub inputs: Schema, pub outputs: Schema,
    pub reach: CapabilitySet,               // closed-world; effective reach = this ∩ the zone's ceiling
    pub label: Label,                       // join of its author's label at the time it was written
    pub provenance: Provenance,             // written by (agent, run) or a human; reviewed by whom
    pub state: ProgramState,                // Draft | Approved{by, signature} | Retired
}
```

**From agent output to approved program.** Code an agent writes is untrusted code, carrying the agent's
taint, so it goes through a **promotion gate**, the same idea as memory promotion (§13.4):
1. The agent emits a program as a handle: source, entrypoint and the reach it claims to need.
2. A human (or, for low-risk programs, an automated check) reviews the diff and the claimed reach, and
   approves it with a passkey signature over the program's digest (§14.1).
3. Only an approved digest can run without an agent. Any change, even one line, is a new digest and needs
   a new approval. A new version that asks for *more* reach is a policy change and needs a decision.

**Running a program** is a workload like any other (§8.1, kind `Program`):
- **Same sandbox, isolation floor, placement and budgets as an agent zone.** There's no LLM proxy socket,
  because there's no model. The egress proxy, credential injection, reach rules, dangerous patterns and
  ledger are unchanged.
- **Escalation without an agent:** a program can't reason about a pending request. Each run says what
  happens: `on_pending: fail` (the default for scheduled runs), `park` until a human decides (the run is
  frozen or checkpointed, §7), or `fail_and_notify`.
- **Triggers:** on demand (a human, the CLI or API), a schedule, an event subscription, or **an agent calling
  it as a tool** through the gateway (`wicket.run_program(name, inputs)`). In that last case the agent gets
  typed outputs and handles back, and never the program's credentials.
- **Determinism and provenance:** pinned image, pinned dependencies, declared network only, inputs passed as
  handles. Every run records (program digest, image digest, input digests, output digests, every egress
  decision), so a result can be traced and re-run.
- **Labels:** outputs carry the join of the program's label, its inputs' labels and whatever it fetched. A
  program an agent wrote while tainted by the web stays tainted until a human's review endorses it.
- **Cheaper than an agent:** no model, no agent start-up. Pure functions can run in the Wasm codemode tier
  in milliseconds (§7.1).

**Verifier zones** [17 §4-5]. Harness search (ADAS, Darwin Gödel Machine, Meta-Harness) and agent-written
programs are natural wicket workloads, and every one of those systems assumes an honest scorer. The evidence
says otherwise: agents game checkers they can see. So the proposer zone emits a candidate as a handle; a
runner zone executes it with only the LLM proxy; a verifier zone that the proposer cannot read scores it and
returns a typed, low-capacity score across the gate. A winning candidate is promoted through the signed
program promotion above.

---

## 18. Crate layout

```
wicket/
  crates/
    wicket-core        types: ids, Resource/Capability algebra, Label, Zone, Gate, Handle, Op, Decision. No I/O.
    wicket-policy      Cedar compilation of org/zone/forbids; decide(Op) -> Decision; ledger trait
    wicket-verify      cedar-policy-symcc + cvc5 sidecar: subset/narrowing/disjointness proofs (feature-gated)
    wicket-adapter     DSL schema, parser, interpreter, canonicalizer, dangerous patterns, resolvers
    wicket-store       ledger, grants, handles, labels, provider label store, audit log (SQLite + replication; Postgres in cluster mode); agent registry, memory versions, object-storage blobs with per-agent keys
    wicket-escalation  request validation/narrowing/classification, deciders, human channel
    wicket-egress      rama MITM proxy, per-box CA, credential injection, decider protocol
    wicket-git         smart-HTTP receive-pack store-and-forward
    wicket-llm         LLM proxy: Anthropic first, OpenAI later; budgets, liveness, taint
    wicket-gateway     rmcp MCP gateway: adapter-generated tools, wicket.* tools, third-party pinning
    wicket-sandbox     Sandbox/Instance traits + backends behind features (docker (dev), process, gvisor, firecracker, seatbelt, e2b, wasm, k8s-agent-sandbox)
    wicket-jail        privileged helper binary for the process backend
    wicket-agent       InnerAgent/AgentSession traits; T1: claude-code, codex (app-server; types generated from its pinned JSON schema), pi (RPC); T2: acp; T3: process
    wicket-view        zone graph, blast-radius, timeline
    wicket-infra       placement vocabulary, compiler + verifier, BillingModel, leases, Reconciler/Store traits
    wicket-operator    kube-rs operator: NodePool/Workload/WarmPool CRDs, admission, reservation pods, Cilium policy
    wicket-node        per-node agent: direct launch, warm pools, parking, local enforcement, per-workload credentials
    wicket-provisioner HostProvider impls (local, vultr/broker, aws, gcp, hetzner, …); the only holder of cloud credentials
    wicket-channels    event log projections, OperatorChannel trait, WebAuthn decision verification, push, RC bridge supervision + tap
    wicket-lifecycle   agent registry state machine, wake sources, hibernation, promotion gate, retention and GC
    wicket-guest       static PID 1 shim inside microVMs (exec, IO, diff, vsock proxy shim)
    wicket-bench       startup, memory and density measurements per backend
    wicket-mandate     mandates: model, consent, connections (OAuth, browser sessions), money/quantity limits, approval points
    wicket-program     program registry: digests, promotion and approval, run contracts, on_pending policy
    wicket-browser     browser workload: a sandboxed headless browser holding a user's session, driven via gateway tools; site adapters
    wicket-console     untrusted web front end (mobile-first PWA) over wicketd's API; no ledger write access, no creds
    wicketd            daemon wiring it together
    wicket-cli         `wicket run | explain | approve | ls | logs`
  adapters/            github-rest.yaml, github-git.yaml, anthropic.yaml, dangerous/github.yaml
  agents/pi/wicket-ext/  tiny in-box pi extension (TypeScript; advisory; hash-pinned in the image)
  third_party/         vendored files with NOTICE (Codex proxy_routing/seccomp/authorization_path/process-hardening, sandstorm runsc parking, smokescreen classifier port)
  tasks/               example manifests
  docs/
```

Dependency rule: `wicket-core` depends on nothing internal. Enforcement crates depend on `core`, `policy`,
`adapter` and `store` only. Nothing in the TCB depends on `wicket-agent`.

---

## 19. Milestones

Each milestone ends with the smallest test that could prove it wrong. From M1 on, every milestone also has to stay within the §7.1 budgets for what it adds.

| # | Milestone | Done when |
|---|---|---|
| **M0** | Workspace, `wicket-core` with the capability algebra and labels | Property tests: `is_subset_of` is a partial order; grant ⊆ ask; label join is monotone. Cedar compile round-trips. |
| **M1** | `process` backend + `wicket-jail`; egress proxy with an allowlist; LLM proxy for Anthropic; `wicket-bench` skeleton | **Claude Code runs a real task in the box holding only a placeholder.** Conformance checks 1–2 pass. All attempted connections over a 30-minute session are logged ([01 E3]). Test whether Claude Code survives a connection reset. Box setup overhead stays under 100 ms and 20 MB beyond Claude Code itself. Every hardening layer is confirmed or the jail refuses to start; the DNS-canary and placeholder-reflection checks pass (release gates from here on). |
| **M2** | Adapter interpreter + ~15 GitHub REST endpoints + git push S&F; per-task GitHub App tokens | The [04 §4.7] matrix runs green in a test org. The red-team agent, scoped to one repo and one directory, finds ≤3 escapes, and each escape becomes a rule. |
| **M3** | Escalation broker (auto + human tiers), ledger (epochs, atomic single-use, fresh-per-use), `wicket approve`, recoverable problem+json / MCP pending | **E1:** 20 tasks × {bare 403, structured pending with remedies, `await_grant` tool} × {Claude Code, Codex app-server, pi × {Claude, GPT, an open-weights model}, Gemini CLI}. Measure wait/retry vs route-around vs give-up, and retry loops. Running pi with several models separates model behaviour from harness behaviour. This decides how much the escalation UX can rely on HTTP, versus T1/T2 permission channels. |
| **M3b** | Operator channels: wicketd event log + API, `wicket` CLI, `wicket-console` PWA (transcript, steer, typed `AmendTask`, pause/kill, escalation queue with passkey approvals verified in wicketd), push; then `vendor_rc` bridge flavour (E-RC1–5) | From a phone, an operator can run a task end to end in wicket's console: watch, steer, amend, approve, kill. In a `vendor_rc` zone the same task is also watchable and steerable in the Claude app, its messages appear in wicket's console with an RC badge, and an RC 'allow' creates no grant. The RC kill switch disconnects RC while the agent keeps running. The E-OP1 phishing red-team yields no wrong approvals. |
| **M3c** | Codex (app-server) and pi (RPC) T1 adapters | Both pass conformance checks 1–13 and experiments E-CX1–3, E-PI1–2. |
| **M4** | MCP gateway with adapter-generated tools | An MCP call and a `gh api` call to each endpoint get identical decisions (differential test). |
| **M4b** | Isolated MCP servers as per-task workloads (§8.2): `wicket-node` direct launch with unbound warm pools (I1); then `wicket-operator` on single-node k3s with reservation pods, Cilium default-deny and gVisor RuntimeClass (I3) | Two third-party MCP servers and the agent each run in their own sandbox. Probing from inside each shows neither server can reach the other, the agent, the API server, the metadata service or DNS, except through the gateway. A pod without a sandboxed RuntimeClass, or a hand-edited CR, is rejected. A changed tool description is refused. State is gone at task end. The same probes pass in single-host mode. A per-task MCP server from the warm pool is `tools/list`-ready within 250 ms, and twenty concurrent instances fit the density budget on one node. |
| **M5** | Handles (including handles as tool arguments), per-argument sink provenance, labels, typed-only gates, two-zone static topology | **The brief's smuggling test**, built as a GitHub-coding suite in AgentDojo's format: a test-org repo, injection slots in issue comments, docs pages and `CLAUDE.md`, deterministic checks on provider state, and an **adaptive attacker** that sees the policy and denial bodies. Free text vs typed vs handles. Report attack success *and* utility over 3 runs, and require a non-zero baseline attack rate before crediting a defence. If typed already gives zero, handles are optional in v1. |
| **M6** | `wicket explain` + zone view + timeline | The three-engineer test. |
| **M7** | Agent lifecycle (§13): agent registry, Active → Idle → Sleeping → Hibernated → Archived → Deleted, gVisor checkpoint, push to object storage (a local directory or Garage/SeaweedFS locally), rebuild path, wake sources (message, schedule, event), memory staging and promotion gate, retention and GC with crypto-shredding | An agent works, sleeps, hibernates to MinIO, and is woken a day later by a schedule. Its node is killed while it's active, and it rebuilds elsewhere from the last checkpoint within the RPO. A skill it wrote is staged, reviewed and only then visible to its next activation; rolling back the memory version removes it. GC deletes an agent after its grace period, and its blobs are unreadable while the audit chain still verifies. Every transition stays within the §13.8 budgets. |
| **M8** | Adapter generator loop | Generated vs hand-written GitHub adapters diffed. Zero too-permissive rules, or find which check missed it. |
| **M9** | ACP (T2) adapter; `wicket.spawn` dynamic topology | Conformance suite passes for one ACP agent. Child ⊆ parent is enforced by the capability algebra, which is tested against SymCC's segment model in CI. |
| **M10** | Many clouds: provisioner with the Vultr (via broker) and AWS or GCP providers, WireGuard + mTLS node join, a KVM pool with Kata/Firecracker, money envelope + human approval for spend, `request_capacity` | One installation spans two providers. An agent's `request_capacity{kvm}` gets a Firecracker sandbox on a newly created per-second-billed host inside the envelope. A Vultr host is released before its next paid hour. Killing the provisioner mid-create leaks nothing, and the daily reconcile matches every provider's charges to the cent. |
| **M11** | Mandates (research 15, MD0–MD9): passkey-signed mandates in the ledger, consent screen, connections (OAuth via a wicket page; websites via a remote browser the user logs into), a session-less agent browser with cookies injected at egress, a site adapter, the seven-layer checkout guard | **Demo:** Claude Code builds an Ocado basket under a 48-hour, £120 mandate. Every step past the basket stays pending, no Ocado cookie reaches the box, and no order is placed. The approve-and-submit path is proven on a local fake shop (`wicket-mart`): a price change after approval voids it, and an injected \"add 50\" is refused. |
| **M12** | Programs: program manifests, source digests, pinned runs without an agent, `on_pending` policy; then promotion from an agent's output with a passkey-signed approval, and `wicket.run_program` as a gateway tool | A program an agent wrote is approved by digest, then runs on a schedule with no model in the loop. A one-line change is refused until re-approved. A request outside its reach fails the run (or parks it), and outputs carry the author's taint. |
| later | Firecracker (on bare metal via the broker), seatbelt, e2b, wasm codemode; parent tier on, once its shadow decisions are measured | |

M1 is deliberately first: until Claude Code runs usefully with no credentials and no direct network, none
of the rest matters.

---

## 20. Decisions taken in this draft

| Decision | Why | Revisit if |
|---|---|---|
| Cedar for authored policy + an own capability algebra for grants | Analysable (SymCC in CI), explains decisions, fast; grants need a cheap syntactic subset check. Experiment #58: SymCC handles realistic org policy diffs in 0–9 ms, but gives `unknown` on some zone globs, so it stays out of the spawn path | Cedar's analysis can decide segment-wise globs quickly and completely |
| Authority in the Biscuit format, checked by a vendored `biscuit-auth` (upstream main plus three patches), with a structural check before loading and a differential test against the stock engine in CI; use counts stay in the ledger | Narrowing, offline attenuation, third-party approvals and subtree revocation come with the format, which outside parties can verify. The patches take a depth-5 request from about 1 ms to 7–11 µs, deterministically (#59, biscuit-fast) | Upstream takes patches 1 and 2 (then only patch 3 is ours), or the fork's upkeep outweighs it (fall back to plain signed records with the same semantics, measured at under 1 µs) |
| `rama` 0.4 parts (rustls termination assembled ourselves) behind the `srt` decider seam | Rust, composable, swappable; no ready rustls MITM relay exists anywhere | rama churn hurts → hyper + tokio-rustls |
| `rmcp` gateway, not agentgateway | agentgateway isn't embeddable (`publish=false`). Its argument rules (CEL guardrails), like ToolHive's and ContextForge's, see raw arguments rather than adapter-bound typed resources. It also passes client headers through by default and runs stdio servers unsandboxed | — |
| Process jail for development; **gVisor as the floor for valuable zones and all third-party servers**; microVMs later | No KVM here; containers and process jails share the host kernel, and models escape misconfigured ones (SandboxEscapeBench); gVisor gives checkpoint/restore without KVM | Bare-metal dev box available |
| Speak Claude Code's stream-json control protocol directly from Rust | No Rust Agent SDK; the protocol is what the SDKs use | Anthropic publishes a spec or Rust SDK |
| Claude subscription token (`claude setup-token`) injected by the LLM proxy; never an Anthropic API key | Owner's rule; the credential still never enters the box | — |
| Subscription tokens only for the unmodified Claude Code binary, in single-owner mode; never for other inner agents, never brokered in platform mode | Anthropic's legal and compliance page; owner: "whatever Anthropic say is ok" | §6 |
| YAML-subset adapter DSL | Diffable by humans and LLMs; JSON canonical form for signing | — |
| Hybrid substrate: Kubernetes for capacity, pools and services; `wicket-node` direct launch for sandboxes and per-task MCP instances; CRDs are desired state, the ledger is authority | Don't rebuild scheduling, autoscaling and GC. But the pod path is 1–2 orders of magnitude too slow for the hot path and can't park |  Kubernetes' TCB or footprint proves unacceptable for hostile workloads → own small reconciler behind the same `Sandbox` trait |
| Enforcement evaluates the whole chain; subset checks only for admission and explanation | A subset-check bug then costs usability, never authority (Fly macaroons) | — |
| Never forward client headers; rebuild upstream requests from the `Op`; swap placeholders only in their declared slot | Every surveyed gateway that forwarded headers or substituted in bodies leaked or reflected credentials | — |
| Codex via app-server (T1), pi via RPC (T1); ACP is the fallback | Native protocols carry host approvals, steering, typed output and resume that ACP drops | — |
| No third-party LLM library in the TCB; a Rust `Model` trait over wicket-llm | pi-ai etc. are Node plus vendor SDKs; borrow the design, not the code | — |
| Agent config locked down by managed files where they exist (Claude managed settings, Codex `requirements.toml`), by ownership plus flags where they don't (pi) | Repo-supplied config is the cheapest injection path | — |
| Long-lived agents by default: durable identity, activations, work items, lifecycle tiers, policy GC | The owner's model; rebuild-from-durable-state always works, so snapshots are only an optimisation; sleep doubles as a declassification checkpoint | — |
| Parent (LLM) decider tier off at first | It's an LLM in the TCB; DRIFT's ablation shows LLM-widened policy roughly doubles attack success; measure it in shadow mode first | Shadow decisions agree with humans ≥ an agreed rate |

## 21. Open questions

1. **Agent behaviour under denial** (E1), the biggest unknown. If agents route around HTTP denials, the
   escalation UX has to live in the T1/T2 permission channels, and T3 agents get a degraded experience.
2. **Utility cost of taint.** Does a coding agent that reads one issue comment become useless for
   pushing? The per-argument stance, handles as arguments, forking at the last clean entry and disposable
   tainted children are the planned answers. M5 measures them.
3. **Claude Code specifics to test:**
   - Does a placeholder key plus proxy injection work end to end?
   - Does it survive connection resets after a snapshot?
   - Does `--bare` suppress managed-settings hooks?
   - Does `--setting-sources ""` behave as expected?
   - Which `api.anthropic.com` calls bypass `ANTHROPIC_BASE_URL` (fast-mode check, feature flags)?
4. **Where the parent-tier "re-derivation" gets its trusted text for dynamic spawns:** the chain of
   labelled task texts (§5.1) is proposed but not validated.
5. **Vultr bare-metal billing:** the API says monthly ($185) and the docs say hourly ($0.25). Settle it
   before buying.
6. **GraphQL:** deny entirely in v1, or allow a persisted-query allowlist? (Proposed: deny.)
7. **Owner decisions for infrastructure** [10 §13]:
   - An AWS or GCP account for minute-billed KVM, or the Mac (is it an M3 or later)?
   - May k3s run on the control host on demand? The host's operator has to agree.
   - Should wicket's Vultr usage share the provisioning broker's $20 cap, or get its own line?
8. **The proposer's view:** what does the strict "nothing fetched" default cost in utility, and which
   labelled context (repo file names, the tree) buys most of it back safely?
9. **`vendor_rc` credentials:** can the proxy swap a placeholder for the vendor session credential
   (E-RC2), or does `vendor_rc` always mean "vendor credential in the box"?
10. **`Placement::Split` before v1?** Codex `exec-server` is experimental; pi's remote tool operations and
    Claude Managed Agents are alternatives. Split is a durability and latency choice, not a security one: the
    loop reads every tool result, so it is as tainted as the box, and moving it out helps only if its host
    also holds no credentials and its egress also goes through the proxies [17 §4-9].
11. **Agent context files in untrusted refs:** removing them is safe but may break legitimate project
    conventions. Should they be exposed as handles, summarised by a quarantined reader, or simply dropped?
    Proposal [17 §4-6]: the dominant 2026 practice keeps the harness in the repo (AGENTS.md, progress files),
    so for trusted refs a task's context files are part of its declared harness and pass through; an agent's
    own progress files pass the §13.4 promotion gate as its memory; for untrusted refs they become handles.
12. **Node transport: SSH for now, explore others** (owner, 2026-11-08: "ssh is fine for now but keep a
    note about exploring other protocols"). SSH (`ssh -R` per run) is not resumable:
    - one TCP connection carries the forwarded sockets and the event stream, and a drop kills the run's
      route out;
    - it has head-of-line blocking, trust-on-first-use host keys, and needs an inbound sshd.

    To explore: the node dials out over QUIC (`quinn`) with mTLS node certificates from the issuer
    (§3.2). That gives independent streams, connection migration and fast reconnect. On top of it goes a
    numbered, acknowledged control and event stream that resumes from the last acknowledged position.
    Proxied requests fail retryably instead of resuming, and pending approvals live in the ledger, so
    they survive drops. Alternatives: WireGuard plus HTTP/2 (gRPC), or WebSocket.
13. **wicket working on wicket** (owner, 2026-11-09: "iterate on wicket from inside wicket"; wicket stays
    general, with nothing development-specific built in). `examples/self-hosting/` is one project describing
    its own workload: the image, the reach, volumes for its caches, and allowlisted adapter settings.
    It works for building, unit tests and commits, with pushes and pull requests waiting for a human.
    Open:
    - Running wicket's own end-to-end tests from inside needs Docker and gVisor in the box. The host's
      Docker socket would be an escape, so this needs a throwaway node per test run, started as a program
      or tool (§17).
    - A push is two approvals today: the push discovery and the push itself. A grant scoped to one push
      would make it one.
    - Steering from a phone needs the console reachable (§14.1).
14. **Name.** "wicket" is a working name (the small door set into a larger gate).
