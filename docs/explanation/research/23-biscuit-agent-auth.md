# 23 — Agent-authorization projects built on Biscuit

Research date: 2026-11-11. Prompted by the owner after wicket chose the Biscuit format for delegated
authority (design, "Identity is JWT; authority is Biscuit"; research [18]; #76). The question: who else
uses Biscuit to authorize AI agents, MCP calls, or agent and workload delegation, what did they build, and
what should wicket borrow, avoid, or reuse?

Method:
- Triage of all 53 crates on crates.io that depend on `biscuit-auth` (its reverse dependencies, 2026-11-11).
- Shallow clones of the repositories of the agent-related ones; the Biscuit code was read, not built or run.
- A web and GitHub search (code and repository search) for projects in other languages, IETF drafts,
  papers, and statements by Biscuit's maintainers. The main hits were cloned and their Biscuit code read.

Confidence tags, as in [18]:
- **[H]** read in source or primary docs in this session;
- **[M]** from READMEs, blogs or design docs, or from the Biscuit spec without a re-run here;
- **[L]** inferred.

Repository figures come from the GitHub and crates.io APIs on 2026-11-11. "Commits in 3 months" counts
commits on the default branch since 2026-08-11, capped at 100 by the API.

---

## 0. Summary: the seven things that matter

1. **One serious project, a few credible ones, and a long tail.** Every agent-focused Biscuit project
   started in 2024–2026.
   - **Google's Agent Mesh** stands apart: 1.2k stars, 10 regular contributors, v0.2.0 on 2026-11-02.
     Every mesh credential is a Biscuit, checked by every node on every connection. [H]
   - Credible but small:
     - **Heddle**, a version-control product for humans and agents;
     - **CPEX**, IBM Research's policy runtime for agents, with one Biscuit plugin;
     - **TokenCrumb**, an MCP proxy;
     - **AgentCreds**, the most complete agent-delegation SDK;
     - **Hessra**, an open-core capability service;
     - the **AIP** IETF individual draft, which defines a Biscuit encoding with an MCP binding.
   - The rest (about 20 repositories) are hackathon demos, prototypes with one author, or empty.

   Nothing except Agent Mesh has visible outside users. None has had an outside security review that I
   could find. Nothing is a dependency candidate for wicket's node: Agent Mesh is a Go mesh, not a
   library. [H]
2. **Agent Mesh already does "the sandbox holds no credential".** In its NVIDIA OpenShell integration:
   - the supervisor outside the sandbox gets a SPIFFE JWT-SVID;
   - it exchanges the SVID for a Biscuit (RFC 7523 client assertion, then token exchange);
   - it attaches the Biscuit to the sandbox's MCP requests.

   That is wicket's split, "identity is JWT, authority is Biscuit, the node holds the token, never the
   box", built by Google and shipping. Everyone else gives the bearer token to the agent or its SDK,
   some with a proof-of-possession key (AgentCreds, Heddle, AIP, TokenCrumb). [H]
3. **The strictest designs don't let attenuation blocks carry Datalog at all.**
   - Agent Mesh refuses any appended block that has a rule or a check. Each block must hold exactly one
     `tar_block("<base64 protobuf>")` fact. Go code decodes the rules and intersects them with the
     authority block.
   - `limes` (Go) does the same with a fixed fact vocabulary.

   Their stated reason is wicket's: a holder can append blocks without a key, so appended Datalog is
   attacker-authored, and biscuit-go's limits "neither preempt a single rule". wicket's structural check
   (fixed-vocabulary checks only) sits between this and stock Biscuit. Data-only blocks are a simpler,
   stronger option for #76 and worth a look. [H]
4. **Everyone hit the wall-clock limit; nobody fixed the per-request cost.** Every project that verifies
   per request raises the time limit far above its default:
   - Agent Mesh: 1 s, against biscuit-go's 2 ms;
   - AgentCreds: 1 s;
   - Heddle: 1 hour, after "load-dependent failures" (their issue weft#247);
   - Hessra and foundry-mcp-gateway: 50 ms;
   - TokenCrumb makes it configurable.

   They all build a fresh authorizer per request. None reuses a loaded token or compiles the checks.
   They get away with it because their tokens are small: Agent Mesh measures about 0.14 ms for a
   realistic token, and AgentCreds blocks have one to four checks, against 56 checks in wicket's depth-5
   chain. Heddle priced replacing Biscuit with a small typed kernel at 20–34 engineer-weeks (heddle#1799).
   It named "a pinned Biscuit fork" with deterministic limits as the cheaper path. Heddle and TokenCrumb
   both vendor or pin 6.0.0 because of the same upstream feature-gating bug. That is the path wicket took.
   [H]
5. **The same Datalog traps keep recurring, and they are wicket's test cases.**
   - Facts in attenuation and third-party blocks are invisible to the authorizer's default scope.
     foundry-mcp-gateway documents this. AgentCreds lets a sub-delegator *add* approval gates as facts in
     its block, which the verifier then reads at the default scope. By the spec's scoping rules those
     gates are never seen. [H, code and spec read; not run, and no test covers it]
   - Rules with the same head union across blocks, so a narrower rule in a child doesn't narrow (AIP
     §12.4). [M]
   - A budget written as `check if budget($b), $b <= N` binds to any budget fact in scope (AIP §5.2.2).
     [M]
   - Datalog built with `format!` lets a string value inject clauses. The AIP reference implementation
     had bypasses of this kind; foundry-mcp-gateway keeps a regression test for it. [M, H]
   - Time is encoded inconsistently: CPEX and Hessra compare `time($t)` with Unix integers, while AIP,
     Heddle and AgentCreds use Biscuit dates. A token from one can't pass another's authorizer. [H]

   wicket's structural check already forbids rules, `.matches` and `check all` in first-party blocks.
   These five belong in its tests.
6. **Human approval as a third-party block has two close precedents.**
   - TokenCrumb: an approver's third-party block carries `approval(tool, path_prefix, expiry)`, read
     with `trusting <approver key>`. A second form lets a tool's owner add `grant(...)` in a block it
     signs.
   - Hessra's *latent capability*: `check if activation($a) trusting {activator_pk}`. The token does
     nothing until the activator appends a block, and single use is keyed by that block's revocation id.

   AgentCreds keeps approvals as signed evidence outside the token. CPEX does them in its own policy
   pipeline. [H]
7. **There is no shared vocabulary to interoperate with.** Each project defines its own predicates
   (`right/3`, `operation/1`, `tool/1`, `tar_block/1`, `designation/2`...). AIP is the only attempt at
   a canonical block encoding, and it has one author. wicket should keep its own fixed vocabulary behind
   its chain interface (#76). If tool servers outside wicket later need to verify wicket authority, a
   node-minted, single-hop token in an outside format is the way to do it, not a change to the internal
   chain. [H read, L recommendation]

---

## 1. Triage of the crates.io reverse dependencies

All 53 crates that depend on `biscuit-auth`, grouped. [H, crates.io API]

| Group | Crates | Verdict |
|---|---|---|
| Agent or MCP authorization | `agentcreds-core`; `cpex-plugin-delegator-biscuit`; `hessra*` (9 crates); `heddle-*` and `heddleco-capability-verifier` (7); `vac-sidecar`; `identikey-capability`; `hatchery-keystore`, `hatchery-m4a-signer`, `tesserax-keytree`; `foundry-mcp-gateway` | Read, §3 |
| Biscuit maintainers' own | `biscuit-cli`, `biscuit-wasm`, `biscuit-actix-middleware` (Eclipse Biscuit) | Not agent-specific |
| Maintainer-adjacent experiments | `biscuit-ssh-core`, `gnap-biscuit` (David Legrand, Clever Cloud; both first published 2026-11-10) | §3.10 |
| P2P and messaging | `hxrts-aura-*` (10 crates); `antenna-protocol`, `antenna-client-web` | "Agent" means a device runtime, not an AI agent. Out |
| Unrelated services | `assay-auth`, `assay-vault` (vault share links); `btdt*` (CI cache); `hook0-api` (webhooks); `mattak` (Axum hypermedia); `devoyage-subgraph`; `tower-biscuit-auth` (2022) | Out |
| Dormant since 2021 | `broker`, `portal`, `files` (apibillme) | Out |

Two notes on the agent group:
- `hatchery-keystore` and `tesserax-keytree` point at GitHub repositories that return 404, so they are
  private or deleted. Only the published crate source can be read.
- `foundry-mcp-gateway` is an MCP server for a tabletop-game tool. It uses Biscuit only as its client
  credential. It's in §3 because its notes on scoping are the clearest of any project.

---

## 2. Comparison table

### 2.1 What each one does with Biscuit

Key: **AB** = authority block; **att** = attenuation block; **3P** = third-party block; **PoP** =
proof of possession of a holder key.

| Project | Who holds the token | Delegation shape | 3P blocks | Approval | Revocation | Expiry | Transport | Per-request verify |
|---|---|---|---|---|---|---|---|---|
| **Agent Mesh** (Google) | The node next to the agent; in OpenShell, the supervisor outside the sandbox | Control plane mints a Member Biscuit (grant facts compiled from mesh policy) or a Delegated Session Biscuit (RFC 8693 exchange of an OIDC token, K8s SA token or JWT-SVID); holders append up to 8 `tar_block` facts, intersected in Go | No | No | Root revocation id on `GET /revocations`; signing key rotates every 24 h | Node and session lifetimes (session default 1 h) | libp2p streams; `X-Mesh-Authentication: Bearer` at the edge; ES256 JWT for outside APIs | Fresh authorizer per request; `max_time` 1 s; appended blocks hold no Datalog |
| **TokenCrumb** | MCP client wrapper (agent key) | Issuer mints AB (Keycloak plugin or CLI); agents attenuate tools, resources, TTL, upstream, call budget | Approver `approval(...)` and owner `grant(...)` | 3P block from an approver key | Signed revocation lists; per-block ids | Date check | `Authorization: Biscuit` plus a signed per-call attestation binding agent key, tool and argument hash | Proxy; configurable `max_time_ms`; vendored 6.0.0 |
| **AgentCreds** | Agent SDK | Agent mints AB under its own key, rooted in a W3C VC from an org anchor; each hop is a 3P block signed by the delegate | Every hop | Separate signed evidence, outside Biscuit | OAuth Token Status List (bitstring JWS), ≤ 30 s | Date check per block | MCP tool argument (`_meta` planned); A2A header | Fresh authorizer, re-parse; `max_time` 1 s |
| **CPEX** (IBM) | Gateway, outbound | Gateway appends one att per outbound hop: audience, operations, TTL | No | In APL policy, not Biscuit | None in plugin | Integer Unix time | Configurable outbound header | Not in plugin; downstream verifies |
| **Hessra** | Agent or service | Central engine mints per-call capabilities (≤ 5 min); holders add designations | For activation and attestation | Latent capability, activated by a key-holder's block | Revocation ids; ledger for single use | Integer Unix time | Base64 token; SDK | Fresh authorizer; `max_time` 50 ms |
| **Heddle** | CLI or agent (with PoP key) | Human → agent → agent atts with signed PoP-key transitions | Presence proof only | No | Revocation ids plus a signed settings graph (planned) | Date check | URL-safe base64; `x-heddle-proof-*` headers | Fresh authorizer; `max_time` 1 h, iterations 100 |
| **AIP** (draft) | Agent | AB from issuer; each delegation is an att with `delegator`/`delegate` facts | Not used (§5.2.4) | No | Signed revocation endpoint, fail closed when stale | Date check | `X-AIP-Token` header, or by reference over 4 KB | Unspecified |
| **VAC** | Agent | AB from control plane; sidecar adds receipts as separate Biscuits | No | No | Heartbeat kill switch (60 s) | Short sessions | `Authorization` and `X-VAC-Receipt` headers | Sidecar; biscuit-auth **3.1** |
| **identikey** | Agent or delegate | AB plus holder-bound atts | No | No | Out of scope | Date check | Host-local socket | Small library |
| **hatchery / tesserax** | Keystore inside the harness | `right(op, subject)` facts; child sessions ⊆ parent; att by op list | No | "Human approval" in keystore | Authority-block revocation id | — | — | Small library |
| **foundry-mcp-gateway** | MCP client | Operator attenuates offline | No | No | Revocation-id list from an env var | Biscuit time | URL path: "several MCP clients can't send an arbitrary header" | Fresh authorizer; `max_time` 50 ms |

### 2.2 Health and maturity [H, GitHub and crates.io APIs]

| Project | Backing | Licence | First → latest release | Downloads | Stars | Commits in 3 months | Contributors (≥ 5 commits) | Maturity |
|---|---|---|---|---|---|---|---|---|
| Agent Mesh | Google ("not an officially supported Google product") | Apache-2.0 | v0.1.0 → v0.2.0 (2026-10-16 → 11-02) | — (Go) | 1,191 | 100+ | 10 of 26 | Releases, hosted docs, Cloud Run and OpenShell guides; A2A's `a2a-serve` depends on it [M] |
| TokenCrumb | vado-innovation-tech | Apache-2.0 | not published (`publish = false`) | — | 0 | 47 | 1 | Prototype with a thorough test suite; Keycloak issuer plugin in Java |
| AgentCreds | "TowerGuardian"; one GitHub account created 2026-06 | Apache-2.0 | 0.1.0 → 0.2.0 (2026-09-08 → 09-22) | 64 (crate) | 0 | 8 (synced from a private monorepo) | 1 | "pre-1.0", recruiting beta testers |
| CPEX | IBM Research (Frederico Araujo, Teryl Taylor) | Apache-2.0 | plugin 2026-06-26 → 0.3.1 (2026-10-16) | 169 (plugin), 6.8k (`cpex`) | 16 | 21 | 5 | Adopters: IBM ContextForge (4.8k stars), Mellea |
| Hessra | Hessra Corp. (US); one developer | Apache-2.0 | 2025-04 → 2026-10-07 | 5.8k (`hessra-token`), 700 each (new crates) | 0–3 | 4 | 1 | Open core plus a hosted service |
| Heddle | HeddleCo (US); hosted backend `weft` is closed source | Apache-2.0 | 2026-05 → 0.31.3 (2026-10-15) | 16k (`heddle-repo`), 11k (verifier) | 17 | 100+ | 2 | Product in use; 51 verifier releases |
| AIP | Sunil Prakash, independent | Apache-2.0 | draft-00 → draft-02 (2026-10-10); PyPI 0.1.0 → 0.6.0 | — | 7 | 28 | 1 | Individual draft; paper arXiv 2603.24775 |
| VAC | Param Chaudhari | MIT | 0.1.0 only (2026-02-10) | 25 | 1 | 0 | 1 | Prototype; dormant since 2026-02 |
| identikey-capability | Duke Dorje, World Tree Network Foundation | Apache-2.0 OR BSD-2-Clause-Patent | 0.1.0 (2026-09-26) | 16 | 3 | 41 (whole repo) | 1 | Draft spec, 417 lines |
| hatchery / tesserax | ZENG3LD | MIT | 2026-10-16 → 10-25 | 618 / 567 | repo 404 | — | — | Personal project; 491-line core |
| foundry-mcp-gateway | one developer | MIT | 2026-07 → 1.8.1 (2026-11-08) | 68 | 2 | 13 | 1 | Hobby product |
| *eclipse-biscuit/biscuit-rust, for scale* | Eclipse Foundation | Apache-2.0 | 6.0.0 (2025-07-16) | — | 254 | 45 | 6 | — |

---

## 3. Per-project notes

§3.1–3.10 are the crates.io projects; §3.11–3.15 were found elsewhere. Agent Mesh (§3.11) matters most.

### 3.1 AgentCreds (`agentcreds-core`, Python and Node bindings, MCP and A2A middleware)

https://github.com/agentcreds/agentcreds

What it is:
- "Verifiable, attenuable delegation for AI agents - org-rooted and verified offline." A Rust core of
  about 24k lines (41k with bindings and runtime), with PyO3 and napi bindings, a Python MCP middleware
  and a Node A2A runtime. [H]
- One author ("Morgan Reece", TowerGuardian). The public repository is a sync from a private monorepo: 8
  commits, 0 stars, 0 forks. [H]
- It reads like an exhaustive spec turned into code: DIDs, W3C VCs, SD-JWT, BBS+, SPIFFE and WIMSE
  bridges, OAuth status lists, an audit compositor, and a Cedar hook. Breadth is far ahead of evidence of
  use. [H read, L judgement]

How it uses Biscuit [H, `src/delegation/mod.rs`]:
- **Authority block**, signed by the *agent's* Ed25519 delegation subkey. The org's authority comes from
  a separate W3C VC that `verify_rooted` checks. The block holds:
  - `vc_id`, `issuer`, `subject`, `max_depth`, `budget`, `root_tool(...)` and `root_resource(...)`
    facts;
  - `check if operation($op), [...].contains($op)`;
  - `check if time($t), $t <= <date>`;
  - `check if action_cost($c), $c <= <cap>`, as a literal per hop so the tightest cap wins;
  - an on-behalf-of binding: `principal(p)` plus `check if acting_for($p), principal($p)`;
  - `gate(kind, tool)` facts naming tools that need human approval.
- **Each delegation hop is a third-party block** signed by the delegate's own delegation key, carrying
  `hop(did)` and narrower `operation`, `resource`, `time` and cost checks. Signing each hop with the
  delegate's key binds hops to identities. AIP §5.2.4 notes this as a gap in plain attenuation blocks.
- **Verification**, per call: parse the token, check every hop's key attestation, then build a fresh
  `AuthorizerBuilder` with `time`, `operation`, `resource`, `action_cost` and `acting_for` facts and
  `allow if true`. `max_time` is raised to 1 s, with a comment that the 1 ms default "is timing-flaky on
  deep on-behalf-of chains".
- **Approvals** are not Biscuit blocks. A request carries `ApprovalEvidence` signed by an approver from
  an `ApproverDirectory`. The verifier matches it to the `gate` facts and returns the approval ids so the
  caller can refuse a second use.
- **Probable bug:** the verifier reads gates with an authorizer query (`gate($k, $t)`) at the default
  scope, which sees only the authority block and the authorizer. A gate that a sub-delegator adds in its
  third-party block is therefore not seen, although the code comments say sub-delegators "may add
  execution-time gates". The spec: "Rules, checks and policies defined in the authorizer can only apply
  on facts created in the authority or in the authorizer." No test adds a gate at a hop. [H, code and
  spec read; not run]
- **Revocation** uses an OAuth Token Status List, not Biscuit revocation ids. [H]
- **Transport:** a base64 CBOR `Presentation` (token, VC, PoP proof) in a reserved MCP tool argument,
  "until the SDK exposes `_meta`". A2A uses an `AgentCreds-A2A-Evidence` header. [H]

For wicket:
- Closest in *shape* to wicket's Architecture A: Biscuit for delegation plus Cedar for conditions the
  token can't express. A useful cross-check, not a dependency: single author, unproven, and built around
  a bearer token held by the agent.
- Borrow: the per-hop literal cost cap ("a check per hop, tightest wins") and binding hop identity with
  a signature. Avoid: approval gates as facts in non-authority blocks.

### 3.2 CPEX and its Biscuit delegator (IBM Research)

https://github.com/contextforge-org/cpex, `builtins/plugins/delegator-biscuit`

What it is:
- CPEX is "a policy enforcement runtime for AI agents": a reference monitor between an agent and its
  tools, prompts, resources, inference providers and A2A methods. Rust core, with Python and Go bindings.
  Policies are YAML routes in its APL language: `require(...)`, `delegate(...)`, `taint(...)`. [H]
- Its adopters list names IBM's ContextForge MCP gateway (4.8k stars, 51 regular contributors) and
  Mellea. [H] Whether ContextForge deployments enable the Biscuit plugin was not checked. [L]
- The Biscuit part is one plugin of about 930 lines, by Teryl Taylor, first published 2026-06-26. [H]

How it uses Biscuit [H, `src/delegator.rs`]:
- It only **attenuates outbound**. Given an inbound base64 Biscuit, it verifies it against a configured
  root key and appends one first-party block:
  - `delegated_to("<target>")` and `audience("<aud>")` facts;
  - one `check if operation("<perm>")` per required permission;
  - `check if time($t), $t <= <unix seconds>`.
- It forwards the result in a configurable outbound header. It says its output is AIP's "Chained Mode"
  (draft-00 terminology).
- No verification of requests, no third-party blocks, no revocation. Datalog is built as a string, with
  quotes escaped.
- Two oddities:
  - One check per permission means a downstream request must hold *every* listed operation at once.
    [H, L intent]
  - The integer time bound only works with an authorizer that supplies `time(<integer>)`; the tests use
    `time(0)`. A stock authorizer supplies a date, and a date-vs-integer comparison is a type error, so
    such tokens would always be denied. [H read, M consequence]

For wicket: IBM's choice is a credible signal that Biscuit is the attenuation format agent gateways
reach for. The plugin itself is too small to reuse. It shows the pattern of a gateway attenuating a token
per outbound hop. That matches wicket's egress and MCP proxies, except that wicket never forwards its
authority token to the destination.

### 3.3 Hessra (`hessra-cap`, `hessra-tokens`, `hessra-sdk`)

https://github.com/Hessra-Labs/hessra-tokens, https://github.com/Hessra-Labs/hessra-cap, https://hessra.net

What it is:
- An open-core capability system from Hessra Corp. (one developer), with a hosted root authority at
  hessra.net. It started in 2025 as an authorization service with mTLS, identity tokens and a Postgres
  extension (`hessra_authz`). Since 2026-02 it has been rebuilt as three token primitives plus an engine
  aimed at agents: the README's example is an "agent harness" with "lethal trifecta prevention". [H]

How it uses Biscuit [H, source]:
- **Capability token**: one subject, one resource, one operation, short-lived (5 minutes by default).
  The authority block is
  `right(sub, res, op); check if resource($res), operation($op), right($sub, $res, $op); check if time($time), $time < <unix>`.
  The subject is kept for audit and not checked by default.
- **Designations**: holders narrow a token with `check if designation(label, value)`, keylessly, and the
  verifier supplies `designation(...)` facts. A `trusting {pk}` form needs the fact to come from a block
  signed by that key.
- **Latent capabilities**: `check if activation($a) trusting {activator_pk}`. The token is inert until
  the activator appends a block, through `amend(...).activate().attest()`, that asserts `activation` and
  tightens the time window. The latest block's revocation id keys a single-use ledger.
- **Context tokens** for information-flow control: each data access appends a third-party block with
  `reject if exposure(label)` plus `exposed_label(label)` metadata. A verifier asserts the labels it
  cares about. A matching reject rule fails, whoever signed the block. Child contexts inherit through
  `fork_context`.
- **Identity tokens**: a delegatable URI hierarchy (`bob` → `bob:agent`), and a "just-in-time" copy with
  a 5-second third-party time block.
- **Limits**: `max_time` 50 ms, "Biscuit's default budget (1ms)... regularly exceeds it" under Wasm or
  on loaded CI.

For wicket:
- The latent-capability pattern is the closest prior art for **human approval as a third-party block**
  plus single use keyed by block id. Cite it in #50, and compare encodings. Hessra puts
  `check if activation($a) trusting {pk}` in the grant; wicket's design puts `approved(...)` rules in the
  approver's block, trusted from a zone block.
- `reject if exposure(label)` is a neat way to carry taint in a token. wicket's information-flow state
  should stay on the node (research [03]), so this is an idea to note, not to adopt.
- Minting a fresh short capability per call needs an online minter on the path, which is against R1 in
  [18]. Don't copy that part.

### 3.4 Heddle (`heddle-biscuit-verifier`, `heddleco-capability-verifier`)

https://github.com/HeddleCo/heddle, https://heddle.sh

What it is:
- "AI-native version control": a Rust CLI over Git with threads, captures, provenance, and writer leases
  for agents. The hosted backend (`weft`) and web app (`tapestry`) are closed source. [H]
- Two main authors; 51 releases of the verifier since 2026-08. The busiest codebase here. [H]

How it uses Biscuit [H, `crates/biscuit-verifier`, `docs/spikes/1799-apex-capability-tokens.md`]:
- Weft mints session tokens with authority facts (`user`, `session`, `device_pop_key`,
  `right(kind, path, action)`, `staff`...) and a mandatory expiry. One shared verifier crate runs in
  native Weft and in a Cloudflare Worker (Wasm).
- **Human → agent and agent → agent delegation** (`delegation.rs`): an attenuation block with
  `agent(id)`, an expiry, and optional operation and resource-prefix checks. It must be paired with a
  separately signed proof-key transition, so each sub-agent gets its own possession key.
- Authority-bearing facts are read **only** with `... trusting authority` queries, with the comment that
  "any-block collection is explicitly unsafe for identity/rights".
- Third-party blocks are used only for a server-signed "presence" block with a 5-minute cap.
- Rule pack: three action-lifting rules (`admin → write → read`). Resource inheritance runs in Rust, not
  Datalog.
- Limits: `max_facts` 1000, `max_iterations` 100, `max_time` one hour, because "fact and iteration limits
  are the deterministic DoS guard. Wall time is only a runaway backstop". The spike cites weft#247:
  "wall-clock evaluation limits produced load-dependent failures."
- Revocation: revocation ids, "revoking an ancestor must kill descendants", checked against an online
  cache that fails closed. They moved from a 15-minute owner-signed snapshot to event-driven signed
  settings with grow-only revocations, and a 7-day maximum token lifetime (weft#872).

The Apex spike (heddle#1799, 2026-09-22 → 23):
- They inventoried what they use: no negation, aggregates, regex or extern calls; small conjunctions;
  `starts_with`; authority-scoped queries.
- They priced a small typed capability kernel (deterministic CBOR, an Ed25519 chain, typed grants, a
  bounded caveat tree) at **20–34 engineer-weeks**.
- The alternative was "a pinned Biscuit fork". It could "remove/disable the time budget and constrain
  programs without a wire replacement", at "a few days to one week" for the build fix and "2–5
  engineer-weeks" for a maintained signing seam and deterministic limits.
- The spike also hit an upstream feature-gating bug when disabling Datalog macros in 6.0.0 (fixed on
  main by PR #306, unreleased). [M]

For wicket:
- The strongest independent evidence for #76. Another production team found the same two problems,
  load-dependent denials and an unreleased upstream, and costed the same two options. They judged a
  pinned fork with deterministic limits the cheaper path.
- Borrow the rule "authority facts only through `trusting authority`". It matches wicket's structural
  check.
- Their resource inheritance runs in host code rather than Datalog, like wicket's `subset.rs`.
- Their in-house kernel design is a ready-made reference for wicket's fallback ("plain signed records",
  #76).

### 3.5 AIP: Agent Identity Protocol (IETF individual draft)

https://datatracker.ietf.org/doc/draft-prakash-aip/, https://github.com/sunilp/aip,
https://arxiv.org/abs/2603.24775

What it is:
- draft-prakash-aip-02 (2026-10-10, Standards Track requested, individual). One author. It "conveys
  delegated authority along a chain of AI agents" where no authorization server is on the path. It is
  meant to compose with OAuth-based frameworks where one is. [H]
- Two encodings: a JWT chain (each link signed by the previous holder's `cnf` key) and a **Biscuit
  encoding**. Python reference implementation, Apache-2.0, 157 commits, 7 stars; the released 0.5.0
  implements draft-01. [H]

The Biscuit encoding [H, draft §5.2, §9.1, §12.4]:
- Canonical blocks, which "implementations MUST emit exactly":
  - authority block: `identity`, optional `principal`, `right(tool)`, optional `domain`, `max_depth`,
    optional `budget_ceiling`, one tool check (`tool($t)` with `.contains`, `starts_with` or a
    wildcard), and a date `time` check;
  - delegation block: `delegator`, `delegate`, `context`, then optional `domain`, `principal`,
    `budget_ceiling`, tool check and time check.
- Three policy profiles: Simple (templates only), Standard (no recursion, bounded), and Advanced (full
  Datalog, at most 1000 iterations, opt-in).
- Structural checks run alongside Datalog. A widening block is reported as malformed, not silently
  ignored. Budget and domain are facts compared structurally, never checks.
- It says plainly that in attenuation blocks "delegator and delegate are asserted, not authenticated",
  and that third-party blocks could fix this but aren't used.
- MCP binding: an `X-AIP-Token` header, or `X-AIP-Token-Ref` by reference above 4 KB.
- Revocation: a signed issuer endpoint, cached, failing closed when the cache is older than a bound.
- Lessons in §12: the named-rule union trap; budget-as-check; Datalog injection ("earlier versions of
  the reference implementation had authorization bypasses of this kind"); and "agreement is not
  conformance": the Python and Rust implementations passed each other's tests while both skipped
  required checks.

For wicket:
- The only attempt at a *shared* Biscuit vocabulary for agents. Worth tracking. Too early to adopt: one
  author, no working-group adoption.
- Its structural-plus-Datalog split is the same as wicket's structural check plus fixed vocabulary.
- Its 4 KB header limit and by-reference transport confirm wicket's choice to keep 10 KB tokens on the
  node.
- Adopt §12.5 as a CI rule: the differential test checks agreement with stock Biscuit, but it also needs
  negative cases taken from wicket's own MUSTs.

### 3.6 VAC protocol (`vac-sidecar`)

https://github.com/certainly-param/VAC-protocol

- A sidecar HTTP proxy for agents. It verifies a Biscuit from the control plane, evaluates
  authorizer-side `allow if` policies, **injects the real API key** so the agent never sees it, and
  returns a signed receipt Biscuit after each call. A later call can require earlier receipts:
  `prior_event(op, correlation_id, ts)`. Revocation is a 60-second heartbeat to the control plane; the
  depth cap is `deny if depth($d), $d > 5`. [H]
- One author, 12 commits, dormant since 2026-02. It pins **biscuit-auth 3.1**, which predates the fix for
  CVE-2024-42350 (third-party block requests). VAC doesn't use third-party blocks, though. [H]
- For wicket: the same architecture as wicket's egress proxy (credential injection, the agent never
  holds the secret). Receipts as a precondition ("charge only after search") are a sequencing control
  that wicket's ledger could provide as facts, if ever wanted. Nothing to reuse.

### 3.7 identikey-capability

https://github.com/identikey/identikey-protocol, `docs/standards/identikey-capability-v1.md`

- Draft spec (2026-08-26) plus 417 lines of Rust. "How does an agent (or any delegate) prove what it may
  do." It compares macaroons, UCAN and custom Ed25519 tokens, and picks Biscuit: "we would be specifying
  a worse Biscuit". The first consumer is a VM-exec product (Mjolnir). [H]
- One rule worth copying: a holder binding is a **check** (`check if holder($fp), $fp == "..."`), and a
  block that asserts a `holder` fact, or a rule whose head is `holder`, is rejected. The verifier
  injects `holder(...)` only after a possession proof. [H]
- For wicket: the same "never let a block assert a fact the authorizer supplies" rule, which wicket's
  structural check enforces by forbidding rules. Add a test that a block asserting a request predicate
  (`host(...)`, `method(...)`, `approved(...)` outside a trusted 3P block) is refused.

### 3.8 hatchery-keystore and tesserax-keytree

- A personal multi-agent workspace (ZENG3LD). The keystore holds account → node → session keys, rooted
  in the human's passkey PRF, with grants per transport, "human approval", and "child sessions: a NEW
  identity with grants ⊆ the parent's, only with `spawn_child`". [H, crate source]
- Biscuit use is minimal (`tesserax-keytree`, 491 lines): `right(op, subject)` facts, and attenuation by
  an op list with `check if operation($op), [...].contains($op)`. [H]
- The repositories are not public, so health can't be judged. It has the same instinct as wicket: the
  harness keeps the keys, and spawn narrows. Nothing to reuse.

### 3.9 foundry-mcp-gateway

https://github.com/wanoo/foundry-mcp-gateway

- An MCP server for Foundry VTT (a tabletop-game tool). It replaced a shared URL secret with a Biscuit.
  The token sits in the URL path because "several MCP clients can't send an arbitrary header". Scope is
  *derived* by trying `write`, then `read`. Revocation ids come from an environment variable. [H]
- Its comments state the scoping rule most clearly: facts in an attenuation block are invisible to the
  authorizer's rules, so a `scope("readonly")` fact added later does nothing; only checks narrow. It
  keeps a test that a `"); right("admin` value can't inject Datalog. [H]
- For wicket: a confirmation that MCP clients can't be relied on to carry custom headers. wicket's MCP
  proxy identifies the box by its connection, not by a token the client sends, so the problem doesn't
  arise.

### 3.10 Biscuit's maintainers and Clever Cloud

- **biscuit-ssh** (David Legrand, Clever Cloud; repo created 2026-11-10). SSH access through a bastion
  that checks the Biscuit "again every 30 s" and cuts the session when access ends. Revocation is by
  block id. Holders attenuate offline: expiry, source networks, servers, accounts, SSH keys. Its README
  has a section on use "from scripts and agents". [H, README]
- **gnap** (same author, 2026-09 →). Experimental Rust GNAP (RFC 9635) libraries, with "an attenuable
  Biscuit token profile for file access" (`gnap-biscuit`) and demos hosted on Clever Cloud. [H, README]
- For wicket: biscuit-ssh's periodic re-check of a long-lived session is the model for wicket's
  long-lived egress connections and MCP streams. Re-decide on a timer and on each revocation push, and
  close the connection when the decision turns to deny.

### 3.11 Agent Mesh (Google)

https://github.com/google/agentmesh

What it is:
- "A private network for AI agents." A node runs next to each agent. It publishes the agent's tools
  and models to the mesh, finds and calls other nodes' services, and gives the agent an identity other
  nodes can verify. Built on libp2p, with relays for NAT. Each node exposes a local MCP server. [H]
- Go, with JS (biscuit-wasm) and Python (biscuit-python) SDKs. Apache-2.0. The README says it is "not an
  officially supported Google product". 1,191 stars, 26 contributors (10 with ≥ 5 commits), 100+ commits
  in 3 months, v0.2.0 on 2026-11-02. [H]
- Guides cover Cloud Run, Kubernetes, SkyPilot, egress destinations, and NVIDIA OpenShell sandboxes. [H]

How it uses Biscuit [H, `internal/identity/biscuit.go`, `site/content/docs/concepts/identity.md`,
`authorization.md`, `guides/openshell.md`]:
- **Member Biscuit**, minted by the control plane at enrolment from an OIDC or bootstrap token, valid 24
  hours by default and renewed in the background. Its authority block carries:
  - the node's identity, `role`, OIDC claims (`user`, `email`, `group`, `idp_role`) and `label` facts;
  - grant facts compiled from mesh policy (`granted_service_*`, `http_granted_*`, `granted_method`,
    `granted_path_*`).

  The control-plane signing key rotates every 24 hours.
- **Delegated Session Biscuit**: a node exchanges a caller's platform JWT (OIDC ID token, Kubernetes SA
  token or SPIFFE JWT-SVID) at the control plane's `/token/exchange` (RFC 8693). It gets back a
  short-lived Biscuit with the caller's resolved roles and `client_peer_id` / `actor_node`, bound to the
  origin node's transport, so "only that node can present it".
- **Attenuation** ("before starting a task or delegating to a sub-agent"): any holder appends up to 8
  blocks. `UnmarshalInbound` refuses any appended block that isn't exactly 0 rules, 0 checks and 1
  `tar_block("<base64url protobuf>")` fact, *before* building an authorizer. The decoded
  `TaskAuthorizationRule` chain is intersected in Go (`IntersectTaskPermissionsAndResources`). The hosting
  node's local `attenuation` config narrows further. Tokens can be sealed.
- **Why no Datalog in appended blocks**, from the code: biscuit-go's fact and iteration limits "neither
  preempt a single rule: one self-join over a few hundred facts runs to completion whatever these say,
  and on timeout biscuit-go's worker goroutine keeps computing. The only bound on attacker-authored rules
  is therefore that Agent Mesh never evaluates any."
- **Per-request decision**: the node middleware builds a fresh authorizer per request and adds request,
  policy and replay facts. The time limit is 1 s because biscuit-go's 2 ms default, against "~0.14ms"
  for a realistic token, turned scheduling noise into denials.
- **Revocation**:
  - banning a node publishes its peer id and its root revocation id at `GET /revocations`. Because
    attenuated children share the root block, that kills every task token derived from it;
  - an orchestrator that finishes a task early calls `POST /oauth/revoke` (RFC 7009) on its local node,
    which records the *leaf* block's revocation id.
- **The sandbox holds no credential** (OpenShell guide):
  1. The agent sends plain MCP to the supervisor.
  2. The supervisor fetches a JWT-SVID from SPIRE and posts it to the edge node as an RFC 7523 client
     assertion.
  3. The node exchanges it for a Biscuit and the supervisor caches it.
  4. The supervisor injects `X-Mesh-Authentication: Bearer <biscuit>` on each request.

  "Revoking a sandbox is a policy change; no token has to be rotated and nothing in the sandbox has to
  change."
- For calls to outside APIs, the egress node turns the Biscuit into an ES256 JWT at `/sts/token`, cached
  by the Biscuit's SHA-256. [H]

For wicket:
- **The closest system to wicket in this survey.** It has the same identity/authority split as #52 and
  the design: JWT-SVID in, Biscuit out. The credential lives outside the sandbox. A node decides per
  request. Root and leaf revocation are by block id. And outside APIs get a translated short-lived JWT,
  not the Biscuit.
- It differs in three ways:
  - its unit is a mesh peer, not a spawn tree;
  - the control plane mints every credential, so there is no offline spawn-time attenuation by the
    node's own key;
  - it has no approval blocks.
- Borrow:
  - **data-only attenuation blocks** (one typed fact, intersected in host code), as an option for #76.
    It would make the structural check trivial and remove attacker-authored Datalog entirely;
  - **leaf revocation through RFC 7009** for leases that end early;
  - **minting an outside-facing JWT from the Biscuit** for destinations that need a bearer token.
- Not a dependency: it's a Go mesh daemon. Interoperating would mean speaking its libp2p protocol. Watch
  it: it is the most likely place a de facto agent vocabulary for Biscuit forms.

### 3.12 TokenCrumb MCP proxy

https://github.com/vado-innovation-tech/tokencrumb-mcp-proxy,
https://github.com/vado-innovation-tech/TokenCrumb---keycloak-Plugin

- A Rust proxy that "checks each tool call against a signed capability and a local policy before
  forwarding it to an existing MCP server". It has:
  - offline attenuation of tools, resources, lifetime, upstream and call budget;
  - third-party approver blocks (`approval(tool, path_prefix, expiry)`, trusted by key) and owner
    `grant(...)` blocks;
  - a signed per-call attestation that binds the agent key, tool, argument hash and token;
  - persistent replay protection and budgets;
  - signed revocation lists and a signed audit log.

  The issuer is a Keycloak plugin (biscuit-java 4.0.1) that exchanges a Keycloak JWT for a Biscuit. [H]
- One author, 47 commits from 2026-10-07 to 10-30, 0 stars, not published. [H]
- **Vendoring practice worth copying for #76.** It vendors biscuit-auth 6.0.0 as `6.0.0-tokencrumb.1`,
  with a one-purpose patch: the same feature-gating bug Heddle hit. The vendor directory has:
  - an `UPSTREAM.json` with the archive checksum, the upstream commit and per-file SHA-256s;
  - the patch as a file;
  - a CI script that refuses any unreviewed change.

  Because `cargo audit` skips path dependencies, a second script audits a copy of the lockfile that names
  the upstream version, so advisories against 6.0.0 stay visible. [H]
- For wicket: the nearest single-purpose analogue of wicket's MCP proxy, with approvals encoded almost as
  wicket plans. The agent holds the token, which wicket avoids. Reuse the vendoring hygiene; nothing else.

### 3.13 limes

https://github.com/oleg-tkachuk/limes

- Go, Apache-2.0, "budgeted, revocable capabilities for agents". 0 stars but about 2.85k commits by 4
  regular contributors since 2026-10-08, v0.177. [H]
- Biscuit is only a container. The authority block holds one `limes_capability("<JWT>")` fact.
  Attenuation blocks may hold only facts from a fixed vocabulary: `limes_op`, `limes_resource_prefix`,
  `limes_expires`, `limes_bind` (a DPoP thumbprint), `limes_max_requests`, `limes_max_budget_nanos`...
  Any rule or check is refused. Narrowing is checked in Go. Revocation uses the last block's id. [H]
- For wicket: a second, independent instance of "data-only blocks, decided in host code". Same lesson
  as Agent Mesh.

### 3.14 Other projects outside crates.io

Found by GitHub and web search. Short because there is little in them. [H unless marked]

| Project | Language | What it does with Biscuit | State |
|---|---|---|---|
| HexGate (Hexamind), https://github.com/HexamindOrganisation/hexgate | Python (biscuit-python), Go collector | Platform API keys and per-request user scope (`check if user("alice")`); tool policy itself is YAML/Rego | MIT, 24 stars, commercial cloud |
| Theoriq agent SDK (ChainML), https://github.com/chain-ml/theoriq-agent-sdk | Python | Namespaced request facts (`theoriq:request(...)`); agents sign third-party blocks with their own keys | Apache-2.0, 56 stars, quiet since 2026-02; used by the Theoriq agent network [M] |
| AIP SDKs, https://github.com/sunilp/aip-node | TS, Python, Rust | §3.5 | One author |
| agent-passport (kushDCFS) | TS (biscuit-wasm) | `capability`, `audience`, `provenance` facts; delegation adds checks plus a PoP challenge | Hackathon, 2026-06 |
| agent-biscuits (dleen) | Python | Refund-agent demo: the agent appends customer, read-only and cap checks | One commit, no licence |
| MCP-biscuit-PoC (esweiss) | Python | Biscuit plus mTLS plus Postgres RLS behind MCP; a taint block after a sensitive read stops internet tools | MIT, 2025 |
| project-mandate-research (Martin-Brewer) | C# | Cross-org agent delegation with biscuit-cli; concluded Biscuit "already covers" it and dropped the product; filed eclipse-biscuit/biscuit#199 | One commit |
| agentgate (Clawdlinux), aikonos (adamdekan), ardur-evidence (ArdurAI), clayseal-identity, ai-parrot | Go, Python | Small gateways or verifiers; aikonos uses Biscuit as one of four gates with OpenFGA and OPA | 3–33 stars; demos or spikes |
| biscuit-sharp, `@smithery/biscuit` | .NET, Workers | Libraries with agent framing, no agent logic | Previews |
| delegateos (newtro) | TS | "Biscuit-compatible" but its own Datalog engine, not Biscuit | Not Biscuit |

OpenAI's Codex has an agent-identity flow (PRs #17385–17388, 2026-04). It fetches a "human biscuit" from
ChatGPT and treats it as opaque. The client has no Biscuit library. Whether that token is an Eclipse
Biscuit at all is unconfirmed, and a blog that calls it Biscuit or AIP delegation isn't supported by the
code. [M, L]

### 3.15 Papers and what the maintainers have said

- arXiv 2603.24775 (AIP): Biscuit "gets the token format right" but lacks identity, bindings and
  provenance. [H]
- arXiv 2602.11865, "Intelligent AI Delegation" (Tomašev, Franklin, Osindero): proposes delegation
  capability tokens "based on Macaroons… or Biscuits". [H]
- arXiv 2609.06500 (CAPMAS) picks macaroons over Biscuit, citing the cost of asymmetric crypto and
  payload size. [H]
- draft-niyikiza-oauth-attenuating-agent-tokens cites Biscuit and criticises the need for a Datalog
  engine at verification time. [M] That is the same objection Agent Mesh and limes answer by not running
  appended Datalog.
- **Biscuit's maintainers have said nothing public about agents** that I could find:
  - the only agent item in the eclipse-biscuit org is issue biscuit#199, filed by a third party, with no
    maintainer reply [H];
  - the biscuitsec.org blog's latest posts (post-quantum, 2026-05; DPoP through third-party blocks,
    2025-09) don't mention agents [M];
  - Clever Cloud's Biscuit posts date from 2021, and its MCP posts (Otoroshi) don't mention Biscuit [M];
  - the nearest is David Legrand's biscuit-ssh and gnap experiments (§3.10).

  So an upstream proposal from wicket (#76, patches 1 and 2) would be the first agent-driven request the
  maintainers see. That makes the downstream evidence in §0 item 4 worth including.

---

## 4. What this means for wicket

**Keep the decision; nothing here replaces it.** The largest project (Agent Mesh) independently built
wicket's custody model. The one product team that costed alternatives (Heddle) reached the trade-off
behind #76. No project is a library wicket could depend on for the node's decision path. [H]

**#76 (vendored Biscuit):**
1. **Consider data-only attenuation blocks.** Agent Mesh and limes both refuse any rule or check in
   appended blocks. Each block is one typed fact, and host code intersects it with its parent.
   - For wicket, spawn and grant blocks would carry one `zone(<canonical encoding>)` fact. The node would
     decide with `subset.rs`-style code instead of Datalog.
   - Datalog would remain only in the authority block (wicket-generated) and in approval third-party
     blocks.
   - Gains: the structural check shrinks to a shape check, attacker-authored Datalog disappears, and
     patch 3's compiled evaluator has much less to compile.
   - Costs: narrowing is no longer enforced by Biscuit's own semantics. The guarantee "a child can't
     exceed its parent" moves into host code, which [18] §0 item 2 warned against relying on alone.
   - A middle course: keep fixed-vocabulary checks (today's design), but also carry the typed zone as a
     fact, so the two can be cross-checked in the differential test.

   This is worth a short experiment before #76 freezes the block format. [L, recommendation]
2. Add the recurring traps to the structural check's tests and the property suite:
   - facts or gates in non-authority blocks are ignored (the AgentCreds case);
   - a narrower named rule in a child doesn't narrow (AIP §12.4);
   - a ceiling written as a check binds to any fact in scope;
   - Datalog injection through string values;
   - date-vs-integer `time` comparisons;
   - a self-join rule in an appended block (Agent Mesh's case; already refused by the no-rules rule).

   Build blocks with the typed builder or `code_with_params`, never `format!`.
3. Copy TokenCrumb's vendoring hygiene:
   - `UPSTREAM.json` with the upstream commit and per-file hashes;
   - the patches kept as files;
   - a CI check that the vendored tree matches;
   - an advisory audit run against the upstream version, because `cargo audit` skips path dependencies.

   Two other projects (Heddle, TokenCrumb) carry local fixes for the same 6.0.0 feature-gating bug.
   wicket's base, upstream main `aa5a672`, already contains the fix (PR #306, merged 2025-09-16), so
   wicket doesn't need that patch. [H, GitHub compare API]
4. Use the downstream workarounds as evidence in the upstream proposal for patch 2 (a step budget
   instead of wall-clock time):
   - Agent Mesh: 1 s against biscuit-go's 2 ms;
   - AgentCreds: 1 s;
   - Heddle: 1 h, with weft#247;
   - Hessra and foundry-mcp-gateway: 50 ms.

   No maintainer has engaged with agent use so far (§3.15), so concrete downstream cases help. Opening the
   proposal still needs the owner's go-ahead, as #76 says.
5. Read Heddle's Apex spike (heddle#1799) before writing wicket's "plain signed records" fallback. It has
   a full threat model and a feature inventory for a typed kernel.
6. Pin the "agreement is not conformance" rule (AIP §12.5) in CI. The differential test against stock
   Biscuit proves agreement; negative tests from wicket's own MUSTs prove conformance.

**#50 (escalation rights; who may request, who may grant):**
- Prior art for approval as a third-party block:
  - TokenCrumb's `approval(tool, path_prefix, expiry)` trusted by approver key;
  - TokenCrumb's owner `grant(...)` blocks, which match "a parent box's grantor key that a zone block
    trusts";
  - Hessra's latent capability, single use by the activation block's revocation id.

  Keep wicket's encoding: `approved(...)` rules only, from keys a zone block trusts. Note that TokenCrumb
  scopes an approval by tool *and* path prefix *and* expiry. wicket's approvals should carry the same
  three, at least.
- AgentCreds' per-hop literal cost cap is a clean encoding for budget ceilings, if wicket grants carry
  spend limits.

**#57 (local authorization):**
- Agent Mesh is the only other system that decides per request at a node holding a credential on the
  agent's behalf. It builds a fresh authorizer each time and lives with about 0.14 ms because its tokens
  are small. wicket's per-token load cache has no outside precedent; the experiment's numbers stand on
  their own.
- Revoke the leaf as well as the root. Agent Mesh's `POST /oauth/revoke` records the *last* block's id
  for a task that ends early. wicket's leases should do the same: end a lease by its block id, without
  touching the zone.
- Re-check long-lived connections on a timer and on revocation push, as biscuit-ssh does every 30 s.
  This should be in #57's revocation bounds.
- Revocation designs in the field:
  - OAuth status lists (AgentCreds);
  - heartbeats (VAC);
  - signed event-driven sets (Heddle);
  - a signed endpoint with a staleness bound (AIP);
  - a revocation endpoint plus ban events (Agent Mesh).

  wicket's signed feed with a freshness lease (research [18], experiment 3) is at the strong end. Nothing
  to change.

**#52 (identity):**
- Agent Mesh's OpenShell flow is the reference design for #52: a supervisor outside the sandbox gets a
  JWT-SVID from SPIRE and exchanges it (RFC 7523 client assertion, RFC 8693 token exchange) for a Biscuit.
  It caches the Biscuit and attaches it to requests. Read its `identity.md` and the OpenShell example
  before writing #52's exchange. Consider the same standard grant types, so wicket's control plane speaks
  the token-exchange API other tools already use.
- AgentCreds and identikey also keep identity apart from authority ("a Biscuit is not a proof of who you
  are").
- Proof of possession matters only for bearer tokens held by agents. Because the box never holds the
  token, wicket can skip PoP inside a node. It needs PoP only if a token leaves the node (a cross-node
  handoff, or an outside verifier). Agent Mesh binds the session token to the origin node's transport
  key for the same reason.

**Interoperability:**
- Don't target any of these formats now. If an outside service ever needs to verify wicket authority
  itself, the node mints an *export*: a short-lived, single-hop token, not the internal chain. Agent Mesh
  does this with an ES256 JWT for outside APIs. Candidates for the export format: a plain JWT (simplest),
  AIP's Biscuit encoding (if it gains a second implementation or working-group adoption), or Agent
  Mesh's vocabulary (if it becomes the de facto one).
- Use a Biscuit date for `time`, as the spec's examples and most projects here do.

**Avoid:**
- Approval gates or ceilings as facts in non-authority blocks.
- Integer time.
- Wall-clock limits on the decision path.
- `allow if` policies or receipts carried by the agent.
- Minting a fresh capability per call from an online service.
- Old biscuit-auth versions (VAC's 3.1).

---

## 5. Assumptions and gaps

- I read the Biscuit code paths, not whole codebases, and built or ran nothing. Bugs flagged [M] or [L]
  come from reading code against Biscuit's scoping rules, not from a test.
- Closed parts were not visible: Heddle's Weft backend, Hessra's hosted service, the private
  hatchery/tesserax repositories, and AgentCreds' monorepo.
- Whether IBM ContextForge enables the CPEX Biscuit plugin in practice was not checked; GitHub code
  search was rate-limited.
- Download counts include mirrors and CI, and say little about use.
- The §3.14 projects were triaged from search results and READMEs, with spot checks of source; they were
  not read as closely as §3.1–3.13.
- Agent Mesh is large (about 2.4k commits). I read its identity, authorization and OpenShell docs and its
  Biscuit code, not the whole daemon.

---

## 6. Sources

Crates and repositories (primary):
- crates.io reverse dependencies of biscuit-auth: https://crates.io/crates/biscuit-auth/reverse_dependencies
- AgentCreds: https://github.com/agentcreds/agentcreds (`agentcreds-core/src/delegation/mod.rs`,
  `src/revocation.rs`, `MCP_INTEGRATION.md`, `agentcreds-runtime/src/agentcreds_runtime/fastmcp.py`) ·
  https://pypi.org/project/agentcreds/
- CPEX: https://github.com/contextforge-org/cpex (`builtins/plugins/delegator-biscuit/src/delegator.rs`,
  `ADOPTERS.md`) · ContextForge https://github.com/IBM/mcp-context-forge
- Hessra: https://github.com/Hessra-Labs/hessra-tokens (`hessra-cap-token/src/mint.rs`, `attenuate.rs`,
  `limits.rs`; `hessra-context-token/src/lib.rs`, `exposure.rs`; `hessra-identity-token/src/jit.rs`) ·
  https://github.com/Hessra-Labs/hessra-cap · https://github.com/Hessra-Labs/hessra-sdk.rs ·
  https://hessra.net
- Heddle: https://github.com/HeddleCo/heddle (`crates/biscuit-verifier/src/lib.rs`, `delegation.rs`,
  `facts.rs`, `rules.biscuit`; `docs/spikes/1799-apex-capability-tokens.md`;
  `docs/SELF_SOVEREIGN_AUTH.md`) · https://github.com/HeddleCo/heddle/issues/1799 · https://heddle.sh
- AIP: https://datatracker.ietf.org/doc/draft-prakash-aip/ ·
  https://www.ietf.org/archive/id/draft-prakash-aip-02.txt · https://github.com/sunilp/aip ·
  https://arxiv.org/abs/2603.24775
- VAC: https://github.com/certainly-param/VAC-protocol (`docs/API.md`, `docs/ARCHITECTURE.md`,
  `sidecar/Cargo.toml`)
- identikey: https://github.com/identikey/identikey-protocol
  (`docs/standards/identikey-capability-v1.md`)
- hatchery-keystore and tesserax-keytree: crate sources from https://crates.io/crates/hatchery-keystore
  and https://crates.io/crates/tesserax-keytree (repositories not public)
- foundry-mcp-gateway: https://github.com/wanoo/foundry-mcp-gateway (`src/mcp/auth.rs`)
- biscuit-ssh: https://github.com/davlgd/biscuit-ssh · gnap: https://github.com/davlgd/gnap
- Agent Mesh: https://github.com/google/agentmesh (`internal/identity/biscuit.go`, `authorize.go`,
  `internal/node/middleware.go`, `internal/credprovider/credprovider.go`;
  `site/content/docs/concepts/identity.md`, `authorization.md`, `architecture.md`;
  `guides/openshell.md`) · NVIDIA OpenShell https://github.com/NVIDIA/OpenShell
- TokenCrumb: https://github.com/vado-innovation-tech/tokencrumb-mcp-proxy (`README.md`,
  `vendor/biscuit-auth/`, `tools/check_vendor.py`, `tests/third_party*.rs`) ·
  https://github.com/vado-innovation-tech/TokenCrumb---keycloak-Plugin
- limes: https://github.com/oleg-tkachuk/limes (`biscuit/biscuit.go`)
- §3.14: https://github.com/HexamindOrganisation/hexgate · https://github.com/chain-ml/theoriq-agent-sdk ·
  https://github.com/sunilp/aip-node · https://github.com/kushDCFS/agent-passport ·
  https://github.com/dleen/agent-biscuits · https://github.com/esweiss/MCP-biscuit-PoC ·
  https://github.com/Martin-Brewer/project-mandate-research ·
  https://github.com/eclipse-biscuit/biscuit/issues/199 · https://github.com/Clawdlinux/agentgate ·
  https://github.com/adamdekan/aikonos · https://github.com/ArdurAI/ardur-evidence ·
  https://github.com/clayseal/clayseal-identity · https://github.com/phenobarbital/ai-parrot ·
  https://github.com/jenolaszlo-sketch/biscuit-sharp · https://github.com/clavia-labs/workers-biscuit ·
  https://github.com/newtro/delegateos · Codex PRs https://github.com/openai/codex/pull/17385 (to 17388)
- Papers: https://arxiv.org/abs/2603.24775 · https://arxiv.org/abs/2602.11865 ·
  https://arxiv.org/abs/2609.06500 ·
  https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-01
- Maintainers: https://www.biscuitsec.org/blog/ · https://www.clever-cloud.com/blog/
- Out of scope after triage: https://github.com/hxrts/aura · https://github.com/developerinlondon/assay ·
  https://github.com/PixelQuasar/antenna

Biscuit:
- Spec, scoping and third-party blocks: https://doc.biscuitsec.org/reference/specifications
- biscuit-rust: https://github.com/eclipse-biscuit/biscuit-rust · PR #306
  https://github.com/eclipse-biscuit/biscuit-rust/pull/306
- CVE-2024-42350: https://nvd.nist.gov/vuln/detail/CVE-2024-42350

Earlier wicket research: [03] policy, authority and IFC; [18] authorization landscape; design
"Identity is JWT; authority is Biscuit"; issues #50, #52, #57, #59, #76.
