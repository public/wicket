# 03 — Policy, authority and information-flow core

Research for wicket, dated 2026-11-08. Scope: policy engines, attenuable capability tokens, typed
escalation, deriving policy from the task, information-flow labels for black-box agents, and audit/UX.
Recommendations come last (§7) and are written so they can be argued with.

Confidence: **[H]** high (checked against a primary source), **[M]** medium (primary source read only in
part, or my own inference from primary material), **[L]** low (secondary source, abstract only, or a guess).

---

## 0. Summary

| Question | Answer |
|---|---|
| Policy engine | **Cedar** (`cedar-policy` 4.14.1, 2026-11-02) for zone and org policy and for explanations. **`cedar-policy-symcc`** 0.8.1 for offline proofs ("new ⊆ old", "child zone ⊆ parent zone"). Grants use a small capability algebra of wicket's own, with a syntactic subset check. |
| Token format | **Biscuit** (`biscuit-auth` 6.0.0) carries authority between the control plane and the enforcement points. **No token of any kind enters the sandbox.** The sandbox is identified by its transport: a per-VM network namespace, vsock or mTLS key. Use counts, approvals and revocation live in a server-side grant ledger. |
| Labels | Coarse product label: **confidentiality = set of data-class tags** (join is union; a destination is allowed if the agent's tags ⊆ the destination's clearance) × **integrity = set of taint-source tags** (empty means trusted). Gate outputs also carry a **capacity type** (FIDES-style). Each agent has a floating label and a zone-level clearance (LIO-style). The gateway keeps a label store for provider-side resources. |
| Escalation | A typed request shaped like RAR `authorization_details`. It moves through a CIBA/GNAP-style async lifecycle (`pending` / `slow_down` / `denied` / `expired` / `granted`). The agent sees an HTTP problem+json body with `request_id` and `Retry-After`, or, over MCP, a tool error, an MRTR `InputRequiredResult` or a tasks-extension handle. Deciders are **reasoning-blind**: they see the typed request and where each field came from, never the agent's justification as authority. |
| UX | Zones and gates generated from the live config. "If compromised" = reach ∪ auto-grantable ∪ send ∪ cross-gate influence ∪ shared provider state. A grant diff timeline. A ratchet budget. Approval-rate feedback into auto-rules. |

---

## 1. Policy engines usable from Rust

### 1.1 What wicket needs from the engine
- Resource model: `(provider, resource path, verb)` + risk class + labels (confidentiality tags, taint).
- Decisions on the hot path (every proxied HTTP request or MCP call). Needs to be sub-millisecond and deterministic.
- **Subset checks.** "Child zone ⊆ parent zone", "generated adapter rule is narrower than the default", "new manifest ⊆ old manifest + the approved delta".
- **Explanations for humans.** Which rule allowed or denied a request, and what a zone can reach.
- Policies written by LLMs (manifests, generated adapters) must be checkable mechanically: typed and analysable.

### 1.2 Cedar (AWS, Apache-2.0) — best fit
- **Status.** `cedar-policy` 4.14.1 on crates.io, updated 2026-11-02 (crates.io API). `cedar-policy-symcc` 0.8.1, also 2026-11-02, pinned to `cedar-policy` =4.14.1 [H]. https://crates.io/crates/cedar-policy, https://docs.rs/cedar-policy-symcc
- **Model.** PARC (principal, action, resource, context). Entities form a DAG through `in`. Schemas are validated (`cedar-policy-validator`). `forbid` beats `permit`, and the default is deny. There are policy **templates**: `permit(principal == ?principal, action, resource in ?resource)`, linked per grant. That maps directly onto wicket grants [H].
- **Explanation.** An authorization response carries the set of determining policy IDs (`diagnostics().reason()`) and any errors. That is enough to render "allowed by zone policy Z-3 + grant G-17; would be denied by forbid F-workflows if risk ≥ R4" [H, standard API].
- **Partial evaluation.** The `tpe` feature adds type-aware partial evaluation (RFC 95, started 2025-01-30, experimental, shipped in 4.9/4.10). It is the recommended replacement for the older untyped `partial-eval`. RFC 95 targets *permission queries* ("which resources can this principal act on"), which is what the blast-radius view needs. The core-crate docs warn that experimental features may break even in patch releases [H]. https://github.com/cedar-policy/rfcs/blob/main/text/0095-type-aware-partial-evaluation.md
- **Formal analysis (the key differentiator).** SymCC compiles Cedar to SMT-LIB and checks these properties [H] (README + docs.rs + Lean docs):
  - `check_implies` — **policy-set subsumption**: every request allowed by A is allowed by B. This is "child ⊆ parent".
  - `check_equivalent`, `check_disjoint`, `check_always_allows`, `check_always_denies`, `check_never_errors`, plus per-policy `matches_implies` / `matches_disjoint` and similar.
  - `*_with_counterexample` returns a synthesized request + entity store. That gives the UI a concrete witness: "here is a request the child would allow that the parent wouldn't."
  - The compiler and verifiers are modelled and proved in Lean (https://github.com/cedar-policy/cedar-spec). The solver is an external **cvc5 1.3.1** binary, and the API is async (Tokio). Checks run per request environment (`schema.request_envs()`).
  - Properties quantify over **all well-formed requests and entity stores** for the schema. For wicket's path prefixes this matters. `resource in Dir::"acme/api/infra"` implies `resource in Dir::"acme/api"` only if the hierarchy is fixed, and SymCC treats the entity store symbolically. So write path scoping as string patterns (`resource.path like "acme/api/infra/*"`) or as explicit conjunctions, not only as entity membership [M — my reading of the symbolic semantics. Verify with a test before relying on it].
  - Cedar Analysis CLI (`cedar-lean-cli analyze compare`, AWS blog 2025-06-16) classifies two policy sets as equivalent, more permissive, less permissive or incomparable. It also reports shadowed permits, impossible conditions, forbid-overridden permits and complete denials. That is a ready-made "policy diff" for the approval UI [H]. https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/
  - LLM synthesis loop: AutoCedar (arXiv 2607.03656, 2026) uses SymCC as the verifier in an agentic policy-synthesis loop. This is close to wicket's "generator may only narrow" rule [L, search snippet only].
- **Weaknesses.** No native path or prefix type, so `like` or entity hierarchies have to stand in. Datalog-style recursion is deliberately absent (fine). SymCC needs a cvc5 sidecar binary in the trusted control plane, though not on the hot path. Some feature coverage limits in SymCC (extension types, `like` edge cases) are not documented on the pages I read [L], so keep wicket's Cedar in a "SymCC-friendly subset" and CI-test it.

### 1.3 OPA / Rego via `regorus` (Microsoft)
- `regorus` 0.14.1 (2026-11-02). Pure-Rust Rego interpreter that tracks OPA and defaults to Rego v1. It has a compiled register VM ("RVM", 0.9+), coverage reports and many language bindings [H on version; M on features]. https://github.com/microsoft/regorus
- Strong for policy over arbitrary JSON (admission-control style). Large ecosystem (Gatekeeper, Conftest).
- **No subset or equivalence analysis.** Rego is a general query language over documents, and nothing like SymCC exists for it [M]. Explanations amount to "which rules evaluated true", plus coverage. It also has more builtins with side effects (http.send in OPA; regorus restricts them).
- Verdict: good for **validating adapter DSL documents and manifests** (structural lint), not for the authority core.

### 1.4 Biscuit Datalog (as a policy language)
- Authorizer Datalog with `allow if` / `deny if` policies, `check if`, `check all`, `reject if` (Datalog 3.3 = schema v6), time and string ops [H]. https://doc.biscuitsec.org/reference/specifications
- The **subset guarantee is structural.** Attenuation blocks can only add checks, and facts in attenuation blocks are not trusted by the authorizer by default (`trusting authority` is the default scope). So "child ⊆ parent" holds by construction, with no solver [H].
- Explaining Datalog derivations to humans is harder than explaining Cedar PARC rules. There is also no analysis tooling for "is policy set A more permissive than B" across authorizers [M].
- Verdict: use for the **token chain**, not for org or zone policy.

### 1.5 Polar / Oso
- The Oso OSS library (Polar) was **deprecated on 2023-12-18** in favour of Oso Cloud. Last crate release 0.27.3 (2024-01) [H]. https://github.com/osohq/oso
- Verdict: don't build on it.

### 1.6 Zanzibar-style (SpiceDB, OpenFGA)
- Relationship-based (ReBAC) with consistency tokens ("zookies"). Built for huge shared object graphs with many principals (Zanzibar, USENIX ATC 2019: https://www.usenix.org/conference/atc19/presentation/pang). SpiceDB has caveats (CEL conditions) and, I believe, expiring relationships (2025) [L]. OpenFGA has conditions.
- Rust clients are thin and young (`spicedb-client` 0.1.1, `openfga-rs` 0.1.0) [H].
- Wicket's graph is small and per-task, made of zones, agents and grants. A separate database service adds ops cost and gives no subset proofs. **Overkill**, as suspected. The one ReBAC-shaped part is the *provider-side label store* (resource → label), and that is a key-value table, not a relation graph.

### 1.7 Fit matrix

| | Cedar | Rego/regorus | Biscuit Datalog | Polar | Zanzibar |
|---|---|---|---|---|---|
| (provider, path, verb) + risk + labels | Good (entities + attrs + context sets) | Good | Good | — | Awkward |
| Subset proof | **Yes (SymCC, Lean-verified)** | No | By construction (token chain only) | No | No |
| Human explanation | Good (determining policies, PARC reads like English) | Medium | Weak | — | Medium |
| Embeddable Rust, hot-path speed | Yes | Yes | Yes | Deprecated | Service |
| LLM-writable + checkable | Yes (schema validation + SymCC) | Partial | Partial | — | — |

---

## 2. Attenuable capability tokens

### 2.1 Biscuit (`biscuit-auth` 6.0.0, 2025-07-16; Eclipse Biscuit project)
- Public-key chained blocks (Ed25519 or P-256). Anyone holding the token can append a block offline, and blocks can only restrict. Verification needs only the root public key [H].
- **Third-party blocks** (format v5, Datalog 3.2). The holder sends a `ThirdPartyBlockRequest` bound to `previousSignature`. The third party signs a block with its own key, and the authorizer trusts it via `trusting ed25519/<key>`. This is how an approver (a human-approval service, or a parent zone) adds a signed attestation, such as `approved(req_id)`, that the verifier only accepts from that key [H]. CVE-2024-42350 concerned `trusted` annotations in third-party block requests and was fixed in spec v4+, so use 6.x [H]. https://nvd.nist.gov/vuln/detail/CVE-2024-42350
- **Revocation IDs.** One per block, derived from the block signature (unique even for identical content). Revoking a block's ID kills every token derived from it. That is **subtree revocation for free**: revoke a parent's grant and every child's token dies [H]. Revocation itself needs external state (a deny list checked by the authorizer) [H].
- **Sealed tokens** stop further attenuation. Use them for leaf grants [H].
- **Time.** `check if time($t), $t < 2026-11-08T14:12:00Z`. The authorizer supplies the ambient `time` fact [H].
- **No use counts.** Biscuit is stateless, so the authorizer has to inject facts from a ledger [H — the spec has no counter mechanism].
- Maturity: 12.7M downloads. The spec repo was last touched 2025-10. Slow-moving but stable [H].

### 2.2 Macaroons
- HMAC chains with first-party caveats and third-party caveats (discharge macaroons). Verification needs the **root secret**, so every verifier is a minter. That is worse for a split control plane and gateway [H — the standard design].
- The Rust `macaroon` crate 0.3.0 hasn't been updated since 2022 [H].
- Production reference: **Fly.io**, "Macaroons Escalated Quickly" (2024) and "Operationalizing Macaroons". A central `tkdb` service verifies tokens and publishes a revocation feed that clients poll. Third-party caveats delegate to SSO and other services [M]. https://fly.io/blog/macaroons-escalated-quickly/, https://fly.io/blog/operationalizing-macaroons/
- Lesson: even macaroon shops end up with a **stateful verification service** for revocation and similar state.

### 2.3 UCAN
- The 1.0 spec is still at **1.0.0-rc.1**: delegation, invocation, promise and revocation, plus a policy language. DID-based and aimed at decentralized, local-first apps [M]. https://github.com/ucan-wg/spec
- The Rust `ucan` crate 0.4.0 dates from 2023. Open discussions concern pre-authorizing one exact invocation and key rotation [M].
- Verdict: wrong trust model (decentralized DIDs) and immature in Rust.

### 2.4 IETF agent-token drafts (watch, don't adopt)
- **draft-niyikiza-oauth-attenuating-agent-tokens** (-01, 2026-06-15; -02 exists; individual draft). JWT chain where each child is signed by the parent's holder key, `par_hash` commits to the parent's bytes, and there is a delegation-depth limit. Capabilities sit in an `authorization_details` entry with a **closed constraint vocabulary** (`exact`, `range`, `one_of`, `not_one_of`, `contains`, `subset`, `wildcard`, `all`, `any`). **"Extension types must define a sound, deterministic subsumption check."** The enforcement point is closed-world (unknown args are rejected). Per-call PoP JWTs. **It recommends stateful `jti` tracking for side-effecting calls** [H]. https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-01
  → Wicket's capability algebra should copy this idea of a closed vocabulary with a subsumption check per constraint type.
- **draft-ietf-oauth-transaction-tokens** (WG draft, 2026) and the individual **Transaction Tokens for Agents** draft (-06, 2026-04). Short-lived, internally signed context tokens that carry the call chain inside a trust domain [L — revision numbers vary between sources].
- **RFC 8693 Token Exchange.** `subject_token` + `actor_token`, with an `act` claim that nests to record the delegation chain and `may_act` to authorize it. Useful vocabulary for recording "agent B acting for parent A for user U" in audit records and in downstream tokens wicket mints [H, RFC]. https://www.rfc-editor.org/rfc/rfc8693

### 2.5 Native attenuation at the provider (defence in depth)
The gateway should mint the **narrowest native credential** before applying its own policy:
- GitHub App installation tokens can be restricted to specific repos and permissions at creation time.
- AWS STS `AssumeRole` with an inline **session policy**: effective permissions = role ∩ session policy.
- GCP **Credential Access Boundaries** (downscoped tokens).
[H for GitHub and AWS; M for GCP naming.] These are true intersections. If wicket's policy has a bug, the native scope still caps the damage, as the origin conversation argued.

### 2.6 Use counts ("1 use, 10 min") — how others handle state
Everyone uses server state:
- The **MCP 2026-07-28 MRTR** spec: integrity-protected `requestState` "does not by themselves guarantee single-use. Servers for which a given `requestState` must be consumed at most once **MUST enforce that invariant server-side**" [H].
- The niyikiza draft: stateful `jti` tracking for side-effecting calls [H].
- Fly.io: the tkdb service [M].
- "Runtime Authorization for Resources Acquired by AI Agents" (arXiv 2609.14744, 2026-09): "single-use effect permits are revalidated and **consumed when the effect executes**", with proofs covering crash/retry and refunds [L — abstract].

**Wicket design.** The gateway is already the single choke point, so put the counter there. On request: reserve one use, atomically, in the ledger (SQLite/Postgres row with `uses_left`). Forward to the provider. Commit on any response where the effect *may* have happened. Release only on a definite pre-send failure. If unsure, count it as used. The Biscuit authorizer receives an ambient fact `uses_left(grant_id, n)` from the ledger, and the token carries `check if uses_left($g, $n), grant($g), $n > 0`.

### 2.7 Do tokens enter the sandbox? — **No.**
- The sandbox is attacker-influenced, so anything inside it can be exfiltrated (through allowed channels, error messages, file names). A leaked bearer Biscuit works from anywhere unless it is PoP-bound, and PoP keys inside the sandbox can be exfiltrated too.
- Identify the caller by **transport**: the egress proxy listens on a per-sandbox veth or netns, or the gateway is reached via per-VM vsock or a per-VM WireGuard or mTLS key held by the VM supervisor rather than by the guest userland. The connection is the capability, as an fd is in Capsicum.
- CLIs that insist on a token get a **non-secret placeholder** (`GH_TOKEN=wicket-placeholder`), which the proxy strips and replaces with the real credential. This is the Browser Use / Docker Sandboxes pattern from the brief.
- A *wicket-aware* orchestrator agent that wants to delegate gets an opaque **grant handle** (`grant:01J…`, meaningless outside the control plane). It calls `wicket.delegate(handle, narrower_cap)` on the harness API, and **the control plane** appends the Biscuit block. The orchestrator never handles key material.
- So where does Biscuit earn its keep? Between the control plane and **distributed enforcement points**: several gateways or proxies, remote microVM hosts (E2B-style), and later cross-org federation. Those points can verify offline with only a root public key, and audit gets a chain of custody. If wicket stays single-host for a long time, a signed append-only grant ledger with parent pointers is functionally equivalent. Design the capability algebra so it compiles 1:1 to Biscuit blocks, and the choice stays reversible [M — judgment call].

---

## 3. Typed escalation requests

### 3.1 The relevant standards
- **RFC 9396 RAR** (`authorization_details`). An array of objects keyed by `type`, with common fields `locations`, `actions`, `datatypes`, `identifier`, `privileges` plus type-specific fields. **The AS may grant a subset**, and the token response MUST return the `authorization_details` actually granted. Comparison rules are per type ("write may imply read"). Use PAR or signed request objects to protect them from tampering [H]. https://www.rfc-editor.org/rfc/rfc9396
  → Use this as wicket's **request schema** (`type: "wicket.capability/v1"`). Its built-in "grant narrower than asked" semantics is exactly the grant-creep mitigation from the brief.
- **OpenID CIBA Core 1.0** (Final, 2021-09-01). Decoupled consumption and authentication devices. `auth_req_id`, `expires_in`, `interval` (default 5 s). Poll, ping and push delivery modes. `binding_message`: a short code shown on both devices so the human knows which request they are approving. Errors: `authorization_pending`, `slow_down` (+5 s), `expired_token`, `access_denied` [H]. https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
  → This is wicket's **human-tier protocol** (push to the owner's phone). Reuse the error vocabulary for agent-facing states.
- **GNAP, RFC 9635** (Oct 2024). Access request arrays shaped like RAR. Interaction modes (redirect, user code, push finish). **Grants are first-class objects with a lifecycle** (processing → pending → approved → finalized). The client continues through a continuation URI and access token with a `wait` hint, and grants can be updated or revoked [H on structure; field details M]. https://www.rfc-editor.org/rfc/rfc9635
  → The **grant-as-stateful-object** model suits wicket better than OAuth's "token is the grant". Copy the state machine, not the wire protocol.
- **RFC 8693 Token Exchange.** Use the `act` chain in audit records and in any downstream tokens wicket mints. It is not the escalation protocol [H].
- **MCP authorization, 2025-11-25** (still current for auth; 2026-07-28 changed only small points such as RFC 9207 `iss`, credential/issuer binding and deprecating DCR) [H]:
  - Runtime `insufficient_scope`: the server SHOULD return `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="…", resource_metadata=…`. The client SHOULD do **step-up authorization** and retry "no more than a few times", with retry limits and tracking of scope-upgrade attempts (SEP-835) [H].
  - **No token passthrough.** MCP servers MUST NOT pass a client's token upstream, and an upstream call needs a separate token [H]. Wicket's gateway is architecturally the MCP server that holds upstream tokens.
  - **URL-mode elicitation** (new in 2025-11-25, SEP-1036; code `-32042` `URLElicitationRequiredError`): for sensitive out-of-band interactions such as third-party OAuth, payments or API keys, the credentials **MUST NOT transit the client**. The server MUST bind the elicitation to the user identity, check that the same user completes it, and never put a pre-authenticated URL in it [H]. https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation
- **MCP 2026-07-28** (stable, latest) [H] https://modelcontextprotocol.io/specification/2026-07-28/changelog:
  - Stateless protocol. Sessions removed. Cross-call state goes through "explicit, server-minted handles passed as ordinary tool arguments" (SEP-2567). That legitimizes wicket's **handle** design at protocol level.
  - **Multi Round-Trip Requests** (SEP-2322): the server returns `resultType:"input_required"` with `inputRequests` and/or an opaque `requestState`. The client retries the *original request* with a new JSON-RPC id, `inputResponses` and the echoed `requestState`. The server MUST treat `requestState` as attacker-controlled and MUST protect its integrity (HMAC or AEAD). It SHOULD bind the principal, a short TTL and a digest of the originating method and parameters. Single-use MUST be enforced server-side [H]. https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
  - `elicitationId` and `notifications/elicitation/complete` are **removed**. The client learns the outcome by retrying [H].
  - Tasks moved to the `io.modelcontextprotocol/tasks` extension: polling `tasks/get`, `tasks/update`, and servers may return task handles unsolicited [H]. This is the right fit for long human waits, *if* clients implement it [L on client adoption].

### 3.2 Mapping "permission pending, retry with request_id"

Wicket's agent is a black box, so the "MCP client" is the agent's own harness, and the human approver is usually **not** the person sitting at that client. Approval goes out of band to the owner (CIBA-style). The agent only needs a machine-readable "not yet, retry" that it will act on.

| Surface | Wicket response while pending | On retry |
|---|---|---|
| HTTP egress (CLIs, SDKs) | `403` + `Content-Type: application/problem+json` (RFC 9457) `{type:"…/permission-pending", request_id, state:"pending", retry_after:30, requested:{…typed…}}` + `Retry-After`. For *fast tiers* (auto or parent, expected < ~20 s), consider holding the connection briefly. Or return **`503` + `Retry-After`**, which many SDKs retry automatically. That is safe because the gateway never forwarded the request [M — design suggestion; test SDK behaviour]. | Same request. The gateway matches the **request digest** (method + canonical resource + salient params + agent identity) to the decided request. No header needed, because black-box CLIs can't add one. |
| MCP tool call, clients ≤ 2025-11-25 | `CallToolResult{isError:true}` with text and `structuredContent` `{request_id, state, retry_after}`. LLM agents read tool errors reliably. | Same call. Digest match, or the optional `request_id` argument if the tool schema exposes `_wicket_request_id`. |
| MCP 2026-07-28 client with MRTR | `InputRequiredResult` with **only** `requestState`. The state is AEAD-sealed `{agent, zone, request_id, call_digest, exp}`. Caveat: "MAY retry immediately" means a busy loop, so pair it with a wait hint in `_meta` or use tasks. | Echoed `requestState`. Verify AEAD + agent + digest + TTL, then look up the ledger. |
| MCP client with tasks extension | Return a **task handle**. The gateway executes the call itself once approved, and `tasks/get` returns the result. | None. Polling replaces retry. |
| Interactive agent with a human at the client | Optionally a URL-mode elicitation pointing at wicket's approval page. Spec rules apply: identity binding, same-user check, no pre-authenticated URL. | Retry. |

Agent-facing states reuse CIBA names: `pending`, `slow_down`, `denied` (with a typed reason and the narrower alternative, if any), `expired`, `granted`.

### 3.3 Who decides, and with what information (confused-deputy hardening)
- **Reasoning-blind deciders.** Anthropic's Claude Code auto-mode classifier (2026-03-25) sees **only user messages and the agent's tool calls**. Assistant prose and tool outputs are stripped, "reasoning-blind by design", so the agent can't argue the classifier into approving. Even so, it misses 17% of real "overeager" actions (n=52) and 5.7% of synthetic exfiltration (n=1000) at 0.4% FPR [H]. https://www.anthropic.com/engineering/claude-code-auto-mode
  → Wicket's parent tier gets the trusted task text, the zone manifest and the **typed** request. The agent's justification is shown, if at all, as quoted untrusted text, and never fed to an LLM decider.
- **Field authority.** A typed request can still carry attacker-chosen *values*, such as `resource: repo:attacker/exfil`. CaMeL's provenance and CXI's "field authority" (arXiv 2607.06000, 2026-07) both require that protected sink fields trace to trusted sources [M]. For each field, wicket checks: does the value appear in the task text or the trusted manifest, or does it lie inside an existing grant's resources? If it came only from fetched data, it goes to a human, flagged "agent-supplied value".
- **Progent v3** (arXiv 2504.11703v3, 2026-05-14): policy updates are classified by **Z3 as narrowing (applied automatically) or expansion (requires approval)**, which they call "monotonic confinement". Only about 6% of AgentDojo updates were expansions [H]. In wicket, an escalation is an expansion relative to the agent's grants but may be a narrowing relative to the **zone ceiling** a human already approved. That distinction drives the tiers in §7.4.

---

## 4. Task→policy derivation and agent-security research

### 4.1 Progent (Berkeley/UCSB; v1 2025-04, v3 2026-05-14, retitled "Progent: Securing AI Agents with Privilege Control")
- DSL: `Effect(allow|forbid) tool when {conditions on args} priority n fallback f update {P…}`. Conditions cover arg index, length, comparisons, `in` and regex `match`. They are implemented as **JSON Schema** per tool argument. Default deny. Higher priority is evaluated first, with forbid before allow at equal priority. Fallbacks: terminate, ask the user, or return a message to the agent. A Z3 overlap analyzer flags overlapping rules [H, v2/v3 HTML].
- An LLM generates policies from the user query and toolset and updates them after each tool call (`LLM.update` sees the latest observation, which is a risk). v3 adds SMT narrowing/expansion classification and an approver module (auto-approve, auto-deny, per-tool rules, human). The experiments use worst-case auto-approve [H].
- Numbers (v3): AgentDojo attack success 39.9% → **1.0%** (initial policy alone 2.5%). ASB 70.3% → **3.9%**, and **0% with manually refined rules**. Below 5% across policy LLMs [H]. The independent re-evaluation (arXiv 2606.26479, 2026-06) reproduced 25.8% → 4.2% on Qwen2.5-7B, and a hand-crafted adaptive attack did not raise it (2.6%). Small scale [M].
- Limits: guarantees cover enforcement, not policy correctness. Out of scope: attacks within least privilege (preference manipulation) and text-output attacks. Proxy mode can't protect built-in tools that bypass MCP [H].
- **For wicket:** keep default-deny, priority + forbid-wins, and a fallback message telling the agent how to proceed. **Don't** let the updater see observations; wicket's re-derivation uses trusted text only.

### 4.2 CaMeL (Google DeepMind; arXiv 2503.18813 v2 2025-06-24)
- A **privileged LLM** sees only the trusted query and writes a restricted Python program (control and data flow fixed up front). A **quarantined LLM** has no tools and parses untrusted data into a schema. Its output schema includes a `have_enough_information` flag, so it can signal failure without free text. A custom interpreter attaches **capabilities** (provenance sources + allowed readers) to every value and checks **policies (Python functions)** at each tool call [H for the overall design, M for field names].
- AgentDojo: **77% of tasks with provable security vs 84% undefended** [H]. The paper discusses side channels (exceptions, timing, loop counts) as residual risk [M].
- **For wicket:** (1) derive the zone manifest **only from trusted task text**, before any data is fetched; (2) values have provenance, and sink fields check it; (3) a quarantined reader has **zero capabilities** and returns schema-bound outputs. Wicket can't rewrite a black-box agent into a program, so CaMeL applies at the *tree* level: the root planner is wicket's trusted deriver, children are black boxes, and gates play the role of the interpreter's checks.

### 4.3 FIDES (Microsoft; arXiv 2505.23643 v2, 2025-09) — read in full for the mechanisms below [H]
- **Lattice.** Product of integrity {T ⊑ U} and confidentiality. Either {L ⊑ H} or the **readers lattice** ℙ(Users): a label is the set of permitted readers, and join is intersection of readers (more data means fewer readers). Only join semi-lattices are needed.
- **Propagation.** The planner context has a label equal to the join of everything appended to it. Tool wrappers join labels. Datastore writes get a label that over-approximates the action label and the labels read.
- **Policies.** **P-T (trusted action):** the tool label must be (T, ⊤). A consequential call is allowed only if the context that produced it was entirely trusted, which gives integrity noninterference. **P-F (permitted flow):** for `send(R, d)`, d's label must allow every reader in R, which gives *explicit secrecy* (no protection against implicit flows). P-T alone is a form of **robust declassification**.
- **Selective hiding (variables).** `HIDE` stores any tool-result node whose label is *more restrictive than the current context label* in a fresh variable. The planner sees `#read_emails_0`, so its context label doesn't rise. `EXPAND` substitutes variable contents into tool arguments at call time, keeping per-argument labels. This allows "the recipient must be T but the message body may be U."
- **Constrained inspection.** `query_llm(var, schema)` runs an isolated LLM with **constrained decoding**. Its output label is (security label, **type**) in a capacity lattice `bool ⊑ enum ⊑ string`. A 1-bit `bool` derived from untrusted data can be allowed to drive consequential actions under a relaxed policy. They describe this explicitly as endorsement and say to "use with care". Their evaluation stuck with strict P-T.
- Result: with policies, FIDES stops all AgentDojo injections and completes more tasks than a strict variable-passing planner (up to 57.5% better for o1).
- **For wicket:** this is the template for gates. **Handles = FIDES variables** at the agent-tree level. **Typed fields = capacity-typed labels.** A **quarantined reader = `query_llm`**. The brief's point that labels are per agent, not per token, also matches: FIDES labels the whole context, and wicket labels the whole black-box agent.

### 4.4 "Design Patterns for Securing LLM Agents against Prompt Injections" (Beurer-Kellner et al., arXiv 2506.08837, 2025-06)
Six patterns. The core principle: once an agent has ingested untrusted input, it must be constrained so that input *cannot* trigger consequential actions [H via the author summary; Simon Willison's write-up https://simonwillison.net/2025/Jun/13/prompt-injection-design-patterns/].
1. **Action-Selector.** The agent picks from fixed actions, and no output flows back. In wicket this is a zone with egress-only, risk-limited actions.
2. **Plan-Then-Execute.** The plan is fixed before untrusted data arrives, but data can still influence arguments. In wicket, the manifest is derived first.
3. **LLM Map-Reduce.** Isolated sub-agents each process one untrusted item and return constrained results. In wicket this is **fan-out into disposable child zones joined by a typed gate**.
4. **Dual LLM.** Privileged plus quarantined, joined by symbolic variables. In wicket, handles + a quarantined reader.
5. **Code-Then-Execute.** CaMeL.
6. **Context-Minimization.** Drop the user prompt or untrusted content before the next step. In wicket, fresh agents per subtask, so label creep resets.
The authors expect no meaningful guarantees for *general-purpose* agents and recommend application-specific agents with clear trust boundaries. That supports wicket's zones.

### 4.5 Other relevant work (2025–2026)
- **Conseca**, "Contextual Agent Security: A Policy for Every Purpose" (Tsai & Bagdasarian, Google; arXiv 2501.17070, v3). An LLM generates per-task, **human-auditable** policies with rationales, from **trusted context only**, isolated from untrusted content. A deterministic enforcer checks them; the prototype ran on a Linux computer-use agent. "Trusting more context gives more precise policy but more risk" [M]. Closest prior art to wicket's manifest generator.
- **MiniScope** (Berkeley/IBM; arXiv 2512.11147, v2 2026-10-06). Reconstructs **permission hierarchies from OAuth scopes** and treats the agent as a delegate in a task-specific role. It cut simulated confirmations by **43–89%** versus per-tool prompts, and found 6 over-privileged connector configurations in ChatGPT and Claude [M — abstract]. Relevant to adapter risk classes and fewer prompts.
- **SEAgent** (arXiv 2601.11893, 2026-01). MAC/ABAC over an information-flow graph of agent–tool interactions. Covers multi-agent privilege escalation, including a **confused-deputy variant** [M — abstract].
- **SPA** (arXiv 2608.27234, 2026-08/09). A plan-first DSL with **dual-lattice IFC across queries**. Persistent results are **labelled artifacts**, and later planning sees **only semantic metadata**, never payloads. AgentDojo attack success 0%; 0.2% on their multi-query AgentDojo-MQ [M — abstract]. Directly relevant to wicket memory: persist label + metadata, keep content behind handles.
- **APPA** (arXiv 2607.24625, 2026-07/08). "Recoverable IFC". A dual-phase reference monitor (pre-dispatch label and history checks, post-dispatch output validation). **Untrusted data is inspected in disposable child branches that absorb the taint**, and results return through **schema-bounded channels**, so the parent's label is preserved. Gradual typing for unannotated tools; MCP gateway enforcement. 0 attacks in 1,320 guarded episodes [M — abstract]. This is wicket's handle and quarantined-child design, already evaluated.
- **ActPlane** (arXiv 2606.25189, 2026-06). eBPF in-kernel enforcement of an **IFC DSL** for agent harnesses, covering paths that bypass the tool layer, with semantic denial feedback. 1.9–8.4% overhead [M]. Relevant to wicket's in-VM layer (doc 01/02 territory).
- **FLOWSEAL** in "Confuse the Model, Control the Flow" (arXiv 2609.14003, 2026-09). Three *non-injection* attacks that leak private data through ordinary interaction ("channel decoupling" splits the request and the disclosure across channels). Defence: tool-level IFC with provenance and controlled declassification, leak rate 52.2% → 0.5% [M]. **Lesson: LLM judgement about privacy over attacker-shaped context fails structurally. Put confidentiality in the reference monitor.**
- **CXI**, Context-to-Execution Integrity (arXiv 2607.06000). Protected sink fields, typed releases, opaque data slots, and a deterministic gate requiring field, effect and invocation authority bound to one action manifest [L — single-author preprint].
- **Adaptive evaluation** (arXiv 2606.26479). Adaptive attacks broke 12 *in-band* defences at over 90% success, while out-of-band (reference-monitor) defences held in small tests [M]. This supports wicket's premise: enforcement outside the model.
- "Capability Gates Are Not Authorization" (arXiv 2606.28679, 2026-06). Frameworks gate *which tools*, not *which values*, and the paper argues for per-call value authorization [L — search snippet].
- **Benchmarks.** AgentDojo (arXiv 2406.13352), ASB (arXiv 2410.02644), MCPSecBench (2508.13220: 17 attack types, 4 surfaces), MCPTox (2508.14925: tool poisoning on 45 live servers, o1-mini 72.8% attack success), MCP-SafetyBench (2512.15163, rev. 2026-03: rug pulls, multi-server), OWASP AgentThreatBench (used by APPA) [M]. For wicket's "smallest tests", AgentDojo-style task/injection pairs are the template, but none of them targets *black-box agents behind a gateway*, so wicket needs its own harness.

### 4.6 Concrete mechanisms to extract

| Mechanism | Source | Wicket form |
|---|---|---|
| Policy derived from trusted query only | CaMeL, Conseca, Progent init | Manifest generator sees the task text + org data-class catalogue + adapter catalogue. Never fetched data or agent context. |
| Monotonic confinement, SMT-classified updates | Progent v3 | Every change to a zone policy is classified by SymCC (`check_implies`): narrowings automatic, expansions go to a decider. |
| Variables / handles | FIDES, MCP SEP-2567, SPA | `Handle{id, label, capacity:Handle, schema?}`. Parents route handles without reading them. |
| Capacity-typed outputs | FIDES type lattice | Gate schema fields carry `Capacity`. Bool or enum may be endorsed per gate rule. |
| Quarantined reader | Dual LLM, CaMeL Q-LLM, FIDES `query_llm` | A zero-capability, zero-egress microVM or sandbox. Input: handle(s) + output schema. Output: capacity-bounded value. |
| Disposable tainted children | APPA, Map-Reduce pattern | Default for "read untrusted then decide": spawn a child zone, get a typed result, destroy the child. |
| Reasoning-blind approver | Claude Code auto mode | Deciders get typed requests + field provenance, not the justification. |
| Field authority | CaMeL, CXI | Check the provenance of each field in escalation requests and consequential actions. |

---

## 5. Information-flow labels for black-box agents

### 5.1 Classic DIFC, distilled
- **Asbestos** (Efstathopoulos et al., SOSP 2005). Per-process labels and event processes. The HiStar label format comes from it. https://www.scs.stanford.edu/~dm/home/papers/efstathopoulos:asbestos.pdf [M URL]
- **HiStar** (Zeldovich et al., OSDI 2006). Six kernel objects, every one labelled. Threads own categories they can untaint ("ownership", ★). **Gates** are the only way to cross protection domains: the caller donates a thread, which runs with the gate's label and privileges. Wicket's "gate" has the same meaning, and the naming is a happy precedent [H]. https://www.usenix.org/legacy/event/osdi06/tech/full_papers/zeldovich/zeldovich.pdf
- **Flume** (Krohn et al., SOSP 2007). DIFC for **standard OS abstractions (processes, pipes, fds)** with a **user-level reference monitor** on Linux. Each process has a secrecy label S and an integrity label I (sets of tags), plus a capability set O of `t⁺` (may add tag t) and `t⁻` (may drop t = declassify). **Endpoints** label each channel. Safe message rule: S_p ⊆ S_q, I_q ⊆ I_p (adjusted by capabilities). Porting MoinMoin changed only 2% of its code [H]. https://www.read.seas.harvard.edu/~kohler/pubs/krohn07information.pdf
  → **Flume is the closest classic analogue to wicket**: coarse, process-granular labels on black-box code, enforced by a monitor that only sees IPC and syscalls. Wicket's unit is the agent VM, and the IPC is the gateway, proxy and gates.
- **LIO** (Stefan, Russo, Mitchell, Mazières, Haskell Symposium 2011). A **floating current label** (rises as you read) bounded by a **clearance** (the ceiling on how high it may float). Writes are allowed only to objects at or above the current label. **DCLabels** (NordSec 2011) are CNF formulas over principals for secrecy and integrity, with privileges as principals [H on concepts]. https://hackage.haskell.org/package/lio
  → **Agent label = floating current label; zone ceiling = clearance.** Reading something above the clearance is denied outright. That is the "an agent can read data only if its clearance covers the label" rule from the brief.
- **DLM** (Myers & Liskov 1997/2000). Decentralized labels with owners and readers; owner-only declassification (who may declassify is part of the label). Wicket's "declassification by human or trusted process" is DLM ownership in practice.

### 5.2 Label creep and how to fight it
Label creep: everything turns ⊤ by the time results reach the root. Mitigations, ordered by how much they help a black-box design:
1. **Fresh agents per subtask** (Context-Minimization). Labels are per agent instance, and a new microVM starts at ⊥. Cheap with snapshots or microVMs.
2. **Handles, not contents** (FIDES variables, SPA metadata-only, MCP stateless handles). A parent routing handles stays at its own label.
3. **Typed low-capacity gate outputs** (FIDES capacity lattice). `tests_passed: bool` from a tainted child can be endorsed by the gate rule. Free text can't.
4. **Disposable tainted branches** (APPA). The child absorbs the taint and dies, and the parent stays clean.
5. **Coarse but not too coarse storage labels.** Label per mount, store or provider resource, not per byte. Per-*task* stores are deleted at task end, so labels can't accumulate across tasks.
6. **Explicit declassification and endorsement**, logged as gate events, with a named decider.
7. **Don't label what you can't use.** A label tag that no policy ever checks is noise. Keep the tag vocabulary small and org-defined.

### 5.3 Labelling provider-side state
The brief's hard case: a child writes a GitHub comment, and a sibling reads it later.
- The gateway keeps a **label store**: `(provider, canonical_resource_id) → {label, writer_agent, task, version/etag, written_at}`. It is updated on every *allowed* write, with the writer's current label.
- On a read, the effective label = the **join** of the stored label (if any) and the **adapter default label** for that resource class. Example: a public-repo issue comment defaults to taint `{ext:github-public}` because anyone can edit or append to it. Private-repo source code defaults to conf `{repo:acme/api}` with taint `{}` if only org members can write. Taking the join stays conservative even if outsiders edited the resource after wicket's write, which wicket cannot see.
- **Resolution before decision.** Opaque IDs (issue 4821 → repo) need resolving before labelling. Bind the decision to the resolved version (etag or `updated_at`) to narrow the TOCTOU window. Where providers support conditional writes (`If-Match`), use them [M].
- **Shared-state edges.** If zone A may write resource class R and zone B may read R, the zone/gate view **must draw an edge A→B** even with no declared gate. Compute these edges from policies (Cedar TPE or SymCC: "∃ resource writable by A and readable by B").
- **Retention.** Labels for resources a task created are kept after task end, because the resource persists at the provider. Mark them "orphaned-label". Any later wicket task reading them inherits the label.

### 5.4 Proposed coarse label model for wicket

```
Label = (Conf, Taint)          — plus Capacity on gate-crossing values
Conf  = Set<DataClass>          join = ∪   (more tags = more secret)
         DataClass examples: "org:internal", "repo:acme/api", "pii", "cust:acme", "secret:prod"
Taint = Set<SourceTag>          join = ∪   (∅ = trusted: task text, owner, wicket itself)
         SourceTag examples: "web", "email:external", "github:public-writable", "agent-output:untrusted"
Capacity = Bool < Enum(n) < Int(range) < BoundedStr(n) < Str < Handle
```

Rules (all enforced by gateway, proxy and gates; none by the agent):
1. **Read (clearance).** An agent may read X iff `X.conf ⊆ zone.clearance` and `X.taint ⊆ zone.taint_admit`. The agent's current label then becomes `agent.label ⊔ X.label`.
2. **Send (no write-down).** An egress to destination D is allowed iff `agent.conf ⊆ D.clearance`. Destinations are adapter-defined: "public internet" has clearance ∅, `github:acme/api` has `{org:internal, repo:acme/api}`, and so on. The rule covers *provider writes too*: writing a GitHub comment is an egress to that resource's readers.
3. **Act (integrity).** An action of risk ≥ `R2_irreversible` is allowed only if `agent.taint ⊆ zone.action_taint_allow[risk]`. A writer zone typically allows `{}` (or `{github:acme-private}`) at R2+, so an agent that read `web` can't push. This is FIDES P-T, coarsened to the agent.
4. **Gate crossing.** A value crossing gate G has label (ℓ, κ). The gate rule decides what survives: `TypedFields(schema)` gives each field its own κ, and the rule may **endorse** (drop specific taint tags) fields with κ ≤ Enum. `HandlesOnly` passes an opaque reference whose label travels with it, and the receiver's label is untouched until it dereferences. `QuarantinedReader` and `Declassify{by}` are explicit.
5. **Stores inherit.** Writing to a store or provider resource joins the writer's label into the stored label (§5.3).
6. **Instruction rule.** Data whose taint is not ⊆ the reader's `action_taint_allow` may be *read* but is presented as data (handles, typed fields). It is never placed in a planner's instruction channel (task text, manifest, adapter generator).
7. **Declassify or endorse** only at gates, by `Decider::{Human, TrustedProcess(id)}`. Each event is logged with before and after labels.

UI summary of integrity: `Trusted` (∅), `Internal` (only org-writable tags), `Untrusted` (any external tag). Humans see three colours; policy sees sets.

Why sets rather than a 2×2 lattice: wicket needs "may push to acme/api although it read acme/api issues (org-writable) but not the web". A 2-point integrity lattice can't express that. Sets of source tags (Flume/DLM style) can, and they stay a lattice (powerset, ∪). [M — design judgment]

---

## 6. Audit and human understanding

### 6.1 Evidence on approval fatigue
- Claude Code: users accept **93%** of manual permission prompts, and the stated motivation for auto mode is that people "stop paying close attention" (2026-03-25) [H]. Auto mode became the default for paid plans in Aug 2026 [L — press].
- Claude Code sandboxing cut permission prompts by **84%** in internal use (Anthropic, Oct/Nov 2025), by moving from per-action prompts to *boundaries set up front* [H]. https://www.anthropic.com/engineering/claude-code-sandboxing
- MiniScope: task-role hierarchies cut confirmations by 43–89% versus per-tool prompts [M].
- Progent v3: only about 6% of policy updates were expansions needing approval [H].
- Consensus in practitioner writing: approve **permission deltas and constrained intents, not individual actions**, and gate only irreversible or external effects [L — blogs, e.g. https://workos.com/blog/approval-fatigue-agent-governance].
→ This supports the brief: humans approve **zones, gates and deltas**, and the tiers keep the human rate low.

### 6.2 Existing blast-radius and diff tooling
- **AWS IAM Access Analyzer**: *unused access* findings; **custom policy checks** `CheckNoNewAccess` (does the updated policy grant anything the old one didn't?) and `CheckAccessNotGranted` (does a policy grant a given dangerous permission?), meant for CI/CD gates. It runs on Zelkova automated reasoning (SMT) [H on features; Zelkova from AWS's published papers]. https://aws.amazon.com/blogs/aws/iam-access-analyzer-updates-find-unused-access-check-policies-before-deployment/
  → Wicket analogues: `check_implies(new, old)` for "no new access", and `check_disjoint(zone_policy, dangerous_set)` for "never grants workflow writes".
- **Cedar Analysis**: compare (more or less permissive, with a witness) plus shadowed and impossible-rule findings (§1.2).
- **Kubernetes**: `rbac-tool` (who-can, viz, policy-gen), `rakkess` (access matrix), KubiScan (risky roles and escalation verbs `bind`, `escalate`, `impersonate`) [M]. Lesson: **escalation-capable verbs** deserve their own highlight. In wicket those are anything that changes policy, mints credentials, writes CI config, or creates agents.
- **Attack-path graphs**: BloodHound (AD/Azure) and PMapper (AWS IAM) compute transitive "can become" edges. Wicket's equivalent edges are gates, shared provider state and auto-grantable escalations [M].

### 6.3 UX patterns for wicket
1. **Generated, never drawn.** The zone/gate graph is compiled from the live Cedar policies, ledger and label store, including *implicit edges* from shared provider state (§5.3).
2. **"If this agent is compromised"** = `Reach(z)` (ceiling ∪ live grants) ∪ **`AutoGrantable(z)`** (anything the auto or parent tiers would grant without a human; this is easy to forget) ∪ `Send(z)` (destinations + clearances) ∪ `Influence(z)` (for each outgoing gate: what the receiving zone may do with κ-bounded values from z, recursively) ∪ `SharedState(z)`. Show it as a **list of concrete worst cases** ("can push to acme/api:feature/*", "can post to #eng (public to 400 people)", "can influence writers' tests_passed: 1 bit"), each with a SymCC counterexample available as a witness.
3. **Approval cards are typed diffs.** Example: "+ write `acme/api/.github/workflows/ci.yml` (R4: code exec with repo secrets) — 1 use, 10 min." Show the blast-radius *delta*, not the total. Show **field provenance**: green = from task text, amber = inside existing grant, red = agent-supplied. Pre-select the narrowest option. Show a CIBA-style `binding_message` code on both the agent-run page and the phone.
4. **The justification is shown as untrusted** (quoted, de-emphasised) and never as the headline.
5. **Timeline of diffs.** "14:02 writers +repo:Y write (parent G-12, expires 14:12)". Each entry links to its decider and the evidence.
6. **Ratchet budget.** Track the cumulative grant set against the original manifest (risk-weighted count of new resources × verbs). Crossing the budget forces a human review of the *whole* delta, not just the next item.
7. **Rubber-stamp detection.** Per (task class, request type), if approval > ~95% over N ≥ 20, suggest an auto-grant rule. If denial > ~95%, suggest auto-deny. The suggestion is itself a policy change, so it is checked with `check_implies` and shown as a diff.
8. **Collapse to 7 or fewer zones** at the top level and expand on demand (from the brief). The SELinux lesson again.

---

## 7. Recommendations for wicket

### 7.1 Policy engine
- **Cedar** is the policy language for org ceilings, zone policies, adapter "dangerous pattern" forbids and gate rules. Embed `cedar-policy` 4.14.x in the control plane, the gateway and the proxy. Keep authored policies inside a **SymCC-friendly subset** (no experimental features; `like` for path scoping), enforced by CI.
- **`cedar-policy-symcc`** with a **cvc5 1.3.1 sidecar**, off the hot path, for: (a) child zone ⊆ parent zone at zone creation; (b) every policy change → narrowing (auto) vs expansion (decider), as in Progent v3; (c) generated adapter rules ⊆ the conservative default, with no overlap with the dangerous list (`check_disjoint`); (d) CI "no new access" on org policy PRs; (e) blast-radius witnesses.
- **Grants are not Cedar policies authored by hand.** They are values in a small capability algebra (§7.5) with **syntactic, per-field subsumption**, after the closed vocabulary of the niyikiza draft. Grants are injected into Cedar evaluation as entities or context. Request decision = `Cedar(org ∧ zone ∧ forbids)` ∧ `∃ live grant ⊇ request` ∧ `label rules` ∧ `ledger(uses, expiry, revocation)`.
- regorus only to lint adapter DSL documents if needed. Skip Oso and Zanzibar.

### 7.2 Tokens and where they live
- **Never in the sandbox.** Sandbox identity = transport (per-VM netns, vsock CID or a supervisor-held key). CLIs get non-secret placeholders, and the proxy injects real credentials.
- **Biscuit** carries authority between the control plane and enforcement points. The authority block is the zone ceiling digest + root grant. Each delegation appends a block, and leaf grants are **sealed**. Approvals are **third-party blocks** signed by the approver service key (`approved(request_id, decider)`). **Revocation IDs** give subtree revocation. Wicket-aware orchestrators get opaque grant handles and ask the control plane to attenuate.
- **Ledger** (server state) holds use counts (reserve, commit, refund-on-definite-failure), approvals, revocation lists and the cumulative-grant ratchet. The authorizer turns ledger rows into ambient facts.
- Upstream: mint the **narrowest native credential** per task (GitHub App repo- and permission-restricted tokens, STS session policies, GCP CAB). No token passthrough (MCP spec).
- [M] If wicket stays single-host for a long time, skip Biscuit in v1 and use a signed ledger. Compile the capability algebra so Biscuit can drop in later.

### 7.3 Label model
§5.4: `(Conf: Set<DataClass>, Taint: Set<SourceTag>)` + `Capacity` on gate values. Floating agent label, zone clearance, and per-risk taint allowances for actions. A gateway label store for provider state, with adapter default labels and the join rule. Declassification and endorsement only at gates by named deciders. Creep is controlled by fresh agents, handles, typed gates and disposable tainted children (APPA).

### 7.4 Escalation state machine

```
             ┌─────────────── malformed / unmapped field ──────────────► Rejected(Invalid)
Received ──► Validated ──► Narrowed ──► Classify
  (typed, canonicalized,   (narrowest grant         │
   digest-bound)            covering the call)      │
                                                     ├─ outside zone ceiling ∪ parent authority ──► PendingUp(parent zone | Human)
                                                     ├─ forbidden by org/dangerous list ─────────► Denied(Forbidden, alt?)
                                                     ├─ ⊆ zone ceiling ∧ risk ≤ auto_max
                                                     │   ∧ field-authority OK ∧ ratchet OK ───────► Granted (tier=Auto)
                                                     ├─ ⊆ parent's authority ∧ re-derivation
                                                     │   from trusted task text says yes ────────► Granted (tier=Parent)
                                                     └─ else ───────────────────────────────────► PendingHuman{auth_req_id, binding_code, expires_at}
PendingHuman ──approve(narrowed?)──► Granted │ ──deny──► Denied(Human) │ ──timeout──► Expired
Granted ──► Active ──(uses exhausted | expiry | task end | revoke(subtree))──► Closed
Agent view:  pending(retry_after) · slow_down · granted · denied(reason, narrower_alt) · expired
```

- **Re-derivation (Parent tier)** is an LLM call that sees **only** the trusted task text, the zone manifest and the canonical typed request. It is reasoning-blind and has no access to the child's context. Disagreement or uncertainty goes up a tier.
- Every grant is **narrower than or equal to** the ask (RAR semantics) and expires at task end at the latest.
- Pending agents: return the §3.2 responses. For waits longer than about 2 minutes, snapshot the microVM (doc on isolation).

### 7.5 Zone/gate data model (Rust-ish)

```rust
// ---- identities (ULIDs) ----
pub struct AgentId(Ulid); pub struct ZoneId(Ulid); pub struct GateId(Ulid);
pub struct GrantId(Ulid); pub struct RequestId(Ulid); pub struct HandleId(Ulid);

// ---- resource model (adapter-canonicalized) ----
pub struct ProviderId(SmolStr);                     // "github", "slack", "fs", "net"
pub struct ResourcePath(Vec<SmolStr>);              // ["repo","acme/api","contents","infra","ci.yml"]
pub enum ResourcePattern {                          // closed vocabulary ⇒ decidable containment
    Exact(ResourcePath),
    Prefix(ResourcePath),                           // subtree
    Segment { prefix: ResourcePath, any_one: bool },// prefix/*  (one level)
}
#[derive(PartialOrd, Ord)]
pub enum RiskClass { R0Read, R1ReversibleInternal, R2IrreversibleInternal, R3ExternalEffect, R4CodeExecOrPrivilege }
pub enum Verb { Read, List, Create, Update, Delete, Execute, Send, Admin, Provider(SmolStr) }

pub enum Constraint {                                 // each variant has a sound `subsumes`
    Exact(Value), OneOf(BTreeSet<Value>), NotOneOf(BTreeSet<Value>),
    Range { min: i64, max: i64 }, Prefix(String), Any,
}
pub struct Capability {
    pub provider: ProviderId,
    pub resources: ResourcePattern,
    pub verbs: BTreeSet<Verb>,
    pub max_risk: RiskClass,
    pub args: BTreeMap<SmolStr, Constraint>,          // closed-world: unlisted args denied
}
impl Capability { pub fn is_subset_of(&self, other: &Capability) -> bool { /* per-field */ } }
pub struct CapabilitySet(Vec<Capability>);          // ⊆ = every member covered by some member

pub struct Budget { pub expires_at: Timestamp, pub max_uses: Option<u32>, pub egress_bytes: Option<u64> }

// ---- labels ----
pub struct DataClass(SmolStr);  pub struct SourceTag(SmolStr);
pub struct Label { pub conf: BTreeSet<DataClass>, pub taint: BTreeSet<SourceTag> }   // join = (∪, ∪)
pub enum Capacity { Bool, Enum(u16), Int { min: i64, max: i64 }, BoundedStr(u32), Str, Handle }
pub struct Destination { pub id: SmolStr, pub provider: ProviderId, pub pattern: ResourcePattern,
                         pub clearance: BTreeSet<DataClass> }        // readers of what you send

// ---- zones & gates ----
pub struct Zone {
    pub id: ZoneId, pub name: String, pub parent: Option<ZoneId>,
    pub reach: CapabilitySet,                        // ceiling ⊆ parent.reach (checked; SymCC on Cedar form)
    pub clearance: BTreeSet<DataClass>,              // what it may see ⊆ parent.clearance
    pub taint_admit: BTreeSet<SourceTag>,            // which taint it may ingest at all
    pub action_taint_allow: BTreeMap<RiskClass, BTreeSet<SourceTag>>, // integrity rule per risk
    pub send: Vec<Destination>,                      // egress
    pub stores: Vec<StoreId>,                        // task-scoped memory; deleted at task end
    pub auto_max_risk: RiskClass,                    // auto tier ceiling
    pub ratchet_budget: u32,
    pub policy: CedarPolicySetRef,                   // compiled from the above + org policy
}
pub enum Direction { Up, Down, Lateral }
pub enum GateRule {
    TypedFields { schema: Vec<(SmolStr, Capacity)>, endorse: BTreeMap<SmolStr, BTreeSet<SourceTag>> },
    HandlesOnly,
    QuarantinedReader { output: Vec<(SmolStr, Capacity)>, reader_profile: SandboxProfileRef },
    Declassify { by: Decider, to: Label },
    HumanApproval,
}
pub struct Gate { pub id: GateId, pub from: ZoneId, pub to: ZoneId, pub dir: Direction, pub rules: Vec<GateRule> }
pub struct Handle { pub id: HandleId, pub origin: AgentId, pub label: Label, pub schema: Option<SchemaRef>, pub expires_at: Timestamp }

// ---- agents, grants, ledger ----
pub struct Agent { pub id: AgentId, pub zone: ZoneId, pub current: Label /* floating */, pub identity: TransportIdentity }
pub enum Decider { Static(PolicyId), Parent(ZoneId), Human(PrincipalId), TrustedProcess(SmolStr) }
pub struct Grant {
    pub id: GrantId, pub parent: Option<GrantId>, pub holder: ZoneOrAgent,
    pub cap: Capability, pub budget: Budget, pub decided_by: Decider,
    pub request: Option<RequestId>, pub biscuit_revocation_id: [u8; 64],
    pub state: GrantState,                           // Active | Exhausted | Expired | Revoked
}

// ---- escalation ----
pub enum FieldProvenance { TaskText, Manifest, InsideGrant(GrantId), AgentSupplied }
pub struct EscalationRequest {
    pub id: RequestId, pub agent: AgentId, pub zone: ZoneId,
    pub ask: Capability, pub budget: Budget,          // RAR-shaped on the wire
    pub call_digest: [u8; 32],                        // binds to the blocked call
    pub provenance: BTreeMap<SmolStr, FieldProvenance>,
    pub justification: Untrusted<String>,             // never shown to LLM deciders
}
pub enum EscalationState {
    Received, Validated, Narrowed { proposal: Capability },
    PendingUp { to: Decider, retry_after: Duration },
    PendingHuman { auth_req_id: String, binding_code: String, expires_at: Timestamp },
    Granted(GrantId), Denied { reason: DenyReason, narrower_alt: Option<Capability> },
    Expired, Withdrawn, Rejected(InvalidReason),
}

// ---- the one decision function every enforcement point calls ----
pub enum Decision {
    Allow { grant: GrantId, label_effect: Label /* join into agent */, store_label: Option<Label> },
    Deny  { reason: DenyReason, explain: Explanation /* Cedar determining policies + label rule */ },
    Pending { request: RequestId, retry_after: Duration },
}
```

### 7.6 Open risks
1. **Re-derivation is still an LLM in the TCB.** Progent shows LLM-generated policies are not 0% (ASB 3.9%). Field-authority checks and conservative auto ceilings limit the damage, but the parent tier will make mistakes, so start with the parent tier off (auto or human only) and measure.
2. **Coarse per-agent taint may starve utility.** Any coding agent that reads an issue comment becomes "untrusted" and can't push. Disposable children and typed gates are the answer, but utility costs are unmeasured. Run the brief's three-way smallest test (free text vs typed vs handles) early.
3. **Provider-side label store is incomplete by design.** Wicket can't see writes by outsiders or provider-side triggers (mentions → email). Default labels must be pessimistic, and adapter quality dominates.
4. **SymCC limits** (feature coverage, cvc5 runtime on large policies, the symbolic-hierarchy subtlety in §1.2) are not fully documented [L]. Prototype the child ⊆ parent proof on realistic policies before building on it.
5. **MRTR and tasks client support** in black-box agents is unknown. The tool-error-text fallback is what will actually be used, and agents may loop or give up. Test with Claude Code, Codex and others.
6. **Covert channels** (timing, request sizes, file names, escalation-request contents) remain. Rate-limit and size-limit escalation requests, and log anomalies.
7. **Biscuit's value depends on distribution.** It may be over-engineering for v1 [M].
8. **Spec churn.** MCP changed elicitation semantics between 2025-11-25 and 2026-07-28. The IETF agent-token drafts are individual drafts. Pin versions, and keep wicket's internal model independent of the wire protocols.

---

## Sources (primary first)
- Cedar: https://crates.io/crates/cedar-policy · https://docs.rs/cedar-policy-symcc · https://github.com/cedar-policy/cedar (symcc README) · https://cedar-policy.github.io/cedar-spec/docs/Cedar/SymCC.html · https://github.com/cedar-policy/rfcs/blob/main/text/0095-type-aware-partial-evaluation.md · https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/ · AutoCedar https://arxiv.org/abs/2607.03656
- regorus: https://github.com/microsoft/regorus · Oso deprecation: https://github.com/osohq/oso · Zanzibar: https://www.usenix.org/conference/atc19/presentation/pang
- Biscuit: https://doc.biscuitsec.org/reference/specifications · https://docs.rs/biscuit-auth/6.0.0 · https://github.com/eclipse-biscuit/biscuit-rust · CVE-2024-42350 https://nvd.nist.gov/vuln/detail/CVE-2024-42350
- Macaroons at Fly.io: https://fly.io/blog/macaroons-escalated-quickly/ · https://fly.io/blog/operationalizing-macaroons/
- UCAN: https://github.com/ucan-wg/spec
- IETF: RFC 9396 https://www.rfc-editor.org/rfc/rfc9396 · RFC 9635 https://www.rfc-editor.org/rfc/rfc9635 · RFC 8693 https://www.rfc-editor.org/rfc/rfc8693 · CIBA https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html · draft-niyikiza-oauth-attenuating-agent-tokens-01 https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-01 · Transaction tokens for agents https://www.ietf.org/archive/id/draft-oauth-transaction-tokens-for-agents-06.html
- MCP: authorization 2025-11-25 https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization · elicitation https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation · 2026-07-28 changelog https://modelcontextprotocol.io/specification/2026-07-28/changelog · MRTR https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr · ext-auth https://github.com/modelcontextprotocol/ext-auth
- Agent security: Progent https://arxiv.org/abs/2504.11703 (v3) · CaMeL https://arxiv.org/abs/2503.18813 · https://github.com/google-research/camel-prompt-injection · FIDES https://arxiv.org/abs/2505.23643 · https://github.com/microsoft/fides · Design patterns https://arxiv.org/abs/2506.08837 · Conseca https://arxiv.org/abs/2501.17070 · MiniScope https://arxiv.org/abs/2512.11147 · SEAgent https://arxiv.org/abs/2601.11893 · SPA https://arxiv.org/abs/2608.27234 · APPA https://arxiv.org/abs/2607.24625 · ActPlane https://arxiv.org/abs/2606.25189 · FLOWSEAL https://arxiv.org/abs/2609.14003 · CXI https://arxiv.org/abs/2607.06000 · Adaptive eval https://arxiv.org/abs/2606.26479 · Runtime authorization for acquired resources https://arxiv.org/abs/2609.14744 · Capability gates https://arxiv.org/abs/2606.28679 · AgentDojo https://arxiv.org/abs/2406.13352 · ASB https://arxiv.org/abs/2410.02644 · MCPSecBench https://arxiv.org/abs/2508.13220 · MCPTox https://arxiv.org/abs/2508.14925 · MCP-SafetyBench https://arxiv.org/abs/2512.15163
- Classic IFC: Flume https://www.read.seas.harvard.edu/~kohler/pubs/krohn07information.pdf · HiStar https://www.usenix.org/legacy/event/osdi06/tech/full_papers/zeldovich/zeldovich.pdf · Asbestos (SOSP 2005) · LIO https://hackage.haskell.org/package/lio · DLM (Myers & Liskov, TOSEM 2000)
- UX/audit: https://www.anthropic.com/engineering/claude-code-auto-mode · https://www.anthropic.com/engineering/claude-code-sandboxing · IAM Access Analyzer https://aws.amazon.com/blogs/aws/iam-access-analyzer-updates-find-unused-access-check-policies-before-deployment/ · https://workos.com/blog/approval-fatigue-agent-governance
