# 04 — Enforcement plane: MCP gateway + credential-injecting egress proxy

Research date: 2026-11-08. Scope: the parts of wicket that sit **outside** the sandbox and
mediate everything the agent can do to the outside world: an MCP gateway (tool calls), an HTTP(S)
egress proxy (gh/aws/curl/SDKs/git), the shared policy engine and resource model, the provider
adapter DSL, codemode, and response-side controls.

Confidence markers: **[H]** verified against a primary source today; **[M]** primary source
partly checked, or inferred from strong evidence; **[L]** my judgement or secondary sources only.

---

## 0. Summary of findings

1. **MCP moved under our feet.** The current spec is **2026-07-28** (stable since 2026-07-28;
   the RC locked 2026-05-21). It removes sessions and the `initialize` handshake, adds
   `server/discover`, replaces server-initiated elicitation/sampling/roots with Multi
   Round-Trip Requests (MRTR), moves Tasks into an extension, deprecates Roots/Sampling/Logging,
   and makes Streamable HTTP carry `Mcp-Method`/`Mcp-Name` headers for gateways. Clients still
   speak 2025-11-25 too, so a gateway has to speak both. **[H]**
2. **The Rust SDK is usable for a gateway.** `rmcp` 3.9.0 (2026-11-05) implements 2026-07-28
   with 2025-11-25 compatibility, has server and client roles, stdio/child-process/streamable-HTTP
   transports and OAuth. **agentgateway's own MCP gateway is built on rmcp 3.9.0**, which settles
   whether you can build one with it. **[H]**
3. **agentgateway is the best reference but not a library.** It's Rust, Apache-2.0, v1.7.0
   (2026-10-27), with CEL-based MCP authorization on tool/prompt/resource names. All workspace
   crates are `publish = false`, so it's an application to deploy or study, not a crate to
   embed. Its policies work on tool names, not on argument semantics. **[H]**
4. **The two closest prior-art egress proxies already do most of what wicket needs, and both
   expose an external-decider seam:**
   - **Anthropic `srt`/`srt-proxy`** (anthropics/sandbox-runtime, Apache-2.0, v0.0.81,
     2026-10-20). It terminates TLS, masks credentials (a sentinel in the sandbox, the real value
     injected on egress to listed hosts), re-signs SigV4, rewrites requests, and runs a
     **framed JSON "decider" protocol v1** in which a separate process allows or denies each
     request, places a credential, or asks for the body. It fails closed, keeps the CA key in
     the proxy, and refuses ambiguous request targets. **[H]**
   - **OpenAI `codex-network-proxy`** (Rust, built on **rama 0.3.0-alpha.4**). It has MITM
     hooks by host/method/path, "limited" mode (GET/HEAD/OPTIONS only), placeholder-exact
     header and body secret substitution, native SigV4 re-signing, and a `NetworkPolicyDecider`
     library hook. **[H]**
   - **Claude Code on the web's GitHub proxy** swaps a scoped in-VM credential for the real
     token, scopes API calls to attached repos, rejects tag pushes and branch deletions,
     **rejects all GraphQL**, and never sends network secrets to registries or the Anthropic
     API. **[H]**
5. **The adapter DSL has strong prior art.** AWS publishes machine-readable JSON per service
   (actions, resources/ARN formats, condition keys, an operation→authorized-actions map, and
   risk annotations `IsWrite`/`IsList`/`IsPermissionManagement`/`IsDataPlane`/`IsTaggingOnly`).
   GitHub publishes a **machine-readable permission→endpoint map** in `github/docs`
   (`src/github-apps/data/<version>/fine-grained-pat-permissions.json`, 1,075 entries), and its
   OpenAPI marks **26 operations `x-github.triggersNotification`**. Cloudflare's OpenAPI carries
   `x-api-token-group` on 3,045 operations. These are the "evidence floors" the
   narrower-never-wider generator should check against. **[H]**
6. **Git push enforcement is feasible.** Ref rules come cheaply from pkt-line parsing. Path
   rules (`.github/workflows/`) need pack resolution against the repo's existing objects (thin
   packs), so the robust design is **store-and-forward**: receive the push into a local mirror's
   quarantine and check it there, then push upstream with the real credential. Deny SSH. **[M]**
7. **Codemode doesn't change the gateway's core.** Every typed call from inside a codemode
   sandbox is still an RPC to the reference monitor. What it changes: rate and budget controls,
   handle-based data flow (intermediate data never reaches the model), and the gateway becomes
   a **code generator for typed stubs that already encode the narrowed policy**. For Claude Code
   specifically, bash plus curl/gh already is codemode, so the egress proxy is that surface. **[M]**
8. **Prompt-injection scanning is not a boundary.** "The Attacker Moves Second" (Nasr, Carlini
   et al., arXiv 2510.09023, Oct 2025) bypassed 12 published defenses at >90% attack success.
   Scanners may only make decisions stricter (tripwires and labels), never grant. **[H]**

---

## 1. MCP itself

### 1.1 Spec revisions and what changed

| Revision | Status (2026-11-08) | Gateway-relevant changes |
|---|---|---|
| 2025-06-18 | old | structured tool output, OAuth resource-server role, protected resource metadata |
| **2025-11-25** | previous, still widely deployed | URL-mode elicitation (SEP-1036), experimental Tasks (SEP-1686), Client ID Metadata Documents (SEP-991), tool calling in sampling (SEP-1577), elicitation enum changes (SEP-1330), incremental scope step-up |
| **2026-07-28** | **current stable** | stateless core, `server/discover`, MRTR, Tasks as extension, `subscriptions/listen`, `Mcp-Method`/`Mcp-Name`/`Mcp-Param-*` headers, cacheable lists, RFC 9207 `iss`, DCR deprecated, Roots/Sampling/Logging deprecated |

Sources: [2025-11-25 changelog](https://modelcontextprotocol.io/specification/2025-11-25/changelog),
[2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog),
[release blog](https://blog.modelcontextprotocol.io/posts/2026-07-28/),
[RC blog](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/). **[H]**

Key 2026-07-28 facts for a gateway **[H]**:

- **No protocol sessions** (SEP-2567). `Mcp-Session-Id` is gone, and `tools/list` "MUST NOT vary
  per-connection" but **MAY vary by the authorization presented on the request**. That's
  exactly what a policy-filtering gateway does: different principals see different tool lists.
  Cross-call state uses server-minted handles passed as ordinary tool arguments. The spec's
  security page says a handle "is a name, not a capability" and must be bound to the
  authenticated user.
- **No `initialize`** (SEP-2575). Every request carries protocol version, client capabilities
  and client info in `_meta`. A gateway can't negotiate once and cache; it has to check `_meta`
  on every request, which also means an untrusted client can claim different capabilities per
  request.
- **MRTR** (SEP-2322) replaces server→client `elicitation/create`, `sampling/createMessage` and
  `roots/list`. A server returns `resultType: "input_required"` with `inputRequests`, plus an
  opaque `requestState` it wants echoed back, and the client retries with `inputResponses`.
  For a gateway, this is a clean, stateless way to say "needs human approval: retry later".
- **Tasks extension** `io.modelcontextprotocol/tasks` (SEP-2663): polling with `tasks/get`,
  input with `tasks/update`, no `tasks/list`, and servers may return a task handle unsolicited.
  This suits the escalation path ("permission pending" while a human decides) when the client
  supports it.
- **Standard headers** (SEP-2243): `Mcp-Method`, `Mcp-Name` and `x-mcp-header`→`Mcp-Param-{name}`
  let L7 intermediaries route without parsing bodies. Mismatches are a defined error
  (`HeaderMismatch`, renumbered to `-32020`). **wicket must treat headers as hints and decide
  on the parsed body**: the agent controls both, and a body/header split is a classic parser
  differential.
- **Cacheable list results** (SEP-2549): `ttlMs` plus `cacheScope: public|private`.
  agentgateway's design note concludes a policy-applying gateway should **disable caching of
  proxied results** and sanitize upstream cache hints, because only the gateway knows its
  policy inputs. Adopt this.
- **Deprecated** (SEP-2577): Roots, Sampling, Logging. A gateway should **block sampling
  entirely**: server-initiated LLM calls are an exfiltration and confused-deputy channel. It
  should also block roots, since filesystem disclosure belongs to the sandbox config, not MCP.
- Schema loosened (SEP-2106): `inputSchema`/`outputSchema` may use any JSON Schema 2020-12
  keyword, and `structuredContent` may be any JSON value. That raises validator complexity.
  wicket should validate against **its own adapter-declared schema**, not trust upstream schemas.

### 1.2 Transports

- **stdio**: the client spawns the server. The authorization spec says stdio implementations
  "SHOULD NOT follow this specification, and instead retrieve credentials from the environment."
  For wicket, a third-party stdio MCP server must run **in its own sandbox** with egress through
  the wicket proxy, never inside the agent's sandbox with tokens in env. **[H]**
- **Streamable HTTP**: POST per request, with an optional SSE response stream. In 2026-07-28,
  SSE resumability (`Last-Event-ID`) is removed and the GET stream is replaced by
  `subscriptions/listen`. Legacy HTTP+SSE is formally Deprecated (SEP-2596). **[H]**
- Spec security guidance for local servers: prefer stdio, or for HTTP require a token or use
  **unix domain sockets/IPC with restricted access**. That's the wicket design: the gateway
  listens on a per-sandbox socket bound into the VM/container.
  ([security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)) **[H]**

### 1.3 Tool annotations, and why they're untrusted

`ToolAnnotations` (since 2025-03-26): `title`, `readOnlyHint` (default false), `destructiveHint`
(default true, meaningful only when not read-only), `idempotentHint` (default false) and
`openWorldHint` (default true). The 2026-07-28 tools page says: *"clients MUST consider tool
annotations to be untrusted unless they come from trusted servers."*
([tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)) **[H]**

Why they can't feed policy:

- The server describing the tool is the party you're constraining, so self-declared risk is
  worth nothing. A malicious or compromised server sets `readOnlyHint: true` on a delete.
- Annotations are per tool, not per argument. `run_query(sql)` is read-only or destructive
  depending on the SQL.
- They describe effects on the server's world, not provider-side triggers (notifications,
  webhooks, CI).
- Many clients auto-approve "read-only" tools, so a false hint is an active attack vector, not
  just missing data.

**wicket rule:** annotations are an *output* of the gateway, computed from the adapter's risk
class and sent downstream so Claude Code's own permission UX behaves sensibly. They're never an
input. **[H on the spec; L on the design]**

### 1.4 Elicitation (form and URL)

([elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)) **[H]**

- **Form mode**: flat primitive schemas only. Servers **MUST NOT** request passwords, API keys,
  tokens or payment credentials through it.
- **URL mode** (added 2025-11-25): an out-of-band browser interaction "that must not pass
  through the MCP client". It's used for third-party OAuth, where the MCP server is the OAuth
  client, and for payments or API-key entry. Requirements: credentials obtained this way
  MUST NOT transit the client; the server MUST NOT reuse the client's token for the third party
  (no passthrough); the server MUST bind the elicitation to the user identity and verify that
  whoever opens the URL is that user (the phishing/account-takeover scenario is spelled out);
  clients MUST NOT prefetch, MUST show the full URL, and MUST open it in a context the
  client/LLM can't inspect. 2026-07-28 removed `notifications/elicitation/complete` and
  `elicitationId`; completion is now learned by retrying with `requestState`.
- **Relevance to wicket:**
  1. URL mode is the standard-compliant way for the gateway to ask *the human* to connect a
     provider account (an OAuth consent page hosted by wicket, outside the sandbox), without the
     agent ever seeing the token.
  2. It's tempting as an approval channel ("open this URL to approve the grant"). But in
     headless or black-box runs (Claude Code `-p`, nobody watching the TUI), the client may not
     declare the capability and may have no human present. wicket's approval path should be
     **out-of-band and wicket-owned** (push notification or CIBA-style), with the MCP-visible
     part being either a portable structured tool error ("pending, request_id=…, retry after
     N s") or `input_required` when the client declares support. **[L]**

### 1.5 Authorization

([authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)) **[H]**

- OAuth 2.1 (draft-13) resource-server model. MCP servers **MUST** implement RFC 9728 Protected
  Resource Metadata. Clients **MUST** use it for AS discovery and **MUST** support both RFC 8414
  and OIDC discovery.
- **Resource indicators (RFC 8707)**: clients **MUST** send `resource=<canonical server URI>` on
  both the authorization and token requests. Servers **MUST** validate that the token audience
  is themselves.
- **Token passthrough prohibited**: "MCP servers MUST NOT accept or transit any other tokens."
  The security page explains the confused-deputy and audit-trail damage.
- **Scope step-up**: runtime `403` with
  `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"`. Clients compute the union
  of previously requested and challenged scopes, then re-authorize. Servers SHOULD emit all
  scopes needed for the operation in one challenge, and MUST account for scope hierarchies.
- **2026-07-28 additions**: RFC 9207 `iss` validation (mix-up defense), issuer-bound client
  credentials, `application_type` in DCR, and DCR deprecated in favor of Client ID Metadata
  Documents. Authorization extensions live in `modelcontextprotocol/ext-auth`, including
  Enterprise-Managed Authorization (rmcp has an `auth-enterprise-managed` feature for EMA/XAA
  ID-JAG exchanges).

**Mapping to wicket:**

- **Agent → gateway.** The black-box agent is the MCP client. It authenticates with a
  per-sandbox credential, but the real binding is the *channel*: the gateway socket exists only
  inside that sandbox. A bearer token alone is weak because the agent can read it. Bind identity
  to the socket or vsock CID, and treat any token as a hint.
- **Gateway → upstream.** The gateway is a *separate* OAuth client/resource holder per provider.
  It never forwards the agent's token, which matches the passthrough prohibition. For remote MCP
  servers the gateway is a standard MCP client with its own tokens: RFC 8707 audience-bound,
  minimal scopes, step-up handled by wicket's escalation path rather than auto-consented.
- Step-up challenges from upstream map onto a **typed escalation request** (provider, scope,
  resource, duration). They must not be auto-consented: the agent's goals drive them, so they
  belong to the confused-deputy surface.

### 1.6 The Rust SDK `rmcp`

([repo](https://github.com/modelcontextprotocol/rust-sdk), [docs.rs](https://docs.rs/crate/rmcp/latest)) **[H]**

- Version **3.9.0, released 2026-11-05**. The 3.x line started with 3.0.0 on 2026-07-28, and
  there's a 3.x migration guide. About 4.1k stars.
- README: "implements the stable MCP `2026-07-28` specification while remaining fully
  compatible with the `2025-11-25` release and earlier." It covers discovery and negotiation,
  subscriptions, tasks, caching, MRTR, and the SEP-2243 headers, which "rmcp emits and
  validates automatically".
- Features: `server`, `client`, `macros`, `schemars`, `auth`, `auth-enterprise-managed`,
  `elicitation`; transports `transport-io`, `transport-child-process`, `transport-async-rw`,
  `transport-streamable-http-{client,client-reqwest,server}`; TLS via rustls (default) or native.
- Client lifecycle modes: `Initialize` (legacy), `Discover` (2026-07-28) and `Auto` (probe, then
  fall back). That's what a gateway needs upstream.
- Stateless Streamable HTTP server by default for 2026-07-28 clients, with
  `with_legacy_session_mode(false)` for older ones.
- **Proxy viability.** agentgateway's `crates/agentgateway/Cargo.toml` depends on
  `rmcp = "3.9.0"` (plus `legacy-rmcp = rmcp 0.10.0` for the old SSE server). That's a
  production gateway built on it. Caveat **[M]**: rmcp's typed models make "forward unknown
  methods/fields verbatim" harder. For wicket that's a *feature*: allowlisting known methods and
  fields is the right default, with unknown-method passthrough added only behind explicit
  config.

---

## 2. Existing MCP gateways: what to learn and borrow

| Gateway | Lang / license / latest | Policy model | What to borrow | Gaps for wicket |
|---|---|---|---|---|
| **agentgateway** ([repo](https://github.com/agentgateway/agentgateway), [mcp-authz](https://agentgateway.dev/docs/standalone/latest/mcp/mcp-authz/)) | Rust, Apache-2.0, v1.7.0 (2026-10-27); Linux Foundation | `mcpAuthorization`: CEL rule sets over `mcp.tool.{name,target}`, `jwt.*` claims; resource types tool/prompt/resource/**task**; per-target `condition` CEL; JWT/OAuth; guardrails (regex, moderation, Bedrock Guardrails, Model Armor, webhooks); OpenAPI→MCP | Old↔new protocol bridging (its `mcp/README.md` design note); multiplexing with server-prefixed names; "disable caching of policy-filtered results"; DNS-rebinding guard module; CEL-forked engine | `publish=false`, so not embeddable. A `MCPTool.arguments` field exists in its CEL context, but its docs suggest basing decisions on name/target **[M]**. No argument-semantic adapters, IFC labels, or escalation workflow |
| **Docker MCP Gateway** ([repo](https://github.com/docker/mcp-gateway), [run ref](https://docs.docker.com/reference/cli/docker/mcp/gateway/gateway_run)) | Go, v0.44.3 (2026-10-26) | Profiles of servers, each server in its own container; `--block-secrets` (default true) scans payloads for secret-like content; `--verify-signatures` on server images; `--interceptor when:type:path` hooks | **Run every third-party MCP server in its own container with minimal privileges**; image signature verification; interceptor hook shape (before/after exec) | Coarse (server/tool level); secret scanning is heuristic |
| **IBM ContextForge** ([repo](https://github.com/IBM/mcp-context-forge), [arch](https://ibm.github.io/mcp-context-forge/latest/architecture/)) | Python, v1.1.0 (2026-10-20) | Teams/RBAC (global/team/personal), virtual servers composing tools across backends, REST/gRPC→MCP adaptation, plugin hooks pre/post request/response (PII, deny, regex, resource filters); RFC 8693 token exchange and Vault per-user credentials (v1.0.6, 2026-07-21) | Virtual-server concept (compose a task-sized server from many upstreams); per-user credential resolution from Vault; token exchange | Heavy, Python, not a reference monitor you can verify |
| **Microsoft mcp-gateway** ([repo](https://github.com/microsoft/mcp-gateway)) | C#, K8s | Control plane registers adapters/tools (container image + tool definition); data plane routes; Entra ID app roles (`mcp.admin`) | Control/data-plane split; tool registration API | K8s/Azure-centric; authz is coarse |
| **Pomerium MCP** ([docs](https://www.pomerium.com/docs/capabilities/mcp)) | Go, v0.34.0 (2026-11-04) | PPL policy with an `mcp_tool` criterion (exact/prefix/suffix/list) composed with identity; **acquires, caches and refreshes upstream OAuth tokens and injects them**; per-user per-route connection state; logs tool + parameters | The "gateway holds upstream OAuth, injects per user" pattern; tool allow/deny lists composed with identity | Tool-name granularity |
| **Cloudflare MCP server portals** ([docs](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/), [GA 2026-09-24](https://developers.cloudflare.com/changelog/post/2026-09-24-mcp-portals-ga/), [code mode 2026-03-26](https://developers.cloudflare.com/changelog/post/2026-03-26-mcp-portal-code-mode/), [code-mode policies 2026-07-30](https://developers.cloudflare.com/changelog/post/2026-07-30-mcp-portal-code-mode-policies/)) | SaaS | Access policies show/hide servers. **Code Mode on by default**: a single `code` tool, with agent JS calling typed `codemode.*` methods in a Dynamic Worker; admin policies Off/Opt-in/On-by-default/Enforced; static OAuth client creds; Logpush | Portal = curated, policy-filtered aggregate; codemode as the default surface | Docs warn **blocked users can still hit a server's direct URL**, so enforce at the server too. That's the complete-mediation lesson |
| **Kong AI Gateway** ([MCP tool ACLs, 3.13, 2026-01-14](https://konghq.com/blog/product-releases/mcp-tool-acls-ai-gateway), [AI MCP Proxy](https://developer.konghq.com/plugins/ai-mcp-proxy/)) | Lua/Enterprise | Default ACL plus per-tool overrides by consumer/group, checked at discovery **and** invocation; audit entry per decision | Enforce on both `tools/list` and `tools/call` | Enterprise-only; name-level |
| **Agent Router (formerly Envoy AI Gateway)** ([repo](https://github.com/theagentrouter/agent-router), [MCP docs](https://aigateway.envoyproxy.io/docs/capabilities/mcp/)) | Go/Envoy; renamed and now an AAIF project **[H on rename]** | MCPRoute: JWT scopes/claims + tool selection + CEL; tool aggregation and filtering | Gateway API CRD shape for declaring MCP routes | K8s-centric |
| **Lasso mcp-gateway** ([PyPI](https://pypi.org/project/mcp-gateway/)) | Python, MIT, v1.2.0 (2026-01-21) | Plugins: basic, Presidio PII masking, Lasso API; pre-load **server reputation scanner** (marketplace + GitHub signals, tool description analysis) | Pre-admission scanning of servers | Heuristic; low activity |
| **Invariant Guardrails / Gateway** ([guardrails ref](https://invariantlabs-ai.github.io/docs/mcp-scan/guardrails-reference)) — Snyk acquired Invariant Labs, announced 2025-06-24 **[M]** | Python, Apache-2.0 | Python-like rules over traces: `raise "..." if: (out: ToolOutput) -> (call: ToolCall) ...`, i.e. **flow rules** (no `send_email` after `fetch_url`), parameter restrictions, ordering, loop detection | Trace/flow-rule vocabulary is close to wicket's taint rules; useful for a "flow policy" layer above per-call authz | Not a hard boundary (evaluates in the gateway, rules are not verified) |
| **mcp-scan → Snyk Agent Scan** ([repo](https://github.com/snyk/agent-scan), v0.6.11, 2026-11-06; [intro](https://invariantlabs.ai/blog/introducing-mcp-scan)) | Python | Static scan of client configs; **tool pinning**: hashes tool descriptions and alerts on change between scans; sends tool metadata to Snyk's API | Hash-pinning idea | Detects drift between scans only, not mid-session; needs a SaaS API |
| **GitHub MCP server** ([repo](https://github.com/github/github-mcp-server), v2.1.0, 2026-11-03; [config](https://github.com/github/github-mcp-server/blob/main/docs/server-configuration.md)) | Go | Toolsets, `--read-only` (precedence over everything), excluded tools, **lockdown mode** (in public repos, only surface content from users with push access; the operator setting is an upper bound the header can't relax) | Lockdown = **response-side integrity filter by author trust**, a concrete precedent for label-based result filtering; "operator setting is an upper bound" = narrower-never-wider at runtime | Single provider |

### 2.1 Tool poisoning and rug-pull defenses

Attack classes:

- **Tool poisoning.** Instructions hidden in tool descriptions or schemas, sometimes in
  invisible Unicode. ([Invariant, Apr 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks))
- **Rug pull.** The definition changes after approval.
- **Shadowing.** One server's description changes how the model uses another server's tool.
- **Name collisions.**
- Injection through the server `instructions` field, prompts and resources.

Defenses ranked by strength, for wicket **[L design, M on prior art]**:

1. **Descriptions come from the adapter, not the server.** For gateway-native tools generated
   from wicket adapters, upstream descriptions never reach the model. This is the only full
   defense.
2. **Pin by hash** for third-party servers: compute
   `sha256(JCS({name,title,description,inputSchema,outputSchema,annotations,icons}))` (RFC 8785
   canonical JSON) per tool at approval time and store it in the task manifest. On every
   `tools/list`, a tool whose hash differs is **dropped and alerted** (fail closed), not
   re-prompted. That covers both rug pulls and mid-session drift, which mcp-scan's
   between-scans pinning misses. Prior art: [ETDI](https://arxiv.org/abs/2506.01333) (signed,
   versioned tool definitions; research, not in the spec) and `mcpseal` (hash pinning, PyPI).
3. **Normalize and limit**: strip control and Unicode tag characters, cap description length,
   drop the server `instructions` field, reject `x-mcp-header` on sensitive params, and
   **namespace every tool** `server__tool` (the spec says server names aren't unique and
   suggests disambiguation).
4. Image and package provenance for local servers (Docker `--verify-signatures`).
5. Scanners (mcp-scan, Lasso reputation) as **admission signals only**.

---

## 3. The egress proxy

### 3.1 How others implement egress allowlists and credential injection

**Anthropic sandbox-runtime (`srt`)** ([README](https://github.com/anthropics/sandbox-runtime),
[srt-proxy.md](https://github.com/anthropics/sandbox-runtime/blob/main/docs/srt-proxy.md);
v0.0.81, 2026-10-20) **[H]**

- Linux: bubblewrap with the network namespace **removed entirely**. The proxies listen on unix
  sockets bind-mounted into the sandbox. HTTP/HTTPS goes through an HTTP proxy and other TCP
  through SOCKS5; seccomp blocks unix sockets. macOS uses sandbox-exec. Windows has a WFP alpha.
- Allow-only domain lists; deny wins. A **resolved-address check** drops loopback, link-local,
  metadata, private and deny-listed IPs, and dials the vetted address with no second lookup
  (DNS-rebinding mitigation).
- `network.tlsTerminate` (experimental): MITM with a supplied or ephemeral CA. A trust bundle
  (MITM CA plus host roots) is injected via `SSL_CERT_FILE`, `GIT_SSL_CAINFO`, etc.
  `excludeDomains` covers **mTLS upstreams and certificate-pinning clients**, which are
  tunnelled opaquely, still allowlisted, but get no filtering or injection.
  `refuseOpaqueTunnels` refuses anything it can't see into. `requireHostMatch` answers 421 when
  Host, SNI and authority disagree with the CONNECT target. Ambiguous request targets (dot
  segments etc.) are refused by default. TRACE/TRACK get 405 because they'd echo injected
  headers.
- **Credentials**: `credentials.envVars` / `credentials.files` with `mode: "deny"` or
  `mode: "mask"`. Mask puts a **sentinel** inside the sandbox, and the proxy substitutes the real
  value on egress to `injectHosts` (default: the allowed domains). Masking requires TLS
  termination unless you explicitly opt out. `credentials.sigv4` re-signs AWS requests.
- **`srt proxy` with an external decider** (protocol v1). The proxy holds no policy. Frames are
  4-byte length plus a strict JSON object (no nulls, no duplicate keys, no unknown fields).
  The flow:
  - Hello: the decider returns host allow/deny lists for CONNECT-time filtering.
  - Per request: `req{id, method, host, port, hostHeader, sni, path, query (as spelled), headers}`.
  - Verdicts: `allow{setHeaders, removeHeaders, cred, credential}` (all client credential
    headers are stripped first), `deny{status, reason}`, or `need_body{max}` → `body{data, cut}`.
  - It **fails closed**: a 5 s verdict timeout gives 503, a protocol violation or decider death
    kills the proxy, and plaintext header-setting is refused unless explicitly enabled.
  - Bounded resources throughout: 256 TLS tunnels, a 2 MiB request head, a 32 MiB body per
    `need_body`, 64 MiB held at once, and 256 cached leaf certificates sharing one key.

  **This protocol is almost exactly wicket's proxy↔engine seam.**

**OpenAI Codex `codex-network-proxy`**
([README](https://github.com/openai/codex/tree/main/codex-rs/network-proxy),
[docs](https://learn.chatgpt.com/docs/agent-approvals-security)) **[H]**

- Rust, on **rama `=0.3.0-alpha.4`** (rama-tls-rustls, rama-socks5, rama-unix) plus `aws-sigv4`.
  HTTP proxy on `127.0.0.1:3128` and SOCKS5 on `:8081`, clamped to loopback.
- Domain rules: exact host, `*.x` (subdomains only), `**.x` (apex plus subdomains), `?`; global
  `*` rejected by default; deny wins. Local/private IPs are blocked even when a hostname is
  allowlisted (best effort; docs say DNS rebinding "is reduced, not eliminated").
- **Limited mode**: only GET/HEAD/OPTIONS. HTTPS needs MITM to enforce this, otherwise it's
  blocked. Websocket CONNECTs get host checks only.
- **MITM hooks** keyed by host + methods + path_prefixes, with named actions (e.g.
  `strip_request_headers`). They're versioned (`version = 2`) so a rollback can't silently enable
  unconditional header injection.
- **Exact secret substitution**: an injected header can require an exact `placeholder` value
  before substituting. Body substitution uses opaque 16–256-byte markers, with bounded
  size and work, and fails closed on compression, trailers or integrity headers. **Native SigV4
  re-signing**: the workload signs with a placeholder access key, and the proxy re-signs with
  the real key after the host/method/path hook authorizes. Presigned URLs, SigV4a and streaming
  signatures are denied.
- Library API: `NetworkProxy::builder().policy_decider(...)`. The decider can only override
  allowlist *misses*, never explicit denies. OTEL audit events avoid logging full URLs.

**Claude Code on the web / cloud sessions**
([cloud sessions](https://code.claude.com/docs/en/claude-code-on-the-web),
[cloud environments](https://code.claude.com/docs/en/cloud-environments)) **[H]**

- Access levels: None, Trusted (registries/GitHub/cloud SDKs), Full, Custom. All traffic goes
  through a security proxy. **Bypass paths documented**: GitHub (own proxy), MCP connectors
  (via Anthropic servers), network-secret hosts, and the Anthropic API even at None ("which may
  allow data to exit the VM").
- **GitHub proxy**: "the git client inside the VM uses a scoped credential, which the proxy
  verifies and swaps for your actual GitHub token". It rejects **branch deletions and non-branch
  pushes (tags)** but doesn't restrict which branches. API requests are limited to attached
  repos (403 otherwise, including archive/codeload URLs for public repos). **GraphQL is rejected
  outright**, even with a user-supplied `GH_TOKEN`, with REST fallback guidance.
- **Network secrets**: added after the request leaves the VM, matched by host and header; never
  sent to GitHub, the Anthropic API, public registries, setup-script requests or telemetry.
- Doc warning: comment-triggered automation (Atlantis, `issue_comment` workflows) can be fired
  by Claude's replies. That's a side effect wicket's adapters must encode (§4.6).

**GitHub Copilot coding agent firewall**
([docs](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall),
[gh-aw-firewall](https://github.com/github/gh-aw-firewall)) **[H/M]**

- Covers only processes started via the agent's Bash tool, **not MCP servers or setup steps**.
  Rules are domain-level (subdomains included) or URL-level (scheme + host + path prefix);
  blocked requests are surfaced on the PR.
- `gh-aw-firewall` (GitHub's agentic-workflows firewall, TypeScript) is **Squid** with optional
  SSL-bump for URL rules, plus an always-on **API-proxy sidecar holding LLM keys**, DLP scanning
  and DNS-over-HTTPS. Whether Copilot's production firewall is exactly this is **[M]**.

**Stripe Smokescreen** ([repo](https://github.com/stripe/smokescreen)): Go CONNECT proxy for
SSRF prevention, host allowlists per client role, no MITM. The MCP security page recommends it.
Good reference for IP-range denial and role-by-client-identity. **[H]**

**Lessons:**

1. Remove the network from the sandbox entirely and expose only proxy sockets (srt).
2. Strip all client credentials, then inject per decision (srt-proxy).
3. Use placeholders for tools that refuse to run without a token (Codex, srt mask).
4. Re-sign SigV4 rather than handing out AWS keys (both).
5. Deny GraphQL until it can be parsed fully (Claude Code web).
6. Refuse ambiguous request targets and Host/SNI mismatches (srt).
7. Fail closed on decider failure (srt-proxy).
8. Document every bypass path, because each is a hole in complete mediation (Claude Code web).

### 3.2 Rust building blocks

| Crate | Version (crates.io, 2026-11-08) | Fit |
|---|---|---|
| **rama** ([repo](https://github.com/plabayo/rama)) | 0.4.0 (2026-08-19), Apache-2.0 | Full proxy framework: HTTP/1.1, HTTP/2, HTTP/3 clients and servers, CONNECT, SOCKS5, **MITM** (example `http_mitm_proxy_boring.rs`; rama CLI has a MITM mode with web UI), rustls or BoringSSL, dynamic certs, WebSockets, SSE, gRPC, ICAP, streaming JSON/JSONPath rewriting, Linux tproxy, Apple NE. **Used by Codex's network proxy.** Risk: pre-1.0 churn (Codex pins an exact alpha); small core team with commercial support. **[H]** |
| **hudsucker** ([repo](https://github.com/omjadas/hudsucker)) | 0.25.0 (2026-07-15) | Simple MITM proxy on hyper: request/response/WebSocket handlers, `rcgen-ca` default, `http2` feature. Fine for a prototype; less control over CONNECT-time decisions, upstream dialing and SSRF pinning. **[H]** |
| **pingora** ([repo](https://github.com/cloudflare/pingora)) | 0.9.1 (2026-11-03) | Reverse-proxy framework. CONNECT and absolute-form parsing was only fixed in Sept 2026 (PRs #912/#923). No first-class forward-proxy MITM. Wrong shape for wicket. **[M]** |
| **hyper 1.x + hyper-util + h2 + tokio-rustls** | hyper 1.12.0, h2 0.4.20 | Hand-rolled: most control and most work (CONNECT upgrade, ALPN, h2, WS upgrade, backpressure). It's what rama and hudsucker wrap. **[H]** |
| **rcgen** | 0.14.10 | CA and leaf generation. Supports NameConstraints, so wicket can mint a **per-sandbox CA name-constrained to the task's allowed domains** with a short validity, making a leaked CA key nearly useless. **[H crate / M that every client enforces nameConstraints: OpenSSL, Go and webpki do]** |
| **rustls** (aws-lc-rs provider) | 0.23.x | TLS both sides. **[H]** |
| **aws-sigv4** | — | SigV4 re-signing, as Codex does. **[H]** |
| **hickory-resolver**, **ipnet** | — | Proxy-side DNS with address pinning; private-range denial. **[L]** |

### 3.3 Protocol and TLS details wicket must handle

- **CONNECT**: decide on host:port at CONNECT. Then, inside the terminated tunnel, re-check
  Host, SNI and authority against the CONNECT target (srt's 421 rule). Refuse IP-literal CONNECTs
  unless they're explicitly listed.
- **Per-sandbox CA**: generate at sandbox creation, keep the key only in the proxy process, and
  inject trust via `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` (Claude Code reads this, and
  `CLAUDE_CODE_CERT_STORE`), `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`,
  `AWS_CA_BUNDLE`, `PIP_CERT`, `CARGO_HTTP_CAINFO`, plus the system store inside the VM image.
  Clients with bundled roots (some Rust `webpki-roots` builds, Java) fail closed, which is safe
  but may stall the agent.
  ([Claude Code network config](https://code.claude.com/docs/en/network-config)) **[H/M]**
- **Claude Code** honors `HTTPS_PROXY` and **doesn't support SOCKS**, so the HTTP CONNECT proxy
  is mandatory and SOCKS is optional for other tools. **[H]**
- **HTTP/2**: negotiate ALPN inside the tunnel. Simplest is offering only `http/1.1` to the
  client unless the destination needs h2 (gRPC). Policy is per request (h2 stream), so the
  adapter interpreter must be stream-aware. **[M]**
- **WebSockets / SSE / long polls**: policy applies at the upgrade request. Frames are opaque
  unless an adapter declares a frame parser. Treat any WS upgrade as R3+ (external channel)
  unless the adapter says otherwise. **[L]**
- **QUIC/HTTP/3**: block UDP, and clients fall back to TCP. **[M]**
- **SNI-only mode** (pinned clients, mTLS upstreams): peek the ClientHello, require
  SNI == CONNECT host, and tunnel opaquely. **No credential injection and no semantics are
  possible**, so such hosts get host-level allow only, and the agent must not hold credentials
  for them. List these explicitly per task, and show them in the zone view as "unmediated
  channel". **[H on mechanism]**
- **Request canonicalization**: reject dot segments, `%2F` in path params, double slashes,
  duplicate query keys, duplicate JSON keys, oversized or deep JSON, unknown
  `Content-Encoding`, method-override headers (`X-HTTP-Method-Override` and friends), and
  `Transfer-Encoding`/`Content-Length` conflicts. srt documents exactly these ambiguity classes.
  Matching the request *as spelled* and refusing anything a normalizer would change is safer
  than normalizing. **[H on srt / L on list completeness]**
- **Response handling**: never follow redirects on the agent's behalf (each hop is a new agent
  request through policy), strip `Set-Cookie` where the credential is wicket's, and redact any
  wicket-held secret value echoed in responses.

### 3.4 Git over HTTPS (smart HTTP) and SSH

**Protocol facts** ([gitprotocol-http](https://git-scm.com/docs/gitprotocol-http),
[gitprotocol-pack](https://git-scm.com/docs/gitprotocol-pack),
[gitprotocol-v2](https://git-scm.com/docs/gitprotocol-v2),
[receive-pack quarantine](https://git-scm.com/docs/git-receive-pack#_quarantine_environment)):

- Discovery: `GET /{owner}/{repo}.git/info/refs?service=git-upload-pack|git-receive-pack`.
- Fetch: `POST …/git-upload-pack` (protocol v2 is used for fetch).
- **Push: `POST …/git-receive-pack`.** The body is pkt-lines
  `<old-oid> <new-oid> <refname>\0<caps>` …, then a flush-pkt, then optional push-options, then
  a **packfile**. Protocol v2 doesn't cover push, so receive-pack still uses the v0/v1 command
  format. **[M-H]**

What a proxy can enforce:

| Rule | How | Difficulty |
|---|---|---|
| Repo allowlist | URL path | trivial **[H]** |
| Read vs write | service name / endpoint | trivial **[H]** |
| Ref rules: no push to `refs/heads/main`, no tags, no deletions (`new-oid` = zeros), only `refs/heads/wicket/<task>/*` | parse the pkt-line command list before the PACK | easy, streaming. Claude Code web does a version of this **[H]** |
| Force-push detection (non-fast-forward) | needs ancestry of `old`→`new` | needs the object graph **[M]** |
| **Path rules** (`.github/workflows/**`, `.github/actions/**`, `CODEOWNERS`, `.gitmodules`, symlinks) | must reconstruct trees for **every new commit** in `old..new` and diff | **hard on the wire**: packs may be *thin*, with deltas against objects only the server has, so a stateless proxy can't resolve them **[M-H]** |

**Recommended design: store-and-forward through a local mirror** **[M]**

1. The proxy keeps a per-task bare mirror of each writable repo, fetched with wicket's real
   credential.
2. On `git-receive-pack`, the proxy runs `git receive-pack` itself against the mirror. Git's
   **quarantine environment** keeps incoming objects in a temp object dir until a pre-receive
   hook accepts them. Git, not wicket, parses the pack and resolves thin deltas.
3. The pre-receive hook (wicket code) gets the ref command list. For each ref it walks
   `git rev-list old..new` and per-commit `git diff-tree --name-status -r`, plus mode changes
   (symlinks, submodules, gitlinks). It evaluates the adapter's ref and path rules and the
   dangerous-pattern list, then calls the engine.
4. If accepted, wicket pushes those refs from the mirror to upstream with the real token, then
   relays a synthesized `report-status` to the client. If rejected, it returns a `report-status`
   with `ng <ref> <reason>` so the agent sees a normal git error message.

Cost: latency and disk, plus git as a TCB dependency. Pure-Rust alternative: `gix` 0.90 /
`gix-pack` 0.77 for pack indexing with the mirror as the base object source. This works, but
you'd be re-implementing what `receive-pack` + quarantine already do correctly.

Also handle:
- **Git LFS** (separate batch API under `…/info/lfs/objects/batch`, uploads to storage hosts).
  Allow only for allowlisted repos, as a write.
- Push options.
- `.gitmodules` URL changes, which can exfiltrate data via submodule fetch on clone. Mark as a
  dangerous pattern.

**Defense in depth on GitHub's side** **[H]**:
- Mint **GitHub App installation tokens** per task with
  `repository_ids` + a `permissions` subset, which expire in 1 h
  ([API](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)).
  A token **without `workflows: write`** can't create or update `.github/workflows/*` via push
  *or* via the Contents/Git-refs APIs. The machine-readable permission map lists `workflows` as
  an additional permission on contents PUT/DELETE, git refs POST/PATCH, and releases POST/PATCH.
- Push rulesets with **file path restrictions** and branch rulesets
  ([about rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)).
  Plan availability varies **[M]**.

**SSH**: deny by default. Port 22 and `ssh.github.com:443` aren't mediated, since SSH's key
exchange can't be MITM'd without the agent holding a key wicket controls. Put
`url."https://github.com/".insteadOf "git@github.com:"` (and the `ssh://` form) in the sandbox's
system gitconfig, and return a model-readable reason. srt's `deniedDomainReasons` example is
exactly "SSH pushes to GitHub are blocked; use an https:// remote". Proxying SSH (terminate with
`russh`, re-originate with wicket's key) is possible later but duplicates the smart-HTTP logic
for no gain. **[H on srt; L on design]**

---

## 4. Provider adapter DSL

### 4.1 Prior art: declarative API→(resource, verb, risk) catalogs

**AWS Service Authorization Reference and service reference JSON** **[H]**
([docs](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html)):

- Entry points: `servicereference.us-east-1.amazonaws.com/` (service list),
  `/v1/<svc>/<svc>.json`, `/v1/global-condition-keys.json`, and `/v1/mapping.json`
  (SDK package → service).
- Per service: `Actions[]` with `ActionConditionKeys`, `Resources`, and
  `Annotations.Properties{IsDataPlane, IsList, IsPermissionManagement, IsTaggingOnly, IsWrite}`;
  `Resources[]` with `ARNFormats`; `ConditionKeys[]` with types; and
  **`Operations[]` → `AuthorizedActions[]`**. One API call can need several actions (e.g. S3
  `GetObject` → GetObject, GetObjectVersion, GetObjectTagging…), and SDK method names are
  included. Updates lag up to 24 h, and some services omit the operation map.
- Smithy models carry `aws.iam#iamAction{name, requiredActions, conditionKeys}` and
  `aws.iam#iamResource` traits ([Smithy IAM traits](https://smithy.io/2.0/aws/aws-iam.html)).
  That's the request-model side of the same mapping.
- **Lesson**: this *is* the DSL wicket needs, written by the provider. The essential pieces are:
  (a) an **operation → action(s)** map that's many-to-many; (b) resource types with **ID
  templates**; (c) typed **condition keys** extracted from requests; (d) **risk annotations as
  orthogonal booleans**, not one ordinal. For AWS, wicket's adapter should be *generated* from
  these files plus Smithy models (to parse `X-Amz-Target` / query `Action=` / REST-XML routes
  into operations). The native narrowing layer is an STS session policy on the role wicket
  assumes.

**GitHub** **[H]**:

- Fine-grained PAT / GitHub App permission tables are machine-readable in `github/docs`:
  `src/github-apps/data/{fpt,ghec,ghes-*}-{2022-11-28,2026-03-10}/fine-grained-pat-permissions.json`
  (76 permission groups, 1,075 endpoint entries in fpt-2026-03-10) and
  `server-to-server-permissions.json` (1,112). Each entry has
  `{verb, requestPath, access: read|write|admin, "additional-permissions": bool}`.
  Example: `workflows` lists PUT/DELETE `/repos/{owner}/{repo}/contents/{path}`, POST
  `/git/refs`, PATCH `/git/refs/{ref}`, POST/PATCH `/releases` as needing it in *addition* to
  contents. ([data dir](https://github.com/github/docs/tree/main/src/github-apps/data))
- Runtime oracle: the `X-Accepted-GitHub-Permissions` response header lists the permission sets
  that would satisfy a route (`;`-separated alternatives)
  ([changelog 2023-08-10](https://github.blog/changelog/2023-08-10-x-accepted-github-permissions-header-for-fine-grained-permission-actors)).
  It's useful in the verification loop.
- OpenAPI ([rest-api-description](https://github.com/github/rest-api-description); versions
  2022-11-28 and **2026-03-10**) has 837 paths / 1,272 operations. The `x-github` extension
  includes `category`, `subcategory`, `enabledForGitHubApps`, `githubCloudOnly`, and
  **`triggersNotification` (26 ops)**: org invitations, add collaborator, commit comments,
  issues create/comment, PR create/review comments/merge/request reviewers, releases create,
  issue dependency and sub-issue ops. **No permission data in the OpenAPI**, so join it with the
  docs data. **[H, counted today]**

**Cloudflare** **[H]**: `cloudflare/api-schemas` OpenAPI carries per-operation
`x-api-token-group` (3,045 ops; e.g. `dns-records-for-a-zone-create-dns-record` →
`["DNS Write"]`) and `x-cfPermissionsRequired` (685 ops; e.g. `#dns_records:edit`). Token
resources are scoped to account/zone.

**Stripe** **[M]**: restricted API keys with a per-resource None/Read/Write matrix
([docs](https://docs.stripe.com/keys/restricted-api-keys)). Coarser than endpoint-level, but a
good native narrowing layer under the gateway.

**Google API Discovery documents** **[H from prior knowledge, not re-fetched]**
([reference](https://developers.google.com/discovery/v1/reference/apis)): per method
`httpMethod`, `path`/`flatPath`, `parameters{location: path|query, required, pattern}`,
`request`/`response` schema refs, `scopes[]`, `supportsMediaUpload`. That's machine-readable
method→scope. IAM permissions per method aren't in discovery (they're in IAM docs).

**Kubernetes** **[H]**: RBAC rules are `{apiGroups, resources (+/subresource), resourceNames,
verbs: get,list,watch,create,update,patch,delete,deletecollection (+ escalate, bind,
impersonate)}` plus `nonResourceURLs`
([RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)). The apiserver's
**RequestInfo resolver** turns an HTTP path into
`(verb, apiGroup, apiVersion, namespace, resource, subresource, name)`
([requestinfo.go](https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiserver/pkg/endpoints/request/requestinfo.go)),
and `GET` on a collection becomes `list`, `?watch=true` becomes `watch`. That's the
best-engineered example of an "endpoint pattern → (resource, verb)" interpreter. Note the
special verbs (`escalate`, `bind`, `impersonate`): they're the k8s "dangerous patterns" list.

**OpenAPI→MCP generators** (what they do and don't do for security):

- **FastMCP** `from_openapi` / `RouteMap` ([docs](https://gofastmcp.com/integrations/openapi)):
  first-match route maps classify routes to TOOL/RESOURCE/EXCLUDE by method, path regex and
  tags. **Default: every endpoint becomes a tool**, and a `route_map_fn` can override even
  exclusions. That's wider-by-default, the opposite of wicket's rule. **[H]**
- **Stainless** ([docs](https://www.stainless.com/docs/mcp)): generated servers expose **two
  tools: docs search plus a code-execution tool** that runs TypeScript against the generated SDK
  (marked experimental). No per-endpoint tools. **[H/M]**
- **Speakeasy Gram** ([docs](https://www.speakeasy.com/docs/mcp/getting-started/openapi)): one
  tool per operation by default, curated into **toolsets**, `x-gram` extension for
  LLM-facing descriptions. **[M]**
- None of them model resources, side effects or argument-level scoping. They're
  *presentation* generators. wicket's generator emits *authorization* adapters and can *then*
  render tools or codemode stubs from them. **[L]**

**GraphQL authorization and parsing in Rust**:

- Crates: `apollo-parser` 0.8.7 (lossless CST, error-tolerant), **`apollo-compiler` 1.33.1**
  (schema + executable document validation, fragment resolution, typed field selections),
  `async-graphql-parser` 7.2.1, `graphql-parser` 0.4.1 (stale since 2024-12). **[H versions]**
- "Parse fully or deny" in practice:
  - Validate the document against a **pinned provider schema** (GitHub publishes its public
    schema).
  - Resolve fragments and variables (variables are in the request JSON).
  - Reject multiple operations unless `operationName` is given, reject unknown directives, and
    reject introspection beyond a whitelist.
  - Walk every selected field and mutation, map `(type, field, args)` to resources via the
    adapter, and require **literal or variable-resolved resource args**.
  - **Deny opaque global IDs (`node(id:)`, `nodes(ids:)`) unless resolved by lookup.**
  - Compute query cost (GitHub's documented node-limit / rate-limit formula) as a size bound.
- Most realistic v1: **deny GraphQL**, like Claude Code web, or **allow persisted operations
  only** (hash-allowlisted documents, each with a hand-written adapter entry). Field-level
  response filtering is then easy because the shape is known. **[M]**

**Policy-engine candidates (Rust)**:

- **Cedar** `cedar-policy` 4.14.1 (2026-11-02, Apache-2.0): schema-validated policies over
  entity hierarchies (`in`) and typed context, plus **`cedar-policy-symcc` 0.8.1**. The symcc
  crate is a Lean-verified symbolic compiler to SMT (cvc5) that checks properties like
  never-errors, always-allows, disjointness and (by construction) equivalence and implication of
  policy sets ([Cedar analysis blog](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies),
  [paper](https://arxiv.org/abs/2407.01688)). **This is the tool for machine-checking
  "narrower, never wider" at the policy layer.** **[H crate; M on fit]**
- **CEL** (`cel` 0.15.0; agentgateway forks it): good for small predicates, no analysis tooling.
- **regorus** 0.14.1 (Microsoft's Rust Rego): OPA-compatible, no symbolic analysis.
- **biscuit-auth** 6.0.0: datalog tokens with attenuation. That belongs to the delegation layer
  (another doc), but its checks could be evaluated at both enforcement points.

### 4.2 Design principles for wicket's adapter DSL

1. **Data, not code.** One interpreter in Rust and a closed set of operators. No embedded
   scripting in generated adapters. A hand-written adapter *may* use a CEL escape hatch, flagged
   `trust: hand-written`, which the generator can never emit.
2. **Total over its inputs.** Every path param, query param, header the provider interprets, and
   body field must be *declared*. Undeclared means deny. That's the "unknown parameter → deny"
   rule, and it closes mass-assignment-style bypasses (e.g. an extra `branch` field).
3. **Canonicalize-or-reject before match** (§3.3).
4. **Resources are typed and hierarchical** (Cedar entities): `github::Repo` ∋ `github::Ref` ∋
   `github::Path`, and `github::Repo` ∋ `github::Issue`. Policies say
   `resource in github::Repo::"acme/widgets"`.
5. **Effects are a set, risk is derived.** Effect flags (inspired by AWS's booleans) give the
   risk class as the max over effects, and the adapter can only *raise* it.
6. **Resolvers for opaque IDs** are declared lookups with a TTL and a TOCTOU note. Results are
   bound into the decision *and re-checked against the response* where possible (e.g. the
   response's `repository_url` must match the resolved repo).
7. **Response rules**: size caps, projection (allowlist fields), label assignment, redaction.
8. **Query rewrite over post-filtering** for over-broad reads (search). Post-filter only as a
   fallback, marked `breaks_pagination: true`.
9. **Provenance and evidence on every rule**: `generated_by`, `source` (OpenAPI op id, docs
   permission entry), `evidence` (test run IDs), `signed_off_by` for downgrades.
10. **Dangerous patterns are a separate, hand-maintained, provider-scoped file** that the
    interpreter applies *after* adapter classification and that can only raise risk or force
    deny.

**Format: strict YAML subset, validated by JSON Schema generated from the Rust types,
canonicalized to JSON (RFC 8785) for hashing and signing.**
- YAML is what LLMs and humans diff best.
- Restrict it: no anchors/aliases/tags/merge keys, and quoted strings for anything
  pattern-like, to avoid YAML's implicit typing traps.
- TOML handles deep arrays-of-tables badly. KDL is pleasant but has thin tooling and little
  LLM familiarity. JSON is the canonical form anyway.

**[L — design choice]**

### 4.3 Risk classes and effect flags

```
effects (set):            meaning                                         floor risk
  read.public             reads data visible to anyone                    R0
  read.scoped             reads in-scope private data                      R1
  read.broad              may return data outside declared resource set    R2 (needs rewrite/filter)
  write.reversible        mutates in-scope state, undoable                 R2
  write.irreversible      deletes/force-updates/merges                     R3
  notify.external         sends notifications/emails/webhooks to humans    R3
  publish                 makes content publicly visible                    R3
  exec.ci                 can trigger code execution (CI, hooks, Actions)  R4
  exec.ci.privileged      triggers execution with secrets/write token      R4
  perm.manage             changes who/what can access (IAM, collaborators) R4
  cred.material           returns or creates credentials/keys/tokens       R4
  money                   spends money / billing                           R4
  unknown                 default for anything generated & unproven        R4

risk class = max(floor(e) for e in effects); adapter may raise, never lower below floor.
R0/R1: auto-grant within manifest scope.  R2: auto-grant within scope + budget.
R3: parent agent may grant (re-derivation check).  R4: human.
```

### 4.4 Adapter schema (sketch)

```yaml
# adapters/github-rest.yaml
adapter: github-rest
schema_version: 1
provider: github
hosts: ["api.github.com"]
api_versions: ["2022-11-28", "2026-03-10"]     # X-GitHub-Api-Version allowed values; missing → default
auth:
  inject:                                       # proxy strips ALL client auth headers first
    header: Authorization
    format: "Bearer {token}"
    token_source: github_app_installation       # minted per task: repository_ids + permissions subset
  placeholder_env: { GH_TOKEN: "wicket-placeholder-gh" }   # so `gh` runs; never a real value
canonicalize:
  path: { reject_dot_segments: true, reject_encoded_slash_in_params: true, reject_double_slash: true }
  query: { reject_duplicate_keys: true }
  body:  { content_types: ["application/json"], reject_duplicate_keys: true, max_bytes: 1048576, max_depth: 32 }
  headers:
    reject: ["x-http-method-override", "x-http-method", "x-method-override"]
types:                                          # Cedar entity types this adapter produces
  Account: { id: "{login}", case_insensitive: true }
  Repo:    { id: "{owner}/{repo}", parent: Account, case_insensitive: true, stable_id: "repo_id" }
  Ref:     { id: "{repo}:{ref}", parent: Repo }
  Path:    { id: "{repo}:{ref}:{path}", parent: Ref }
  Issue:   { id: "{repo}#{number}", parent: Repo }
resolvers:
  default_branch:
    request: { method: GET, path: "/repos/{owner}/{repo}" }
    extract: { default_branch: "/default_branch", repo_id: "/id" }
    cache_ttl: 300s
  repo_by_id:                                   # for /repositories/{id}/... alias routes
    request: { method: GET, path: "/repositories/{repository_id}" }
    extract: { owner: "/owner/login", repo: "/name" }
    cache_ttl: 300s
param_types:
  gh_login: { regex: "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$" }
  gh_repo:  { regex: "^[A-Za-z0-9._-]{1,100}$" }
  git_path: { regex: "^[^\\x00-\\x1f]{1,4096}$", reject_segments: ["..", "."], max_len: 4096 }
  branch:   { regex: "^(?!.*\\.\\.)(?!/)(?!.*//)[^\\x00-\\x20~^:?*\\[\\\\]{1,255}(?<!\\.lock)(?<!/)$" }
endpoints: [ ... ]      # see §4.5
unmatched: deny          # fixed; not configurable
```

Endpoint entry fields:

```yaml
- id: <stable id>                       # e.g. repos.contents.put
  source: { openapi_op: "repos/create-or-update-file-contents", api_version: "2026-03-10" }
  match: { method: PUT, path: "/repos/{owner}/{repo}/contents/{path+}" }
  params:                               # every input the provider interprets, or deny
    <name>: { from: path|query|header|body, pointer: "/json/pointer", type: <param_type>,
              required: bool, default: <literal> | { resolve: <resolver>.<field> } }
  body: { schema: strict|declared_only }   # strict: any undeclared field → deny
  resources:                            # one or more; ALL must be allowed
    - <Type>: { <template fields> }
  verb: <provider verb, e.g. contents.write>   # becomes Cedar action
  effects: [ ... ]                      # §4.3 flags
  risk: R0..R4                          # optional explicit raise
  rewrite: [ ... ]                      # request transforms (only narrowing ones allowed)
  response:
    max_bytes: <n>
    project: [ "/json/pointer", ... ]   # allowlist; others dropped
    label: <label expr>                 # IFC label attached to returned data
    verify: [ { pointer: "/repository_url", equals: "https://api.github.com/repos/{owner}/{repo}" } ]
  native: { permission: { contents: write }, also: [ { workflows: write, when: "<pattern id>" } ] }
  evidence: { generated_by: ..., tests: [...], signed_off_by: ... }
```

### 4.5 Worked example: GitHub (6 entries plus git and GraphQL notes)

```yaml
endpoints:

# 1. Read a file: R1, response projected and labelled
- id: repos.contents.get
  source: { openapi_op: "repos/get-content" }
  match: { method: GET, path: "/repos/{owner}/{repo}/contents/{path*}" }
  params:
    owner: { from: path, type: gh_login }
    repo:  { from: path, type: gh_repo }
    path:  { from: path, type: git_path, required: false, default: "" }
    ref:   { from: query, type: branch, required: false, default: { resolve: default_branch.default_branch } }
  resources:
    - Path: { repo: "{owner}/{repo}", ref: "{ref}", path: "{path}" }
  verb: contents.read
  effects: [read.scoped]
  response:
    max_bytes: 1048576
    project: ["/type", "/name", "/path", "/sha", "/size", "/encoding", "/content", "/0/name", "/0/path", "/0/type", "/0/sha"]
    label: { from_resource: true, taint: "repo-content:{owner}/{repo}" }   # repo text is untrusted input
  native: { permission: { contents: read } }

# 2. Write a file: the .github/workflows/ case
- id: repos.contents.put
  source: { openapi_op: "repos/create-or-update-file-contents" }
  match: { method: PUT, path: "/repos/{owner}/{repo}/contents/{path+}" }
  params:
    owner:   { from: path, type: gh_login }
    repo:    { from: path, type: gh_repo }
    path:    { from: path, type: git_path }
    message: { from: body, pointer: "/message", type: string, max_len: 8192 }
    content: { from: body, pointer: "/content", type: base64, max_bytes: 1048576 }
    sha:     { from: body, pointer: "/sha", type: git_oid, required: false }
    branch:  { from: body, pointer: "/branch", type: branch, required: false,
               default: { resolve: default_branch.default_branch } }   # absent branch = default branch!
    committer: { from: body, pointer: "/committer", type: git_identity, required: false }
    author:    { from: body, pointer: "/author", type: git_identity, required: false }
  body: { schema: strict }
  resources:
    - Path: { repo: "{owner}/{repo}", ref: "refs/heads/{branch}", path: "{path}" }
  verb: contents.write
  effects: [write.reversible, exec.ci]      # any push can trigger `on: push` workflows
  response:
    max_bytes: 65536
    project: ["/content/path", "/content/sha", "/commit/sha", "/commit/html_url"]
  native: { permission: { contents: write } }
  # dangerous patterns (§4.6) gh.workflow_path / gh.default_branch_write apply automatically

# 3. Issue comment with @mentions: external notification, may trigger ChatOps
- id: issues.comments.create
  source: { openapi_op: "issues/create-comment", x_github: { triggersNotification: true } }
  match: { method: POST, path: "/repos/{owner}/{repo}/issues/{issue_number}/comments" }
  params:
    owner: { from: path, type: gh_login }
    repo:  { from: path, type: gh_repo }
    issue_number: { from: path, type: u64 }
    body:  { from: body, pointer: "/body", type: string, max_len: 65536 }
  body: { schema: strict }
  resources:
    - Issue: { repo: "{owner}/{repo}", number: "{issue_number}" }   # covers PRs too (same number space)
  verb: issues.comment
  effects: [write.reversible, notify.external, publish]   # subscribers + participants are notified
  rewrite:
    - id: neutralize_mentions          # narrowing transform, policy-selectable
      when: { param: body, matches_pattern: gh.mention }
      action: { wrap_in_code_span: gh.mention }   # `@alice` in backticks → no notification
  response: { max_bytes: 16384, project: ["/id", "/html_url", "/created_at"] }
  native: { permission: { issues: write } }   # PRs: pull_requests: write

# 4. Search issues: read that returns too much → query rewrite
- id: search.issues
  source: { openapi_op: "search/issues-and-pull-requests" }
  match: { method: GET, path: "/search/issues" }
  params:
    q:        { from: query, type: gh_search_query, max_len: 256 }
    sort:     { from: query, enum: [comments, reactions, created, updated, interactions], required: false }
    order:    { from: query, enum: [asc, desc], required: false }
    per_page: { from: query, type: u8, max: 100, required: false }
    page:     { from: query, type: u16, max: 10, required: false }
  resources:
    - Repo: { each_of: "scope.repos" }      # resources = the task's in-scope repos
  verb: issues.search
  effects: [read.broad]
  rewrite:
    - id: pin_repo_scope
      action:
        search_qualifiers:
          deny_qualifiers: [repo, org, user, owner, involves, author, assignee, mentions, commenter]
          deny_operators: [OR, NOT]          # keep the rewrite sound; parse fully or deny
          append: "repo:{scope.repos | join(' repo:')}"   # GitHub ANDs terms, ORs same-qualifier repos
  response:
    max_bytes: 262144
    verify: [ { each: "/items/*/repository_url", in: "https://api.github.com/repos/{scope.repos}" } ]  # belt and braces: drop non-matching items
    project: ["/total_count", "/items/*/number", "/items/*/title", "/items/*/state", "/items/*/repository_url", "/items/*/html_url", "/items/*/user/login", "/items/*/author_association"]
    label: { taint: "github-user-content" }
  native: { permission: { issues: read, metadata: read } }

# 5. Move a branch pointer: force updates and protected refs
- id: git.refs.update
  source: { openapi_op: "git/update-ref" }
  match: { method: PATCH, path: "/repos/{owner}/{repo}/git/refs/{ref+}" }
  params:
    owner: { from: path, type: gh_login }
    repo:  { from: path, type: gh_repo }
    ref:   { from: path, type: git_refname }   # e.g. heads/feature-x (no refs/ prefix in this API)
    sha:   { from: body, pointer: "/sha", type: git_oid }
    force: { from: body, pointer: "/force", type: bool, required: false, default: false }
  body: { schema: strict }
  resources:
    - Ref: { repo: "{owner}/{repo}", ref: "refs/{ref}" }
  verb: git.ref.update
  effects: [write.reversible, exec.ci]
  raise:
    - when: { param: force, equals: true }
      effects: [write.irreversible]
    - when: { param: ref, not_glob: "heads/**" }       # tags, notes, other namespaces
      effects: [write.irreversible, publish]
  # Can't see which paths the new commit touches → gh.ref_move_unknown_tree (§4.6) applies
  native: { permission: { contents: write }, also: [ { workflows: write, when: gh.workflow_path } ] }

# 6. Alias route: same resources, different spelling. Must be mapped or denied.
- id: repos.by_id.alias
  match: { method: "*", path: "/repositories/{repository_id}/{rest*}" }
  params: { repository_id: { from: path, type: u64 } }
  alias_of: { resolve: repo_by_id, rewrite_path: "/repos/{owner}/{repo}/{rest}" }  # re-dispatch, re-match
```

**Git smart-HTTP adapter** (protocol adapter, not REST):

```yaml
adapter: github-git
hosts: ["github.com"]
endpoints:
  - id: git.discover
    match: { method: GET, path: "/{owner}/{repo}.git/info/refs", query: { service: [git-upload-pack, git-receive-pack] } }
    resources: [ { Repo: { repo: "{owner}/{repo}" } } ]
    verb: "git.{service == git-receive-pack ? push.discover : fetch}"
    effects: [read.scoped]
  - id: git.fetch
    match: { method: POST, path: "/{owner}/{repo}.git/git-upload-pack" }
    resources: [ { Repo: { repo: "{owner}/{repo}" } } ]
    verb: git.fetch
    effects: [read.scoped]
    response: { label: { taint: "repo-content:{owner}/{repo}" } }
  - id: git.push
    match: { method: POST, path: "/{owner}/{repo}.git/git-receive-pack" }
    handler: receive_pack_store_and_forward      # §3.4; per-ref and per-path decisions
    per_ref:
      resources: [ { Ref: { repo: "{owner}/{repo}", ref: "{refname}" } } ]
      verb: git.push
      effects: [write.reversible, exec.ci]
      raise:
        - when: { new_oid: zero }            # deletion
          effects: [write.irreversible]
        - when: { non_fast_forward: true }   # force push
          effects: [write.irreversible]
        - when: { refname: { not_glob: "refs/heads/**" } }
          effects: [write.irreversible, publish]
    per_changed_path:                          # every path changed in old..new, every commit
      resources: [ { Path: { repo: "{owner}/{repo}", ref: "{refname}", path: "{path}" } } ]
      verb: contents.write
  - id: git.lfs
    match: { method: POST, path: "/{owner}/{repo}.git/info/lfs/objects/batch" }
    verb: "git.lfs.{body.operation}"          # upload | download
    effects: [write.reversible]               # for upload
```

**GraphQL** (`POST /graphql`): v1 is `deny`, except `persisted_operations` (a sha256 of the
normalized document → a hand-written entry with params and resources from `variables`, effects
and a response projection). The generator may *propose* persisted entries but never auto-enable
them.

### 4.6 Dangerous-patterns list (GitHub, hand-maintained)

Applied after classification. A match can only raise risk or force deny.

| id | Pattern | Effect |
|---|---|---|
| `gh.workflow_path` | any write whose changed path matches `.github/workflows/**`, `.github/actions/**`, `**/action.yml`, `**/action.yaml`, `.github/dependabot.yml`, `.github/copilot-*`, `.devcontainer/**` | raise `exec.ci.privileged` (R4). Native: token lacks `workflows` unless granted |
| `gh.repo_policy_files` | `CODEOWNERS`, `.github/CODEOWNERS`, `docs/CODEOWNERS`, `.gitattributes` (filters/LFS), `.gitmodules` | raise `perm.manage` / `exec.ci`; `.gitmodules` URL changes → deny by default |
| `gh.agent_config_files` | `CLAUDE.md`, `AGENTS.md`, `.claude/**`, `.cursor/**`, `.mcp.json`, `.vscode/settings.json`, `.vscode/tasks.json` | raise R3: these instruct future agents (cross-agent smuggling via repo state) |
| `gh.build_hooks` | `Makefile`, `package.json` (`scripts`), `setup.py`, `build.rs`, `.husky/**`, `.pre-commit-config.yaml`, `Dockerfile`, `**/conftest.py` | raise `exec.ci` (code that CI or a later agent runs). Advisory: incomplete by nature |
| `gh.default_branch_write` | any write whose ref == resolved default branch (or `main`/`master` when unresolved) | raise R3; pair with branch protection |
| `gh.ref_move_unknown_tree` | git-refs create/update or PR-branch update via API (tree unknown to gateway) | treat changed paths as `**`, so all path patterns apply; usually forces R4 unless the commit's tree diff is resolved by lookup (`GET /compare/{old}...{new}`) |
| `gh.pr_merge` | `PUT /pulls/{n}/merge`, merge-async, auto-merge enable | `write.irreversible` + `exec.ci` + inherit **all** path patterns of the PR's diff (resolve via `GET /pulls/{n}/files`, paginated, ≤3,000 files cap → deny if over) |
| `gh.mention` | `(?:^|[^\w`])@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:/[A-Za-z0-9._-]+)?` outside code spans/blocks, in any text field | `notify.external`; rewrite option `neutralize_mentions` |
| `gh.cross_ref` | `[\w.-]+/[\w.-]+#\d+` or full issue/PR URLs to repos outside scope | writes a backlink into **another repo's timeline**: deny unless target in scope |
| `gh.closing_keywords` | `(close[sd]?|fix(e[sd])?|resolve[sd]?) #\d+` in PR bodies/commit messages | `write.irreversible` on referenced issues at merge |
| `gh.chatops` | body line starting with `/` (`/deploy`, `/approve`), `atlantis apply`, bot-specific triggers configured per repo | `exec.ci.privileged` (`issue_comment` workflows run on default branch with secrets) |
| `gh.markdown_exfil` | images/links to non-GitHub hosts in any rendered text (`![](https://…?q=…)`) | `publish` + flag: human viewers' browsers (via camo) fetch them, a classic exfil channel; default rewrite: strip external images |
| `gh.collaborators_perm` | collaborators, teams, deploy keys, secrets, variables, hooks, environments, branch protection/rulesets, actions permissions, app installations | `perm.manage` / `cred.material` (R4) |
| `gh.visibility` | repo PATCH of `private`/`visibility`, fork, transfer, archive, release publish, pages | `publish` / `write.irreversible` |
| `gh.graphql` | any `/graphql` not in persisted allowlist | deny |
| `gh.alias_routes` | `/repositories/{id}/…`, `/user/repos`, renamed-repo 301 redirects, `uploads.github.com` release assets | must resolve to canonical repo before deciding, else deny |
| `gh.actions_dispatch` | `POST /actions/workflows/{id}/dispatches`, `/rerun*`, `/repository_dispatch` | `exec.ci.privileged` |

The generator must run its output against this list and **cannot remove entries**. A new
dangerous pattern is a human-reviewed change to this file, which then applies to all existing
adapters.

### 4.7 Generated-adapter verification loop

**Generation** (no agent context, per the brief):
- Inputs: OpenAPI op + docs permission entry + provider risk metadata (GitHub
  `triggersNotification`, AWS `Is*`, Cloudflare `x-api-token-group`) + the observed request
  *shape* (method, path template, field names, not values).
- Output: one endpoint entry at **R4/`unknown`**, every observed field declared, resources
  bound from path params, `body: strict`.

**Static checks** (mechanical; reject on fail):
1. JSON Schema validity and type-check of templates (every `{param}` used in a resource is
   declared and typed).
2. **Coverage**: every parameter in the OpenAPI op is declared or explicitly `reject`ed, and
   every required path param flows into some resource. Otherwise the param can't influence the
   decision.
3. **Floors**: risk ≥ floor from provider metadata. GitHub `access: write` → ≥ R2;
   `triggersNotification` → `notify.external`; AWS `IsPermissionManagement` → `perm.manage`.
   The dangerous-pattern pass is re-run.
4. **Narrower-never-wider vs the previous adapter version**: compile both to Cedar (the adapter
   yields the action and resource typing, the policy is fixed). Use `cedar-policy-symcc` to check
   that for the fixed task policy, `allows(new) ⊆ allows(old) ∪ approved_delta`. For
   adapter-level changes symcc can't see (classification functions), use the differential
   corpus below.

**Dynamic checks in a sandbox provider account** (GitHub: a dedicated test org with fixture
repos `in-scope/*` and `out-of-scope/*`, branches `main`/`feature`, issues, PRs, a workflow that
posts to a webhook sink, and a second user account for mention and notification sinks):

1. **Allow/deny matrix.** For each endpoint, generate requests over
   {in-scope, out-of-scope} × {each resource-bearing param} × {canonicalization attacks:
   `%2F`, `..`, case variants (`ACME/Widgets`), trailing slash, duplicate query/JSON keys,
   method override headers, alias routes (`/repositories/{id}`), renamed repo, default-branch
   omission}. Run them through the gateway. **Expected**: deny for every out-of-scope or
   ambiguous variant.
2. **Execute the allows** against the test org with a credential that has *wider* native
   permissions than the task. Then confirm the resource actually touched matches the adapter's
   claimed resource (`GET` it back, check audit log and events API). That's resource-extraction
   correctness, the part the origin brief estimated as ~70% automatable.
3. **Side-effect observation.** Watch the webhook sink, notification API of the second user,
   Actions runs and email sink (a catch-all domain) for effects not declared. An observed
   undeclared effect gets added (raise). An *absence* is evidence but not proof, so downgrades
   below R3 (`notify.external`, `exec.*`) need human sign-off on a small diff.
4. **Oracle cross-check.** Compare against the `X-Accepted-GitHub-Permissions` response header
   and the docs permission JSON. A mismatch between the adapter's `native.permission` and either
   source fails the check.
5. **Red-team regression.** Escapes found by the red-team agent (origin brief: >3 escapes =
   rethink) become permanent matrix rows.

**Result**: the adapter lands at the lowest risk class the evidence supports, carries signed
evidence references, and the matrix is re-run on every adapter change and on every provider
OpenAPI version bump (GitHub now has two REST versions, 2022-11-28 and 2026-03-10).

---

## 5. Codemode as an enforcement surface

Prior art:
- **Cloudflare Code Mode** ([blog, 2025-09-26](https://blog.cloudflare.com/code-mode/)): MCP
  tools become a TypeScript API, and the model writes code run in a Dynamic Worker. The Worker
  Loader's `globalOutbound: null` blocks all `fetch()`/`connect()`, and tool calls go over RPC
  **bindings** to the host, which holds the credentials
  ([egress control](https://developers.cloudflare.com/dynamic-workers/usage/egress-control)).
  Note that omitting `globalOutbound` gives *full* internet. MCP portals default to Code Mode
  (one `code` tool) since 2026-03 and have admin "Enforced" mode since 2026-07. **[H]**
- **Anthropic "Code execution with MCP"**
  ([2025-11-04](https://www.anthropic.com/engineering/code-execution-with-mcp)): servers as a
  filesystem of TS modules, progressive disclosure / `search_tools`, filtering large results in
  code, **PII tokenization by the MCP client** before data reaches the model, state in files, and
  skills from saved code. It explicitly calls out sandboxing, resource limits and monitoring as
  costs. **[H]**
- Stainless's MCP servers are code-mode only. Codex has `code-mode*` crates running V8 with
  `v8_enable_sandbox` **[M]**.

**Does it change the gateway design?** Mostly no, with five adjustments **[L]**:

1. **The reference monitor doesn't move.** Each `codemode.github.createComment(...)` call is
   an RPC through the same gateway, adapter and engine. Codemode is a *client* of the gateway.
   The codemode sandbox gets **no network** (only the gateway binding), the same as the agent
   sandbox.
2. **Generate typed stubs from adapters, not from upstream schemas.** The gateway emits `.d.ts`
   (or Python stubs) from its narrowed adapters, so the type *is* the policy: e.g.
   `repo: "acme/widgets"`, `branch: \`wicket/${string}\``. The model sees fewer and narrower
   capabilities, and an attempt outside them fails type-checking before it reaches the gateway.
3. **Handles become natural.** Intermediate results can stay in the codemode runtime as
   handles, and only typed, low-information fields return to the model. That's FIDES/CaMeL's
   "variables, not contents" idea, which the origin brief wants for agent trees. The gateway
   should support a `result_mode: handle` where it stores the result, returns
   `{handle, schema, label, summary_fields}`, and allows later tool calls to take handles as
   arguments (resolved gateway-side, label-checked).
4. **Rate, budget and ratchet controls matter more.** A loop in code can make 10,000 calls in
   a minute with no model turn in between. Per-task budgets (calls, bytes, distinct resources,
   R2 writes) belong in the engine, not the stub.
5. **No atomicity.** A code block can partially execute before hitting a deny or pending
   approval. The structured "pending/retry" error must be catchable in code, and compensation
   isn't the gateway's job. Optional future work: **static pre-flight** of the program (extract
   the set of stub calls and their literal args) to request grants up front, CaMeL-style. That's
   only sound if the code was written before untrusted data was read **[L]**.

**For Claude Code specifically**, the agent already has codemode via Bash: it writes curl, gh
and Python scripts. So the **egress proxy is Claude Code's codemode enforcement surface**, and
the MCP gateway is the structured surface. Both must use the same adapters, which is the core
reason for the single resource model.

---

## 6. Response-side controls

| Control | Mechanism | Boundary? |
|---|---|---|
| **Size limits** | per-endpoint `max_bytes`; per-task byte budget; truncate with an explicit marker + handle to the rest. Claude Code caps MCP output at ~25k tokens by default, adjustable via `MAX_MCP_OUTPUT_TOKENS` **[M, secondary sources]** | yes (resource) |
| **Projection** | allowlist JSON pointers per endpoint (§4.4). Dropping unknown fields also stops new provider fields leaking data | yes, deterministic |
| **Integrity filtering by provenance** | drop or label items authored by non-collaborators (GitHub MCP lockdown mode precedent; `author_association` field) | yes for what it filters, not for injection in trusted authors' content |
| **Scope verification** | `response.verify` re-checks returned items' resource IDs against the decision (catches TOCTOU on opaque IDs, search leaks) | yes |
| **Secret redaction** | the proxy knows every real credential it injects, so it scans responses for those exact values (and their base64/url forms) and redacts | yes for wicket-held secrets |
| **Labels** | every response gets an IFC label (resource set + `taint`) stored **gateway-side** and keyed by the handle or the agent; MCP content `annotations.audience/priority` are hints for the client only | yes, if enforced at egress (no write-down) |
| **Handles** | `result_mode: handle`: content never enters the model context; typed summary fields only | yes, strongest |
| **Structured output validation** | validate `structuredContent` against the *adapter's* output schema; drop free text when structured exists | partial |
| **Prompt-injection scanning** | classifiers (PromptGuard-class, Lakera, Model Armor, Bedrock Guardrails) on tool results | **no** |

**Why scanning isn't a boundary** **[H on evidence]**:
- Adaptive attackers bypassed 12 recent defenses at >90% ASR, most of which reported near-zero
  ASR originally ([arXiv 2510.09023](https://arxiv.org/abs/2510.09023)).
- Classifiers are probabilistic; the attacker iterates offline; and natural language has no
  grammar to separate data from instructions.
- The structural approaches have the guarantees: Meta's
  [Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/) (no more than two
  of: untrusted input, sensitive access, external state change), Willison's
  [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/),
  [CaMeL](https://arxiv.org/abs/2503.18813), [FIDES](https://arxiv.org/abs/2505.23643), and the
  [design-patterns paper](https://arxiv.org/abs/2506.08837).

**wicket rule:** a scanner hit may *raise* a label (taint), trigger an alert, or tighten
budgets. A scanner pass may never lower a label or grant anything (narrower-never-wider again).

---

## 7. Recommendations for wicket's enforcement plane

### 7.1 Architecture

```
            ┌──────────── sandbox (microVM / container; NO network namespace route) ────────────┐
            │  claude (black box)   gh / git / curl / aws / SDKs     optional codemode runtime   │
            │     │ MCP (streamable HTTP over unix sock)   │ HTTPS_PROXY (CONNECT over unix/vsock)│
            └─────┼────────────────────────────────────────┼─────────────────────────────────────┘
                  ▼                                        ▼
      ┌────────────────────────┐              ┌───────────────────────────────┐
      │  MCP gateway (rmcp)    │              │  Egress proxy (rama)          │
      │  - 2025-11-25 + 2026-07│              │  - CONNECT host gate, SNI/Host│
      │  - tools from adapters │              │  - per-sandbox CA (rcgen, NC) │
      │  - pinned 3rd-party    │              │  - canonicalize-or-reject     │
      │    tools (hash)        │              │  - git receive-pack S&F       │
      │  - handles, labels     │              │  - strip+inject / SigV4 resign│
      └──────────┬─────────────┘              └──────────────┬────────────────┘
                 │  normalize → Op{provider, verb, resources[], effects, risk, labels, budget}
                 ▼                                           ▼
           ┌───────────────────────────────────────────────────────────┐
           │  Decision engine (in-process lib, one per host)            │
           │  adapter interpreter (YAML→typed IR) + dangerous patterns   │
           │  Cedar policies (task manifest → policy) + budgets + labels │
           │  escalation broker (typed requests → parent/human, IDs)     │
           │  credential vault (GitHub App tokens, OAuth, AWS STS)       │
           │  audit log (append-only, per Op, both planes)               │
           └───────────────────────────────────────────────────────────┘
                 │ upstream HTTP client (shared: DNS pinning, SSRF deny, no redirects)
                 ▼
          providers (GitHub, AWS, Slack, …), remote MCP servers, sandboxed 3rd-party MCP servers
```

- **One resource model and one engine.** Both planes normalize to the same `Op`. A
  gateway-native MCP tool is *defined by* an adapter endpoint, and its implementation executes
  the HTTP call through the **same upstream client and adapter match** the proxy uses. A tool
  call and a `gh api` call to the same endpoint get the same decision by construction.
- **Three kinds of MCP tools**:
  1. Gateway-native, generated from adapters (preferred; descriptions are wicket's).
  2. Third-party MCP servers run **in their own sandbox** with egress through the wicket proxy,
     so their HTTP is mediated by the adapters too. Tool-level policy plus hash pinning sit on
     top.
  3. Remote MCP servers (SaaS). Only tool-level adapters (argument extraction → resources) are
     possible, plus response controls, with upstream tokens held by wicket and RFC 8707
     audience-bound.
- **Proxy↔engine seam**: adopt **srt-proxy decider protocol v1 semantics** (framed strict JSON;
  allow with set/remove headers and credential, deny, need_body; fail closed; per-request
  timeout) as wicket's internal interface. Then:
  - (a) A v0 prototype can run Anthropic's `srt-proxy` (Node/Bun) with a Rust decider while the
    rama proxy is built.
  - (b) A Rust data plane can be swapped behind it later.
  - (c) The decider is testable offline from recorded `req` frames.

  **[M]** Check the srt license (Apache-2.0) and the protocol's stability before depending on it.
- **Escalation surface**: a deny returns 403 with
  `X-Wicket-Request-Id` and a JSON body `{error: "pending_approval"|"denied", request_id,
  retry_after, typed_request}`. MCP returns an `isError` result with the same, or
  `input_required` / a task handle when the client supports them. Never hold connections open
  for humans.
- **Native narrowing first**: per-task GitHub App installation tokens (repo IDs + permission
  subset, *without* `workflows`/`administration` unless granted), AWS STS session policies,
  Stripe restricted keys, and Cloudflare scoped tokens. The gateway narrows further. A gateway
  bug is then capped by native scope.

### 7.2 Crates to build on

| Need | Choice | Fallback |
|---|---|---|
| MCP server + client | **rmcp 3.9** (`server`, `client`, `transport-streamable-http-server`, `transport-streamable-http-client-reqwest`, `transport-child-process`, `auth`) | study agentgateway's `crates/agentgateway/src/mcp/*` for multiplexing and version bridging |
| Proxy data plane | **rama 0.4** (follow Codex's precedent, pin exact versions) | hyper 1.12 + h2 + tokio-rustls hand-rolled; hudsucker 0.25 for a spike |
| TLS / CA | rustls 0.23 (aws-lc-rs), **rcgen 0.14** with NameConstraints | — |
| AWS | aws-sigv4 (re-sign), service-reference JSON for adapter generation | — |
| Policy | **cedar-policy 4.14** + **cedar-policy-symcc 0.8** (verification) | CEL (`cel` 0.15) for hand-written predicates only |
| GraphQL | **apollo-compiler 1.33** (validate against pinned schema) | deny |
| Git | `git receive-pack` with quarantine + wicket pre-receive; **gix 0.90** for mirror management and diffs | pure gix pack indexing later |
| JSON | serde_json with a **duplicate-key-rejecting visitor** (serde_json's `Value` silently keeps the last key) **[M]**; `jsonschema` for body validation; RFC 8785 canonicalization for hashing | — |
| Matching | `regex` (linear-time, no backtracking; lookarounds in §4.4's branch regex would need rewriting as explicit checks since `regex` lacks them), `globset`, `url`/`percent-encoding` (match as spelled) | — |
| DNS / SSRF | hickory-resolver (resolve once, dial the vetted IP), ipnet | — |

### 7.3 Build order (smallest tests first)

1. A **decider + adapter interpreter** for ~15 GitHub REST endpoints plus the git smart-HTTP
   push handler. Front it with `srt-proxy` or a thin rama proxy. Run the §4.7 matrix in a test
   org.
2. A **gateway-native MCP tools** generator from the same adapters (rmcp server), so Claude Code
   gets MCP tools and `gh` hits the same rules. Diff the decisions.
3. A **red-team agent** scoped to one repo and one directory (origin brief). Every escape
   becomes a dangerous pattern or matrix row.
4. Third-party MCP server sandboxing plus hash pinning. Then remote MCP with wicket-held OAuth.
5. Handles and labels on responses. Typed stubs for codemode.

### 7.4 Open risks

1. **Parser differentials** between wicket and providers (paths, JSON duplicates, query arrays,
   multipart, Unicode case folding of repo names, GraphQL). Mitigation: reject-ambiguous plus a
   differential test corpus. This is where bypasses will come from. **[M]**
2. **Undeclared provider side effects** (CI triggers on any push, `issue_comment` ChatOps,
   notifications, cross-repo backlinks, camo image fetches). Testing can't prove absence, so
   human sign-off for downgrades stays permanent.
3. **Alias routes and completeness**: `/repositories/{id}`, the git data API, PR merge,
   `update-branch`, release uploads, renamed-repo redirects. Any unmapped equivalent route has
   to be denied, and the matrix has to keep up with new API versions (GitHub's 2026-03-10).
4. **Pinned/mTLS clients** force SNI-only tunnels with no semantics or injection. Those hosts
   are unmediated channels and must appear as such in the zone view.
5. **Git store-and-forward** adds latency, disk, git-in-TCB, LFS and submodule edge cases, and
   non-fast-forward checks needing a fresh mirror (race with concurrent upstream pushes; the
   upstream push uses `--force-with-lease`-style expected old-oids).
6. **MCP churn**: 2026-07-28 broke the protocol shape eight months after 2025-11-25. The gateway
   must bridge versions (agentgateway's notes show how), and Claude Code's per-surface support
   for 2026-07-28 wasn't documented as of today **[M]**.
7. **rama is pre-1.0**: pin exactly, as Codex does, and keep the decider seam so the data plane
   is replaceable.
8. **Opaque-ID TOCTOU** (issue transfer, ref moves between check and use). `response.verify`
   catches some cases after the fact. Writes can't be un-done, so writes on resolved IDs should
   carry the expected state (e.g. `sha` preconditions) where the API supports it.
9. **Codemode velocity**: thousands of allowed calls per minute can exfiltrate through allowed
   writes. Budgets and label checks, not per-call allow, are the control.
10. **Covert channels through allowed writes** (commit messages, branch names, comment timing)
    remain. Labels and egress-clearance rules bound them, and nothing eliminates them.

---

## Sources (primary unless noted)

- MCP: [2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog) · [2025-11-25 changelog](https://modelcontextprotocol.io/specification/2025-11-25/changelog) · [authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) · [tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) · [elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation) · [security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) · [release blog](https://blog.modelcontextprotocol.io/posts/2026-07-28/) · [Claude blog 2026-07-28](https://claude.com/blog/bringing-mcp-2026-07-28-to-claude)
- rmcp: [repo](https://github.com/modelcontextprotocol/rust-sdk) · [docs.rs](https://docs.rs/crate/rmcp/latest)
- Gateways: [agentgateway](https://github.com/agentgateway/agentgateway) · [agentgateway mcp-authz](https://agentgateway.dev/docs/standalone/latest/mcp/mcp-authz/) · [Docker MCP gateway](https://github.com/docker/mcp-gateway) · [docker mcp gateway run](https://docs.docker.com/reference/cli/docker/mcp/gateway/gateway_run) · [ContextForge](https://github.com/IBM/mcp-context-forge) · [Microsoft mcp-gateway](https://github.com/microsoft/mcp-gateway) · [Pomerium MCP](https://www.pomerium.com/docs/capabilities/mcp) · [Cloudflare MCP portals](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/) · [Kong MCP ACLs](https://konghq.com/blog/product-releases/mcp-tool-acls-ai-gateway) · [Agent Router (ex-Envoy AI Gateway)](https://github.com/theagentrouter/agent-router) · [Envoy AI GW MCP](https://aigateway.envoyproxy.io/docs/capabilities/mcp/) · [Lasso mcp-gateway](https://pypi.org/project/mcp-gateway/) · [Invariant guardrails ref](https://invariantlabs-ai.github.io/docs/mcp-scan/guardrails-reference) · [Snyk agent-scan](https://github.com/snyk/agent-scan) · [mcp-scan intro](https://invariantlabs.ai/blog/introducing-mcp-scan) · [tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) · [ETDI](https://arxiv.org/abs/2506.01333) · [GitHub MCP server config](https://github.com/github/github-mcp-server/blob/main/docs/server-configuration.md)
- Egress: [sandbox-runtime](https://github.com/anthropics/sandbox-runtime) · [srt-proxy decider protocol](https://github.com/anthropics/sandbox-runtime/blob/main/docs/srt-proxy.md) · [codex-network-proxy](https://github.com/openai/codex/tree/main/codex-rs/network-proxy) · [Codex approvals & security](https://learn.chatgpt.com/docs/agent-approvals-security) · [Claude Code cloud sessions](https://code.claude.com/docs/en/claude-code-on-the-web) · [Claude Code cloud environments](https://code.claude.com/docs/en/cloud-environments) · [Claude Code network config](https://code.claude.com/docs/en/network-config) · [Copilot agent firewall](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall) · [gh-aw-firewall](https://github.com/github/gh-aw-firewall) · [smokescreen](https://github.com/stripe/smokescreen) · [rama](https://github.com/plabayo/rama) · [hudsucker](https://github.com/omjadas/hudsucker) · [pingora](https://github.com/cloudflare/pingora) · [rcgen](https://github.com/rustls/rcgen)
- Git: [gitprotocol-http](https://git-scm.com/docs/gitprotocol-http) · [gitprotocol-pack](https://git-scm.com/docs/gitprotocol-pack) · [gitprotocol-v2](https://git-scm.com/docs/gitprotocol-v2) · [receive-pack quarantine](https://git-scm.com/docs/git-receive-pack#_quarantine_environment) · [GitHub rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets) · [installation access tokens](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)
- Adapter prior art: [AWS service reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html) · [Smithy IAM traits](https://smithy.io/2.0/aws/aws-iam.html) · [GitHub permission data](https://github.com/github/docs/tree/main/src/github-apps/data) · [GitHub REST OpenAPI](https://github.com/github/rest-api-description) · [X-Accepted-GitHub-Permissions](https://github.blog/changelog/2023-08-10-x-accepted-github-permissions-header-for-fine-grained-permission-actors) · [fine-grained PAT permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens) · [Cloudflare api-schemas](https://github.com/cloudflare/api-schemas) · [Stripe restricted keys](https://docs.stripe.com/keys/restricted-api-keys) · [Google discovery](https://developers.google.com/discovery/v1/reference/apis) · [k8s RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) · [k8s requestinfo.go](https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiserver/pkg/endpoints/request/requestinfo.go) · [FastMCP OpenAPI](https://gofastmcp.com/integrations/openapi) · [Stainless MCP](https://www.stainless.com/docs/mcp) · [Speakeasy Gram](https://www.speakeasy.com/docs/mcp/getting-started/openapi) · [Cedar](https://github.com/cedar-policy/cedar) · [cedar-policy-symcc](https://docs.rs/cedar-policy-symcc) · [Cedar analysis blog](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies) · [Cedar paper](https://arxiv.org/abs/2407.01688)
- Codemode: [Cloudflare Code Mode](https://blog.cloudflare.com/code-mode/) · [Dynamic Workers egress control](https://developers.cloudflare.com/dynamic-workers/usage/egress-control) · [Anthropic code execution with MCP](https://www.anthropic.com/engineering/code-execution-with-mcp)
- Injection: [The Attacker Moves Second](https://arxiv.org/abs/2510.09023) · [Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/) · [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) · [CaMeL](https://arxiv.org/abs/2503.18813) · [FIDES](https://arxiv.org/abs/2505.23643) · [design patterns](https://arxiv.org/abs/2506.08837) · [Willison on both papers](https://simonw.substack.com/p/new-prompt-injection-papers-agents)
