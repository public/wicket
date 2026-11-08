# 08 — Open-source gateways, proxies, policy engines and tokens, read at source level

*2026-11-08. Scope: the enforcement plane only, meaning MCP gateways, egress and credential proxies, policy engines, capability tokens, credential brokers, and guardrail and scanner tools. Sandbox and runtime projects (srt, the Codex sandbox, microsandbox, E2B and others) are covered by another study.*

Earlier research ([03](03-policy-authority-ifc.md), [04](04-enforcement-plane.md)) worked mostly from docs and READMEs. This file reads the **code** and checks it against [`../design.md`](../design.md) §3, §4, §8, §9, §10 and §13.

**How the study was done:**
- About 50 projects were shallow-cloned into `refs/repos/<name>` (`git clone --depth 1`, sparse for the large repos; hooks disabled). The SHA, date and licence of each are in `refs/tools/manifest.txt`.
- Nothing was built, installed or run.
- Instructions embedded in the repos (CLAUDE.md, AGENTS.md) were treated as data.
- Citations name files and functions at the recorded commit.
- Confidence: **H** = code read; **M** = partly read or inferred; **L** = docs or memory only.

**Excluded:** `Dicklesworthstone/flywheel_connectors`. Its licence rider withholds every right from Anthropic and from anyone acting for it, and it defines "use" to include "analyzing". The clone was deleted after reading the LICENSE.

**Contents:**
1. MCP gateways and the SDK
2. Egress and credential proxies
3. Policy engines, capability tokens, catalogs and generators
4. Guardrails, scanners and audit
5. Gateway ↔ isolated MCP servers (cross-project)
6. Synthesis: (a1) reuse plan, (a2) ranked design changes, (a3) gateway ↔ isolated servers, (a4) contradictions, (b) table

---

## 1. MCP gateways and the SDK

### agentgateway/agentgateway — Rust data plane for MCP, A2A and LLM traffic (https://github.com/agentgateway/agentgateway, Apache-2.0, commit d327d10bc92b, v1.7.0 2026-10-27)
- Local path: `refs/repos/agentgateway`. Rust. Mature and very active; a Linux Foundation project, and kgateway's data plane. Every workspace crate is `publish = false` (root `Cargo.toml`; `crates/agentgateway`, `crates/llm` and `crates/core` all inherit it), and the version is `0.0.0`. It also carries its own CEL fork (`crates/cel-fork`, `crates/celx`).
- **Architecture as implemented** (`crates/agentgateway/src/mcp/`, about 23k lines of which 10k are `mcp_tests.rs`):
  - **What it takes from rmcp.** Only rmcp's *model types*, its child-process and client pieces, and the upstream HTTP client: `rmcp = 3.9.0` features `client, server, server-side-http, transport-child-process`, plus `legacy-rmcp = rmcp 0.10.0` for old SSE. It does **not** use rmcp's `ServerHandler`/`serve`. The downstream Streamable HTTP server (`streamablehttp.rs`, its own `StreamableHttpService`) and the session relay (`session.rs`, `handler.rs`) are its own code, working on `ClientJsonRpcMessage`/`ServerJsonRpcMessage` values. This is the pattern for a *relaying* gateway: a message-level relay over rmcp types.
  - **Upstreams** (`upstream/mod.rs`): `McpTargetSpec::{Sse, Mcp (streamable HTTP), Stdio{cmd,args,env,clear_env}, OpenAPI}`. A stdio server is a plain `tokio::process::Command` wrapped in rmcp's `TokioChildProcess`, with no isolation at all. The process runs with the gateway's privileges, and its env is inherited unless `clear_env` is set.
  - **Multiplexing** (`handler.rs`). Names are prefixed `target_name` (`DELIMITER = "_"`). Target names are validated against the Gateway API SectionName pattern, where `_` and `+` are reserved (`types/agent.rs` ~l.2056), so `split_once('_')` cannot misroute.
    - With prefixing off, `resolve_unprefixed` lists *every* target on each call (there is a TODO to cache this). A name served by two targets is an error, and `duplicate_names` drops ambiguous names from lists.
    - Server-initiated request IDs are namespaced `agw_<upstream>_{n|s}_<id>` so IDs from different upstreams can't collide.
  - **Version bridging** (`mcp/README.md`, `merge_discover`, `merge_initialize`, `normalize_outbound_for_protocol`).
    - `server/discover` is fanned out and the intersection of supported versions is returned. Any upstream error makes the client fall back to `initialize`.
    - Old clients keep the old protocol upstream.
    - There is no "compatibility mode" in which the gateway downgrades on the client's behalf (a deliberate non-goal).
    - **All caching of proxied results is disabled**, and upstream cache fields are stripped (`with_gateway_cache_policy`). The reason: policy may depend on request attributes, so `private`/`public` scopes would be wrong.
- **Policy model and enforcement**:
  - `mcpAuthorization` (`rbac.rs`) is a CEL `RuleSet` evaluated per tool, prompt, resource or task, through `McpAuthorizationSet::validate(res, method, cel)`.
  - **The CEL context for authorization holds only `{target, name}` and `methodName`.** `MCPInfo::from(&ResourceType)` (`mod.rs` l.912) builds `MCPTool{target,name,..Default}`, so `mcp.tool.arguments` is *None* during authorization. Arguments are available only to **guardrails** (`mcp.params.arguments`, `guardrails/`), which run *before* authorization and may mutate params (`authorize_with_ctx`: "run guardrails before other policies, as it may add context to CEL").
  - So design.md's "matches tool names" is accurate for authorization. A CEL guardrail can deny on arguments, but nothing binds arguments to resources, and a guardrail mutating params is a second writer before the decision.
  - **No rules means allow** (`if !self.0.has_rules() { return true; }`). Merging is sound: a base deny survives a higher-precedence allow (test `test_backend_policies_merge_composes_mcp_authorization`).
  - List results are filtered through the same `validate` (`merge_tools`/`merge_prompts`/`merge_resources`, with `methodName` distinguishing list from call).
  - Denials surface as `UpstreamError::Authorization{resource_type, resource_name}`, which becomes a JSON-RPC error.
  - Guardrail `FailureMode` defaults to **FailClosed** (`guardrails/mod.rs` l.215). FailOpen is opt-in, and in `resolve_unprefixed` FailOpen also skips upstreams that error.
- **Credentials**: backend auth policies (`http/auth/mod.rs`) insert configured keys, GCP tokens and others into a declared location. JWT authentication removes the validated token unless `preserve_token` (`http/jwt.rs` l.627).
- **Bugs, gaps and bypass risks**:
  1. **Client headers pass through by default.** `IncomingRequestContext::apply` (`upstream/mod.rs` ~l.95) copies *every* inbound header not already set, except content-encoding, content-length and the session ID, onto upstream MCP *and OpenAPI* requests. Without a JWT policy that strips it, the client's `Authorization` reaches the upstream: token passthrough, which the MCP spec forbids.
  2. With JWT `Mode::Permissive`, a token that *fails* validation returns early (l.605), before the strip, so the invalid token is forwarded too.
  3. Stdio servers are unsandboxed child processes of the gateway.
  4. Arguments reach the upstream as rmcp `JsonObject = serde_json::Map`. Duplicate keys are last-wins and there's no duplicate rejection on that path, so a server parser that keeps the first key would see a different argument from the one a guardrail saw **[M — not tested]**.
  5. Not a bug: DNS-rebinding protection (`dns_rebinding.rs`) is opt-in and off by default. It rejects duplicate `Origin` headers.
- **OpenAPI→MCP** (`upstream/openapi/mod.rs`) has good hygiene:
  - `substitute_path_params` percent-encodes everything except the RFC 3986 unreserved set, and rejects `""`, `.` and `..` segments after splitting on `/` and `\`.
  - Header parameters must be declared in the spec, and Host, Content-Length, Content-Type and Transfer-Encoding are protected.
  - But "first header set wins including headers set by ctx.apply", so passed-through client headers beat declared ones.
- **Fuzzing**: `fuzz/fuzz_targets/{cel_expression, llm_request_conversions, proxy_protocol}.rs`. There is no MCP-message fuzz target.
- **LLM side**: `crates/llm` (about 19k lines) converts between Anthropic, OpenAI, Bedrock, Vertex, Gemini, Azure and Copilot formats, with golden tests. It is a reference for wicket-llm's multi-provider translation.
- **For wicket**:
  - **REUSE**: nothing as a dependency (`publish = false`, no semver). Licence permits **vendoring specific files with attribution** (Apache-2.0 §4: keep the notice, mark changes). Candidates:
    - `dns_rebinding.rs`;
    - `substitute_path_params`;
    - the discover/initialize merge logic as a reference when writing wicket's version bridge;
    - `crates/llm` conversion tables, as a test oracle rather than code.
  - **BORROW**:
    - A message-level relay on rmcp model types for third-party servers, alongside rmcp `ServerHandler` for gateway-native tools.
    - Disable caching of policy-filtered results.
    - Filter list results through the same function as calls.
    - Namespace server-initiated request IDs per upstream.
    - Reserve delimiter characters in target names.
    - Fail closed by default.
    - Base deny survives allow on merge.
  - **AVOID**:
    - default header passthrough;
    - guardrails that mutate params before the decision;
    - unsandboxed stdio children;
    - "no rules = allow".
  - **Implications for design.md**:
    - §15's reason for not using agentgateway stands. Add that it also does not isolate stdio servers and passes client headers through.
    - §8.2 should state: the gateway builds every upstream request from scratch and copies no client header; arguments are pre-parsed with duplicate-key rejection before rmcp decodes them; results are never cacheable.
- Confidence: H (code read for every claim except item 4).

### modelcontextprotocol/rust-sdk (rmcp) — the official Rust MCP SDK (https://github.com/modelcontextprotocol/rust-sdk, Apache-2.0 for new code; some older contributions remain MIT pending relicensing (LICENSE preamble), commit 5596a8a0bba2, rmcp 3.9.0 2026-11-05)
- Local path: `refs/repos/rmcp`. Rust; crates `rmcp`, `rmcp-macros`; official, very active. Has a conformance directory and a `DEPENDENCY_POLICY.md`.
- **Architecture**:
  - `model.rs` and `model/` hold typed messages for both eras: `mrtr.rs`, `task.rs`, `request_state.rs` and `extension.rs`. Unknown methods decode to `CustomRequest`/`CustomNotification`, so a gateway can see them and refuse them.
  - `service.rs` is the role-generic peer (`RoleClient`/`RoleServer`), `handler/` holds `ServerHandler`/`ClientHandler`, and `transport/` the transports.
  - Feature flags matter for wicket:
    - `transport-async-rw` takes any `AsyncRead + AsyncWrite`, so a vsock or UDS stream from a sandbox works directly.
    - `transport-child-process` uses `process-wrap`, so the command can be wrapped in `wicket-jail`.
    - `transport-streamable-http-client-unix-socket` is a Streamable HTTP client over a UDS: exactly the gateway→sandboxed-server hop.
    - `transport-streamable-http-server` / `server-side-http` provide a tower `StreamableHttpService` that can be served on any listener, UDS included.
    - `request-state` provides `RequestStateCodec`, an HMAC-SHA256 seal/open for SEP-2322 MRTR `requestState`, with a keyring and rotation.
    - `auth` and `auth-enterprise-managed` provide OAuth.
- **Enforcement-relevant behaviour**:
  - `StreamableHttpServerConfig` (`transport/streamable_http_server/tower.rs` l.219):
    - `allowed_hosts` defaults to loopback (Host validation against DNS rebinding);
    - `allowed_origins` is empty by default, which means Origin is *not* checked;
    - `legacy_session_mode` applies only to versions before 2026-07-28 (the newer version is always stateless).
  - `validate_standard_headers` enforces SEP-2243: `Mcp-Method`/`Mcp-Name`/`Mcp-Param-*` must agree with the body. Duplicate or non-UTF-8 values are rejected (regression test for issue #1271). `mcp_headers.rs` also rejects case-insensitive duplicate `x-mcp-header` declarations.
  - `CallToolRequestParams.arguments: Option<JsonObject>`, a `serde_json::Map`. Duplicate argument keys are last-wins. Derived structs reject duplicate *fields*, but `#[serde(flatten)]`/untagged paths may not **[M]**. A strict pre-parse of the raw bytes is therefore needed before rmcp decodes.
  - Since a 2026-07-28 `requestState` "does not by itself guarantee single-use", the codec gives integrity and expiry, and wicket's ledger must provide single use.
- **Suitability**:
  - *Server*: yes, for gateway-native tools via `ServerHandler`, with tool schemas generated from adapters.
  - *Client*: yes, for upstream servers in sandboxes (UDS/async-rw/child-process) and remote servers (reqwest + auth).
  - *Proxy*: there is no built-in proxy. agentgateway shows the working pattern: rmcp model types + own HTTP server + own relay. A typed relay drops unknown fields by construction, which for wicket is the desired allowlist behaviour. The cost: each new spec revision needs an rmcp upgrade before the gateway can pass new fields through.
- **Gaps**: the server's Origin check is off by default. No duplicate-key rejection. A fast release cadence (3.0 on 2026-07-28, 3.9 by 2026-11-05) means exact pins and a conformance suite.
- **For wicket**:
  - **REUSE (depend)**: `rmcp = "=3.9.x"` with `server, client, macros, schemars, transport-async-rw, transport-child-process, transport-streamable-http-server, transport-streamable-http-client-unix-socket, transport-streamable-http-client-reqwest, auth, request-state`.
  - **BORROW**: SEP-2243 validation as the model for the egress proxy's header/body agreement checks.
  - **Implications for design.md §8.2**: the hop to a sandboxed server is Streamable HTTP over a UDS (or stdio over the jail's pipes) using rmcp's own transports. Turn on `enforce_origin_validation`. Seal MRTR `requestState` with `RequestStateCodec` and bind it to the Op digest plus a ledger nonce.
- Confidence: H on structure and features; M on serde duplicate behaviour through flatten.

### kgateway-dev/kgateway — brief (https://github.com/kgateway-dev/kgateway, Apache-2.0, Go; not cloned)
- The Kubernetes Gateway API control plane that programs agentgateway (and Envoy) as its data plane. agentgateway's `controller/` and `crates/xds` are the in-repo half of that. It holds no MCP enforcement logic of its own beyond what agentgateway implements, so it has nothing for single-host wicket. Relevance 1. Confidence: M (from repo metadata and agentgateway's xds crate, not read).

### toolhive (proxy/authz side) — MCP runner/proxy with the most thorough Cedar authorizer in the space (https://github.com/stacklok/toolhive, Apache-2.0, commit 42cd9b7e497b, v0.63.0 2026-11-06)
- Local path: `refs/repos/toolhive` (full clone, shared with the sandbox study). Go; very active, production (Stacklok).
- Architecture as implemented: an HTTP middleware chain in front of each MCP server. `pkg/mcp/parser.go` `ParsingMiddleware` parses the JSON-RPC body once and publishes a `ParsedMCPRequest` in the request context; `pkg/authz/middleware.go` `Middleware` authorizes it; `pkg/authz/response_filter.go` (1.7k lines) rewrites list responses; `pkg/auth/upstreamswap` swaps the client's ToolHive JWT for a stored upstream IdP token; `pkg/vmcp` is a virtual-MCP aggregator (backends, `aggregator/{prefix,priority,manual}_resolver.go` for name conflicts, `optimizer` meta-tools `find_tool`/`call_tool`, `codemode`, `mrtr.go`). `pkg/mcp/revision.go` models both eras (`MCPVersionLegacy = "2025-11-25"`, `MCPVersionModern = "2026-07-28"`).
- Policy model: `pkg/authz/authorizers/cedar/core.go` maps every MCP op to Cedar PARC: principal `Client::<sub>` (+ `THVGroup` parents from group/role claims), action `Action::call_tool|get_prompt|read_resource|list_*`, resource `Tool::<name>` with parent `Backend::<id>`. Context = JWT claims prefixed `claim_` + **arguments prefixed `arg_`** (`preprocessArguments`, l.1033): only top-level scalars become values; arrays/objects/null only set `arg_<k>_present` (deliberately, so a `has`/`!=` permit can't match them). Floats become Cedar `decimal` or an opaque "number marker" (`entity.go` `convertFloatToCedar`). Tool annotations (`readOnlyHint` etc., from an `AnnotationCache` filled from upstream `tools/list`) are merged into resource attributes *under* the standard attrs so they can't overwrite `name/operation/feature`. Uses **cedar-go v1.9.0**, not Rust Cedar (so no SymCC).
- Enforcement: `tools/list` responses filtered per item through the same authorizer; `handleToolsCall` re-authorizes the *inner* tool name for the `call_tool` meta-tool (decoding exactly as dispatch does, because `encoding/json` matches struct fields case-insensitively) and filters `find_tool` output. Denial = HTTP 403 + JSON-RPC error `JSONRPCCodeDenied` "Unauthorized" (`handleUnauthorized`). `ping`/`initialize`/non-POST skip authz.
- Parser-differential hardening (best in class): `authz/case_smuggling_test.go` rejects *before* authorization: duplicate keys (`"name":"denied","name":"allowed"`), case variants at every level (`Method`, `Name`, `URI`, nested `arguments.Mode`), and case variants hidden behind `1e1000` number overflow. Batches rejected. `upstreamswap.createCustomInjector` strips the inbound `Authorization` (fix for issue #5504, credential passthrough).
- Gaps/bypass risks: (1) argument model is flat — nested objects are presence-only, so rules can't constrain `files[].path`; (2) policy can depend on **server-asserted annotations** (`resource.readOnlyHint`), which the spec calls untrusted; a malicious server can relabel a destructive tool read-only; (3) `arg_<k>_present` can collide with a scalar argument literally named `<k>_present` (map-order-dependent); (4) GET/SSE and server→client traffic aren't authorized; (5) if no `Identity` in context, upstreamswap passes through without a token (relies on authn ordering).
- For wicket: BORROW the Cedar mapping shape (principal/action/resource + typed context), the meta-tool re-authorization rule, list/call consistency, and **lift `case_smuggling_test.go`'s cases into wicket's canonicalizer fuzz corpus**. AVOID trusting annotations as policy input; AVOID flat `arg_` context — wicket's adapters bind args into `Resource`s instead. Not reusable as code (Go). Design implication: §9 should state "arguments become resources/typed context via the adapter, never raw", and §8.2 should list the meta-tool rule (`wicket.*`, codemode, any `call_tool`) explicitly.
- Confidence: H (code read).

### docker/mcp-gateway — Docker's MCP gateway: one container per server, interceptors, Desktop governance hook (https://github.com/docker/mcp-gateway, MIT, commit 7e0f34277c91, v0.44.3 2026-10-26)
- Local path: `refs/repos/docker-mcp-gateway`. Go (go-sdk v1.4.1); mature product (Docker Desktop "MCP Toolkit").
- Architecture: `pkg/gateway/clientpool.go` runs each stdio server as `docker run --rm -i --init --security-opt no-new-privileges [--cpus] [--memory] --pull never`; `--network none` only if the catalog entry sets `DisableNetwork`, else attached to the gateway's networks. Optional egress isolation (`pkg/gateway/proxies/`): an internal Docker network plus an L7 sidecar (`docker/mcp-l7proxy@sha256:…`, `ALLOWED_HOSTS=host:port,…`, `http(s)_proxy` env) and per-host L4 proxies; a DNS forwarder. Middleware chain `pkg/interceptors/interceptors.go` `Callbacks`: telemetry → GitHub-401-to-OAuth-link → user `--interceptor before|after|around:exec|docker|http:…` → `BlockSecretsMiddleware` → call logging. `--verify-signatures` (`pkg/gateway/pull.go`) requires digest-pinned images. Gateway meta-tools `mcp-find`, `mcp-add`, `mcp-exec`, `code-mode` (reserved names, `tool_names.go`).
- Policy model: `pkg/policy/policy.go` `Request{catalog, workingSet, server, tool, action: load|invoke|prompt}` — **names only, no arguments**. `withInvokePolicy` (`tool_policy.go`) wraps each backend handler at registration so direct calls, `mcp-exec` and code-mode share one gate (fail-closed on evaluator error). But `NewDefaultClient` returns `NoopClient` (allow-all) unless running in Docker Desktop with the `MCPGovernance` flag: **outside Desktop there is no policy**. Denial = Go error → JSON-RPC error. Secrets: catalog `Spec.Secrets` resolved and passed as **plain env vars** into the server container (`argsAndEnv`), i.e. the server holds the real credential.
- Name collisions (`tool_names.go`): fail-closed, **case-insensitive** collision and reserved-name detection, optional `server.Prefix`/`--tool-name-prefix`. Good.
- Gaps: `block-secrets` is Trivy-derived regexes over `tools/call` args and text results (`secretsscan/rules.go`, compiles each regex per match) — heuristic and bypassable by encoding; dynamic tools (`mcp-add` at runtime, feature-flagged, disabled with `--servers`) let the agent widen its own tool set; default network attachment is wide.
- For wicket: BORROW one-sandbox-per-third-party-server + digest-pinned images, case-insensitive collision rejection, "wrap at registration so every dispatch path shares the gate". AVOID secrets-as-env into server containers (contradicts principle 2; wicket gives sandboxed servers placeholders and injects at its egress proxy), AVOID runtime self-service server addition. Confidence: H.

### IBM/mcp-context-forge — Python gateway/registry: virtual servers, plugin hooks, multi-engine PDP, RFC 8693 (https://github.com/IBM/mcp-context-forge, Apache-2.0, commit 7d34038ca1f2, v1.1.0 2026-10-20)
- Local path: `refs/repos/mcp-context-forge`. Python (FastAPI, `mcp>=2.0`); large (tool_service.py alone 8.7k lines), active.
- Architecture: `mcpgateway/services/*` (tool/gateway/server/resource services, RBAC `permission_service.py`, `token_exchange_actor.py`, `encryption_service.py` = Argon2id-derived Fernet for stored client secrets); plugin framework `mcpgateway/plugins/` with hooks `tool_pre_invoke/post_invoke`, `resource_pre_fetch`, `agent_pre_invoke`; ~45 plugins in `plugins/` (deny_filter, regex_filter, pii, header_injector, schema_guard, vault, unified_pdp…). Config `protocol_version = "2025-11-25"` downstream; upstream connect mode `auto` negotiates 2026-07-28 or `legacy`.
- Policy: RBAC is team/visibility scoped per tool/server. `plugins/unified_pdp` fans out to native RBAC, Bell-LaPadula MAC, OPA sidecar, Cedar sidecar (`cedar-agent` over HTTP) with `combination_mode` (`all_must_allow` default) and `default_decision` (deny) on engine error; action string `tools.invoke.<name>`, args passed as `context.extra.tool_args`. Arguments *are* visible to OPA/Cedar policies.
- REST tool adaptation (`tool_service.py` `_substitute_url_template`, l.941): path params are percent-encoded, **dot segments and pre-encoded input rejected**; `query_mapping` acts as an allowlist; header mapping rejects CRLF/NUL and sensitive targets. Good canonicalize-or-reject example.
- Bugs/gaps: (1) **MAC engine trusts the caller for the resource's classification**: `unified_pdp.py` `tool_pre_invoke` sets `Resource.classification_level = tool_args.get("classification_level")`, so an agent passing `classification_level: 0` satisfies "no read-up" for any tool (and read/write is guessed from keywords in the tool name, `mac_engine._is_read`). (2) plugins may return a `modified_payload` that changes `name`/args *after* RBAC resolved the tool (`tool_service.py` ~l.5803) — authorization and execution can see different calls. (3) `plugins/vault` takes upstream tokens from a **client-sent `X-Vault-Tokens` header**, i.e. the client holds the secret. (4) `ENABLE_HEADER_PASSTHROUGH`/sensitive passthrough exists (off by default).
- For wicket: BORROW `_substitute_url_template`'s rules, per-tool header/query mapping as allowlists, the "virtual server = task-sized composition" idea (≈ a zone's tool set). AVOID policy inputs taken from arguments for security labels, post-authz payload mutation, client-held vault tokens. Too heavy to reuse. Confidence: H on cited code, M on RBAC consistency (not traced end to end).

### microsoft/mcp-gateway — K8s control plane deploying MCP "adapters" + a session-affine reverse proxy (https://github.com/microsoft/mcp-gateway, MIT, commit cf9f5e9eff89, v1.0.0)
- Local path: `refs/repos/ms-mcp-gateway`. C# (.NET, official C# MCP SDK); 2026-07-28 only (`McpProtocol.Version`).
- Architecture: Management (`Microsoft.McpGateway.Management`) stores adapters/tools and deploys them as K8s workloads; Service `AdapterReverseProxyController` routes `/adapters/{name}/mcp` to a random pod, `HttpProxy.CreateProxiedHttpRequest` builds the upstream request; Tools gateway (`Microsoft.McpGateway.Tools`) exposes registered HTTP tools (`HttpToolExecutor`).
- Policy: `SimplePermissionProvider`: read = creator ∨ `mcp.admin` ∨ one of the resource's `RequiredRoles`; write = creator ∨ admin. Adapter-level only; no tool or argument rules. Denial = HTTP 403 before MCP.
- Notable code: `HttpProxy` strips inbound `Authorization`, `Cookie`, `Proxy-Authorization`, `Mcp-Session-Id`, and the forwarded-identity headers (`X-Mcp-UserId/Roles`, `X-Gateway-Secret`) and re-injects identity from the authenticated principal; the shared gateway secret is only sent to the first-party tool gateway, never to user-deployed adapter pods (`forwardGatewaySecret: name is null`); response headers are **allowlisted**. `McpEndpointMiddleware` enforces a single exact `Origin` (DNS-rebinding guard). `McpToolHeaderValidator` checks SEP-2243 `x-mcp-header`/`Mcp-Param-*` headers against the body arguments (`McpErrorCode.HeaderMismatch`).
- Gaps: request-header handling is a denylist (other client headers flow to adapter pods); coarse authz.
- For wicket: BORROW response-header allowlist, header/body agreement check for 2026-07-28 (`Mcp-Method`/`Mcp-Name`/`Mcp-Param-*` must equal the body or reject), Origin check. Otherwise low relevance. Confidence: H.

### github/github-mcp-server — the reference single-provider server; scoping, lockdown, and IFC labels on outputs (https://github.com/github/github-mcp-server, MIT, commit 99d6d6503a7b, v2.1.0 2026-11-03)
- Local path: `refs/repos/github-mcp-server`. Go; production (GitHub's hosted remote server).
- Architecture: `pkg/inventory` (toolsets, `ServerTool`, typed input/output schemas, feature flags), `pkg/inventory/filters.go` `isToolEnabled` = tool's `Enabled` → `readOnly` (drops any tool whose `Annotations.ReadOnlyHint` is false; the annotation is the server's *own* trusted metadata here) → builder filters → toolset/additional-tools selection → feature rules. Request headers `X-MCP-Toolsets/Tools/Exclude-Tools/Readonly/Lockdown/Features/Insiders` narrow per request; operator flags are the upper bound.
- Scopes: `pkg/scopes` — each tool has `ScopeAccess{Scopes (exhaustive max), Visible, Challenge(args, active) → missing scopes}`. **Per-call, argument-aware**: `repository_path.go` `workflowScopeChallengeForPath` cleans `path` with `validateRelativePath` and asks for `workflow` in addition to `repo` only when the path is under `.github/workflows/`; `…ForFiles` does the same over `files[].path`. Classic PATs are filtered at startup via `X-OAuth-Scopes`; fine-grained PATs/App tokens get no filtering ("API enforces").
- Lockdown: `pkg/lockdown/lockdown.go` `RepoAccessCache.IsSafeContent(user, owner, repo)` = trusted bot ∨ private repo ∨ author has push ∨ author is viewer; used to drop untrusted authors' issue/PR/comment content in public repos. Response-side integrity filter.
- **IFC labels (new)**: `pkg/ifc/ifc.go` defines `SecurityLabel{integrity: trusted|untrusted, confidentiality: public|private}` and per-tool label functions; `pkg/github/ifc_labels.go` attaches them as `CallToolResult._meta["ifc"]` behind feature flag `ifc_labels`. Rules: public-repo user content (issues, files, commits — anyone can PR) = public/untrusted; private-repo content = private/trusted; repo metadata needing push (labels, branches, releases) = trusted; draft releases and collaborator rosters = private even on public repos; multi-repo search results get the **join** of all items' labels ("per-item labels would invite unsafe declassification"). "The actual IFC enforcement engine lives in a separate service" — i.e. GitHub is building the consumer side.
- Gaps: scope challenges return `nil` (no challenge) on unparsable `path`, so the step-up check is UX, not enforcement (GitHub's token scope is the real gate). Private-repo content as "trusted" is a policy choice wicket shouldn't copy blindly (collaborators can be compromised; agent-authored commits).
- For wicket: BORROW (1) `pkg/ifc` as the **default label table for the GitHub adapter** (§4.2 "adapters give pessimistic default labels"), including the join rule for multi-resource results; (2) argument-aware risk via cleaned paths — exactly wicket's `.github/workflows/**` dangerous pattern, validated against GitHub's own reasoning; (3) "operator config is an upper bound, request headers only narrow". Also: when wicket proxies the *real* github-mcp-server as a third-party server, start it with `--read-only`/toolsets as a cheap native narrowing layer, and read `_meta.ifc` as an *input* to labels (never to lower them). Confidence: H.

### pomerium — identity-aware proxy with MCP routes: PPL `mcp_tool`, dual-role OAuth, upstream token injection (https://github.com/pomerium/pomerium, Apache-2.0, commit a04c468238de, v0.34.0 2026-11-04)
- Local path: `refs/repos/pomerium` (sparse: `internal/mcp`, `pkg/mcp`, `authorize`, `pkg/policy/criteria`, `config/envoyconfig`). Go + Envoy; mature.
- Architecture (`internal/mcp/DESIGN.md`): Envoy ext_authz (`authorize/`) authenticates and evaluates policy; ext_proc (`internal/mcp/extproc/server.go`) injects upstream tokens on request headers and intercepts upstream 401/403 to start upstream OAuth (PRM/RFC 9728 discovery, DCR/CIMD, PKCE) as a client. Tokens stored per `{user_id, route_id, upstream_server}` in the databroker, refreshed with singleflight (`upstream_auth.go`).
- Policy: `pkg/policy/criteria/mcp_tool.go` compiles to Rego: false for non-`tools/call`, else string-matcher on `input.mcp.tool_call.name` (exact/prefix/suffix/list). **Tool name only**; arguments are parsed (`authorize/evaluator/mcp.go`) and logged (`authorize/log.go`) but not matchable. Denial = JSON-RPC error `-32602` "access denied, see authorization log for request <id>" with HTTP 200 (`check_response.go` `deniedResponseForMCP`).
- Hardening: body over `max_request_bytes` rejected (Envoy truncates one byte past the limit, `grpc.go` l.290); non-JSON content-type, empty, invalid or batch bodies rejected; `unmarshalMembers` decodes params **by exact member name** because Go's `encoding/json` is case-insensitive and "authorization would then see a different value than an MCP server reading the same message"; body inspected even with the runtime flag off "so mcp_tool rules fail closed". `headers_evaluator_evaluation.go`: for MCP server routes the client's `Authorization` is removed (ext_proc re-adds the upstream token); `header.CredentialHeaders` stripped generally.
- Gaps: duplicate JSON keys are not rejected (Go `map` keeps the last; an upstream parser keeping the first would differ); "no cached token → continue without auth" means the upstream sees an unauthenticated call (fine) but decisions for `tools/list` are not filtered by `mcp_tool` (list isn't a tool call, so a `mcp_tool` allow rule doesn't apply to it; tools are visible but uncallable).
- For wicket: BORROW the ext_authz/ext_proc split (decide on parsed body, inject on headers) — it is the same seam as srt's decider; the upstream-OAuth-as-client flow (PRM → AS metadata → DCR/CIMD → PKCE, tokens keyed by user×route×upstream) for design §8.2 kind 3 (remote MCP servers with wicket-held tokens); denial body carrying a request id. Confidence: H.

### teleport (lib/srv/mcp) — Teleport's MCP access: RBAC tool matchers, tools/list filtering (https://github.com/gravitational/teleport, **AGPL-3.0**, commit 1283425b60ec, v18.10.0 2026-07-09)
- Local path: `refs/repos/teleport` (sparse `lib/srv/mcp`). Go. **AGPL: BORROW ideas only, copy nothing.**
- Architecture: `session.go` `sessionHandler` sits between client and server for stdio/SSE/streamable HTTP; `processClientRequest` checks `tools/call` via `Checker.CheckAccess(app, state, &MCPToolMatcher{Name})` (role `mcp.tools` globs/regex); an `IDTracker` (cap 50) remembers request IDs so the `tools/list` response can be filtered per tool (`makeToolsCallResponse`). `sanitize.go` deletes **non-canonical-case keys** (`Name`, `ID`, `Method`, `Params`) before forwarding, re-encoding via `json.RawMessage` to avoid float corruption. Audit events per message (`audit.go`).
- Policy: tool-name globs per role; no arguments. Denial = JSON-RPC `-32602` "RBAC is enforced by your Teleport roles".
- Gaps: list filtering is best-effort (lost IDs ⇒ unfiltered list; "tools/call will still be blocked"); `rewriteHTTPRequestHeaders` comment: the client's `Authorization` "can also come from the client and Teleport just pass it through" — token passthrough by default for HTTP MCP apps; a TODO admits `initialize` ordering isn't enforced.
- For wicket: BORROW "sanitize to canonical then forward the re-encoded form" (wicket goes further: reject, don't rewrite). Second independent instance of the Go case-insensitive-key bug class (with Pomerium and ToolHive) → treat as a known attack class in §8.1's canonicalizer and in MCP parsing. Confidence: H.

### agent-router (theagentrouter, formerly Envoy AI Gateway) — Envoy-based LLM + MCP gateway with CEL rules over arguments and both-era bridging (https://github.com/theagentrouter/agent-router, Apache-2.0, commit d41f08217b8d, v1.2.1 2026-11-06)
- Local path: `refs/repos/agent-router`. Go (Go module path still `github.com/envoyproxy/ai-gateway`; go-sdk); mature, AAIF project.
- Architecture: `internal/mcpproxy/` is a full MCP proxy (not just a filter): `handlers.go` reads the body (`MaxBytesReader`), `jsonrpc.DecodeMessage`, dispatches; `modern.go` (stateless 2026-07-28) and `legacy.go` (session era) with `era.go` detecting **era mixing** (`legacyOnlyMethods` such as `initialize`, `logging/setLevel`, `resources/subscribe` on a modern request ⇒ error; `Mcp-Method`/`Mcp-Name`/`Mcp-Param-*` header constants, `CodeHeaderMismatch -32020`); `session.go`/`crypto.go` encrypt the aggregated session state into the client-visible session id. Forwarded requests are **re-encoded from the parsed message** (`jsonrpc.EncodeMessage`), so authz and upstream see the same bytes. Fan-out `tools/list` merges backends with `<backend>__<tool>` prefixes (`nameSeparator`, prefix modes Always/Never with admission-time uniqueness for bare names).
- Policy: `MCPRoute.authorization` rules = target (backend+tool list) ∧ source (JWT claims/scopes) ∧ optional **CEL over `request.{method,host,headers,path,auth.jwt.*,mcp.{method,backend,tool,params}}`** (`authorization.go` `buildCELActivation`, cost limit 10000), first match wins, `defaultAction`. Arguments are reachable as `request.mcp.params.arguments`. CEL runtime error ⇒ **deny the whole request** (explicit comment: errors must not fall through to a later allow/default). Missing scopes produce an RFC 6750 `insufficient_scope` challenge with `resource_metadata`. Tool selectors include/exclude (exact/regex, exclude wins). `tools/list` items are filtered by evaluating the rule set as a `tools/call` with no params. Backend credentials: `MCPBackendAPIKey` from a K8s Secret injected into a header/query; `forwardHeaders` can copy client headers to the backend (passthrough when configured).
- Gaps: list-time evaluation without arguments means CEL rules on args make tools disappear from lists (errors ⇒ deny) or appear though uncallable — list/call are only approximately consistent; arbitrary CEL over args has no subset analysis; `forwardHeaders` makes passthrough a config choice.
- For wicket: BORROW era detection + header/body agreement (directly applicable to the §8.2 "bridge both" requirement), re-encode-after-parse forwarding, "CEL error ⇒ deny all", `<backend>__<tool>` naming with collision admission. Confirms that argument-level rules exist in the wild but as unanalysable CEL; wicket's adapter-bound resources + Cedar remain the better shape. Confidence: H.

### bifrost (core/mcp) — Go LLM gateway that executes MCP tools itself; credstore, Starlark code mode (https://github.com/maximhq/bifrost, Apache-2.0 (core), commit 6e640279b363, ent-v2.5.0 2026-11-06)
- Local path: `refs/repos/bifrost` (sparse `core/mcp`). Go; high-traffic product.
- Architecture: the LLM gateway connects to MCP servers as a client and runs tool calls on behalf of model responses (agent mode). `credstore/credstore.go` dispatches per `MCPAuthType` (`none`, shared headers, shared OAuth, per-user OAuth, per-user headers, token exchange); per-call extra headers from the caller pass only if in `AllowedExtraHeaders` (`utils.ExtractFilteredExtras`). `exec.go` `checkToolExecutionPermitted` enforces **the same filters as discovery, in the same order** (client disabled → client include list → `ToolsToExecute` allowlist → request include-tools), with the comment "without these a caller could invoke a tool by name that was deliberately hidden". `codemode/starlark/sandbox.go`: Starlark with `SetMaxSteps` and `MaxToolCalls` limits; tool calls from code go through the same executor.
- Policy: tool-name allowlists per client and per request; no arguments.
- For wicket: BORROW the "discovery filters = execution filters, same function, same order" invariant and **step + tool-call budgets for codemode** (matches design §4 risk 9: budgets are the control, not per-call allow). Shows the LLM-proxy-executes-tools pattern (relevant if wicket's LLM proxy ever runs server tools). Confidence: M (read the authz path only).

### lasso-security/mcp-gateway — Python plugin gateway with regex guardrails and a reputation scanner (https://github.com/lasso-security/mcp-gateway, MIT, commit 7e7f1f6e5314, v1.2.0 2026-01-21)
- Local path: `refs/repos/lasso-mcp-gateway`. Python, ~4.7k lines; low activity.
- Architecture: `gateway.py` proxies stdio servers; plugins `guardrails/basic.py` (regex secret masking), `presidio.py` (PII), `lasso.py` (SaaS API); `security_scanner/` scores servers from npm/GitHub metadata (`scanner.py`: blocked if score ≤ 30) and `tool_poisoning_analyzer.py` matches ~40 English regexes ("ignore previous instructions", "don't tell the user", `.env`, `id_rsa`).
- Policy: none beyond block/allow per server and response masking.
- For wicket: AVOID as enforcement; at most an admission *signal* (design already says so, 04 §2.1). The regex list is a cheap tripwire seed for third-party description review. Confidence: H.

---

## 2. Egress and credential proxies

### superfly/tokenizer — Fly.io's credential-injecting HTTP proxy with sealed, self-authorizing secrets (https://github.com/superfly/tokenizer, Apache-2.0, commit 0f51c9d780d0, 2026-10-29; no tagged releases)
- Local path: `refs/repos/superfly-tokenizer`; Go (~3.6k LOC non-test, on `elazarl/goproxy`); production at Fly (`docs/FlyTokenizer.md`). Maturity: small, old (2023), actively maintained.
- **Architecture as implemented.** `NewTokenizer` (`tokenizer.go`) wraps goproxy. **CONNECT is refused** (`HandleConnect`: "request validators check the Host header, but a tunneled request is delivered to whatever the CONNECT line named"). Clients speak plain `http://` to the proxy; `dialFunc` forces TLS upstream (`tls.DialWithDialer`, port 80→443, refuses `:443` as "proxied request must be HTTP"). No MITM CA at all. `DisableKeepAlives: true` "to not worry about desync/smuggling". Response gets `Connection: close`.
- **Secrets are sealed to the proxy, not stored in it.** `Secret{AuthConfig, ProcessorConfig, RequestValidators}` is JSON, NaCl `box.SealAnonymous` to the proxy's public key (`secret.go`), sent per request in `Proxy-Tokenizer: <b64>[;<params json>]` (multiple allowed). `processorsFromRequest` opens each, runs `secret.AuthRequest` (who may use it), then `RequestValidators` (where), then builds the processor. `FilteredHeaders` (`Proxy-Authorization`, `Proxy-Tokenizer`) are deleted before forwarding.
- **Who may use a secret** (`authorizer.go`): `bearer_auth` (SHA-256 digest of a `Proxy-Authorization` bearer, constant-time compare), `macaroon_auth` (HMAC key in the secret; client presents a macaroon bundle whose caveats are checked against the live request: `macaroon/caveats.go` `RequestMethod`, `RequestPath`, `RequestPathPrefix`, `RequestPathPattern`, `RequestHost`), `flyio_macaroon_auth` (Fly org macaroons), `fly_src_auth` (a **platform-signed `Fly-Src` header naming org/app/instance** — identity from the transport, not a bearer), `no_auth`.
- **Processors** (`processor.go`): `inject` (header or `query:<p>` destination, `fmt` with exactly one `%s`/`%x`; `ApplyFmt`/`ApplyDst`), `inject_hmac`, `inject_body` (placeholder replace), `oauth`/`oauth_body`, `sigv4` (re-sign; strips `Authorization`, `X-Forwarded-*`, `Via`, `Accept-Encoding` first), and three **mint-and-reseal** processors: `jwt_processor` (GCP SA JWT-bearer), `client_credentials`, `github_app` (`GitHubAppProcessorConfig`: signs the App JWT, rewrites the request to the installation-token endpoint, then the **response processor seals the returned installation token into a new `inject` secret pinned to api.github.com** so the caller only ever sees ciphertext). `StripHazmat` redacts secrets for logs.
- **SSRF:** `dialFunc` uses `net.Dialer.ControlContext`, so the check runs on the **actual IP being dialed** after resolution (no rebinding gap): denies private, loopback, unspecified, link-local, `fdaa::/8` (Fly 6PN) and the proxy's own addresses (`circular request`). CGNAT `100.64/10` and NAT64/6to4/Teredo are *not* denied (smokescreen does deny them).
- **Bugs/gaps.** (1) `allowed_hosts`/`allowed_host_pattern` are **optional**: a secret sealed without them is injectable towards any host the client names, and with unsealed `dst`/`fmt` the client chooses the header (e.g. one the upstream reflects). The README itself warns to seal `dst`. (2) Path caveats match `URL.EscapedPath()` with `HasPrefix`/regex and **no dot-segment rejection**; `RequestPathPrefix("/v1/charges")` also matches `/v1/chargesX` and `/v1/charges/../customers` if the upstream normalises. (3) `RequestHost` / `allowedHosts` compare `r.Host` verbatim (port included), so it fails closed on `host:80` but there is no case/trailing-dot normalisation. (4) `inject` uses `Header.Set` on the destination only; other client auth headers pass through (fine when the dst is `Authorization`).
- **For wicket.** BORROW: (a) the **mint-and-reseal pattern**: the proxy calls the token endpoint itself and hands the agent side only a sealed reference. That is exactly §8.4 "vault mints the narrowest native credential", with zero plaintext outside the vault. (b) A credential carries its own **validators** (host, method, path) and auth binding: in wicket terms a credential record must carry `(provider, hosts, header slot, format)` *sealed with it*, and the adapter decision is a second, independent check. (c) Dial-time IP check in the socket `Control` hook (Rust: vet in a custom `TcpStreamConnector` before `connect`). (d) `Fly-Src` = transport identity for multi-host wicket. AVOID: plaintext-HTTP-to-proxy (black-box agents use `https://`, so wicket must MITM). Optional host binding: wicket must make the host set mandatory and non-empty. Design.md: §8.4 should say credentials are *bound to host + slot at mint time* and the agent can never choose the slot or format. Confidence: H.

### openai/codex `codex-network-proxy` — Codex CLI's rama-based egress proxy, now with a credential broker (https://github.com/openai/codex/tree/main/codex-rs/network-proxy, Apache-2.0, commit 748ab55ca7de, 2026-11-08)
- Local path: `refs/repos/codex-network-proxy/codex-rs/network-proxy` (sparse; another agent has the full `refs/repos/codex`). Rust, ~34.5k LOC including tests. Maturity: production (ships with Codex), very high churn.
- **rama usage, exactly** (`Cargo.toml`): `rama-core`, `rama-http`, `rama-http-backend` (tls), `rama-net` (http, tls), `rama-socks5`, `rama-tcp`, `rama-tls-rustls`, `rama-unix` (unix), `rama-dns` (macOS only), all pinned **`=0.3.0-alpha.4`**, still today, two releases behind rama 0.4.0 (2026-08-19) and the 0.5.0 on rama `main`. rcgen is used **through `rama_tls_rustls::dep::rcgen`** (`certs.rs`: P-256 CA, `IsCa`, `KeyUsagePurpose`, SANs), with no direct rcgen dependency. `aws-sigv4` for re-signing. The rustls TLS-termination path is hand-assembled from rama primitives (`mitm.rs`), not rama's boring-only `TlsMitmRelay` (see rama below).
- **Module map:** `http_proxy.rs` (2.1k) and `socks5.rs` (1.2k) listeners; `mitm.rs` (TLS terminate + per-request policy; `authority_header_value` **rewrites `:authority`/`Host` to the CONNECT target** and rejects inner requests whose authority or Host differ, `"tunnel destination mismatch"` / `"MITM host mismatch"`, also refusing `@` userinfo in authority); `mitm_hook.rs` (`MitmHookConfig{host, matcher{schemes, ports, methods, path_prefixes, query, headers, body}, actions{strip_request_headers, inject_request_headers, body_secret_substitution}}`); `network_policy.rs` (`NetworkPolicyDecider` trait, `NetworkPolicyRequest{protocol, host, port, method, command, exec_policy_hint, …}`, a `Deny{decision: Ask}` variant for "ask the user"); `connect_policy.rs`, `domain_matcher.rs`, `secret_substitution.rs`, `body_budget.rs`, `aws_sigv4.rs`, `brokered_tunnel.rs`, `upstream.rs`.
- **New `credential_broker/`** (`credential_broker.rs` 1.8k plus `registry.rs`, `matching.rs`, `configured.rs`, `environment.rs`, `providers/{github,openai}.rs`). Flow: `discover_parent_credentials` finds real tokens in the *parent* env (`GH_TOKEN`, `GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN`, OpenAI keys, plus configured providers). `virtualize_child_env` replaces each in the child env with a **format-preserving dummy** (`shaped_dummy_value`: same prefix such as `ghp_`/`github_pat_`, same minimum length, random alphanumerics), so CLIs' token-shape checks pass. Each dummy gets a `CredentialHostBinding` (`ExactHost`, `ExactHosts`, `HostPattern{exact_hosts, suffixes}`, `ConfiguredHosts`). On egress, `inject_request_headers_for_environment` → `select_credentials` → provider `translate_request_header`. For GitHub that is **exact equality only, in `Authorization` only**: `Bearer|token <dummy>`, or Basic where the user *or* password equals the dummy. No substring replacement. "Ambiguity removes the whole header." `virtualize_text`/`restore_text` mask real values in text crossing back. `CredentialMaskingFailureMode` decides what happens when a raw credential is left in a prepared env.
- **Gaps.** (1) The GitHub cloud binding includes suffix **`.ghe.com`** (`GITHUB_CLOUD_HOST_SUFFIXES`), so a github.com token's real value would be injected towards *any* `*.ghe.com` tenant the policy allows. That is cross-tenant leakage when the egress allowlist is broad [M]. (2) The decider sees host/port/method plus the *command line* (`command`, `exec_policy_hint`), not the path or body. Path-level rules exist only as MITM hooks, so policy is split across two mechanisms. (3) The broker starts from real secrets in the parent env and the proxy is in-process with the agent's harness. That is the right model for a local CLI, not for wicket's hostile box (wicket never has the real value anywhere near the sandbox's process tree).
- **For wicket.** REUSE (Apache-2.0, permitted): read `mitm.rs` (authority pinning), `credential_broker/providers/github.rs` (`translate_request_header`, `shaped_dummy_value`) and `aws_sigv4.rs` as reference implementations, and lift them with attribution if convenient. The crate itself is not a sensible dependency: it is unpublished, tied to the Codex workspace, and churns daily. BORROW: format-preserving placeholders. Exact-value translation in the declared auth slot only. Ambiguity → remove the header. Authority/Host forced to the CONNECT target. "Ask" as a distinct deny reason. **Contradiction with design.md §8.1:** "rama 0.4, pinned exactly as Codex does" is wrong twice: Codex pins `=0.3.0-alpha.4`, and Codex's rustls path does not use a rama MITM relay. Rewrite as "rama 0.4.x pinned exactly, rustls termination assembled from rama-net/rama-tls-rustls primitives as Codex does (or boring's `TlsMitmRelay`)". Confidence: H (code read).

### plabayo/rama — modular async proxy framework (https://github.com/plabayo/rama, MIT OR Apache-2.0, commit 3872267a9afc, 2026-11-08; release 0.4.0 2026-08-19, `main` at 0.5.0)
- Local path: `refs/repos/rama`; Rust; ~45 workspace crates; MSRV 1.96 on `main`; commercially backed (ramaproxy.com). Maturity: pre-1.0, frequent breaking changes; the 0.4.0 changelog has a "Breaking API Changes" section.
- **Where things are:** CONNECT/forward proxy in `rama-http-backend` + `rama-net` (`examples/src/http_connect_proxy.rs`, `https_connect_proxy.rs`, `socks5_and_http_proxy.rs`); SOCKS5 `rama-socks5`; unix sockets `rama-unix` (`examples/src/unix_socket_http.rs`); DNS `rama-dns`; TCP connectors `rama-tcp::client::TcpStreamConnector` (the trait to implement resolve-once + IP vetting; `DenyTcpStreamConnector` exists, but I found **no built-in private-range/SSRF filter** [M]); HTTP stack `rama-http-core` (a hyper/h2 fork kept in sync upstream); WebSockets `rama-ws`; ICAP `rama-icap`; HTTP/3 `rama-quic`; TLS `rama-tls-rustls` and `rama-tls-boring`.
- **MITM, important:** the production MITM machinery, **`rama-tls-boring::proxy::mitm`** (`issuer/{cache,memory,static_pair,deny,either}.rs`, `egress.rs`, `handshake.rs`, `client_auth.rs`, `revocation.rs`), is **BoringSSL-only**. `examples/src/http_mitm_proxy_rustls.rs` says verbatim: rama "does not yet provide a paired Rustls ingress/egress `TlsMitmRelay`… Prefer `http_mitm_proxy_boring` as the starting point", and calls the rustls variant "not the recommended proxy architecture". The rustls example acknowledges CONNECT, then lets `EasyHttpWebClient` dial per decrypted request, so a CONNECT 200 does not prove egress reachability. Useful tests to copy as a matrix: `rama-http-backend/tests/mitm_bound_authority.rs` ("trusted interception origins are checked before and after HTTP middleware"), `h2_mitm_relay_*`.
- **For wicket.** REUSE: depend on it, pinned exactly (`=0.4.x`), keeping the decider seam so it is swappable (design already says this). Decide **boring vs rustls** explicitly. Boring gives rama's relay, issuer cache and revocation handling, at the cost of a C dependency and a FIPS/aws-lc question. rustls means hand-assembly as Codex did. Recommendation: rustls ingress + rustls egress assembled from `rama-net`/`rama-tls-rustls`, with **one egress connection per CONNECT, dialled at CONNECT time to the vetted IP** (don't copy the example's per-request redial). Implement IP vetting in a custom `TcpStreamConnector`. Confidence: H on structure, M on "no SSRF filter".

### stripe/smokescreen — CONNECT egress proxy for SSRF prevention, role-based ACLs (https://github.com/stripe/smokescreen, MIT, commit 5b4b7aabca9b, 2026-11-03; v0.1.0 2026-09-21)
- Local path: `refs/repos/smokescreen`; Go (~6k LOC, goproxy). Maturity: production at Stripe for ~10 years.
- **Architecture.** `BuildProxy` (`pkg/smokescreen/smokescreen.go`). **Role from client identity:** `RoleFromRequest` hook; the default (`main.go defaultRoleFromRequest`) is the **mTLS client-cert CN**. ACL v1 YAML (`acl/v1/acl.go`, `testdata/acl_mitm_config.yaml`): per service `{project, action: enforce|report|open, allowed_domains (globs), mitm_domains[{domain, add_headers, detailed_http_logs}], external_proxy_globs}` plus a `default`. Globs are validated: no middle wildcards, `publicSuffixHint` rejects `*.co.uk`-style rules.
- **DNS and SSRF, the reference implementation:** `safeResolve` → `resolveTCPAddr` → `selectTargetAddr` classifies **every** resolved IP (`classifyAddr`: not-global-unicast, private, CGNAT `100.64/10`, **IPv6 embeddings of IPv4** (NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/32`), self-connection via `LocalIPs`, user allow/deny ranges, `MostSpecificIPRules`) and picks an allowed one. `dialContext` dials the **resolved address stored in the decision** and re-resolves only if the dial target differs from `OutboundHost`. Inside MITM, every inner request **reuses the CONNECT role but is re-checked against its own `req.Host`** (`OnRequest` branch `ConnectMitm`), and a missing CONNECT context rejects.
- **Gaps.** Host-level only (MITM is for header add and logging, not path policy). The client can request an upstream proxy via `X-Upstream-Https-Proxy` (gated by `external_proxy_globs`). Errors leak in `X-Smokescreen-Error`.
- **For wicket.** BORROW (port to Rust; MIT is compatible): the **IP classifier list verbatim** (CGNAT, NAT64, 6to4, Teredo, self-IPs; IPv4-mapped handled by normalisation), "classify all A/AAAA, dial the chosen vetted IP", "re-check each inner MITM request's Host against the CONNECT decision", and the glob validator (no middle wildcards, public-suffix check). Design.md §8.1 "SSRF deny" should cite this list explicitly. Confidence: H.

### paradigmxyz → ironsh/iron-proxy — MITM egress proxy with built-in DNS, secret swap, MCP tool policy (https://github.com/ironsh/iron-proxy, Apache-2.0, commit 3d96ce8dd2ca, 2026-11-04; v0.56.0 2026-11-04)
- Local path: `refs/repos/iron-proxy`; Go (~18k LOC). Maturity: young, very active (56 minor releases).
- **Architecture.** A transparent mode: the built-in DNS server (`internal/dns`, `dnsguard`) answers with the proxy IP, then the HTTPS listener either MITMs (`certcache`, `cagen`; leaf per SNI; **no SNI → reject**, `getCertificate`) or runs **SNI-only passthrough** (`serveHTTPSSNI`). Optional explicit `HTTP_PROXY`/SOCKS5 tunnel listener (`proxy/tunnel.go`). Pipeline of named transforms (`transform/pipeline.go`): `allowlist`, `headerallowlist`, `secrets`, `awsauth`, `gcp*`, `oauth`, `hmacsign`, `grpc`, `bodycapture`, and **`judge`** (an LLM decides per request from `system_prompt.md`, with a circuit breaker). Plus a Postgres MITM (SQL AST walk; injects `SET ROLE`), an SSH proxy, and an MCP interceptor (`internal/mcp`) and gateway (`internal/mcpgateway`).
- **Canonicalisation done right:** `handleHTTP` **rejects `.`/`..` segments** in the decoded path (`containsDotSegments`, with a comment explaining why), **rejects SNI ≠ Host** (400), and checks `Upgrade: websocket` properly (`headerHasToken`). Rules (`hostmatch/rule.go`) match `{host|cidr, methods, paths}`; paths use `path.Match` or a `/*` prefix on **decoded** `URL.Path` while the upstream gets `RawPath`, so `%2F` is a residual decoded-vs-raw differential [M].
- **Secrets** (`transform/secrets/secrets.go`): two modes. `inject` sets a header or query param. `replace` does **substring swap of `proxy_value`** in matched headers (literal names or `/regex/`), and optionally query, path and **body**, scoped by host/method/path rules; `require: true` rejects when the secret is unavailable or wasn't swapped.
- **MCP policy** (`internal/mcp/policy.go`, `argmatch.go`, `intercept.go`): per server `{rules (host/path), tools[{name, when[{path, equals|in|matches}]}]}`. Argument constraints are JSON-path clauses over `arguments`, ANDed. `tools/list` responses are filtered (JSON and SSE per event, `sseFilter`). Denial is a JSON-RPC error (`-32001`, configurable). Batches and oversize bodies are denied. Every POST is inspected regardless of Content-Type.
- **Bugs/bypass risks.** (1) **JSON parser differential** in `jsonrpc.go`: `decodeJSONRPC`/`extractToolCallName` unmarshal into Go structs with `encoding/json`, which matches keys **case-insensitively** and lets the **last duplicate win**. So `{"method":"tools/call","Method":"ping",…}` is seen by the proxy as `ping` (unchecked) and by a JS/TS or rmcp upstream as `tools/call`. Likewise `"name"`/`"NAME"` in params. That is a tool-policy bypass if the upstream tolerates the extra key [H on Go semantics, M on upstream tolerance]. (2) `replace` mode with `match_body`/all-headers is a **secret-reflection oracle**: an agent that writes the proxy token into an issue body or any echoed header on an allowed host gets the *real* secret written there. (3) The `judge` transform puts an LLM in the request path (fail mode via breaker config) and sees agent-controlled bodies: prompt-injectable by construction. (4) Transparent DNS mode means anything that bypasses the resolver (hard-coded IPs) relies on the CIDR allowlist.
- **For wicket.** BORROW: dot-segment rejection and SNI==Host as hard 400s; `require` semantics; per-event SSE filtering of `tools/list`; the MCP-over-HTTP interception as a *T3 fallback* for third-party remote MCP servers the box reaches over HTTPS. AVOID: substring swap anywhere but an exact declared auth slot; LLM judge on the hot path; Go-struct JSON decoding. Design.md §9 canonicalise-or-reject should add **"reject JSON objects with duplicate keys *or* keys differing only in case from a schema key"**. serde-derived structs reject duplicate fields but `serde_json::Value` keeps the last, so parse to a duplicate-rejecting `Value` first. Confidence: H.

### github/gh-aw-firewall (AWF) — GitHub Agentic Workflows firewall: Squid + API-proxy sidecar + gh CLI proxy (https://github.com/github/gh-aw-firewall, MIT, commit f040e76584da, 2026-11-07; v0.29.10 2026-11-08)
- Local path: `refs/repos/gh-aw-firewall`; TypeScript CLI (~140k LOC incl. Cloud Hypervisor/enclave backends) + Node sidecars + one C/Rust LD_PRELOAD lib. Maturity: active, GitHub Next.
- **Squid generation** (`src/squid/*.ts`). `acl-generator.ts` emits `dstdomain`/`dstdom_regex` allow and block lists, plus http-only/https-only variants. `access-rules.ts` ends in `http_access deny all`. `config-sections.ts` restricts `Safe_ports` to 80/443 plus explicit extras. `ssl-bump.ts` has two modes: (a) **SNI guard**, `generateTlsSniGuardSection`: `peek` at step 1, then `splice` only if the **ClientHello SNI** (`ssl::server_name --client-requested`, so it does *not* fall back to the CONNECT host when SNI is absent) is allowlisted, else `terminate`; (b) full SSL bump for URL rules. Every operator string passes `assertSafeForSquidConfig`, which guards against config injection.
- **API proxy** (`containers/api-proxy/`): holds the LLM keys and OIDC token providers (Anthropic, AWS, GCP, GitHub). `proxy-utils.js STRIPPED_HEADERS` = `host, authorization, proxy-authorization, x-api-key, api-key, x-goog-api-key, forwarded, via, x-awf-caller, x-forwarded-*`, i.e. **all client auth is stripped**. `claude-hosted-web.js` enforces a **domain policy on Anthropic's server-side `web_search`/`web_fetch` tools by rewriting the tool definitions** in the request (intersect `allowed_domains`, reject conflicting filters, cap `max_uses`), explicitly to close the "Squid only sees api.anthropic.com" gap. Model allowlists, budgets, pricing catalogues.
- **cli-proxy** (`containers/cli-proxy/`): `gh` runs *outside* the agent container with the token; the agent sends argv. `security.js` denies meta-commands (`alias`, `auth`, `browse`…), `DENIED_COMMAND_PATHS` (`repo clone`, `pr checkout`…), `--hostname`/`GH_HOST`, `@file` inputs and absolute URLs for `gh api`; one profile (`ENCLAVE_ISSUE_PATH` regex) narrows to issue reads. `github-api-point-limiter.js` meters API cost.
- **DLP** (`src/dlp.ts`): Squid `url_regex` for token shapes (`ghp_`, `github_pat_`, `sk-proj-`…) in **URLs only**. DoH sidecar (`--dns-over-https`, host iptables pinning).
- **Gaps.** `one-shot-token` (LD_PRELOAD that caches and unsets token env vars) means **real tokens do enter the agent container** in some modes. That defends only against `/proc/self/environ` reads, not ptrace or memory. The SNI guard splices without seeing `Host`, so **domain fronting** to any allowlisted CDN host remains. `ssl_bump splice !tls_sni_guard_port` passes non-443 CONNECTs unchecked at the TLS layer. URL-only DLP misses bodies and headers. The argv deny-list is a deny-list.
- **For wicket.** BORROW: (a) **rewrite server-side tool definitions in the LLM proxy** (`web_search` `allowed_domains` ∩ zone reach, `max_uses`), a concrete mechanism for design.md §8.3, which today only says "taint ingress". (b) The stripped-header set as a minimum floor. (c) The SNI-guard `--client-requested` rule, if wicket ever offers SNI-only tunnels. (d) Running the CLI host-side as a typed service is an alternative to MITM for `gh`. wicket's adapters make it unnecessary, but it is a fallback for pinned clients. AVOID: tokens inside the box, even "one-shot". Confidence: H (code read; Copilot production parity still M).

### Infisical/agent-vault — standalone HTTP credential proxy and vault for agents (https://github.com/Infisical/agent-vault, MIT outside `ee/` (no `ee/` directory present at this commit), commit 16ec8d5a5db3, 2026-11-06; v0.40.2 2026-10-22)
- Local path: `refs/repos/agent-vault`; Go (~39k LOC). Maturity: **deprecated by its README** in favour of the hosted "Infisical Agent Vault" (the README also carries an instruction aimed at AI agents, which I ignored). Code is still maintained.
- **Architecture.** MITM proxy (`internal/mitm/{connect,forward,websocket}.go`, `internal/ca`); the agent authenticates with a session token in `Proxy-Authorization` (`brokercore/proxyauth.go ParseProxyAuth`), i.e. a **bearer inside the box**. Services match on host/port/path (`broker.MatchService`, scored). `Auth` types resolve credentials to headers (`brokercore/credential.go StoreCredentialProvider.Inject`), with OAuth refresh and Infisical dynamic secrets. `ApplyInjection` drops hop-by-hop headers, `Connection`-named headers and every header the injection will set, then sets them. `netguard` blocks private/reserved ranges, and cloud metadata always.
- **Substitutions** (`brokercore/substitution.go`): placeholders like `__anthropic_api_key__` (unreserved chars only) replaced in `path`, `query`, **every header value**, and the **body** (JSON-escaped, form-escaped, raw; multipart skipped). There is a CR/LF guard for headers.
- **Proposals** (`internal/proposal`, `server/handle_proposals.go`): an agent can *propose* a new service or credential slot. A human approves via a tokenised link, and `merge.go` applies it. That is a working typed-escalation precedent.
- **Gaps.** (1) **`UnmatchedHostPolicy` defaults to `passthrough`**: unmatched hosts are proxied unfiltered unless an operator flips to `deny`. Fail-open. (2) Body and all-header substitution is the **reflection oracle** again: write the placeholder into an issue body posted to the matched host and the real secret is stored there. (3) Bearer session token in the box.
- **For wicket.** BORROW: proposal → approval-link → merge as a UX reference for `request_access`; the `ApplyInjection` strip order. AVOID: passthrough default; substitution outside the auth slot; bearer proxy auth. Confidence: H.

### onecli/onecli — sandboxed agent harness whose Rust gateway brokers credentials and holds requests for approval (https://github.com/onecli/onecli, Apache-2.0 except `*/ee/` (enterprise licence: `apps/gateway/crates/ee`, `packages/api/src/ee`, `apps/web/src/ee`, `apps/sandbox-supervisor/src/ee`), commit afb4a19cc378, 2026-11-05; v2.19.0 2026-11-05)
- Local path: `refs/repos/onecli`; TS monorepo (~310k LOC). **The gateway is Rust** (`apps/gateway/crates/*`; hyper 1 + tokio-rustls + rustls 0.23 (ring) + rcgen 0.13, no rama). Maturity: young (2026-03), very active, commercial.
- **Gateway crates:** `proxy` (18k: `connect.rs` CONNECT resolution and app-connection selection, `mitm.rs`, `forward.rs`, `websocket.rs`, `method_override.rs`, `github_org_access.rs`), `inject` (agent token from `Proxy-Authorization`; rules `set_header|remove_header|set_param|set_path|replace_path_regex`; format placeholders such as `sk-ant-onecli-gateway-placeholder`), `policy` and `policy-engine` (priority-ordered first match over `{path_pattern, method, action: block|rate_limit|allow|manual_approval, conditions (body contains…)}`, kept in parity with a TS translator by a shared golden corpus), `approval` (holds the request; Redis `BLPOP` or in-memory; **`APPROVAL_TIMEOUT_SECS = 180`**), `summary` (18k: **per-app human-readable approval cards** such as "Send email · To · Subject", with `generic::summarize` redacting secret-looking values and capping length, and record resolvers linking to the touched GitHub issue or Drive file), `vault`, `ca`, `dbproxy-postgres`.
- **Good engineering:** `condition_match.rs` "FAIL-CLOSED LAW": a truncated body makes `contains` **unknown**, which resolves by rule polarity (restrictive rules match, permissive rules don't; GraphQL is classified as a mutation). `method_override.rs` **refuses** `X-HTTP-Method-Override`/`_HttpMethod` naming a different method, before any rule runs.
- **Gaps.** (1) **Deny-by-default applies only to credentialed traffic** (`PolicyRequest::enforce_deny = has_injections && !is_llm_host`): uncredentialed egress is not blocked by the gateway. (2) `policy::is_llm_host` is **substring** (`h.contains("anthropic.com")`), so `anthropic.com.evil.net` counts as an LLM host and **bypasses deny-default** for credentialed rules. It is used in `proxy/src/forward.rs`, `tunnel.rs`, `websocket.rs` [H]. (3) I found no dot-segment or encoded-slash rejection before `inject::path_matches` (prefix/segment globs on the raw path) [M]. (4) **Holds connections open for up to 3 min** for human approval.
- **For wicket.** BORROW: the **approval-summary crate design** (per-provider summarizer trait, generic redacting fallback, record links). It maps directly onto design.md §10's human channel, where today the request card is unspecified. Also the fail-closed truncation law and method-override refusal; add both to §8.1 canonicalisation. Could vendor `summary` patterns (Apache-2.0, not under `ee/`). AVOID: substring host checks, credential-only deny-default, held connections. Confidence: H on read modules, M overall (large codebase).

### cloudblue/chaperone — sidecar egress proxy that injects credentials via compiled-in plugins (https://github.com/cloudblue/chaperone, Apache-2.0, commit fb311dd0b8a3, 2026-10-13; no releases)
- Local path: `refs/repos/chaperone`; Go (~18k LOC). Maturity: early, low adoption (8 stars).
- **Architecture.** Not a forward proxy: the client POSTs to `/proxy` with `X-Connect-Target-URL` and context headers (`X-Connect-Vendor-ID`…); mTLS client auth (TLS 1.3 minimum). `router/allowlist.go` checks host (exact/glob, port-aware) **and path globs** with `checkPathTraversal` (`../` and encoded variants). Plugins (Caddy-style static compile, `plugins/contrib`: OAuth, Microsoft token) inject credentials. `httputil.ReverseProxy` with `Rewrite`. **Response "credential reflection protection"** (`buildModifyResponse`): strips a static sensitive-header list and **every header name the plugin injected on this request** from the response.
- **For wicket.** BORROW: strip injected header names (and, better, the injected *values*) from responses before they reach the box. Add to design.md §8.1 flow as "response: scrub injected credentials". Confidence: M (skimmed).

### omjadas/hudsucker — small MITM proxy library on hyper (https://github.com/omjadas/hudsucker, MIT OR Apache-2.0, commit 7b7baf3c528f, 2026-08-25; v0.25.0 2026-07-15)
- Local path: `refs/repos/hudsucker`; Rust (~3.3k LOC). hyper 1.7, tokio-rustls, rcgen 0.14 (`rcgen-ca`), hyper-tungstenite. Maturity: stable, single maintainer.
- **Architecture** (`src/proxy/internal.rs process_connect`): after CONNECT it reads 4 bytes. `GET ` → plaintext HTTP; `\x16\x03` → TLS (`LazyConfigAcceptor`, leaf for the **ClientHello SNI, falling back to the CONNECT authority**); upstream URI authority is forced to the CONNECT authority (`serve_stream`), but the **`Host` header is not reconciled**.
- **Fail-open paths [H]:** any other first bytes (e.g. `POST`, `PUT`, or a non-HTTP protocol) log "Unknown protocol" and fall through to a **raw `TcpStream::connect(authority)` + `copy_bidirectional` tunnel**: uninspected plaintext. The same happens when `should_intercept_connect`/`should_intercept_tls` return false. SNI and authority may differ, and there is no check. Upstream dialling uses OS DNS with no IP vetting hook.
- **For wicket.** Spike-only, as 04 said. If used, wicket must override these defaults (deny unknown protocols, enforce SNI == authority == Host). rama is the better base. Confidence: H.

### cloudflare/pingora — reverse-proxy framework (https://github.com/cloudflare/pingora, Apache-2.0, commit 1adcb3815b70, 2026-10-30; 0.9.1 2026-11-03), brief
- Local path: `refs/repos/pingora`; Rust. `pingora-core/src/protocols/http/authority.rs` now validates absolute-form and CONNECT authority ("ambiguous HTTP absolute-form request target", missing Host for absolute-form CONNECT), and `raw_connect.rs` exists, but there is still no forward-proxy MITM pipeline. **For wicket:** AVOID as the data plane. BORROW `authority.rs`'s ambiguity rules as test cases. Confidence: M.

### Dicklesworthstone/flywheel_connectors — Rust connector platform with zones, capability tokens, secretless egress (https://github.com/Dicklesworthstone/flywheel_connectors, "MIT License (with OpenAI/Anthropic Rider)", commit f165287b1029, 2026-11-08)
- Local path: none. The clone was **deleted** after reading the LICENSE, and the code was not studied. Rust, ~2M LOC across `crates/fcp-*` and 176 connectors.
- **Licence, decisive:** the rider grants **no rights to OpenAI, Anthropic, their affiliates, or "any person… acting directly or indirectly on behalf of, for the benefit of, or under the direction of" them, including contractors and service providers**. It defines "use" to include "analyzing, indexing, or incorporating… into any… pipeline for machine learning or other automated systems". It forbids making the software or derivatives available "to or for any Restricted Party", and breach terminates the licence. This is not an OSI licence. A wicket TCB designed and written with Claude (an Anthropic system) cannot safely reuse, vendor or even have an agent analyse this code. **I stopped at the licence and the directory listing.**
- **For wicket:** AVOID entirely. Don't depend on it or vendor it, and don't feed it to Claude-driven tooling. The clone has been deleted, and the catalogue records it as "excluded: licence". Its public description (zones, capability-token typestate, egress-proxy secretless credentials, signed hash-linked audit chain) only confirms that the design space is converging; it contributes nothing wicket can take. Confidence: H on the licence text.

### Cross-cutting lessons from the egress proxies
1. **Inject only into a declared auth slot, by exact match.** Substring placeholder swap in bodies, queries or arbitrary headers (iron-proxy `replace`, agent-vault substitutions, tokenizer unsealed `dst`) turns any allowed write into a secret-exfiltration oracle. Codex's exact-equality `Authorization` translation is the right model. wicket goes further: strip all client auth and set the slot from the adapter.
2. **Bind the credential to (hosts, slot, format) at mint time** (tokenizer validators, Codex host bindings), independently of the request decision. Watch broad suffix bindings (Codex `.ghe.com`).
3. **Canonicalisation checklist from the code:** dot segments rejected (iron-proxy, chaperone); SNI == Host == CONNECT authority (iron-proxy, Codex, smokescreen re-check); `@` in authority refused (Codex); method-override refused (onecli); truncated body → unknown, resolved by polarity (onecli); JSON duplicate *and case-variant* keys rejected (iron-proxy's bug); unknown protocols after CONNECT denied (hudsucker's fail-open).
4. **Fail-open defaults are common:** agent-vault passthrough, onecli credential-only deny, hudsucker raw tunnel, tokenizer optional hosts. wicket's "no Direct egress mode" principle is right; the conformance suite should test each of these.
5. **The LLM proxy needs request rewriting**, not just observation: AWF rewrites Anthropic `web_search`/`web_fetch` tool definitions to enforce domains and `max_uses`.
6. **Approval UX is real code elsewhere:** onecli `summary` (per-provider cards) and agent-vault proposals. Both hold or poll; wicket keeps "never hold the connection".

---

## 3. Policy engines, capability tokens, catalogs and generators

### cedar-policy/cedar + cedar-policy-symcc — policy language, authorizer, symbolic compiler (https://github.com/cedar-policy/cedar, Apache-2.0, commit 5af7b8cd78e4, 2026-11-06; crates.io cedar-policy 4.14.1 / cedar-policy-symcc 0.8.1, 2026-11-02)
- Local path: `refs/repos/cedar`. Rust (MSRV 1.89). Mature: AWS Verified Permissions runs it; CNCF sandbox. `main` still says workspace `4.14.0`, symcc `0.8.0` (releases are cut from branches), and symcc pins `cedar-policy = "=4.14.0"` exactly. Pin both together.
- **Architecture as implemented.**
  - Workspace: `cedar-policy-core` (AST, evaluator, validator; the validator now lives under `cedar_policy_core::validator`), `cedar-policy` (public API), `cedar-policy-symcc`, `-formatter`, `-cli`, `-wasm`, `cedar-language-server`, `cedar-testing`.
  - Authorization is `Authorizer::is_authorized(&Request, &PolicySet, &Entities) -> Response` (`cedar-policy/src/api.rs:1116`). `Response::diagnostics().reason()` (`:1359`) gives the determining `PolicyId`s, and `errors()` the evaluation errors. Templates are linked with `PolicySet::link(template_id, new_id, slots)` (`api.rs:3255`).
  - **TPE** (`api/tpe.rs`, feature `tpe`, inside `experimental`): `PolicySet::query_resource` / `query_principal` / `query_action` take a `ResourceQueryRequest` / `PrincipalQueryRequest` and `PartialEntities`. A `TpeResponse` exposes `residual_permits()`, `true_forbids()` and so on, plus `reauthorize()`. There is also `is_authorized_batched` with on-demand entity loading (`tpe.rs:759`); the old `entity-manifest` feature is deprecated in its favour. This is the API for "what can zone X reach", which feeds the blast-radius view.
  - **SymCC** (`cedar-policy-symcc/src/lib.rs`): `CedarSymCompiler<S: Solver>` with `check_{never_errors, always_matches, never_matches, matches_equivalent, matches_implies, matches_disjoint, implies, always_allows, always_denies, equivalent, disjoint}`. Each has `_with_counterexample` and `_opt` variants (the `_opt` ones take pre-compiled `CompiledPolicy`/`CompiledPolicySet`, compiled once per `RequestEnv`). Inputs must be `WellTypedPolicies` built against a `Schema` and a `RequestEnv`.
  - The solver is a child process: `LocalSolver::cvc5()` reads the `CVC5` env var or `PATH` (`symcc/solver.rs:23`). `cvc5_with_args(["--rlimit=…"])` and `from_command(z3 …)` also exist. A solver answer of `unknown` becomes `Error::SolverUnknown` (`symcc.rs:172`), so it fails closed.
- **What the SMT encoding covers.**
  - `like` compiles to `string.like` and then to SMT `(str.in_re …)` with `re.*`/`re.allchar` (`symcc/compiler.rs:113`, `encoder.rs:458,732`). It is fully supported.
  - All four extension types are supported: `ipaddr`, `decimal`, `datetime`, `duration` (`term_type.rs:131`). So are entity tags (`hasTag`/`getTag`) and `is`.
  - **Unsupported** (`CompileError::UnsupportedFeature`): templates/slots (`compiler.rs:797`), partial-eval unknowns, empty set literals, `AnyEntity`, open record attributes, singleton-Bool types.
  - This **refutes 03 §1.2's worry** that extension types or `like` might be unsupported. The real limits are templates and open attributes.
- **Entity hierarchy is symbolic. This confirms 03 §1.2's path-prefix caveat.**
  - Ancestors are uninterpreted functions per (type, ancestor-type) (`symcc/env.rs:89-102`). The only constraints are acyclicity and transitivity (`symcc/enforcer.rs:18-246`).
  - So SymCC cannot prove `resource in Dir::"acme/api/infra"` ⇒ `resource in Dir::"acme/api"`: the edge between those two concrete UIDs is a free variable.
  - The Lean theorems (`cedar-spec/cedar-lean/Cedar/Thm/Verification.lean`) state soundness and completeness over all *strongly well-formed* environments (no dangling references, ancestors = transitive closure of a DAG) represented by the `SymEnv`. A fixed hierarchy can be supplied with `SymEnv::from_concrete_env` / `compile_with_custom_symenv`, but the docs say the latter has "no analogue in the Lean … use at your own risk" (`lib.rs:170-178`).
  - Conclusion: encode wicket resource paths as strings and constrain them with `like`, as 03 recommends.
- **Policy model concretely.** PARC plus context. Rules can match anything that is typed in the schema: entity attributes, context records (so tool arguments can be matched if they are put in context), sets, IPs, datetimes. Forbid overrides permit, and the default is deny.
- **Bugs, gaps and bypass risks.**
  - `like` `*` matches `/`. Wicket's `ResourcePattern::OneLevel` ("exactly one more segment") is **not expressible** as a single `like`. Compile it to `like "p/*" && !(like "p/*/*")`, or carry segments as a typed record or set. Without that, `OneLevel` silently becomes `Prefix` in Cedar while the hot-path algebra treats it differently: a differential between the two.
  - SymCC rejects templates, so every grant has to be **linked before** verification. Also, the wicket-algebra→Cedar compiler sits outside every proof.
  - The SMT-LIB encoder (`Cedar/SymCC/Encoder.lean`) has no theorem, so the encoder and cvc5 are trusted. DRT (`cedar-spec/cedar-drt`, 111 fuzz targets including `symcc-cex-drt`, `symcc-check-*-ok`) differential-tests the Rust code against the Lean model. That is testing, not proof.
  - No cvc5 time limit is set by default. Pass `--tlimit`/`--rlimit` yourself.
- **For wicket.**
  - REUSE: depend on `cedar-policy =4.14.1` and `cedar-policy-symcc =0.8.1` (Apache-2.0). Ship the cvc5 1.3.1 binary (BSD-3) as a control-plane sidecar, not on the hot path. Use `tpe` (experimental, so pin exactly) for `wicket explain` reachability queries.
  - BORROW: the Lean-plus-DRT methodology for `wicket-core`. Write a small reference model of `is_subset_of` and decide, then differential-fuzz the production code against it. That fits principle 8 better than proving.
  - AVOID: symbolic `in`-hierarchies for paths; templates inside proofs; trusting `compile_with_custom_symenv`.
  - design.md §4.1: (1) list SymCC's real exclusions (templates, open attributes, `AnyEntity`); (2) state that `OneLevel` compiles to a two-`like` conjunction; (3) put the algebra→Cedar compiler in the TCB list with a differential test (Cedar `is_authorized` vs `wicket-core` decide on random Ops).
- Confidence: H (code read). M on the OneLevel workaround performance under cvc5's string theory.

### cedar-policy/cedar-spec — Lean model, proofs, differential testing (https://github.com/cedar-policy/cedar-spec, Apache-2.0, commit a4c5a89cd156, 2026-11-06)
- Local path: `refs/repos/cedar-spec`. Lean 4 plus Rust (DRT harness). Mature research-grade.
- **Architecture as implemented.**
  - `cedar-lean/Cedar/{Spec,Validation,SymCC,SymCCOpt,TPE,BatchedEvaluator}` hold the executable model, and `Cedar/Thm/*` the proofs. `grep sorry Cedar/Thm` finds 0 hits.
  - Proven: authorizer properties (forbid trumps permit, default deny), validator soundness, SymCC verifier soundness and completeness (`Thm/Verification.lean`: e.g. `verifyNeverErrors_is_sound` / `_is_complete`), and TPE and batched-evaluator correctness.
  - Assumed: that the Rust implementation matches Lean (checked by DRT in `cedar-drt/fuzz/fuzz_targets/*`), the SMT encoder and solver, and that inputs are well typed (`Cedar/SymCC.lean:45`, where `wellTypedPolicy` must be called first).
  - `cedar-lean-cli` holds the `analyze compare` policy-diff tool mentioned in 03.
- **For wicket.**
  - BORROW: the DRT shape, as noted above.
  - REUSE: `cedar-lean-cli analyze` as an offline "does this manifest change widen?" report, for humans only and not in the TCB (it needs the Lean toolchain).
  - AVOID: putting Lean in the build.
- Confidence: H.

### eclipse-biscuit/biscuit-rust — public-key attenuable tokens with Datalog (https://github.com/eclipse-biscuit/biscuit-rust, Apache-2.0 (per crate `Cargo.toml`; no root LICENSE file), commit 21e650f31a85, 2026-10-29; biscuit-auth 6.0.0, 2025-07-16)
- Local path: `refs/repos/biscuit-rust`. Rust. Mature, though slow-moving. Crates: `biscuit-auth` 6.0.0, `biscuit-parser` 0.2.0, `biscuit-quote` 0.3.0 (the `biscuit!`/`authorizer!` macros), `biscuit-capi` 6.0.0-beta.3. All Apache-2.0.
- **Architecture as implemented** (`biscuit-auth/src/token/mod.rs`).
  - Token methods: `Biscuit::builder()`, `append(BlockBuilder)`, `seal()` (`:158`), `revocation_identifiers()` (`:209`, one per block, from the signature), `third_party_request()` / `append_third_party(_with_key)` (`:412-425`), `external_public_keys()`, `authorizer()`.
  - `Biscuit<K: SerializePrivateKey = PrivateKey>` is now generic over the signing key, so a KMS or HSM-held root key is possible.
  - Datalog limits: `AuthorizerLimits{max_facts: 1000, max_iterations: 100, max_time: 1ms}` (`datalog/mod.rs:744-756`). `max_time` is checked against wall-clock time (`datalog/mod.rs:622`, `token/authorizer.rs:157`).
- **Policy model.** Facts, rules, checks and allow/deny policies over a token's blocks plus authorizer facts. Attenuation blocks can only add checks. Third-party blocks are trusted only via `trusting ed25519/<pk>`.
- **Gaps and risks.**
  - The **wall-clock 1 ms default** makes decisions depend on load: a slow box fails checks, which is non-deterministic though it fails closed. Set limits by iteration and fact count, and generously.
  - There is no use counting (as 03 says).
  - Revocation needs an external deny list.
- **For wicket.** REUSE later (multi-host, per design §15). Keep the 03 §2.7 plan: no tokens in the box. Nothing in this code changes it. When adopted, set `max_time` high and rely on `max_iterations`/`max_facts`.
- Confidence: H.

### microsoft/regorus — Rego interpreter in Rust (https://github.com/microsoft/regorus, licence field `MIT AND Apache-2.0 AND BSD-3-Clause`, commit 9c2d5db76a87, 2026-11-06; 0.14.1, 2026-11-02)
- Local path: `refs/repos/regorus`. Rust. Production use at Microsoft (ACI and Kata policy, Azure Policy).
- **Architecture as implemented.**
  - There is a tree interpreter (`src/interpreter.rs`) and a compiled register VM (`src/rvm/*`, feature `rvm`, on by default).
  - Feature-gated builtins (`full-opa`). `languages/azure_policy` and `languages/azure_rbac` hold non-Rego front-ends.
  - `explanations` (off by default) produces causality reports and **partial evaluation** (`src/explain/mod.rs`). Its doc says: "Consumers that enforce a `PartialEvalResult` must instead fail closed."
  - Limits: `Engine::set_execution_timer_config`, `PolicyLengthConfig`, and allocator memory limits (`utils::limits`).
  - `src/verify/*` holds Verus proofs, but **only of number arithmetic** (bigint/f64), not of policy semantics.
- **Safe to embed?** Yes. `http.send` is a stub returning `Undefined` (`src/builtins/http.rs:17-21`), so there is no I/O. Set the time and memory limits.
- **Analysis.** There is none comparable to SymCC (no subsumption).
- **For wicket.**
  - BORROW/optional REUSE: lint adapters and manifests structurally in CI (e.g. "every POST rule declares effects"). That is not in the TCB, and a JSON Schema plus Rust checks probably suffice.
  - AVOID: using it for authority decisions. Its licence is a conjunction including BSD-3, which is compatible with Apache-2.0/MIT but adds notice obligations.
- Confidence: H on code, M on licence nuance.

### superfly/macaroon — Fly.io's production macaroons (https://github.com/superfly/macaroon, Apache-2.0, commit 7413ea9ac684, 2026-11-06; tag v0.3.2)
- Local path: `refs/repos/superfly-macaroon`. Go, about 6.5 kLOC. In production at Fly. The README itself says "We don't think you should use any of this code" (it is Fly-specific).
- **Architecture as implemented.**
  - Token format (`macaroon.go`):
    - Messagepack-encoded caveats, chained with HMAC-SHA256 (symmetric: the verifier holds the root key).
    - Third-party caveats seal a random key under the current tail with ChaCha20-Poly1305 (`Add3P`, `:528`). At most one 3P caveat per location (`:236`).
  - `verify()` (`:333-474`):
    - Recomputes the chain.
    - For each `Caveat3P`, unseals the discharge key and verifies the discharge macaroons, which **cannot nest** (`nil /* don't let them nest yet */`).
    - **Merges the discharge's caveats into the result set**, so the authenticator can add `ConfineUser` and the like.
    - Trusts *attestations* only from proof-type discharges by a trusted 3P key.
    - Checks `BindToParentToken`, so a discharge is bound to the exact attenuated parent tail and can't be replayed onto a sibling token.
  - Validation (`caveat_set.go:55-79`): every non-attestation caveat's `Prohibits(access)` must return nil, for **every** access. Unregistered caveat types return `ErrBadCaveat` (`caveats.go:115`), so they fail closed.
  - `resset` (resource sets):
    - `Action` is an RWX-style bitmask {read, write, create, delete, control} with `IsSubsetOf(a,b) = a&b==a` (`resset/resource_set.go`).
    - `ResourceSet[ID, Action]` is a map from id to mask. The zero id means "any" and can't be mixed with others. **When several entries match, their masks are intersected**, not unioned.
    - `Prefix` IDs match with `strings.HasPrefix`.
  - `IfPresent{Ifs, Else}` (`resset/if_present.go`) applies `Ifs` only when the access names that resource type (a caveat returning `ErrResourceUnspecified` means "not about this"). Otherwise it allows the `Else` action mask.
  - `flyio.Access.Validate` (`flyio/access.go`) forces **one action on one object per access**: parent resources required, siblings mutually exclusive. A multi-object operation is several accesses.
  - Domain caveats (`flyio/caveats.go`):
    - `Mutations` (GraphQL mutation-name allowlist).
    - `Commands` (argv prefix or `Exact` match for machine exec).
    - `StorageObjects` (prefix resource set).
    - `FlySrc` / `FromMachine`: the token is only valid when the **network-attested source** (the `Fly-Src` header added by Fly's proxy) is a given org, app or instance.
    - `ValidityWindow`, `MaxValidity`, and `Confine{User,Organization,GoogleHD,GitHubOrg}`.
  - Discharge protocol (`tp/server.go`, `tp/client.go`):
    - `POST /.well-known/macfly/3p` with the ticket.
    - The server returns a discharge immediately, **or** a `poll_url`, **or** `user_interactive{user_url, poll_url}`. The client polls with backoff until the third party calls `DischargePoll` / `DischargeUserInteractive` or `Abort*`.
    - Poll and user secrets are stored hashed (`tp/store.go`).
  - tkdb, revocation and the root-key service are **not in the repo**. The 03 description comes from Fly's blog.
- **Compared with wicket's Capability algebra (§4.1).**
  1. Fly never computes "token A ⊆ token B". **Attenuation is conjunction evaluated per access**: safety comes by construction, and no subset algorithm is in the TCB. Wicket's child ⊆ parent and grant ⊆ ask checks are valuable for *explaining and refusing* requests. But enforcement can (and should) **evaluate the whole chain**: an Op is allowed iff every ancestor zone's ceiling and the grant all admit it. Then a bug in `is_subset_of` can cost UX, never authority. → Design change.
  2. One access per (action, object), with multi-resource ops checked as several accesses. Wicket's "`resources: Vec`, ALL must be allowed" is the same idea and is confirmed.
  3. `IfPresent` is the missing piece for **optional arguments and resources**: "if the request names a branch, it must be `wicket/fix-*`; if it names none, only read". Wicket's closed-world `args` handles absent args as deny. Consider an explicit `Constraint::IfPresent{then, else_verbs}` rather than encoding it ad hoc.
  4. Bit-mask actions with a fixed small verb lattice make subset checks trivial. Wicket's `BTreeSet<Verb>` with adapter-canonical verbs is finer, and fine.
  5. **Bug class to avoid**: `resset.Prefix` is a raw string prefix, so `Prefix("bucket/a")` matches `bucket/ab…`. Wicket's segment-vector `ResourcePath` already avoids this. Add the case to the property tests.
  6. Third-party discharge with poll and user-interactive states is a production precedent for wicket's **PendingHuman** flow (CIBA-shaped), and `BindToParentToken` mirrors binding an approval to the Op digest.
  7. `FlySrc` is principle 2 in production: identity from the transport, asserted by the proxy, not from a bearer token.
- **For wicket.**
  - BORROW: items 1, 3, 6 and 7. The caveat registry's fail-closed handling of unknown types should apply to adapter `Constraint` variants.
  - AVOID: the code itself (Go, Fly-specific, HMAC needs the root key at every verifier).
- Confidence: H.

### macaroon-rs/macaroon — Rust macaroon crate (https://github.com/macaroon-rs/macaroon, MIT, commit ba1c81c8fa61, 2022-10-13; crate 0.3.0)
- Local path: `refs/repos/macaroon-rs`. Rust. **Stale since 2022.** Classic libmacaroons format; `Verifier::satisfy_exact` / `satisfy_general(fn)` string predicates (`src/verifier.rs`).
- Gaps: string-predicate caveats, no typed caveats, no binding of discharges beyond the classic scheme, unmaintained.
- For wicket: AVOID. If HMAC tokens are ever needed, port Fly's typed-caveat ideas rather than use this.
- Confidence: H.

### ucan-wg/rs-ucan — UCAN 1.0 in Rust (https://github.com/ucan-wg/rs-ucan, Apache-2.0, commit 59ff9b9c8479, 2026-03-29; `main` = `ucan` 0.5.0; crates.io stable 0.4.0 (2023), 0.7.0-alpha.1)
- Local path: `refs/repos/rs-ucan`. Rust. README: "Work in progress… conforms to UCAN v1.0.0-rc.1… not formally audited".
- **Architecture.** `ucan/src/{delegation,invocation,promise,envelope}` plus a separate `varsig` crate. Delegation policies are a jq-like selector language: `delegation/policy/predicate.rs` has `Equal`, `GreaterThan`/`LessThan`(`OrEqual`), `Like` (glob), `Not`, `And`/`Or`, and `All`/`Any` quantifiers over invocation arguments. They are evaluated conjunctively along the chain at invocation time, and again there is no subset check at delegation.
- For wicket: BORROW the predicate vocabulary as a sanity check on the `Constraint` enum (it is close to the niyikiza draft's). AVOID the DID trust model and the immature crate.
- Confidence: M (skimmed).

### tailscale/tsidp — Tailscale OIDC/OAuth IdP (https://github.com/tailscale/tsidp, BSD-3-Clause, commit 43c68a646380, 2026-11-07)
- Local path: `refs/repos/tsidp`. Go, about 4.7 kLOC. Young, but an official Tailscale project.
- **Architecture.**
  - Identity comes from the tailnet: `WhoIs(remoteAddr)` gives the node and user. Authorization comes from **application capability grants** in the tailnet policy, `tailscale.com/cap/tsidp` → `capRule{users, resources, allow_admin_ui, allow_dcr, extraClaims}` (`server/appcap.go`).
  - **RFC 8693 token exchange** (`server/token.go:299-500`):
    - Only access-token to access-token.
    - Requires `audience`; each one is checked against cap rules and **disallowed audiences are silently dropped**, giving narrower-than-ask.
    - Supports `actor_token` → `act` claim.
  - Access tokens are opaque and kept in an in-memory map.
- **Gaps.**
  - Requests from **loopback get full admin and DCR rights** (`appcap.go`).
  - In `localTSMode` the client address comes from the **last `X-Forwarded-For`**, which is spoofable unless a trusted proxy fronts it.
  - Audience matching is exact or `*` only.
- For wicket: BORROW the shape "network identity → capability grant in central policy → RFC 8693 exchange that narrows audiences and records `act`". It is a clean pattern for wicket-minted downstream tokens to remote MCP servers (§8.2 kind 3). AVOID loopback trust: a box's proxy socket may look like loopback.
- **Tailscale Aperture**: the gateway is closed source. Only `tailscale/aperture-cli` (BSD-3, a launcher that points Claude Code, Codex and others at `http://ai` on the tailnet) and recipes are public. That is the "LLM proxy via base URL, identity by network" pattern, matching design §8.3. Not cloned.
- Confidence: H (tsidp), M (Aperture).

### OpenFGA (brief, not cloned) — Zanzibar ReBAC server (https://github.com/openfga/openfga, Apache-2.0, Go, CNCF incubating)
- Relationship tuples, a modelling DSL, CEL "conditions", and `ListObjects`/`ListUsers`. It is a service with a datastore. No subsumption analysis. 03 §1.6's verdict stands: overkill. The provider-side label store is a key-value table.
- Confidence: M (from knowledge).

### iann0036/iam-dataset — AWS/Azure/GCP IAM datasets (https://github.com/iann0036/iam-dataset, MIT, commit edf8511acb5e, 2026-11-07)
- Local path: `refs/repos/iam-dataset` (sparse, `util/` only), plus `refs/repos/iam-dataset-sample/{MAP-README.md, access_level_overrides.json}` fetched as data. Python and JS generators feeding JSON.
- **Data as implemented.**
  - `aws/map.json` (7.3 MB, schema 1.0.2) maps **SDK method → IAM actions**, with `resource_mappings` from ARN variables to request fields (`"BudgetName": {"template": "${Budget.BudgetName}"}`), `resourcearn_mappings`, `arn_override`, `undocumented: true`, and a draft `conditions`. Plus `sdk_permissionless_actions` and service and CloudTrail mappings.
  - `aws/iam_definition.json` (12.8 MB) is the Service Authorization Reference scraped via Parliament and patched by `util/aws_patch_iam_definition.py`.
  - `access_level_overrides.json` holds corrections where AWS mislabels access levels, e.g. `autoscaling:CreateAutoScalingGroup` listed as Tagging when it is Write.
  - Risk tags come from `util/aws_generate_tags.py` (sourced from primeharbor/sensitive_iam_actions: CredentialExposure/PrivEsc/ResourceExposure/DataAccess) and `util/gcp_get_risks.py` (iam-privilege-catalog: `escalation:privilege`, `exfiltration:data`, `takeover:account`).
  - `util/aws_js/aws_capture_undocumented.js` **fuzzes calls with no-permission credentials and parses the AccessDenied messages** to discover undocumented actions.
- **For wicket.**
  - REUSE the data (MIT) for an AWS adapter generator: `map.json` is exactly "request → (verb, resources)" with ARN templates bound to request fields. The risk tags give R-floors.
  - BORROW the access-denied oracle fuzzing (cf. design §9 step 5's `X-Accepted-GitHub-Permissions` oracle).
  - Implication: **provider metadata is wrong often enough that someone maintains override lists**. design §9's "risk floors from provider metadata" should take the *max* over provider metadata and override lists, never trusting a single source downward.
- Confidence: H on schema, M on coverage quality.

### salesforce/policy_sentry — least-privilege IAM policy writer (https://github.com/salesforce/policy_sentry, MIT, commit 5a4ec2561787, 2026-10-08)
- Local path: `refs/repos/policy-sentry`. Python. Mature (Salesforce, about 2k stars).
- **Architecture.**
  - `shared/data/iam-definition.json` (19.5 MB) is per service: `privileges{access_level, resource_types{required, condition_keys, dependent_actions}}`, resources and conditions.
  - Access levels: Read, Write, List, Tagging, Permissions management. `access-level-overrides.yml` comments that "many AWS IAM Actions … are incorrect". `audit/*.txt` holds credentials-exposure (26), privilege-escalation (35), resource-exposure (240) and resource-policies (105).
  - `writing/sid_group.py::add_by_arn_and_access_level` derives actions from (ARN, access level) and groups them into SIDs.
- **Gap.**
  - `add_by_arn_and_access_level` adds **dependent actions that don't support the ARN's resource type with `Resource: "*"`** (`add_action_without_resource_constraint`), which silently widens.
  - Wildcard-only actions are also emitted as `*`.
- **For wicket.**
  - REUSE the data and access-level vocabulary (MIT) to build **STS session policies** for §8.4 native narrowing.
  - BORROW the five access levels as the AWS effect mapping (Permissions management → R4, Tagging → R2, …).
  - AVOID its dependent-action widening: wicket's minting must refuse rather than fall back to `*`.
- Confidence: H.

### PrefectHQ/fastmcp — OpenAPI → MCP provider (https://github.com/PrefectHQ/fastmcp, Apache-2.0, commit 936a9659d871, 2026-11-06)
- Local path: `refs/repos/fastmcp` (sparse: `fastmcp_slim/fastmcp/{server/providers/openapi,utilities/openapi}`). Python. Very popular.
- **Architecture.**
  - `utilities/openapi/parser.py` produces `HTTPRoute`s. `schemas.py` flattens parameters into one tool input schema. On collisions (the same name in several locations, or in body and path/query) it **suffixes `name__location`** (`schemas.py:653-707`); body properties are never suffixed.
  - `routing.py` uses `RouteMap{methods, pattern, tags, mcp_type}`, where the first match decides TOOL/RESOURCE/EXCLUDE.
  - `director.py`:
    - `_unflatten_arguments` **drops arguments not in the parameter map**, logging a warning.
    - `_encode_path_scalar` rejects dot segments at every percent-decoding layer, up to a maximum depth, and encodes `.` as `%2E` (`:487-508`). That is good hardening.
- **Credential handling.**
  - The upstream client is a user-supplied `httpx2.AsyncClient` holding the credentials.
  - **Incoming MCP HTTP headers are copied onto the upstream request** unless already set (`components.py:265-269`). The exclusion list is a deny-list (`server/dependencies.py:620-639`: host, authorization, cookie, proxy-*, mcp-session-id, …).
  - So `x-api-key`, `private-token`, `x-http-method-override`, `x-forwarded-*` and any vendor auth header **pass through** from the MCP client to the upstream API.
- For wicket:
  - BORROW the collision suffix scheme and the multi-layer dot-segment rejection, as a canonicalize-or-reject test vector source.
  - AVOID the deny-list header forwarding and silent dropping of unknown args. Wicket should *reject* unknown args (principle 3) and forward **no** client headers.
- Confidence: H.

### harsha-iiiv/openapi-mcp-generator — OpenAPI → TS MCP server codegen (https://github.com/harsha-iiiv/openapi-mcp-generator, MIT, commit 835374e1dea8, 2026-10-24)
- Local path: `refs/repos/openapi-mcp-generator`. TypeScript. Moderate (about 640 stars).
- **Architecture.**
  - `src/parser/extract-tools.ts`:
    - Tool names are abbreviated and truncated with a deterministic hash suffix for uniqueness (`:80-109`, `:238-299`).
    - `getToolAnnotations` derives `readOnlyHint`/`destructiveHint` from the HTTP method, **overridable by the spec's `x-mcp-annotations`** (`:133-198`).
  - `src/utils/parser-security.ts` blocks external `$ref` fetching (SSRF, issue #68).
  - `src/index.ts::checkInboundAuthOptions` refuses forwarding `authorization` when inbound bearer auth is on, but **defaults to `inboundAuth: 'none'`** with only a warning when the upstream has security: an unauthenticated confused deputy by default.
- For wicket:
  - BORROW the external-`$ref` ban for wicket's adapter generator input.
  - AVOID letting spec-supplied hints lower risk (the opposite of design §9's "adapter may raise risk, never lower").
- Confidence: H.

### ArcadeAI/arcade-mcp — tool SDK with OAuth/secret requirements (https://github.com/ArcadeAI/arcade-mcp, MIT, commit 9fb03000e7f8, 2026-11-06)
- Local path: `refs/repos/arcade-mcp`. Python. Active. The token broker ("Arcade Engine") is closed. The SDK and MCP server are open.
- **Architecture.**
  - Tools declare `requires_auth=GitHub(scopes=[…])` and `requires_secrets=[…]` (`arcade-core/arcade_core/schema.py:183-245`, `ToolRequirements`).
  - At call time `arcade_mcp_server/server.py:1962-1985` calls `_check_authorization(tool, user_id)` against the Engine:
    - If the status isn't `completed`, it returns an error result whose `llm_instructions` tell the model to show the user the authorization URL.
    - Otherwise it **injects the bearer token into `ToolContext.authorization`**, in the tool's own process.
  - Secrets come from settings or the environment (`:1221-1223`).
- **Gaps.**
  - The live user token sits in the tool process, so a compromised tool or toolkit has it.
  - The auth URL travels through the model (a phishing and injection surface).
  - Scopes are static per tool, not per call or resource.
- For wicket: BORROW per-tool or per-endpoint *declared scope requirements* as adapter metadata that drives native-credential minting (§8.4). AVOID tokens in tool processes and auth URLs via the model. Wicket's human channel is out of band.
- Confidence: M (server path read; Engine closed).

---

## 4. Guardrails, scanners and audit

### snyk/agent-scan — machine-wide scanner for agent configs, MCP servers and skills, plus "Agent Guard" hooks (https://github.com/snyk/agent-scan, Apache-2.0, commit 99d404778f6f, v0.6.11 2026-11-06)
- Local path `refs/repos/agent-scan`; Python (~15.7k lines in `src/agent_scan`); mature as a product, but it is a thin client for a closed SaaS analysis backend.
- **Architecture as implemented.** Discoverers per client (`agents/claude_code.py`, `codex.py`, `vscode/*`, ...) find MCP configs and skills. `inspect.py` connects to each server (stdio launch only with consent since 0.5.9; remote URLs with per-server confirmation, no redirects, link-local/metadata refused since 0.6.5) and collects a `ServerSignature` (`models/mcp.py:408`: metadata, prompts, resources, resource templates, tools). `verify_api.build_scan_request` → POST to `api.snyk.io` `/hidden/mcp-scan/analysis-machine` or `/hidden/agent-scan/async/analysis` (API version `2026-07-10`), after `redact.py` (detect-secrets plugins + flag/header allowlist) strips secrets. **All analysis happens server-side**; the client only renders risk indicators (`docs/risks.md`: `prompt_injection_tool_desc`, `untrusted_content`, `private_data`, `destructive_capabilities`, skill risks such as `suspicious_download_url`, `direct_money_access`), scored 100/300/600/1000.
- **Tool pinning is gone.** The "whitelisting of tools" (0.1.4.6) and the description-hash storage of mcp-scan ≤0.3 no longer exist in the tree (no hashing of tool definitions anywhere in `src/`); the `mcp-scan proxy` live mode (0.2.1) was also removed — the subcommands are now `scan`, `inspect`, `evo`, `guard {install,discover,uninstall}` (`cli.py:863–1016`). So 04 §2's "hash-pinning idea" now has no live reference implementation here.
- **Agent Guard** (`guard.py`, `hooks/snyk-agent-guard.sh`) writes PreToolUse-style hooks into `~/.claude/settings.json`, Cursor, Codex (`requirements.toml` managed hooks) and Copilot. The hook base64-POSTs the raw hook payload to Snyk's "agent-monitor" and returns its verdict. **It fails open by design**: transport/HTTP errors and the 60 s timeout `exit 0` with a `systemMessage` (`fail_open()` in the .sh). It detects tampering only of its own hook script (sha256 of the installed file, `guard.py:2010`).
- **Gaps.** Detection runs in a vendor cloud with no local policy. Hook-based enforcement runs *inside* the agent's trust domain (principle 1). Fail-open hooks. Scan time ≠ run time (a server can change after the scan). The risk categories are LLM-assigned.
- **For wicket.** REUSE nothing (SaaS-bound). BORROW: (1) the risk taxonomy `untrusted_content` / `private_data` / `destructive_capabilities` as **default labels for third-party MCP tools** (taint source, conf class, effect floor) when no adapter exists; (2) the redaction pass before anything leaves the host (wicket's audit export, LLM calls for adapter generation); (3) the consent rule "don't launch stdio servers to inspect them" — wicket should only ever start third-party servers inside a sandbox. AVOID: fail-open hook verdicts; scan-then-trust. design.md §8.2 pinning must be wicket's own (JCS hash per tool, checked on every `tools/list`); there is no upstream to borrow.
- Confidence: H (code read).

### invariantlabs-ai/invariant-gateway — LLM and MCP proxy that runs Invariant guardrails (https://github.com/invariantlabs-ai/invariant-gateway, Apache-2.0, commit 9baeade022cc, 0.0.9, last commit 2025-11-06 — dormant)
- Local path `refs/repos/invariant-gateway`; Python/FastAPI, ~5.1k lines; prototype maturity.
- **Architecture.** Provider routes (`routes/anthropic.py`, `open_ai.py`, `gemini.py`) forward to the real API. MCP transports `mcp/stdio.py` (wraps the server process), `sse.py`, `streamable.py`; `mcp_transport_base.hook_tool_call` / `hook_tool_call_response` convert JSON-RPC into Invariant trace messages. Each check sends **the whole session trace** (`self.messages + [message]`, `mcp_sessions_manager.get_guardrails_check_result`) to the Guardrails service at `GUARDRAILS_API_URL`, default `https://explorer.invariantlabs.ai` (`common/constants.py`): `/api/v1/policy/check/batch`, 5 s timeout. Blocked tool calls get a JSON-RPC error. A blocked `tools/list` rewrites each tool to `blocked_<name>` with an empty schema.
- **Bypasses found in the code:**
  1. **The client picks the policy.** `routes/anthropic.py:102`: `guardrails=header_guardrails or dataset_guardrails`; the `Invariant-Guardrails` request header (`config_manager.extract_policy_from_headers`, which even `unicode_escape`-decodes it) *replaces* the dataset policy. The operator's file policy applies only when neither is present (`request_context.py:63`). An agent that can set headers can send `Invariant-Guardrails: raise "x" if: False` and is unguarded.
  2. **Credential passthrough.** The client's provider key goes upstream (`extract_authorization_from_headers` → `headers[ANTHROPIC_AUTHORIZATION_HEADER]`): this is exactly the containment-post exfil path.
  3. **The upstream is chosen by the client.** The MCP upstream comes from the `mcp-server-base-url` request header (`get_mcp_server_base_url`), with localhost rewritten to `host.docker.internal`. That is SSRF / open relay.
  4. **Dedup turns into fail open.** A call is blocked only if `check_if_new_errors` finds an annotation not already on the session. When the service errors, `check_guardrails` returns a synthetic error with the fixed range `messages[0].content:L0` (`integrations/guardrails.py:209`). The first outage blocks; a repeat of the same error string matches the stored annotation and **passes** [M, from reading; not run].
- **For wicket.** AVOID as an architecture: remote policy evaluation, client-supplied policy, client-supplied upstream and credentials. BORROW only the trace normalisation idea (tool calls and outputs as one ordered message list), which wicket's audit log already does. Its failure list is a good **negative test checklist for wicket's conformance suite**: does a request header change policy? Is the client key forwarded? Is the upstream chosen by the request?
- Confidence: H on 1–3, M on 4.

### invariantlabs-ai/invariant — the Invariant Policy Language (guardrails rule language) (https://github.com/invariantlabs-ai/invariant, Apache-2.0, commit 2340fe2d9cd6, 0.3.5, last commit 2026-01-12)
- Local path `refs/repos/invariant`; Python; research-grade but complete (Lark grammar, typing, optimizer, async evaluator, stdlib of detectors).
- **Language.** `language/parser.py` is a Lark EBNF grammar with Python-like indentation: `raise "msg" if: (call: ToolCall) -> (out: ToolOutput) ...`. It has quantifiers, list comprehensions, `:=` binding and imports. Tool patterns are written `tool:send_email({to: r".*@evil.com"})`; `transform()` turns them into `SemanticPattern`s.
- **Evaluator.** `runtime/evaluation.py` finds variable assignments over the trace that satisfy the condition, with **three-valued logic** (`Unknown` propagates through and/or). `RaiseAction.can_eval` (`runtime/rule.py:43`) only fires on a definite result, so a rule whose condition stays Unknown does not raise.
- **What `->` really means.** `a -> b` is `has_flow`, and `runtime/input.py:Dataflow.visit_top_level` builds a **sequential graph**: every earlier message or tool call "flows" to every later one. So `->` means "happened before in the same trace", not data dependence. It is coarse temporal taint, which is the same thing wicket's floating agent label computes. `~>` means immediate predecessor.
- **Argument matching** (`runtime/patterns.py`): `ToolCallMatcher` does a regex full match on the tool name. `DictMatcher` matches only the listed keys, and extra keys are ignored. `ConstantMatcher` falls back to `re.match(value + "$", DOTALL)` on the joined text. Matchers for PII, moderation and secrets call ML/LLM detectors (`runtime/utils/*`).
- **The model is a deny-list.** Rules raise violations; anything that matches no rule passes. That suits a tripwire layer and does not suit an authority layer. Regex-on-strings means the usual parser differentials: case, Unicode, whatever the JSON encoder emits.
- **For wicket.** BORROW its vocabulary for an optional **flow-rule layer that can only make decisions stricter**, evaluated over wicket's own audit trace: "no `notify.external` after a `web` read in this zone", ordering, loop and rate rules. Most of these compile directly to wicket labels: `(read with taint web) -> (op with effect X)` is exactly `action_taint_allow`. The few that labels can't express (sequence counts, "after N reads of private data") could be a small Rust evaluator over `Op` records. Don't depend on it: Python, LLM detectors inside the evaluator, and Unknown ⇒ no-raise. It also confirms design.md §4.2's choice: the expressive "flow" language in prior art turns out to be ordering-based taint.
- Confidence: H.

### Cygnux-Labs/Tracekit — tamper-evident, signed "flight recorder" plus pre-call policy for agents (https://github.com/Cygnux-Labs/Tracekit, MIT, commit d5916e92e387, v1.5.3 2026-11-03; repo created 2026-09-26)
- Local path `refs/repos/tracekit`; Python, ~37k lines in `tracekit/`, plus TS verifiers; young but unusually well specified: normative test vectors and a conformance kit under `tests/kit/`. A single vendor; much of the docs reads as generated.
- **Architecture.** A separate **signer** process (`signer/`, `daemon.py`) decides every call (allow/deny/ask) and appends signed records to a per-run hash chain. Clients hold a run token, never a key. Clients include SDK wrappers, agent hooks (`agent_hooks.py`, `hook.py`), an **MCP gateway** (`mcp_gateway.py`: upstream creds stay in the gateway, tools are namespaced `server__tool`, `approval_wait_s`), an **egress observer** (`egress.py`: a CONNECT proxy with no TLS interception, attribution via `Proxy-Authorization` run token or loopback uid from `/proc`), and an **srt-proxy decider** (`srt_decider.py`: a complete client for Anthropic's decider protocol v1). Records are exported as `.tkb` bundles and verified offline.
- **Record format** (`docs/format-v2.md`, `format/`, `merkle/`):
  - RFC 8785 JCS everywhere, with a **strict parser** (`format.canon.loads_strict`) that rejects duplicate keys, lone surrogates, non-finite numbers, ints above 2^53 and depth over 128.
  - The args digest is `sha256(JCS({tool,args}))`, published only as an **HMAC commitment** with a per-record salt: auditors can test guesses, and the log leaks no content.
  - Per-run `run_seq`/`run_prev_hash` and global `seq`/`prev_hash`; Ed25519 signatures; **C2SP checkpoint notes cosigned by witnesses** (Certificate-Transparency style); a signed gap record when a client counter skips.
- **OTel.** `otel.py` exports `invoke_agent` / `chat` / `execute_tool` spans with `gen_ai.*` semconv attributes (`gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.usage.*`), and ingests agentgateway's `mcp:<target>/<tool>` spans (`docs/otel.md:42`).
- **Policy** (`policy2/`, `docs/policy-v2.md`): rule packs with IDs (`TK-SHELL-PARSE`, `TK-P003`, ...), and a bash parser that asks on dynamic constructs. **Value-level provenance:** values (hosts, emails, payees) seen in results of tools listed `untrusted` are indexed, and a `from: untrusted` rule matches only if an argument value is *untrusted-only*. Following a link exactly as given doesn't count as sending. **When the index is incomplete** (`partial`/`truncated`), `from: untrusted` rules match whenever their pattern does, so they **fail closed**. Ask ⇒ refuse, and once approved, the identical request (method, URL, body digest) is allowed **once**. "Intent grants" (`grants.py`) are bounded standing approvals with caveats and totals.
- **Fail modes.** The default is `fail_modes` closed per tool class. In v1, hooks fail open on unparseable payloads (`docs/limits.md:80`), and an unreachable signer gives 503 at the srt decider.
- **Gaps.**
  - Hook and SDK modes run in the agent's domain; their own threat-model table admits dev mode lets the agent re-sign.
  - Provenance is verbatim string matching, so any transformation (base64, "evil dot example", splitting) defeats it. It is a tripwire, not a boundary.
  - Python in the TCB.
- **For wicket.**
  - BORROW (high value) for `wicket-store`'s audit log (design.md §12 timeline):
    - JCS + strict parse + per-record HMAC commitments over args;
    - a hash chain per run *and* a global chain;
    - C2SP checkpoints with optional witness cosign;
    - OTel export with `gen_ai.*` attributes;
    - a signed gap record when an enforcement point misses events.
  - BORROW the **value-level "untrusted-only" provenance** as a *strictly additive* refinement of design.md §10's field-provenance rule. An escalation field or an R3 send target whose value appears only in tainted responses becomes ineligible for auto-grant. This is cheap and fails closed when the index overflows.
  - BORROW "approved ⇒ identical-digest request allowed once": it is §8.5's `request_id` + `Op.digest` binding.
  - `srt_decider.py` is a working third-party client of the srt decider protocol, which supports design.md §3.1's seam choice (and is a reference for frame limits: 32 MiB body, 5 s verdict).
  - REUSE: MIT licence allows vendoring its JSON test vectors (`tests/vectors/jcs.jsonl`, `sig_v2.jsonl`) for wicket's canonicaliser tests.
- Confidence: H on format and decider (read); M on policy-engine internals (read docs + headers, not all of `policy2/`).

### meta-llama/PurpleLlama — LlamaFirewall (scanner orchestration: PromptGuard, AlignmentCheck, CodeShield) (https://github.com/meta-llama/PurpleLlama, LlamaFirewall/ is MIT (repo root LICENSE is the Llama 3.2 Community licence, which covers the models/benchmarks), commit f64eebd53003, llamafirewall 1.0.3, last commit 2026-10-30)
- Local path `refs/repos/purplellama/LlamaFirewall`; Python library; stable but small.
- **Architecture.** `llamafirewall.py:LlamaFirewall.scan` runs the scanners configured per role. Defaults: TOOL → CodeShield + PromptGuard; USER → PromptGuard; ASSISTANT → CodeShield. Combining: **BLOCK wins; otherwise the decision with the highest score; ALLOW if nothing** fired.
- **The scanners:**
  - `PromptGuardScanner`: Llama Prompt Guard 2 classifier, `block_threshold=0.9`. The weights are under a Llama community licence, not MIT [M].
  - `CodeShieldScanner`: Semgrep/regex insecure-code detection across languages, BLOCK on any issue.
  - `HiddenASCIIScanner`: Unicode tag characters.
  - `RegexScanner`, `PIICheckScanner`.
  - `AlignmentCheckScanner` (experimental): an LLM judge via an API key env var, given the **full trace**.
- **AlignmentCheck failure modes** (`scanners/experimental/alignmentcheck_scanner.py`):
  - With no trace or no user message it returns **ALLOW** with `status=ERROR`.
  - An LLM error is treated as compromised and returns `HUMAN_IN_THE_LOOP_REQUIRED`.
  - `_pick_user_input` takes the first `Role.USER` message as "the task". In Anthropic-shaped traces, tool results ride in user-role messages, so mapping traces wrongly could make injected text "the user's intent" [M].
  - The judge reads agent reasoning and untrusted outputs, the opposite of design.md principle 4.
- **For wicket.** BORROW: `HiddenASCIIScanner` logic, which belongs in §2.1's normalise step, and the "BLOCK wins" combiner, which is right for tripwires. Optionally run PromptGuard 2 *outside* the box on tool results and fetched pages as a **label raiser** (add `suspected-injection` taint). It never grants. AVOID AlignmentCheck-style judges in any decider (prompt-injectable, reads the agent's justification) and anything that turns "no data" into ALLOW. Licence: the code is MIT, but the PromptGuard weights would add a Llama licence obligation to a deployment.
- Confidence: H (code read); M on the model licence.

### NVIDIA-NeMo/Guardrails — programmable rails around LLM apps (https://github.com/NVIDIA-NeMo/Guardrails, Apache-2.0, commit 537fd7742982, v0.24.1 2026-09-16)
- Local path `refs/repos/nemo-guardrails` (sparse: `nemoguardrails/{rails,library,guardrails}`); Python, plus one Rust crate (a NeMo Relay plugin client); mature.
- **Architecture.**
  - Colang flows (`rails/llm/llm_flows.co`, `llmrails.py`) wrap an LLM app's input, output, retrieval and tool rails.
  - `guardrails/` is a newer engine, with `iorails.py`, `rails_manager.py` and `tool_rail_action.py`.
  - `library/` holds about 35 detectors: jailbreak and injection detection, Llama Guard, content safety, sensitive-data detection, and vendor APIs such as CrowdStrike, Zscaler, F5, Pangea and Trend Micro.
  - The new `library/cel` rail evaluates CEL expressions over tool-call and tool-result arguments. It explicitly **fails closed**: a tool with no expressions, a CEL error or a non-boolean result raises (`cel/actions.py:_tool_options`, `_evaluate`).
- **For wicket.** NeMo Guardrails assumes it *is* the application's LLM loop, and wicket's inner agents are black boxes, so it cannot sit in wicket's path except inside the LLM proxy. Not a boundary. BORROW the fail-closed CEL tool rail semantics (missing rule ⇒ block) as a sanity check on wicket's own adapter interpreter. AVOID embedding it.
- Confidence: M (brief read).

### Kong/kong — OSS AI gateway plugins (`ai-proxy`, `ai-prompt-guard`, `kong/llm`) (https://github.com/Kong/kong, Apache-2.0, commit 21032122ab80, 3.9.4 2026-10-12)
- Local path `refs/repos/kong` (sparse); Lua/OpenResty; mature.
- **Architecture.**
  - `kong/llm/drivers/*.lua` normalises requests to OpenAI, Anthropic, Bedrock, Gemini, Azure and others.
  - **Credential injection:** `anthropic.lua:577–592` / `shared.lua:733` set the configured `auth.header_name` / `param_name`. With `allow_override=false` (the default, `llm/schemas/init.lua:114`) the client's value is overwritten. With `true`, **a client-supplied key wins** (passthrough).
  - Only the *configured* header name is replaced. Other auth headers the client sends (e.g. `Authorization` when Kong injects `x-api-key`) are not stripped by this code [M]. That is the strip-all-then-inject lesson again.
  - `ai-prompt-guard` (`filters/guard-prompt.lua`) applies PCRE `ngx.re.find` allow/deny patterns to the concatenated **user-role** messages only (unless `match_all_roles`). Non-string content gives `bad_format_error`, which rejects Anthropic content-block arrays.
- **MCP.** No MCP plugin or tool ACL exists in the OSS tree: the MCP Proxy and tool ACLs from 04 §2 are Enterprise-only.
- **For wicket.** AVOID. BORROW the conformance check "inject only after stripping every credential-shaped header", with the `allow_override` footgun as the counterexample.
- Confidence: H on the Lua read; M on the header-strip gap.

### Agent-Threat-Rule/agent-threat-rules (ATR) — Sigma-style detection rules for agent threats (https://github.com/Agent-Threat-Rule/agent-threat-rules, MIT, commit 5759a0f00612, v4.3.0 2026-11-06)
- Local path `refs/repos/agent-threat-rules`; YAML rules with a TS reference engine (Go/Python interface contracts only); young, but has a test-case discipline.
- **Rule format.** 844 rules under `rules/<category>/ATR-YYYY-NNNNN-*.yaml`. Each has `detection.conditions[]` of `{field, operator: regex, value}` over the fields `content`, `tool_response`, `user_input`, `tool_args`, `tool_name` and `tool_description`, combined `any`/`all`. Each also carries `response.actions` (alert/snapshot/block), compliance mappings, and **embedded true-positive/true-negative test cases**. 805 rules are `pattern` tier and 33 `semantic`; 84 use lookaround, which Rust's `regex` lacks.
- **For wicket.** REUSE (MIT) as a **tripwire corpus** applied outside the box to third-party tool descriptions at admission and pin time, and to tool responses and fetched content. A hit raises taint or forces R4/human review; it never allows. Use `fancy-regex` or drop the lookaround rules, and run the embedded test cases in CI. Regex corpora are easy to bypass: treat hits as signals only (04 §0.8).
- Confidence: M (format and stats read, engine not read).

### cisco-ai-defense/mcp-scanner — admission-time MCP server scanner (https://github.com/cisco-ai-defense/mcp-scanner, Apache-2.0, commit 9ff8fc84b792, 4.8.7 2026-10-20)
- Local path `refs/repos/cisco-mcp-scanner`; Python; active.
- Analyzers in `mcpscanner/core/analyzers/`: YARA (`data/yara_rules`), LLM, Cisco AI Defense API, VirusTotal, protocol, schema-reference, vulnerable-package and behavioral. Static **source** analysis (`core/static_analysis/{cfg,dataflow,taint,interprocedural}`) of server code. A `package_sandbox.py` for npm/PyPI packages.
- **For wicket.** An optional **pre-admission signal** for a third-party server (design.md §8.2 kind 2) before its tool hashes are pinned. Its source-level taint analysis could suggest which tools read untrusted content (default labels). Never in the request path.
- Confidence: M (structure read).

### Quick notes (not cloned)
- **getagentseal/agentseal** (Python, licence NOASSERTION): local scanner and monitor for skills and MCP configs. It overlaps agent-scan, and the unclear licence rules out reuse.
- **mcp-firewall variants** (ressl/mcp-firewall AGPL-3.0, dzervas/mcp-firewall GPL-3.0, hyprmcp/mcp-gateway MIT): small regex/allowlist MCP proxies; nothing beyond agentgateway/ToolHive. Copyleft ones can't be vendored.

---

## 5. Gateway ↔ isolated MCP servers (cross-project)

How each gateway launches, confines, feeds and reaches its MCP servers, read from code (2026-11-08). "Shared" means one server instance serves many clients.

**docker/mcp-gateway** (`pkg/gateway/clientpool.go`, `pkg/gateway/proxies/`)
1. Launch: one container per server via the `docker` CLI (`newClientGetter`→`mcpclient.NewStdioCmdClient("docker", env, run …)`); `baseArgs`: `--rm -i --init --security-opt no-new-privileges --pull never`, optional `--cpus/--memory`; `--privileged` if `DOCKER_MCP_IN_DIND=1`. No `--user`, no `--cap-drop`, no `--read-only`. Images pinned by digest only when `--verify-signatures` is on (`pull.go`). The gateway itself needs the Docker socket (host-root equivalent).
2. Network: default = attached to the gateway's own networks (`argsAndEnv`), i.e. internet and the other servers. `DisableNetwork` ⇒ `--network none`. `--block-network` only engages when the server declares `AllowHosts` (`GetClient`: `BlockNetwork && len(AllowHosts) > 0`); then the server joins a fixed internal network `docker-mcp-proxies-int` (shared by *all* proxied servers, so they can reach each other) with an L7 sidecar (`ALLOWED_HOSTS`, `http(s)_proxy` env) and L4 forwarders. Hostname allowlist only: no TLS inspection, no credential injection.
3. Secrets: `Spec.Secrets` become `-e NAME` with values in the docker CLI env (`argsAndEnv`); under Desktop, `se://` URIs resolved by Desktop at container start (`secrets_uri.go`). The server holds real credentials.
4. stdio: the gateway owns the container's stdin/stdout through `docker run -i`; "static" mode instead socat-dials `mcp-<name>:4444` (compose-managed containers). Upstream `initialize` is sent as `2024-11-05`.
5. Instances: `longLived` servers are kept per `clientKey{serverName, session}`, i.e. per client session; remote servers are always kept; short-lived servers get a fresh container per acquisition (per call). `runToolContainer` runs one container per *tool call* for container-tools. Least leakage of the group, at a high start-up cost.
6. Remote: `Spec.Remote.URL` streamable HTTP/SSE with OAuth from Desktop's broker; no auth between the gateway and its local containers (stdio).

**IBM/mcp-context-forge** (`mcpgateway/translate.py`, `services/gateway_service.py`, `charts/mcp-stack`)
1. The gateway does not sandbox servers. It is a registry of remote HTTP/SSE servers, and `translate.py` is a separate stdio→SSE/HTTP bridge (`StdIOEndpoint.start`: `asyncio.create_subprocess_exec` of `shlex.split(cmd)`, run wherever the bridge runs). The Helm chart hardens the gateway pod itself (`runAsNonRoot`, drop caps, `readOnlyRootFilesystem`, a NetworkPolicy).
2. Network: whatever the bridge's host or pod allows. Gateway→server dials use resolve-once IP pinning with an SNI-pinned transport (`utils/ssrf_pinning.py`, `SniPinningTransport`), and `SecurityValidator.validate_url` applies SSRF checks.
3. Secrets: the subprocess gets `os.environ.copy()` (the bridge's whole environment) plus configured vars. With `header_mappings`, **a client's HTTP headers become env vars and the shared process is restarted with them** (`post_message` → `stdio.stop(); stdio.start(additional_env_vars)`).
4. stdio: one subprocess per bridge; `_pump_stdout` publishes every stdout line to a `_PubSub`, and **every SSE subscriber receives every message**.
5. Instances: shared. Responses and notifications for client A reach client B, and client B's header-derived credentials become client A's. This is a cross-tenant leak if one bridge serves several clients.
6. Remote: registered gateway URLs; auth by stored OAuth, headers, or RFC 8693 exchange (`token_exchange_actor.py`).

**microsoft/mcp-gateway** (`Management/src/Deployment/KubernetesAdapterDeploymentManager.cs`, `deployment/k8s/cloud-deployment-template.yml`)
1. Launch: one K8s StatefulSet + Service per adapter; `RunAsUser/Group 1100`, `AllowPrivilegeEscalation=false`, `Drop ALL`, limits of 1 CPU, 512Mi memory and 2Gi ephemeral storage, ServiceAccount `workload-sa`. Image is `registry/name:tag` with `ImagePullPolicy: Always` (a tag, not a digest). No read-only rootfs. `DeploymentOwnership` verifies StatefulSet/Service UIDs before routing.
2. Network: NetworkPolicies are **ingress-only** (default deny ingress; adapters reachable only from `app: mcpgateway|toolgateway` pods). There is no egress policy, so adapters reach the internet, cluster services and each other's Services.
3. Secrets: plain `V1EnvVar{Name, Value}` from the create request; no `SecretKeyRef`.
4. stdio: none. Adapters must speak streamable HTTP on :8000.
5. Instances: shared by all authorized users. `ForwardStreamableHttpRequest` picks a random pod per request (2026-07-28 statelessness); `Mcp-Session-Id` is stripped. Isolation comes from adapter RBAC, not instances.
6. Remote: in-cluster only (headless Service DNS via `AdapterKubernetesNodeInfoProvider`). Identity is forwarded as `X-Mcp-UserId/Roles`; the shared `X-Gateway-Secret` goes only to the first-party tool gateway.

**toolhive** (`pkg/container/docker/client.go`, `squid.go`, `envoy.go`, `pkg/transport/stdio.go`, `pkg/transport/proxy/streamable/`)
1. Launch: one container per workload (`DeployWorkload` → `createMcpContainer`). `getPermissionConfigFromProfile` sets `CapDrop: ALL`, `SecurityOpt: label:disable`, `Privileged` from the profile, and read-only/read-write mounts from the profile's `read`/`write` lists (with `.thvignore` overlays). No user and no read-only rootfs are set. A K8s operator (`cmd/thv-operator`) is the multi-host path.
2. Network (best of the group): `--isolate-network` defaults to true (`run_flags.go`). It creates a **per-workload internal network** `toolhive-<name>-internal` (`createNetwork(…, internal=true)`), so servers can't reach each other or the internet directly. Each workload gets:
   - its own DNS container;
   - an egress proxy, Squid or Envoy (`newNetworkProxy`), with `allowed_dsts dstdomain` + `allowed_ports` from the permission profile, then `http_access deny all`;
   - explicit deny rules for Docker bridge-gateway IPs, so the host stays unreachable (`writeDockerGatewayDenyRules`; Envoy RBAC `buildGatewayDenyRBAC` even matches IPv4-mapped and textual IPv6 authorities);
   - an ingress proxy for HTTP transports.
   Gaps:
   - A **nil network permission section means `http_access allow all`** (`createTempEgressSquidConf`).
   - Isolation is silently dropped for host/custom network modes, with only a warning (`degradeNetworkIsolation`, #5775).
   - Hostname ACLs only: no TLS inspection or injection.
   - No private-IP filtering beyond the gateway IPs.
3. Secrets: `--secret NAME,target=ENV` fetched from the secrets provider into container env (`runner/env.go` `addAsSecret`). Upstream user tokens go to *remote* servers via `upstreamswap`, never into containers.
4. stdio: the proxy owns the container's attached stdio (`StdioTransport.Start` → `deployer.AttachToWorkload`, reattach on socket errors) and exposes streamable HTTP or SSE on a localhost **TCP** port (`proxy/socket` sets `SO_REUSEADDR`; no UDS).
5. Instances: one backend shared by all clients of the workload. `streamable/dispatcher_routing.go` `sessionRouter` prevents protocol-level leaks:
   - proxy-minted progress tokens, restored per request;
   - ref-counted per-session `resources/subscribe`;
   - log level reconciled to the most verbose requested.
   Server-internal state is still shared.
6. Remote: `SetRemoteURL` with an OAuth token source; vMCP aggregates backends; header-forward secrets per backend.

**pomerium** (`internal/mcp/`, `config/envoyconfig/routes.go`)
1–4. It launches nothing. Upstreams are HTTP URLs behind Envoy routes, so stdio servers need an external bridge.
5. Instances: shared upstreams with per-user credentials (`GetUpstreamToken` keyed by user × route × upstream).
6. Remote: Envoy clusters to `UpstreamURL`. The client's `Authorization` is stripped (`headers_evaluator_evaluation.go`) and the per-user upstream OAuth token is injected by ext_proc. Discovery and metadata fetches go through an SSRF-guarded dialer (`ssrf.go` `resolveAndValidate` rejects private, loopback, link-local and multicast addresses).

**teleport** (`lib/srv/mcp/stdio.go`, `http.go`; AGPL, ideas only)
1. Launch: per-session `exec.CommandContext(mcpSpec.Command, Args…)` on the app-agent host as `RunAsHostUser` (`makeExecServerRunner`, `MaybeSetCommandCredentialAsUser`). No container, namespace or limits. SIGINT then SIGKILL after 10 s. `cmd.Env` is not set, so the child inherits the agent's environment [M].
2. Network: the host's.
3. Secrets: env/host files. HTTP apps get a Teleport-signed JWT in `teleport-jwt-assertion` plus header rewrites with traits.
4. stdio: the agent owns the pipes. The client reaches them through Teleport's reverse tunnel.
5. Instances: **per client session** (new process per `handleStdio`).
6. Remote: reverse tunnel to the app agent. Upstream auth is the Teleport JWT, though a client `Authorization` header may pass through.

**bifrost** (`core/mcp/clientmanager.go` `createSTDIOConnection`, `credstore/`)
1. Launch: stdio servers are bare child processes of the gateway (mcp-go `transport.NewStdio(cmd, envs, args…)`), with no sandbox. Connect-plugin pre-hooks may **rewrite the command, args or URL** (`BifrostMCPConnectRequest` overrides).
2. Network: the gateway host's.
3. Secrets: inline `KEY=value` envs or referenced gateway env vars (checked with `os.Getenv`). HTTP credentials come from the CredStore and are layered after plugins, so plugins never see bearer tokens.
4. stdio: the gateway owns the pipes, in process.
5. Instances: shared, except for per-user auth types, where `RequiresPerCallConnection` forces a per-call connection.
6. Remote: HTTP/SSE/OpenAPI clients with CredStore headers.

**agent-router** (`internal/mcpproxy/mcpproxy.go`, `session.go`, `cmd/aigw/stdio2http.go`)
1–4. In K8s, backends are Services/Envoy clusters the operator manages. Standalone `aigw` wraps stdio servers in local streamable-HTTP proxies (`stdio2http.go`, `exec.Command`), unconfined.
5. Instances: shared backends. The client-facing session id is an AES-encrypted composite of per-backend session ids, **bound to route and authenticated subject** (`sessionFromID`, `errSessionRouteMismatch`), which blocks session hijack and route-hopping.
6. Remote: the proxy re-enters Envoy at `backendListenerAddr` with backend/route headers. Envoy routes to the backend and injects `MCPBackendAPIKey` from a K8s Secret, or forwards configured client headers.

**What nobody does:**
- No project has all four of: a server with no network route of its own, egress only through an inspecting proxy, credentials injected only at that proxy, and a gateway-owned non-TCP transport.
- ToolHive comes closest on the network side (internal network + egress proxy + host deny), but it still puts secrets in env and uses domain-only ACLs.
- Shared instances are the norm. Where they are shared, cross-client leaks are either real (ContextForge's broadcast and header-to-env restart) or need elaborate protocol-level routing (ToolHive's `sessionRouter`).

**Recommendations for wicket**
1. **One sandbox per third-party server, per task/zone.** A server is a workload under the same `Sandbox` trait as agents. It gets its own "server zone" (reach = the hosts and adapter endpoints it needs, clearance and labels as for any zone) and is never shared across tasks or zones. Start it per task and destroy it at task end, like Docker's per-session keying but without a container per call. This removes the shared-state leak class outright (no `sessionRouter` needed). Pin by digest (OCI) or content hash (binary/npm/pip lockfile) in the manifest, next to the tool-description hash.
2. **netns with no interfaces, only the egress-proxy socket.** Use the same `process`/`gvisor` backend as agents: empty netns, UDS-bridged `HTTPS_PROXY` to `wicket-egress`, and the per-sandbox CA. The server's HTTP then goes through adapters and decisions like any other Op, with `agent` = the server's identity and the label joined from the calling agent's request. ToolHive's per-workload internal network shows that per-server separation is practical; wicket gets it without Docker networks. No server-to-server or server-to-host path exists. DNS is resolved only in the proxy.
3. **Secrets only via proxy injection.** The server's env and files hold placeholders (`GITHUB_TOKEN=wicket-placeholder-…`). `wicket-egress` strips and injects per decision. Never env (as Docker, ToolHive, Microsoft, Bifrost and ContextForge do), never client-header-to-env (ContextForge), never inherited parent env (Teleport, ContextForge `os.environ.copy()`): launch with an explicit, minimal env.
4. **Gateway-owned transport, no TCP.**
   - stdio servers: `wicket-jail` spawns the server, the gateway holds the stdin/stdout fds directly, and nothing in the box listens.
   - HTTP-only servers: streamable HTTP over a UDS bind-mounted out of the server sandbox (vsock on Firecracker).
   - Agent side: the gateway's UDS bind-mounted into the agent box.
   - The gateway terminates MCP on both sides and re-encodes, never byte-forwarding (agent-router's re-encode-after-parse).
   - Upstream protocol version: whatever the server supports (rmcp `Auto`); downstream: both eras.
5. **No runtime server addition by the agent** (Docker's `mcp-add`) and no plugin that rewrites launch commands or URLs (Bifrost pre-hooks). The server set is part of the approved manifest. Adding a server is an escalation.
6. **Remote servers**: dial through the shared upstream client (resolve once, SSRF deny, as Pomerium's `ssrf.go` and ContextForge's `ssrf_pinning` do), strip the client's auth, and inject a vault-held, audience-bound token. Bind gateway sessions to agent identity and route (agent-router's `sessionFromID`).

**design.md changes implied**
- §7: add a workload role `ToolServer` (vs `Agent`) to `SandboxSpec`. `Instance::attach` must return the raw stdio fds for the gateway. State that server sandboxes use the same `EgressMode::ProxyOnly` as agents and are created and destroyed with the task. Add a resource-limit default (Microsoft's 1 CPU / 512Mi is a reasonable floor).
- §8.2 kind 2: replace "run in their own sandbox" with the explicit contract above (per-task instance, empty netns + egress UDS, placeholder-only secrets, gateway-owned stdio/UDS, digest/hash pin, no agent-initiated additions). Record that a server's outbound requests are Ops attributed to the server zone, carrying the invoking agent's label (otherwise a server becomes a label-laundering deputy).
- §8.1: the egress proxy must accept per-server identities (one UDS per sandbox already gives this).
- §12: list each server sandbox as a node in the zone view, with its reach.

---

## 6. Synthesis

### (a1) Reuse plan

wicket is meant to be Apache-2.0/MIT. Everything below is Apache-2.0, MIT or BSD-3, so it is compatible. Two obligations:
- Code **vendored** from an Apache-2.0-only source keeps its licence header and NOTICE, and the changes must be marked.
- A dual-licensed wicket should keep vendored Apache-only files in a clearly marked `third_party/` path, or rewrite them rather than copy.

**Depend on (exact pins, behind wicket's own traits):**

| Crate | Licence | Use | Pin note |
|---|---|---|---|
| `rmcp` 3.9.x | Apache-2.0 (residual MIT) | gateway server (`ServerHandler` for native tools), upstream client, `transport-async-rw`, `transport-child-process`, `transport-streamable-http-client-unix-socket`, `transport-streamable-http-server`, `auth`, `request-state` | releases roughly every two weeks; pin `=` and run the conformance suite on every bump |
| `rama` 0.4.x (`rama-net`, `rama-http-backend`, `rama-tls-rustls`, `rama-tcp`, `rama-unix`, `rama-socks5` if needed) | MIT OR Apache-2.0 | egress data plane | pin `=`. rustls has **no ready MITM relay**, so assemble termination as Codex does, with a custom `TcpStreamConnector` for IP vetting |
| `cedar-policy` =4.14.1 + `cedar-policy-symcc` =0.8.1 | Apache-2.0 | authored policy, proofs; `tpe` (experimental) for `explain` | symcc pins cedar exactly, so bump the two together. cvc5 1.3.1 (BSD-3) runs as a sidecar with `--tlimit`, and `unknown` means fail |
| `rcgen`, `rustls` (aws-lc-rs), `aws-sigv4`, `hickory-resolver`, `ipnet` | MIT/Apache | CA, TLS, re-signing, DNS | — |
| `biscuit-auth` 6.0 (later) | Apache-2.0 | multi-host grants | raise the default 1 ms Datalog time limit |

**Lift with attribution (small files, reference implementations):**
- From agentgateway (Apache-2.0):
  - `mcp/dns_rebinding.rs`;
  - `upstream/openapi/mod.rs::substitute_path_params`;
  - the discover/initialize merge logic in `mcp/handler.rs` as a reference for the version bridge.
- From Codex `network-proxy` (Apache-2.0):
  - `mitm.rs` authority pinning (Host/`:authority` forced to the CONNECT target, `@` refused);
  - `credential_broker/providers/github.rs` (`translate_request_header`, `shaped_dummy_value`);
  - `aws_sigv4.rs`.
- From smokescreen (MIT): the IP classifier. Port it to Rust; it covers CGNAT, NAT64, 6to4, Teredo and the proxy's own addresses.
- **Test corpora:**
  - ToolHive `pkg/authz/case_smuggling_test.go` cases (Apache-2.0);
  - rama `mitm_bound_authority` tests (MIT/Apache);
  - Tracekit canonical-JSON/commitment test vectors (MIT);
  - Agent-Threat-Rules (MIT) as a tripwire corpus. 84 of its rules need lookaround rewritten for `regex`.
- **Data** (an adapter-generator input, never code in the TCB):
  - github-mcp-server `pkg/ifc` label table and `pkg/scopes` (MIT);
  - iam-dataset `map.json` (MIT);
  - policy_sentry access levels and privilege-escalation lists (MIT).

**Read, don't take:** Teleport (AGPL-3.0), and onecli `*/ee/` (enterprise licence).
**Excluded:**
- Dicklesworthstone/flywheel_connectors: its licence rider withholds all rights from Anthropic and from anyone acting for it, including "analyzing". The clone was deleted and the code was not studied.
- PurpleLlama model weights (Llama licence). LlamaFirewall's code is MIT.

**Build ourselves (nobody has it in reusable form):**
- the adapter interpreter and canonicalizer;
- the capability algebra;
- tool-description hash pinning (Snyk removed its implementation, see 04 §2.1);
- the label store;
- the escalation ledger;
- the version bridge for a typed relay.

### (a2) Ranked design changes

1. **One strict pre-parser in front of every parser (§8.1, §8.2, §9).** Four Go gateways (Pomerium, Teleport, ToolHive, iron-proxy) independently hit the same bug: `encoding/json` matches keys case-insensitively and the last duplicate wins. The dangerous differential is between wicket and the *upstream server or provider*, not inside Rust (serde is case-sensitive), so wicket must account for how the upstream parses.
   - **Rule:** reject duplicate keys, keys that differ only in case at any level, number overflow (`1e1000`), batches, non-UTF-8 and oversized bodies.
   - Then forward the **re-encoded canonical bytes** that the decision saw (agent-router's `EncodeMessage`), never the original bytes.
   - Apply this to MCP JSON-RPC, adapter-matched REST bodies and LLM requests.
2. **Enforce by evaluating the chain, use the subset check for admission and explanation (§4.1, §10).** Fly's macaroons never compute "A ⊆ B": every caveat in the chain is checked on every access.
   - wicket should decide `Op` as `org ∧ every ancestor zone's reach ∧ grant ∧ labels ∧ ledger`.
   - `is_subset_of` stays for refusing over-wide spawns and asks and for rendering diffs. A bug in it then costs usability, never authority.
   - Add `Constraint::IfPresent { then, else_verbs }` for optional arguments and resources (Fly `resset.IfPresent`).
3. **Never forward a client header (§8.1–8.3).** Several gateways pass client headers through by default:
   - agentgateway's `IncomingRequestContext::apply` copies all of them;
   - Teleport passes `Authorization` through;
   - FastMCP forwards everything outside a short deny list;
   - Kong's `allow_override` lets the client's key win;
   - invariant-gateway forwards the client's key and lets a header choose the policy and the upstream.

   The gateway and the egress proxy should build each upstream request **from the Op and the adapter**: declared headers only, auth slot set by the vault. Responses get a header allowlist (Microsoft) and **scrubbing of any injected credential value** (chaperone).
4. **Credentials are bound at mint time and swapped only by exact match in the declared slot (§8.4).**
   - Each vault record carries `(provider, hosts (non-empty), header slot, format)`, sealed with the credential (tokenizer validators, Codex `CredentialHostBinding`).
   - Placeholders keep the token's shape (Codex `shaped_dummy_value`) so CLIs accept them.
   - Substitution happens only on exact equality, inside the declared auth header. Never in bodies, queries or arbitrary headers: iron-proxy, agent-vault and tokenizer's `inject_body` turn any allowed write into a way to read the secret back.
   - The proxy mints and holds short-lived tokens itself. Tokenizer's `github_app` processor calls the installation-token endpoint and seals the result; plaintext never leaves the proxy.
   - Watch broad suffix bindings: Codex binds a github.com token to `*.ghe.com`.
5. **Correct §8.1's rama statement.** Codex pins `=0.3.0-alpha.4`, not 0.4, and uses no rama MITM relay. rama's `TlsMitmRelay` is BoringSSL-only.
   - Decide: rustls termination assembled from `rama-net`/`rama-tls-rustls`.
   - **One upstream connection per CONNECT**, dialled at CONNECT time to the vetted IP. Don't use the rustls example's per-request redial.
   - SSRF vetting in a custom `TcpStreamConnector`, with smokescreen's classifier.
   - Add to the canonicalize list:
     - `@` in the authority;
     - Host ≠ SNI ≠ CONNECT target;
     - method-override headers;
     - unknown protocols after CONNECT (hudsucker falls through to a raw tunnel);
     - a truncated body counts as "unknown" and gets the strict outcome (onecli).
6. **Make §8.2's version bridge concrete.**
   - Detect the protocol era and reject legacy-only methods on 2026-07-28 requests (agent-router `era.go`).
   - Enforce SEP-2243 `Mcp-Method`/`Mcp-Name`/`Mcp-Param-*` agreement with the body (rmcp `validate_standard_headers`, Microsoft `McpToolHeaderValidator`).
   - Strip cache fields and mark every result uncacheable (agentgateway).
   - Namespace server-initiated request IDs per upstream.
   - Reserve the namespace delimiter in server names and reject case-insensitive collisions (Docker).
   - Use a *message-level relay* over rmcp model types for third-party servers (agentgateway's pattern) and rmcp `ServerHandler` for gateway-native tools.
   - Seal MRTR `requestState` with rmcp's `RequestStateCodec`, bound to the Op digest. The ledger enforces single use.
7. **Discovery and execution share one filter (§8.2).** The function that hides a tool from `tools/list` must be the one that blocks `tools/call`, applied in the same order (Bifrost `checkToolExecutionPermitted`, agentgateway `merge_tools`).
   - Meta-tools must re-authorize the *inner* call: `wicket.*`, codemode, any `call_tool`/`find_tool` (ToolHive).
   - Codemode gets step and tool-call budgets (Bifrost Starlark).
8. **Server-asserted metadata is never a policy input (§4.2, §9).** ToolHive lets Cedar read `readOnlyHint`, and ContextForge's MAC engine takes `classification_level` from the caller's arguments. Both are anti-patterns.
   - Upstream labels may only *raise* wicket's labels. For example, github-mcp-server's `_meta.ifc`, whose label table and join rule should seed the GitHub adapter's default labels.
9. **Cedar compilation details (§4.1).**
   - `OneLevel` compiles to `like "p/*" && !like "p/*/*"`, because `*` crosses `/`.
   - Link templates before SymCC, which rejects templates, open attributes and `AnyEntity`.
   - Put the algebra→Cedar compiler in the TCB, with a differential test of Cedar `is_authorized` against `wicket-core`'s decide.
   - 03's `like` and extension-type worry is refuted; its hierarchy-is-symbolic caveat is confirmed.
10. **The LLM proxy rewrites, not just observes (§8.3).** GitHub's AWF rewrites Anthropic `web_search`/`web_fetch` tool definitions to impose `allowed_domains` and `max_uses`. wicket-llm should do the same from the zone's reach, and still taint the results.
11. **Audit log format (§12, `wicket-store`).** Take Tracekit's format:
    - RFC 8785 canonical records, parsed strictly;
    - salted HMAC commitments over arguments, so the log is shareable without content;
    - a per-task hash chain plus a global chain with checkpoints;
    - OTel `gen_ai.*` export.

    Tracekit's `srt_decider.py` also shows the srt decider protocol has third-party users, which supports the §3.1 seam.
12. **Risk floors are the maximum over provider metadata *and* community overrides (§9).** policy_sentry and iam-dataset both keep corrections for AWS access levels AWS got wrong. A spec may never lower risk (openapi-mcp-generator does let it).

### (a3) Gateway ↔ isolated MCP servers

Detail for each project is in §5. In short:

**What the field does today:**
- **No project combines all four of the following:**
  - the server has no network route of its own;
  - its egress goes only through an inspecting proxy;
  - credentials are injected only at that proxy;
  - the gateway owns a non-TCP transport.
- **ToolHive comes closest.** Each workload gets an internal Docker network, its own DNS, and a Squid/Envoy egress allowlist that denies the host gateway IPs. But a profile with a nil network section means allow-all, the ACLs are by domain only, secrets go in env, and the gateway reaches the server over a localhost TCP port.
- **Docker MCP gateway** runs one container per server but attaches it to the gateway's networks by default. Its "blocked" mode puts every proxied server on one shared internal network, so those servers can reach each other.
- **Microsoft's gateway** uses ingress-only NetworkPolicies, so adapters have open egress.
- **Unconfined host processes.** agentgateway, Teleport, Bifrost and standalone agent-router all run stdio servers this way.
- **Inherited parent environment.** Teleport and ContextForge pass the gateway's whole environment to the server process.
- **gh-aw-firewall** runs stdio servers inside the agent's own container, sharing its filesystem and network.
- **Secrets are in env everywhere.**
- **Shared instances are the norm, and they leak:**
  - ContextForge `translate.py` sends every stdout line to every SSE client.
  - It also restarts the shared process with one client's header-derived env.
  - ToolHive needs a protocol-level `sessionRouter` to keep clients apart.
- **Best ideas to copy:**
  - Docker keys long-lived servers per client session.
  - agent-router's client session id is an encrypted composite bound to route and subject.

**wicket's contract for third-party MCP servers (design.md §8.2 kind 2):**
1. **One sandbox per server, per task and zone.** The server is a workload under the same `Sandbox` trait, with its own *server zone*: reach covers only the hosts and adapter endpoints it needs. It is created and destroyed with the task and never shared across tasks or zones. It is pinned by image digest or lockfile hash in the manifest, next to the tool-description hashes.
2. **An empty netns.** The only route out is the UDS-bridged `HTTPS_PROXY` to `wicket-egress`, with that sandbox's own CA. The server has no path to other servers, to the host, or to DNS.
3. **Placeholder-only secrets.** The server is launched with an explicit minimal env; nothing is inherited. Real credentials are injected by the egress proxy per decision, so the server is just another client of the vault.
4. **A gateway-owned transport, never TCP:**
   - stdio servers: `wicket-jail` hands the server's stdin/stdout fds to the gateway, using rmcp `transport-async-rw`;
   - HTTP-only servers: Streamable HTTP over a UDS bind-mounted out of the sandbox (rmcp `transport-streamable-http-client-unix-socket`), or vsock on Firecracker.

   The gateway terminates MCP on both sides and forwards re-encoded messages, never raw bytes.
5. **The server's own egress is an Op attributed to the server zone, carrying the invoking agent's label.** Otherwise the server becomes a label-laundering deputy. When one call is in flight, attribution is exact. With concurrent calls, join the labels of all in-flight callers. That is pessimistic, and is why the per-task instance in item 1 matters.
6. **No runtime additions.** No `mcp-add`-style self-service and no plugin that rewrites launch commands. The server set is part of the approved manifest, and adding a server is an escalation.
7. **Remote servers on other hosts** go through the shared upstream client (resolve once, SSRF deny). The client's auth is stripped and replaced with a vault-held, audience-bound token: the Pomerium pattern of tokens keyed by agent × route × upstream. Gateway sessions are bound to agent identity and route (agent-router `sessionFromID`).

**design.md deltas:**
- **§7:** add a `ToolServer` workload role to `SandboxSpec`. `Instance::attach` must be able to return raw stdio fds to the gateway. Server sandboxes use `EgressMode::ProxyOnly`, have the task lifecycle, and default to resource limits of 1 CPU / 512 MiB.
- **§8.1:** the egress proxy identifies callers per sandbox; one UDS per sandbox already gives this.
- **§8.2:** replace "run in their own sandbox" with items 1–7 above.
- **§12:** each server sandbox is a node in the zone view, with its reach and label edges.

### (a4) Where the code contradicts the current docs

- **design.md §8.1**: "rama 0.4, pinned exactly as Codex does". Codex pins 0.3.0-alpha.4 and has no rama MITM relay on rustls (change 5).
- **design.md §15**: "agentgateway … matches tool names, not argument semantics".
  - True for `mcpAuthorization`, whose CEL context gets `{target, name}` only (`MCPInfo::from(&ResourceType)`).
  - But agentgateway's CEL *guardrails* see `mcp.params.arguments`, and agent-router (CEL), ToolHive (`arg_*` in Cedar context) and ContextForge (OPA/Cedar context) all do argument rules.
  - The real difference is that theirs are raw, flat or unanalysable arguments, while wicket's are arguments bound by an adapter into typed resources. Reword the reason; the decision stands. Add that agentgateway also runs stdio servers unsandboxed and passes client headers through.
- **04 §2 / §2.1**: mcp-scan's "tool pinning … between scans" is gone from `snyk/agent-scan`. Hashing and the proxy mode were removed and analysis moved to Snyk's servers. wicket's pinning has no OSS reference left.
- **03 §1.2**: the worry that SymCC might not cover `like` or the extension types is wrong; they are covered. The real exclusions are templates, open attributes and `AnyEntity`. The path-prefix advice (strings + `like`) is right.
- **design.md §4.1 `OneLevel`**: not expressible as one Cedar `like` (change 9).
- **design.md §8.4** is incomplete rather than wrong: add binding at mint time, exact-slot swap and response scrubbing (change 4).

### (b) Project table

| name | url | licence | lang | local path (refs/repos/) | what wicket takes | rel |
|---|---|---|---|---|---|---|
| agentgateway | https://github.com/agentgateway/agentgateway | Apache-2.0 | Rust | agentgateway | message-level relay on rmcp types; version bridge; no-cache; list=call filter; lift `dns_rebinding.rs`, `substitute_path_params`; avoid header passthrough | 3 |
| rmcp (rust-sdk) | https://github.com/modelcontextprotocol/rust-sdk | Apache-2.0 (+residual MIT) | Rust | rmcp | **depend**: server, client, UDS/async-rw/child transports, SEP-2243 validation, `RequestStateCodec` | 3 |
| toolhive | https://github.com/stacklok/toolhive | Apache-2.0 | Go | toolhive | Cedar mapping of MCP ops, meta-tool re-authorization, case-smuggling corpus, passthrough fix | 3 |
| agent-router | https://github.com/theagentrouter/agent-router | Apache-2.0 | Go | agent-router | era detection, header/body agreement, re-encode-before-forward, CEL error ⇒ deny | 3 |
| github-mcp-server | https://github.com/github/github-mcp-server | MIT | Go | github-mcp-server | `pkg/ifc` label table + join rule, argument-aware scope challenges, operator config as upper bound | 3 |
| superfly/tokenizer | https://github.com/superfly/tokenizer | Apache-2.0 | Go | superfly-tokenizer | mint-and-reseal, credential bound to host+slot, dial-time IP check | 3 |
| codex network-proxy | https://github.com/openai/codex (codex-rs/network-proxy) | Apache-2.0 | Rust | codex-network-proxy | rama usage, authority pinning, shape-preserving placeholders, exact-slot swap, SigV4 | 3 |
| rama | https://github.com/plabayo/rama | MIT OR Apache-2.0 | Rust | rama | **depend**: data plane; custom `TcpStreamConnector` | 3 |
| smokescreen | https://github.com/stripe/smokescreen | MIT | Go | smokescreen | SSRF classifier, resolve-once, MITM re-check | 3 |
| cedar + symcc | https://github.com/cedar-policy/cedar | Apache-2.0 | Rust | cedar | **depend**: authorizer, SymCC, tpe | 3 |
| superfly/macaroon | https://github.com/superfly/macaroon | Apache-2.0 | Go | superfly-macaroon | chain enforcement, `IfPresent`, discharge/poll flow, `FlySrc` | 3 |
| iam-dataset | https://github.com/iann0036/iam-dataset | MIT | data | iam-dataset | AWS call→action/ARN map, risk tags | 3 |
| Tracekit | https://github.com/Cygnux-Labs/Tracekit | MIT | Python/TS | tracekit | audit format, HMAC commitments, hash chains, approve-once-by-digest, srt-decider client | 3 |
| pomerium | https://github.com/pomerium/pomerium | Apache-2.0 | Go | pomerium | decide/inject split, upstream OAuth client flow, exact-key decode | 2 |
| docker mcp-gateway | https://github.com/docker/mcp-gateway | MIT | Go | docker-mcp-gateway | container per server, digest pinning, collision rules; avoid secrets-as-env | 2 |
| teleport (lib/srv/mcp) | https://github.com/gravitational/teleport | AGPL-3.0 | Go | teleport | ideas only: canonical-key sanitizing, list filtering | 2 |
| mcp-context-forge | https://github.com/IBM/mcp-context-forge | Apache-2.0 | Python | mcp-context-forge | URL-template rules, virtual servers; anti-patterns (MAC from args, post-authz mutation) | 2 |
| bifrost | https://github.com/maximhq/bifrost | Apache-2.0 | Go | bifrost | same filter for discovery and execution, codemode budgets | 2 |
| iron-proxy | https://github.com/ironsh/iron-proxy | Apache-2.0 | Go | iron-proxy | canonicalization checks; JSON-differential lesson | 2 |
| gh-aw-firewall | https://github.com/github/gh-aw-firewall | MIT | TS | gh-aw-firewall | LLM tool rewriting, header-strip list, SNI guard | 2 |
| onecli | https://github.com/onecli/onecli | Apache-2.0 (ee/ excluded) | Rust/TS | onecli | approval cards, truncated-body rule, method-override refusal | 2 |
| agent-vault | https://github.com/Infisical/agent-vault | MIT | Go | agent-vault | proposal/approval UX; avoid substitution and passthrough defaults | 2 |
| cedar-spec | https://github.com/cedar-policy/cedar-spec | Apache-2.0 | Lean/Rust | cedar-spec | Lean+DRT method for `wicket-core` | 2 |
| biscuit-rust | https://github.com/eclipse-biscuit/biscuit-rust | Apache-2.0 | Rust | biscuit-rust | later: multi-host tokens | 2 |
| tsidp | https://github.com/tailscale/tsidp | BSD-3-Clause | Go | tsidp | network identity → capability grant → narrowing token exchange | 2 |
| policy_sentry | https://github.com/salesforce/policy_sentry | MIT | Python | policy-sentry | access levels, risky-action lists, STS session policies | 2 |
| fastmcp (openapi) | https://github.com/PrefectHQ/fastmcp | Apache-2.0 | Python | fastmcp | collision suffixes, dot-segment rejection; avoid header forwarding | 2 |
| arcade-mcp | https://github.com/ArcadeAI/arcade-mcp | MIT | Python | arcade-mcp | per-tool scope declarations; avoid tokens in tool processes | 2 |
| agent-scan | https://github.com/snyk/agent-scan | Apache-2.0 | Python | agent-scan | risk taxonomy as default third-party labels | 2 |
| invariant-gateway | https://github.com/invariantlabs-ai/invariant-gateway | Apache-2.0 | Python | invariant-gateway | negative conformance tests | 2 |
| invariant | https://github.com/invariantlabs-ai/invariant | Apache-2.0 | Python | invariant | flow-rule vocabulary (optional tighten-only layer) | 2 |
| LlamaFirewall | https://github.com/meta-llama/PurpleLlama | MIT code / Llama-licence models | Python | purplellama | hidden-ASCII normalizer, block-wins combiner | 2 |
| agent-threat-rules | https://github.com/Agent-Threat-Rule/agent-threat-rules | MIT | YAML/TS | agent-threat-rules | tripwire corpus with tests | 2 |
| ms mcp-gateway | https://github.com/microsoft/mcp-gateway | MIT | C# | ms-mcp-gateway | response-header allowlist, Origin check, header validator | 1 |
| lasso mcp-gateway | https://github.com/lasso-security/mcp-gateway | MIT | Python | lasso-mcp-gateway | regex tripwire seed | 1 |
| chaperone | https://github.com/cloudblue/chaperone | Apache-2.0 | Go | chaperone | scrub injected credentials from responses | 1 |
| hudsucker | https://github.com/omjadas/hudsucker | MIT OR Apache-2.0 | Rust | hudsucker | spike only; its fail-open paths become tests | 1 |
| pingora | https://github.com/cloudflare/pingora | Apache-2.0 | Rust | pingora | authority-ambiguity test cases | 1 |
| regorus | https://github.com/microsoft/regorus | MIT AND Apache-2.0 AND BSD-3 | Rust | regorus | optional CI lint | 1 |
| macaroon-rs | https://github.com/macaroon-rs/macaroon | MIT | Rust | macaroon-rs | avoid (unmaintained since 2022) | 1 |
| rs-ucan | https://github.com/ucan-wg/rs-ucan | Apache-2.0 | Rust | rs-ucan | cross-check for the Constraint vocabulary | 1 |
| openapi-mcp-generator | https://github.com/harsha-iiiv/openapi-mcp-generator | MIT | TS | openapi-mcp-generator | ban on external `$ref`; avoid spec-lowered risk | 1 |
| NeMo Guardrails | https://github.com/NVIDIA-NeMo/Guardrails | Apache-2.0 | Python | nemo-guardrails | fail-closed tool-rail idea | 1 |
| Kong AI plugins | https://github.com/Kong/kong | Apache-2.0 | Lua | kong | counterexample (`allow_override`, single-header replace) | 1 |
| cisco mcp-scanner | https://github.com/cisco-ai-defense/mcp-scanner | Apache-2.0 | Python | cisco-mcp-scanner | admission-time scan signal | 1 |
| kgateway | https://github.com/kgateway-dev/kgateway | Apache-2.0 | Go | (not cloned) | nothing (K8s control plane for agentgateway) | 1 |
| OpenFGA | https://github.com/openfga/openfga | Apache-2.0 | Go | (not cloned) | nothing (overkill) | 1 |
| flywheel_connectors | https://github.com/Dicklesworthstone/flywheel_connectors | MIT + anti-Anthropic rider | Rust | (deleted) | **excluded: licence** | 0 |
