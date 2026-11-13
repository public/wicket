# 14 — Multi-tenancy: wicket as a platform for agentic SaaS

Research date: 2026-11-08. Owner requirement (2026-11-08): wicket must also work as a **platform for
agentic SaaS products**, with good multi-tenant support and isolation, not only as a developer tool.
Refinement the same day: **tenants are not hermetically sealed**. Isolation is the default, and sharing
between tenants is an explicit, policy-governed exception (§7).

Scope:
- prior art for multi-tenant sandbox platforms and hosted agent runtimes (§2, §3);
- brokering end users' credentials (§4);
- the multi-tenant control plane (§5);
- isolation between tenants at every layer of wicket (§6);
- cross-tenant sharing (§7);
- compliance, only where it constrains the architecture (§8).

Then come the recommended types (§10), the isolation matrix (§11), the embedding API (§12), changes to
design.md section by section (§13), tests (§14) and milestones (§15). This is research only: nothing was
installed or built.

Confidence tags, as in [10]:
- **[H]** verified against a primary source page that was read: official docs, a spec, an RFC, a vendor
  security page or a primary research write-up;
- **[M]** a secondary source, a search snippet, or an inference from a primary source;
- **[L]** unverified.

"ND" means not documented on the pages read. Vendor claims about their own isolation are [H] as
*statements*, not as verified properties.

---

## 0. TL;DR

- **Most of wicket is already stricter than per-tenant**: no secrets in boxes, a per-box CA, per-task MCP
  instances, claim-then-bind pools, a server-side ledger. The new work sits *above* the zone (platform,
  plan, tenant, workspace, end user), in components wicket shares *across* zones (proxies, caches, pools,
  nodes, provider accounts, egress IPs, the control plane), and in the new people: embedders, end-user
  approvers and tenant admins.
- **Every published cross-tenant break of an AI platform** (Hugging Face, Replicate, SAP AI Core, ChaosDB,
  NVIDIA toolkit) came through a **shared component or internal service**, not through the sandbox
  kernel. wicket's per-node enforcement points are its version of that risk. So in shared cells,
  **sandbox nodes hold no tenant secrets**: credential-injecting enforcement runs on separate enforcement
  nodes as tenant-sharded workers, which also own per-tenant static egress IPs.
- **Tenancy is one more set of conjuncts**: `platform ∧ plan ∧ tenant ∧ workspace ∧ zones ∧ grant ∧ labels
  ∧ ledger`.
  - Tenant admins only narrow. symcc proves it for the user experience, and evaluation enforces it anyway.
  - Labels get **owners** (the decentralized label model), so one mechanism gives both isolation and
    controlled sharing.
- **Isolation tiers by plan**: Pooled → PooledHardened → Dedicated → Silo/BYOC. gVisor is the floor for
  every tenant workload, and `process` and `vendor_rc` are off in multi-tenant mode. Warm pools stay
  shareable because they are pristine, and are never returned after use. Tenant templates are per tenant.
  There is no KSM and no SMT-sibling sharing across tenants. Dedicated hosts are for tenants whose threat
  model includes cache side channels.
- **End-user credentials**: the vault is keyed by (tenant, subject, provider, connection), and workspaces
  are policy edges.
  - Consent is per purpose, through a wicket-owned `/connect` page that proves the consenting user is the
    initiating user (COAT, AgentCore session binding, the MCP spec's MUST).
  - Each task gets the narrowest native token, with envelope encryption under tenant KEKs and an option for
    tenants to bring their own keys.
  - The market (Anthropic and OpenAI vaults, Vercel, E2B, Pipedream, WorkOS relay) has converged on
    wicket's "placeholder in the box, inject at egress" pattern.
- **End users approve escalations inside the SaaS product**, through an embeddable passkey-backed
  approval component served from wicket's origin (CIBA-shaped). The SaaS backend can start tasks but
  never decide anything above R2.
- **Prompt caches are shared across every tenant sent through one provider workspace or project.** So
  each tenant gets its own Anthropic workspace or OpenAI project (which also gives spend caps and rate
  limits), and self-hosted models get a per-tenant `cache_salt`.
- **Cross-tenant sharing goes only through `Share` objects.** Each needs:
  - bilateral consent, with the target opting in inside its own ledger (ReferenceGrant, the KMS key policy
    plus IAM pattern);
  - reference rather than copy;
  - revocation on every `Op`, and a mandatory expiry;
  - a platform-stamped on-behalf-of tuple (the ExternalId lesson);
  - audit in both tenants' ledgers.

  Owner tags travel with shared data, so tenant B can use A's data but can't send it where A didn't allow.

---
## 1. The problem in wicket's terms

**Owner requirement (2026-11-08).** wicket must also work as a **platform for agentic SaaS products**, with
good multi-tenant support and isolation, not only as a developer tool. A SaaS company (the **platform
operator**) runs wicket. Its customers are **tenants**. Their **end users** trigger tasks, for example "an
agent that triages my company's GitHub issues". **Refinement (same day):** tenants are not hermetically
sealed. Isolation is the default, and sharing is an explicit, policy-governed exception (§7).

**Who is who.**

| Party | Example | Trusted for | Not trusted for |
|---|---|---|---|
| Platform operator | the SaaS company | running wicket, plans, the platform ceiling | tenant content (it sees metadata unless break-glass) |
| Embedder | the SaaS backend calling wicket's API | starting tasks for its tenants; saying who the user is (unless the tenant federates its IdP) | deciding R3+ escalations; choosing which tenant's credentials apply |
| Tenant | Acme Ltd, a customer of the SaaS | its own policy inside its plan's ceiling, its data classes, its approvers | anything about other tenants |
| Tenant admin | Acme's IT lead | narrowing Acme's policy, approving Acme-level grants and shares | widening past the plan |
| End user | an Acme employee | instructions at their own authority; consenting to their own accounts; approving Ops on their own resources | Acme-wide resources unless they hold a role |
| Agent / box | Claude Code triaging issues | nothing (principle 1) | everything |

**Threat model additions.** Everything in design.md §2 still holds per tenant. New adversaries:
1. **A hostile tenant**: its admin, its end users, its agents, its MCP servers, its uploaded templates and
   images, all colluding against another tenant on shared infrastructure.
2. **A hostile end user** inside a tenant, against the tenant's own resources or against other users.
3. **A buggy or compromised embedder**: mixes tenant or user ids, or tries to approve on users' behalf.
4. **Cross-tenant leakage through shared components**: proxies, caches, pools, snapshots, queues, logs,
   provider accounts, egress IPs, side channels.
5. **The platform operator's own staff**, for tenants that need assurance against them (BYOK, Silo).

Every one of the published cross-tenant breaks of AI platforms (§2.1) came from category 4 or from a
shared internal service, not from the sandbox kernel itself.

**What already fits.** Most of wicket's design is already per-zone, and per-zone is stricter than
per-tenant: no secrets in boxes, per-box CA, per-task MCP instances, claim-then-bind warm pools, the
ledger, labels. The new work is the layers *above* the zone (tenant, plan, workspace, end user), the
components wicket shares *across* zones (per-node proxies, caches, pools, nodes, provider accounts, egress
IPs, the control plane), and the people (embedders, end-user approvals, tenant admins).

---

## 2. Prior art: multi-tenant sandbox and compute platforms

*Tags: **[H]** read on a primary page; **[M]** secondary source, snippet or inference; **[L]** unverified.
"ND" = not documented on the pages read.*

| Platform | Tenancy unit | Isolation boundary | Noisy-neighbour control | Residency | Egress identity | Secrets / credentials |
|---|---|---|---|---|---|---|
| **E2B** | team → project (rate limits per project, shared across keys) [H] | Firecracker microVM per sandbox; "never share a kernel, filesystem or memory" with another customer [H] | concurrency (Hobby 20, Pro 100–1,100), create rate 1–5/s, runtime 1–24 h, size caps [H] | GCP us-west1 default; AWS/GCP others via support [H] | **rotating ephemeral IPs, no static IPs on any plan**; run your own proxy [H] | header-injection proxy (beta): per-host transforms from `Secret` refs or workload-identity tokens, sandbox trusts E2B CA [H] |
| **Daytona** | organization (every sandbox, snapshot, volume in exactly one) [H] | container (namespaces + limits), VM, or GPU container [H] | org-wide resource pools by spend tier; hard reservations per sandbox [H] | shared US/EU, dedicated and custom (BYOC Helm chart) regions [M/H] | static IPs ND; domain allowlist terminates TLS with Daytona CA [H] | ND |
| **Modal** | workspace → environments (environments are *not* a hard boundary: explicit cross-env lookup) [H] | gVisor or a VM with its own kernel [H] | ND beyond per-function limits | `region=` pinning, but inputs route via us-east and >2 MiB payloads stored there [H] | **Proxies: static IPs per workspace, "not shared between workspaces"**, WireGuard (vprox) [H] | env vars in the container; "keep Secrets out of untrusted workloads" [H] |
| **Fly.io Machines / Sprites** | organization; **6PN private network per org, packets never forwarded between 6PNs**; custom private networks "to isolate tenants or users" [H] | Firecracker [M] | shared-CPU cgroup quota slices with burst credits [M] | per region | app-scoped static egress IPs per region ($3.60/mo) [H] | Sprites: network policy set by external API; "even root cannot modify its own network policy" [H] |
| **Cloudflare Workers for Platforms / Dynamic Workers** | dispatch namespace holds all customers' Workers; per-customer limits set by the platform's dispatch Worker [H] | V8 isolates in a second-layer sandbox; **cordons** by trust level ("Free will not share a process with Enterprise"); Spectre: frozen timers, suspicious Workers moved to own process, periodic reshuffling, V8 patch gap <24 h [H] | per-customer CPU/subrequest limits in the dispatch Worker [H] | — | outbound Worker intercepts every `fetch()`; Dynamic Workers `globalOutbound` injects credentials so the code "never knows the secret" [H] | outbound Worker injects auth per customer [H]; untrusted mode: no shared cache [H] |
| **Cloudflare Sandbox / Containers** | per sandbox; "the sandbox is the smallest unit of trust" — one per user or job, name derived from authenticated identity [H] | VM per sandbox [H] | per-sandbox quotas [H] | — | internet off by default [H] | credentials added by a Worker outbound handler; **snapshots persist tokens** (e.g. `.git/config`) [H] |
| **Vercel Sandbox** | team → project [H] | Firecracker, own kernel [H] | strict CPU/mem/disk limits [H] | region per sandbox, failover [H] | static IPs via Secure Compute [H]; firewall is SNI-only (fronting documented), `subnets.allow` leaves DNS open [H] | **`transform` rules inject headers outside the VM; per-sandbox CA**; `forwardURL` adds an audience-bound OIDC token with team/project/sandbox claims [H] |
| **Browserbase** | project [H] | dedicated VM per browser, killed after each session; no GPU (shared GPU memory risk) [H] | ND | US W/E, EU, SG "for data sovereignty" [H] | residential proxies or BYO proxy [M] | **Contexts** (cookies/auth) uniquely encrypted at rest, per project — the end-user credential store [H] |
| **Replit** | repl / project | microVM: "a container inside it is not a separate equivalent boundary" [H] | ND | "no guarantees about data residency" [H] | ND | env vars, shareable with collaborators [M] |
| **Lovable / Bolt** | Lovable: each generation session in a Modal Sandbox (20k concurrent) [H, vendor]; Bolt: WebContainers in the end user's browser [M] | inherited | inherited | — | — | generated Supabase backends: **CVE-2025-48757**, missing RLS exposed generated apps' data [M] |
| **Devin** | customer; Enterprise: "each session on its own isolated machine"; dedicated single-tenant VPC deployment over PrivateLink [H] | VM per session [H] | ND | dedicated deployment | — | decrypted at session start into env vars [M] |
| **Cursor cloud agents** | team; VMs in a separate AWS account from Cursor prod [H] | Firecracker per agent [H] | ND | ND | egress allowlist lockable org-wide [H] | KMS-encrypted, injected as env vars, "never reach the model"; repo access "inherited, never widened" [H]; self-hosted workers have no per-agent isolation [H] |

### 2.1 Cross-tenant incidents on AI platforms (all [H] unless marked)

| Incident | Root cause | Lesson for wicket |
|---|---|---|
| **Hugging Face** (Wiz, 2024) | malicious pickle → RCE in an inference pod on EKS → node IAM role via IMDS → node Kubernetes token → cluster secrets; build-time `RUN` weaker than runtime; one registry writable by all customers | builds are tenant workloads too; metadata unreachable; registries per tenant |
| **Replicate** (Wiz, 2024) | tenant container root with `CAP_NET_RAW/ADMIN` in a netns shared with a neighbour's plaintext Redis connection → sniff and inject into a **multi-tenant queue**, rewrite other tenants' webhooks | never share a netns; authenticate and encrypt every internal hop; partition queues by tenant |
| **SAPwned** (Wiz, 2024) | admission allowed `runAsUser: 1337` (Istio's exempt UID) → sidecar egress bypass → open internal network: Loki config leaked AWS keys, EFS per customer unauthenticated, Helm Tiller → cluster admin | in-pod egress enforcement is bypassable; enforcement outside the tenant boundary; internal services are hostile ground |
| **ChaosDB** (Wiz, 2021) | default-on Jupyter feature in Cosmos DB → other customers' primary keys | default-on features widen surface; long-lived keys amplify |
| **NVIDIA Container Toolkit** CVE-2024-0132 / CVE-2025-23359 [M] and **NVIDIAScape** CVE-2025-23266 [H] | privileged host OCI hook consumed tenant-controlled image env (`LD_PRELOAD`) → host root on shared GPU clusters | no tenant-controlled input to privileged host hooks; VMs, not containers, as the boundary |
| **Lovable CVE-2025-48757** [M] | platform-generated authorization default failed | authorization defaults are part of the platform's TCB |
| **Vercel Sandbox / AIR** (2026) [M] | allowlisted server fetches attacker URLs on the sandbox's behalf | an allowlist is not an exfiltration barrier (wicket already applies no-write-down to reads, §9.0) |

### 2.2 Patterns

1. **VM per sandbox is the norm** for agent compute (E2B, Vercel, Cursor, Fly, Cloudflare Containers,
   Browserbase, Replit). Modal and GKE Sandbox run gVisor multi-tenant. Cloudflare is the only isolate-based
   option, and compensates with cordons, Spectre work and fast patching. [H]
2. **Credential injection outside the box is converging** (E2B transforms, Vercel `transform`, Cloudflare
   outbound Workers, Anthropic and OpenAI vault placeholders, §3). Modal, Replit, Cursor and Devin still use
   env vars. wicket's design is ahead here; Vercel's audience-bound OIDC token carrying team/project/sandbox
   claims is a pattern worth copying for tenant identity on forwarded requests.
3. **Egress allowlists are mostly SNI-only** and vendors document the holes (fronting, DNS, literal IPs,
   server-side fetch). TLS termination with Host/path enforcement, as wicket does, is the only fix.
4. **Static egress IPs per tenant are rare and coarse** (Modal per workspace, Fly per app per region, Vercel
   via Secure Compute, E2B none). Nobody offers them per *end user*. A platform has to run its own egress
   pools keyed by tenant.
5. **Tenancy is shallow**: org/workspace, then project/environment. **No platform makes its customers' end
   users first-class**, so the SaaS operator enforces sub-tenant fairness itself. Cloudflare's dispatch
   Worker is the exception.
6. **Dedicated hosts and side channels are almost never documented.** Single tenancy is sold as BYOC,
   custom regions or dedicated VPCs, and even then the vendor's control plane usually stays in the loop.
7. **Snapshots and templates are a sharing vector**: tokens persist in them (Cloudflare), images are
   shareable across teams (Vercel), snapshots can't be deleted on demand (Cursor), they are excluded from
   HIPAA scope (Modal).

---

## 3. Prior art: hosted agent runtimes

### 3.1 AWS Bedrock AgentCore — the closest analogue

**Runtime.** Each session gets its own microVM; at the end "the entire microVM is terminated and memory is
sanitized" [H]. microVMs are restored from a **pre-session snapshot**, so clients created at module scope
carry pre-session credentials [H]. Idle 15 min / max 8 h by default [H]. Quotas are per account per
region: 2,500–5,000 active sessions, 25 new sessions/s, 2 vCPU / 8 GB fixed per session [H]. Cross-account
invokes count against the *runtime owner's* quota [H].

The load-bearing admission: **"AgentCore does not enforce session-to-user mappings – your client backend
should maintain the relationship"** [H]. Session context keys on the execution role "do not prove that a
request was made from inside the corresponding microVM" [H]. User delegation via
`InvokeAgentRuntimeForUser` + a user-id header is something AWS tells you to restrict, deriving the user
from the authenticated principal and preferring the JWT path [H]. Any code in the microVM can read the
execution role's credentials from MMDS [H]. AWS recommends fronting the runtime with a Gateway and
restricting it to gateway-only invocation, "otherwise callers can bypass policy" [H].

**Identity.** Workload identities per agent. Two ways to name a user:
`GetWorkloadAccessTokenForJWT` (validates the IdP token, keys the user by `iss`+`sub`) and
`GetWorkloadAccessTokenForUserId` (an opaque, unverified string; "development or trusted upstream" only) [H].
The **token vault** scopes tokens "to the specific user-agent pair" [H], under AWS-owned or customer KMS
keys (`SetTokenVaultCMK`, preview [M]). **3LO session binding** is the best documented defence against
OAuth CSRF in a multi-user agent platform [H]:
1. `GetResourceOauth2Token` returns an authorization URL and a session URI (10 min).
2. After consent, AgentCore redirects to a registered return URL.
3. The app checks the browser's logged-in user is the user who started the request.
4. The app calls `CompleteResourceTokenAuth(session_uri, user)`, with the user taken from the browser
   session, "NOT … any remote session cache".

A hosted consent portal keeps the flow server-side so "the browser never holds a token" [H].

**Gateway and Policy.** Gateway turns OpenAPI/Smithy/Lambda into MCP tools with inbound and outbound auth
[H]. **AgentCore Policy** evaluates Cedar policies "at the boundary outside of agent's code" on every tool
call, with automated-reasoning checks for over-permissive policies, plus a temporal language for
session-scoped conditions ("approval granted before transfer", running budgets) [H, single source for the
temporal language's name and details]. CMK only for Gateway and Memory; Runtime uses AWS-owned keys [H].

**Multi-tenancy guidance.** Silo / pool / bridge; a dedicated runtime per tenant gives the "strongest
noisy-neighbor protection"; tenant context in JWT claims and headers; RFC 8693 token exchange [H]. Pool
example: `actorId = {tier}-{tenant}-{user}`, tool Lambdas never see the user JWT, a token-vending role
assumed with session tags and `dynamodb:LeadingKeys` ABAC, per-tier throttling via usage plans [H].
Memory namespaces with a **trailing slash "prevents prefix collisions in multi-tenant applications"** [H].

### 3.2 Google Vertex AI Agent Engine (now marketed as part of Gemini Enterprise Agent Platform)

- VPC-SC, CMEK and residency at rest for Runtime, Sessions, Memory Bank, Code Execution; CMEK only on
  single-region endpoints, immutable after creation [H].
- **Agent Identity**: a SPIFFE ID per agent (`spiffe://agents.global.org-<ORG>.system.id.goog/…`), 24 h
  X.509 certs, mTLS with certificate-bound tokens, and a managed Context-Aware Access policy enforcing mTLS
  and DPoP so tokens can't be replayed outside the runtime. Redeploying gives a new principal and leaves
  stale bindings [H].
- 3LO via an auth manager with a Google-managed credential vault and a consent-nonce validation endpoint
  (the same "consenting user = initiating user" check) [H].
- Agent Gateway: default-deny egress by exact hostname [H]. Sessions and Memory Bank scope by a
  caller-set user id, restrictable with IAM Conditions on `sessionUserId` [M/H].

### 3.3 Anthropic Claude Managed Agents and the API

- Agent loop, history and vault secrets live outside the sandbox; one container per cloud session; a
  memory store attached to several sessions *is* shared between them [H]. **Not ZDR- or HIPAA-eligible**,
  including self-hosted sandboxes [H].
- **Vaults**: "the collection of credentials associated with an end user", passed per session as
  `vault_ids`; **workspace-scoped, so any key with workspace access can reference any vault** [H].
  `environment_variable` credentials put an **opaque placeholder in the sandbox, substituted at egress**,
  scoped by `allowed_hosts` and an `injection_location` (header and/or body) [H]. Caveats Anthropic
  documents: SigV4 breaks; substitution is outbound only, so a token returned by an exchange arrives in the
  sandbox in clear [H]. End-user OAuth consent is left to the developer [H].
- **Workspaces**: 100 per org by default, workspace-scoped keys, workspace rate and spend limits below the
  org's, created through the Admin API [H]. Residency: per-request `inference_geo` (`us`/`global`),
  workspace defaults; storage geo US only [H].
- **Prompt caching: "Caches are isolated between organizations… also isolated by workspace within an
  organization on the Claude API, Claude Platform on AWS, and Microsoft Foundry; Claude Models on Google
  Cloud and Bedrock use organization-level isolation only"** [H]. So a wicket platform sending every
  tenant's traffic through one workspace shares one cache across tenants.

### 3.4 OpenAI

- Agent Builder is being shut down (2026-11-30); ChatKit (embeddable chat UI) stays [H].
- Agents API (managed Codex harness): environments `openai_hosted` or `self_hosted`, **US-only, not ZDR
  eligible**, vault secrets as placeholders with "a proxy supplies the real secret only for approved hosts";
  advice is one project per application and separate environments for users who must not share data [H].
- Projects carry hard spend limits (`429 project_spend_limit_exceeded`, "not instant") and per-project
  residency (US, EU, UAE processing; others storage only) [H].
- **Prompt caching: not shared across organizations**; `prompt_cache_key` "helps prevent cache-hit probing
  across users" but is **not documented as an isolation boundary** [H].

### 3.5 Microsoft Foundry Agent Service

Standard setup puts threads and files in **customer-owned** Cosmos DB, Storage, AI Search and Key Vault
with project-level isolation [H]. Hosted agents run in per-session VM-isolated sandboxes; each agent gets
an **Entra agent identity**; with a user token it uses **OAuth On-Behalf-Of**, otherwise its own identity;
a state store can partition per end user [H].

### 3.6 The prompt-cache side channel

- **Gu et al., "Auditing Prompt Caching in Language Model APIs"** (ICML 2025): 7 of 17 providers shared
  caches globally across users; Anthropic and OpenAI chat showed only documented per-org sharing; at least
  five providers changed behaviour after disclosure [H].
- **InputSnatch** (2024): prefill-timing attacks on vLLM/SGLang prefix caches, 87% accuracy at recovering
  cache-hit prefix length [M].
- **vLLM `cache_salt`**: mixed into the first block's hash so only requests with the same salt share KV
  blocks, explicitly to prevent timing attacks [H]. A later vLLM CVE dropped the salt on `/v1/responses`
  tool continuations, turning cached-token counts into a cross-tenant membership oracle [M, single source]:
  the salt must be carried on every path, and cached-token counts are themselves a leak.

### 3.7 What hosted runtimes teach

1. **Nobody else owns the (tenant, user, session) binding**; wicket must. Session ids are minted by wicket,
   never accepted from clients, and the tenant and user are stamped on every hop from the transport.
2. **Key credentials to (agent identity, verified user)**, never to a bare user-id string from the caller.
3. **Consent must prove the consenting user is the initiating user** (AgentCore session binding, Google's
   consent nonce).
4. **Placeholders + egress substitution is now the industry pattern.** wicket's "declared header slot
   only" is stricter than Anthropic's header-*or-body* injection, and stays: body injection reflects.
5. **Policy at a boundary the agent can't bypass**, with temporal/session conditions (AgentCore Policy) —
   which wicket's ledger already expresses.
6. **Provider-side caches and quotas are per account or workspace**, so tenant → provider workspace /
   project mapping is required for cache isolation, spend caps and fairness.

---
## 4. End-user credential brokering

### 4.1 Vendors

| Vendor | Key a credential is stored under | Whose OAuth client | Credentials reach… | Encryption | Notes |
|---|---|---|---|---|---|
| **Pipedream Connect** | `external_user_id` within a project environment [H] | Pipedream's by default; custom client per `oauth_app_id`, secrets write-only [H] | **API proxy** injects into "the appropriate header or URL param", host must be in the app's `allowed_domains`; rejects `Cookie`/`Host`/`Origin`/`Sec-*`/`Proxy-*`; only `x-pd-proxy-*` headers forwarded [H]. Raw tokens only for accounts on your own client; "Never return user credentials to the client" [H] | ND | connect tokens: user+env scoped, 4 h, single use [H] |
| **Arcade** | `user_id` per project (exact key ND) [H] | Arcade's default apps fall back to Arcade's own verifier; production multi-user needs your own app **plus a custom user verifier** (`confirm_user {flow_id, user_id}` → 400 `user_mismatch`) [H] | **the Engine sends the token to the MCP server ("worker") with each call**; the LLM never sees it [H] | encrypted in Postgres; root keys in config; KMS when self-hosted [H/M] | JIT authorization per tool scope [H]. **COAT** (Black Hat 2025): attacker starts a connection flow, victim completes it; fix = bind the flow to a verified user session; PKCE does not help [H] |
| **Composio** | developer-chosen `userID` + auth config; several connected accounts per toolkit [H] | Composio-managed by default; custom auth config = your app, needed for your name on the consent screen [H] | Proxy Execute injects server-side [H] | ND | revoke upstream is "best effort" [H]; verify the account's user binding server-side, not from callback params [H] |
| **Nango** | connection + `tags` (`end_user_id`, `organization_id`) [H] | per-integration client, overridable per connect session; end users can bring their own app [H] | proxy, or tokens to your backend | **AES-256-GCM, DEK wrapped by AWS KMS** (cloud) [H]; self-hosted single `NANGO_ENCRYPTION_KEY`, **no rotation** [M] | refresh before expiry and ≥ every 24 h; gives up after days, webhook on failure [H] |
| **Auth0 for AI Agents** | connected account linked to the Auth0 user; org members each link their own [H] | per connection | **Token Vault** exchanges an Auth0 token for a provider token (RFC 8693-style custom grant) [H/M] | ND | **async authorization = CIBA with RAR `authorization_details`**, poll mode, Guardian push [H]; FGA filters RAG results per user [H] |
| **WorkOS Pipes** | `user_id` + `organization_id` (null = user-scoped) + provider, exact-match lookup [H] | per provider | **Relay mode: a forward proxy where "the token never enters your environment"**, 402 + `authorization_url` when unconnected; strips `Authorization`, cookies, forwarding headers; no redirects [H] | per-object DEK under an HSM KEK; **BYOK on AWS/GCP/Azure** [H] | deleting a connection **does not revoke** the provider grant [H] |
| **AgentCore Identity** | (workload identity, user) — "scoped to the specific user-agent pair" [H] | per credential provider | to agent code via SDK | AWS-owned or CMK (preview) [H/M] | 3LO session binding (§3.1) |
| **Anthropic vaults** | vault per end user, **workspace-scoped** [H] | developer's | placeholder in box, substituted at egress for `allowed_hosts`, header or body [H] | ND | refresh by Anthropic if given a refresh block [H] |
| **Okta XAA / ID-JAG** | IdP-issued identity assertion per (user, requesting app, resource app) | none per connection: the enterprise IdP mints the ID-JAG by policy, no per-connection consent prompt [H] | resource AS issues an audience-bound token | — | the enterprise answer: admin-managed instead of user-consented |

### 4.2 MCP authorization (spec 2025-11-25 and 2026-07-28) [H]

- The MCP server is an OAuth 2.1 **resource server**: RFC 9728 metadata, RFC 8707 `resource` in every
  authorization and token request, tokens audience-validated, **"MUST NOT accept or transit any other
  tokens"**, never pass the client's token upstream.
- **Proxies with a static client id** must obtain per-user consent for each dynamically registered client:
  a per-user registry of approved `client_id`s, a consent screen showing client, scopes and
  `redirect_uri`, `__Host-` signed consent cookies, exact redirect matching, single-use short-TTL `state`
  set only *after* consent.
- **Sessions must not be used for authentication**; queued state is bound as `<user_id>:<session_id>`.
  2026-07-28 removes protocol sessions altogether (stateless MCP, MRTR replaces server-initiated
  requests), requires RFC 9207 `iss` validation, keys client credentials by issuer (SEP-2352), deprecates
  DCR in favour of **Client ID Metadata Documents**.
- **URL-mode elicitation** is the sanctioned path for third-party OAuth: third-party credentials "MUST NOT
  transit through the MCP client"; servers "MUST bind elicitation requests to the client and user identity"
  and verify that the user opening the URL is the user who triggered it; URLs must not be pre-authenticated
  or carry PII.
- **Enterprise-Managed Authorization extension** (stable in 2026-07-28): RFC 8693 exchange at the IdP for an
  ID-JAG (`audience` = the MCP AS), then an RFC 7523 jwt-bearer grant; the token is audience-restricted to
  `resource`. ID-JAG draft -06 adds `tenant` / `aud_tenant` claims, and a resource AS **must reject an
  ID-JAG from a multi-tenant issuer unless `tenant` is present and trusted** [H].

### 4.3 Standards that matter (all [H] unless marked)

- **RFC 8693 token exchange**: `subject_token` (on whose behalf) vs `actor_token` (who acts); delegation
  keeps the actor's identity; nested `act` records the chain, but decisions use only the top level plus
  the current actor; `may_act` says who may act.
- **Entra OBO**: user principals only, delegated scopes, consent gathered up front.
- **RFC 9396 RAR**: typed `authorization_details`, usable in CIBA, the response says what was granted,
  refresh can narrow. This is already wicket's typed-request shape.
- **CIBA Core**: poll/ping/push, one hint, `binding_message` on both devices, `auth_req_id` ≥ 128 bits.
- **DPoP (RFC 9449)**: sender-constrains tokens; no help against code that holds the key.
- **Transaction Tokens** (draft -11): short-lived, `txn` + `sub` + `tctx`/`rctx`, may not widen when
  replaced; not sender-constrained. A good shape for wicket's *internal* hop context (tenant, user, task).
- **AI-agent drafts**: the on-behalf-of-user draft expired; **AAuth** (individual draft, Sept 2026: signed
  requests, agent ids, a Person Server for consent) and Agentic JWT are individual submissions. Nothing to
  build on yet.
- **SPIFFE**: X.509-SVIDs preferred over JWT-SVIDs (replay).
- **GitHub**: installation tokens last 1 h and can be narrowed to ≤ 500 repos and a permission subset;
  user-to-server tokens are user ∩ app, 8 h, 6-month refresh, and **`repository_id` at code exchange
  narrows a user token to one repository**.
- **Google domain-wide delegation** lets a service account impersonate any user, super-admins included;
  Google itself advises against it [M]. wicket should refuse DWD credentials in pooled tiers.

### 4.4 Key management (all [H] unless marked)

- **AWS KMS**: 100k keys per region; the symmetric crypto quota (10k–100k rps) is **shared across all keys
  in an account and region**; each external key store gets 1,800 rps. **Encryption context is AAD**,
  enforceable with `kms:EncryptionContext:<k>` conditions and logged in CloudTrail. AWS's own per-tenant
  pattern: a key per tenant (~$1/month) or a shared key with tenant encryption context at scale.
- **XKS / HYOK**: disconnecting makes ciphertext undecryptable; permanently revoking access "effectively
  crypto-shredded" it; the customer owns availability (RTT ≤ 35 ms).
- **KMS grants and deletion are eventually consistent**: revoke usually seconds, "typically under 5
  minutes"; key deletion "might not immediately affect data keys" already unwrapped and cached.
- **Vault/OpenBao transit**: derived keys from a context, rewrap without plaintext, BYOK import. OpenBao
  namespaces are open source since 2.3 and had **two cross-tenant namespace CVEs in 2026** [M]. That is a
  reason not to make a namespace feature of a third-party vault the tenant boundary.

### 4.5 Recommendation: how wicket's vault and routes become tenant- and user-scoped

1. **Records.** `CredentialKey = (tenant, subject, provider, connection)` with `subject ∈ {Tenant,
   EndUser(U), Service}`. **Workspaces are a policy edge, not part of the key**: a `WorkspaceGrant
   (workspace, connection, tools, hosts, scopes)` row says which workspaces may use a connection. Each
   `Connection` stores the OAuth client it was issued to, the scopes actually granted, its status, and the
   **provider subject** (GitHub user id, Google `sub`) so a wrong-account connection is detected. Refresh
   tokens are only ever used with their issuing client; changing the client forces re-consent.
2. **Whose OAuth client.** Three levels: `WicketDev` (development only), `Platform` (the SaaS operator's
   app: the production default, its brand on the consent screen) and `TenantByo` (the tenant's own app, for
   internal Google apps, single-tenant Entra, or tenants who want their own name on consent). For GitHub:
   the platform's GitHub App, one installation per tenant org; **installation tokens for actions as the
   app, user-to-server tokens only when the action must be attributed to the user.**
3. **Consent.** A `ConnectSession` bound to (tenant, user, client, scopes, purposes, return URL), single
   use, ≤ 30 min. An agent that needs a connection gets a pending result whose remedy is a **wicket-owned
   `/connect` URL** (MCP URL-mode elicitation where the client supports it), never the provider URL. The
   `/connect` page re-authenticates the user and checks **consenting user = initiating user** (COAT,
   AgentCore session binding, MCP MUST), shows wicket's own consent screen (client, scopes, purposes,
   redirect) before redirecting, sets `state` only after consent, uses PKCE and validates `iss`. Consent is
   **per purpose** (task classes), so a connection granted for "triage issues" does not silently serve
   "push code". Re-consent on `invalid_grant`, long refresh failure, `insufficient_scope`, client change or
   a tenant policy change. Never ask for credentials in chat or form elicitation.
4. **At task time.** The task carries `(tenant, workspace, on_behalf_of=U, purpose)`. The vault checks the
   `WorkspaceGrant` and the consent's purposes, then mints the **narrowest** credential the provider
   supports: an installation token narrowed by `repository_ids` + `permissions`, a user token narrowed by
   `repository_id`, a cloud STS session policy, or a plain access token from the refresh token where the
   provider can't narrow (then the adapter is the only narrowing — shown as such in `explain`). Anything
   beyond goes to typed escalation (RAR-shaped, CIBA-delivered, passkey-decided).
5. **Delivery.** A `CredentialLease` goes only to the enforcement process that serves that task (§6.2),
   audience-bound, in memory, ≤ min(task end, token expiry, 1 h). The egress proxy resolves the box's
   transport identity → task → `(tenant, connection)` → lease, injects into the one declared slot, strips
   every client auth/cookie/`Sec-*`/`Proxy-*` header (Pipedream and WorkOS relay do the same), follows no
   redirects, scrubs echoes. Leases are never shared across tasks. Internal hops carry a
   Transaction-Token-shaped context `{txn: task, sub: U, tctx: {tenant, workspace, connection}}`, signed by
   wicketd; the provider token never leaves the vault/proxy plane.
6. **Encryption hierarchy.** Record DEK (AES-256-GCM, AAD = `{platform, tenant, subject, provider,
   connection, key_version}`) → tenant KEK → KMS: a shared platform key with tenant encryption context
   (Pooled), a key per tenant (Dedicated), a tenant-owned key granted cross-account (BYOK), or an external
   key store (HYOK, budget 1,800 rps and its outages). Cache unwrapped tenant KEKs briefly (minutes) to stay
   inside the account-wide KMS quota, and bound that cache because it is also the crypto-shred latency.
   Rotation and rewrap from day one.
7. **Revocation and erasure.** Disconnect = call the provider's revocation endpoint (best effort; Composio
   and WorkOS both warn deletion does not revoke), delete, tombstone, invalidate leases. GitHub uninstall
   webhook → revoke all the tenant's connections. User erasure → destroy U's DEKs. Tenant offboarding →
   delete the tenant KEK, or the tenant revokes BYOK/XKS access.
8. **Remote MCP servers** (design §9.2 kind 3): tokens keyed by (tenant, end user, upstream issuer),
   obtained through the same `/connect` flow; wicket is the MCP *client* toward them and follows the
   2026-07-28 issuer-keying and `iss` rules. Third-party servers wicket hosts never receive end-user tokens
   (they get placeholders and egress through the proxy, as today) — the opposite of Arcade's worker model.

---

## 5. Multi-tenant control plane

### 5.1 Hierarchy and ceilings

`Platform ⊇ Plan ⊇ Tenant ⊇ Workspace (nested) ⊇ Task ⊇ Zone ⊇ child Zone`, with `EndUser` as a principal
inside a tenant who belongs to workspaces. The existing **Org** concept becomes the **Tenant** (its
ceiling, data classes, approvers, money envelope); a single-tenant installation is tenant zero.
Enforcement evaluates the whole chain on every `Op`:

  `decide(op) = platform ∧ plan ∧ tenant ∧ workspace ∧ every ancestor zone ∧ live grant ∧ labels ∧ ledger`

This is the same rule as design §4.1, with three more conjuncts on top. Because every layer is AND-ed at
evaluation, **a tenant admin cannot widen anything even if the subset proof is wrong** (Fly macaroon
style, already a design decision).

### 5.2 Delegated administration (admins only narrow within the plan)

- Tenant and workspace admins write policy in Cedar, inside the tenant's namespace. The validator rejects
  references to entities of other tenants; wicket injects a `resource in Tenant::"T"` guard.
- **Narrowing is proved for UX**: `cedar-policy-symcc` `check_implies(tenant_set ∧ base, ceiling)` and
  `check_never_errors` at write time, returning a counter-example when the admin's policy would permit
  something outside the plan [H for the API, M for this use]. Cedar templates only have principal/resource
  slots, so they suit role grants, not tenant-authored conditions [H].
- Platform ceilings are `forbid`s plus the plan's capability set; forbid overrides permit [M].
- Per-tenant policy stores (AVP's recommendation when tenants have many tenant-specific policies; offboarding
  is "delete the store") [H]: wicket compiles one policy set per tenant and never evaluates one tenant's
  request against another's set.
- Plan downgrades narrow immediately (live grants outside the new ceiling are revoked at the next `Op`);
  upgrades are a platform decision.

### 5.3 Authorization for the control plane itself

| Option | Fit |
|---|---|
| **Cedar** (recommended, v1) | Already wicket's policy language and analyser. Entities: `Platform`, `Plan`, `Tenant`, `Workspace`, `EndUser`, `Role`, `Share`, `ApiKey`. Small, analysable, one engine for data plane and control plane. AWS's AgentCore Policy shows the same choice for tool calls [H]. |
| OpenFGA | Official guidance: one store for all tenants with an `organization` parent; cross-tenant sharing is "individually granted users from other organizations — same model, no special case" [H]. Good for large relationship graphs (document-level sharing); a second engine to operate and keep consistent. |
| SpiceDB | Caveats (CEL), CONDITIONAL results [H]; hard isolation means an instance per tenant; prefixes are only a naming convention in open source [M]. |

Recommendation: Cedar entities loaded from wicketd's own store, a per-tenant policy set, and the
relationship data (memberships, roles, shares) in tables keyed by tenant. Revisit OpenFGA only if
cross-tenant sharing of individual objects becomes a large graph. **Return 404 for other tenants' ids**
(no existence oracle); AVP's guide prefers 403, but for hostile tenants an existence oracle is a leak.

### 5.4 Embedding, identity and who the user is

- The SaaS backend is an `Embedder`. It can start tasks, create connect and approval sessions and read
  status. **It can never decide an escalation above `EmbedderAttested`**, and never chooses credentials:
  credentials follow from `(tenant, on_behalf_of, purpose)`.
- End-user identity: an embedder-signed short-lived assertion, or the **tenant's own IdP** (OIDC/SAML, or an
  ID-JAG with a trusted `tenant` claim). The first makes the SaaS part of each tenant's TCB for "who is
  U"; the second removes it. Plans decide which is allowed for which risk.
- **wicket mints session and task ids** and never accepts them from the caller (the AgentCore gap).
- The full API sketch is in §12.

### 5.5 Quotas, fairness, metering and cost attribution

- **Quotas** at every level (`QuotaSet`, §10): platform → plan → tenant → workspace → end user. Admission
  control rejects cheaply ("load shedding is cheaply rejecting work") and reports headroom to clients
  [H, AWS Builders' Library]. Stacked token buckets per dimension: API calls, task starts, `Op`s,
  escalations, LLM tokens, egress bytes, concurrent sandboxes and MCP instances.
- **Fairness**: weighted fair queueing for warm-pool claims and node capacity; **shuffle sharding** of
  tenants across enforcement workers and node groups so a poisoned or noisy tenant affects ~1/C(n,k) of
  others (8 workers, shards of 2 → 1/28) [H].
- **Upstream quotas are per provider account**, so they are shared by every tenant on a platform key
  (AgentCore 25 new sessions/s per account; Anthropic Managed Agents 300 creates/min per org) [H]. Big
  tenants get their own provider workspace/project or BYO key.
- **Metering**: every enforcement point emits `UsageRecord`s with a deterministic id (`source + id`, the
  CloudEvents dedup rule) [H]. Tokens are counted from the **provider response at the LLM proxy**, never
  from agent claims; egress bytes at the egress proxy; CPU, memory and wall time from cgroups on the node;
  storage from the store. Records go to the ledger first; Stripe/OpenMeter/Lago are downstream (Stripe
  meters: dedup `identifier`, 35-day backdating, cardinality limits) [H].
- **Money** uses the existing worst-case reservation rule per tenant: an LLM call reserves
  `max_tokens × price`, a sandbox lease reserves `lease × rate`; spend caps are hard stops in the ledger.
  Provider-side caps are a second line (OpenAI project hard limits are "not instant"; Anthropic workspace
  spend limits) [H].
- **Cost attribution**: LLM cost per tenant is exact when each tenant has its own provider workspace or
  project; compute is attributed from usage records and reconciled daily against provider invoices
  (design §8.5); shared overhead (enforcement nodes, idle warm pools) is allocated by a declared rule.

### 5.6 End users approve escalations inside the SaaS product

- **Who decides** follows the credential: an `Op` that uses U's credential goes to U (or U's delegate); an
  `Op` on tenant resources (an installation token on the company org) goes to the tenant's approver role;
  some go to both (`ApproverRule`).
- **How strongly** follows the risk: `ApprovalAssurance` per risk class with a plan floor, defaulting to
  `WicketPasskey` for R3+, `TwoPerson` for R4, money and cross-tenant shares, and `EmbedderAttested` at most
  for R2 where the tenant opts in.
- **Where**: an embeddable approval component served from wicket's origin (or a tenant CNAME using WebAuthn
  related origins), CIBA through the tenant's IdP, or a hosted page linked from the SaaS's own
  notification. The approval card is the design §13.1.3 card; its security blocks can't be themed. Flow in
  §12.
- Fatigue metrics (design §11) become per (tenant, approver); a tenant whose end users approve 99 % of
  requests gets a warning in the tenant admin view, not a silent auto rule.

### 5.7 Audit export, retention and deletion

- **Per-tenant hash chains** (and per joint zone, §7), with the global chain holding only partition heads,
  anchored periodically to an external WORM store. **Chain over ciphertext**, so destroying a key never
  breaks verification [M]. Per-tenant HMAC salts for argument commitments (design §13.2 already uses
  salted commitments).
- **Export** per tenant in **OCSF** (API Activity 6003 plus the AI Operation profile, which has `ai_agent`,
  `ai_model`, `delegation` and MCP `message_context`) [H], to the tenant's S3/GCS (assumed role) or a signed
  webhook, plus a JSONL format that carries wicket's typed requests and grant timeline.
- **Retention** per tenant within plan bounds: floor ≥ 6 months where the tenant is an EU AI Act high-risk
  deployer (Art. 26(6)), long retention for HIPAA documentation (6 years, §164.316) [H]; legal hold; erasure
  exceptions recorded under GDPR Art. 17(3)(b)/(e) [H].
- **Erasure** = crypto-shredding: per-end-user content subkeys, per-tenant KEKs, per-tenant audit salts.
  Pseudonymised data stays personal data while the key exists (EDPB 01/2025) [M], so erasure destroys the
  HMAC salt too and records an erasure event. Treat the result as "beyond use", with legal sign-off, not as
  guaranteed anonymisation. Backups: tombstones re-applied on restore, and backup retention stated.
- **Platform staff access** to tenant content is break-glass only: two-person, announced to the tenant,
  logged in both the platform chain and the tenant's.

### 5.8 Residency and cells

- A **cell** = a regional deployment of the whole control plane, enforcement tier and node pools, with its
  own stores and keys. A tiny **global directory** maps tenant → cell and holds nothing else. Cells give
  residency, blast-radius containment and a natural Silo tier (a dedicated cell, or a BYOC cell in the
  tenant's own cloud account, as E2B BYOC and Devin dedicated deployments do [H]).
- Residency derives everything: placement (`Residency(j)` already exists), stores, snapshots, egress IPs and
  **model endpoints**. Model residency is uneven (Anthropic storage geo is US only, `inference_geo`
  us/global; OpenAI processing in US/EU/UAE; Managed Agents and the OpenAI Agents API US-only and not ZDR)
  [H], so residency-constrained tenants route through regional cloud endpoints (Bedrock, Vertex, Foundry)
  or self-hosted models, and the zone compiler refuses a model route whose region isn't cleared.
- Sub-processors (clouds, model providers) are data: a machine-readable list per tenant's cell, with
  change notification (GDPR Art. 28(2), DORA Art. 30) [H].

---

## 6. Isolation between tenants, layer by layer

### 6.1 Kernel

- In `MultiTenant` mode **gVisor is the floor for every tenant workload**, MCP servers and builds
  included, and the `process` tier is disabled. Modal and GKE Sandbox run gVisor multi-tenant; the
  Kubernetes docs say sandboxing "is often recommended when … workloads are assumed to be malicious" [H].
- microVMs (Firecracker/Kata) where KVM exists, and required for Dedicated tiers and for tenants who run
  arbitrary binaries with valuable labels. Most agent platforms are VM-per-sandbox (§2.2).
- **Builds are workloads**: tenant image builds and template preparation run in the same sandbox tier as
  runs (the Hugging Face lesson). No tenant-controlled input reaches a privileged host hook (NVIDIAScape).

### 6.2 Nodes, placement and where secrets live

The weakest point of design §8 for multi-tenancy is that **enforcement points run per node**, so a node
that hosts several tenants also holds several tenants' credential leases and box CA keys. EKS's guide is
blunt: a compromised host "can retrieve *all* Secrets, ConfigMaps, and Volumes mounted on that host…
impersonate the Kubelet" [H]. Recommendation:

1. **Split the node roles in multi-tenant cells.**
   - **Sandbox nodes** run tenant workloads plus `wicket-node` and a **dumb forwarder**: each box's
     listener is relayed over mTLS to the enforcement tier, stamped with the box id. Sandbox nodes hold
     **no credential leases, no CA keys and no model keys**.
   - **Enforcement nodes** run the egress proxy, LLM proxy and gateway as **tenant-sharded worker
     processes**, own the tenant egress IPs, terminate TLS with the per-box CA, and receive leases.
   - A compromised sandbox node can then *use* the grants of boxes placed on it (the ledger rejects claims
     about boxes placed elsewhere) but cannot *steal* tokens. Cost: one extra in-region hop per request
     (around a millisecond; to be measured in `wicket-bench`), small against model latency.
   - Dedicated tiers may keep enforcement node-local, because the node is single-tenant anyway.
   - Single-host and single-tenant modes are unchanged.
2. **Tenants per node are capped** (`TenantSpread{max_tenants_per_node: K}`), and tenants are shuffle-sharded
   across node groups, so one node compromise reaches at most K tenants.
3. **Tenant-dedicated node pools** use the `node-restriction.kubernetes.io/` label prefix, so a compromised
   kubelet can't relabel itself to attract other tenants' workloads [H]. Admission mutates and validates,
   and fails closed.
4. **Node attestation before leases**: the vault releases a lease only to an enforcement worker on an
   attested node, for a task the ledger placed there.

### 6.3 Warm pools, snapshots, templates, images

- **Pristine warm pools may be shared across tenants**: they hold nothing tenant-specific and are bound on
  claim (design §7.1). The new rule: a claimed sandbox is **destroyed after use and never returned** to any
  pool.
- **Platform templates** (an agent version booted to "ready", with no tenant data) may be restored for any
  tenant, with RNG reseeding and identity rotation. Copy-on-write memory sharing between clones is allowed
  only from platform templates.
- **Tenant templates** (a prebuilt repo, a tenant image, an MCP server with tenant config) carry the
  tenant's id and labels and are restored only into that tenant. Cloudflare's warning applies: tokens
  persist in snapshots (`.git/config`) [H], so templates are built from placeholders only, and a scan for
  registered honeytokens runs before a snapshot is stored.
- **Image layers**: platform layers are shared and digest-pinned; tenant layers live in per-tenant registry
  namespaces and per-tenant node caches, with no cross-tenant dedup. A shared registry writable by all
  customers was one Hugging Face finding [H].

### 6.4 Side channels

- **Facts.** gVisor "does not provide protection against hardware side channels" [H]. Core scheduling
  "does not protect kernel contexts running on sibling hyperthreads" and "the only full mitigation of
  cross-HT attacks is to disable Hyper Threading" [H]. Firecracker's production guide says disable SMT and
  KSM and swap for tenant separation [H]. AWS Nitro never shares cores between customers via SMT and never
  shares memory pages, but "some instance sizes can share some last level cache lines" [H]. An LLC
  Prime+Probe across tenants on Cloud Run recovered 81 % of ECDSA nonce bits in 19 s [H]. VMScape (2025)
  lets a guest steer branch prediction in a userspace VMM such as QEMU [H].
- **Consequence for wicket.** When each tenant node is a whole cloud VM, wicket inherits the cloud's
  isolation. When wicket packs several tenants' sandboxes into **one VM or one bare-metal host** (the
  Pooled tier), the side-channel burden moves onto wicket:
  - **KSM off** across tenants (already a rule) and **swap off**;
  - **no two tenants on SMT siblings**: cpusets allocated in sibling pairs. Inside a cloud VM, adjacent
    vCPUs are usually hyperthreads of one physical core, so the guest topology must be read and respected.
    Core scheduling is a second layer;
  - current microcode, `mitigations=auto` with the cross-thread vector on, and the VMScape/ITS mitigations
    checked at node preflight (refuse to register otherwise);
  - LLC sharing remains. That is stated in `explain` for Pooled tenants.
- **When to dedicate.** Offer Dedicated (node pools of whole VMs per tenant, or dedicated hosts / sole-tenant
  nodes) for tenants handling key material, regulated data, or competitors on the same platform. Shared
  GPUs are out for hostile tenants (Browserbase avoids GPUs for this reason [H]; the GKE docs say GPU driver
  vulnerabilities are not fully mitigated [H]).

### 6.5 Network and egress identity

- No change to box networking (interface-less netns, proxy-only route), and **no tenant-to-tenant path
  exists** except gateway-mediated service calls (§7). The Replicate break (a shared netns with a
  neighbour's Redis) is structurally impossible here, and the M4b probes are rerun with two tenants.
- **Every internal service is authenticated and encrypted** (SAPwned, Replicate), and queues are
  partitioned by tenant.
- **Per-tenant static egress IPs** are a real customer need (GitHub Enterprise IP allow lists, SaaS network
  policies) and rare in the market (§2.2). wicket's egress proxy dials upstream itself, so it can **bind
  the tenant's source address** on the enforcement node. That is simpler than Cilium egress gateway
  policies, which are cluster-scoped, briefly leak a non-gateway IP for new pods, and break connections on
  failover [H]. Pooled tenants share a published platform pool. Document the consequence: a customer who
  allowlists a shared IP also admits other tenants' traffic, which still needs credentials, and one
  tenant's abuse can get a shared IP blocklisted. PooledHardened and above get dedicated IPs per region.
- **Tenant-configured URLs** (webhooks, audit sinks, BYO MCP endpoints) are platform egress `Op`s through
  the SSRF classifier.

### 6.6 Keys and CAs

- Per-box CA as today. In the split-node design the CA key lives only in the enforcement worker serving
  that tenant.
- Tenant KEKs (§4.5). Mutual TLS client certificates a tenant's upstreams require are vault credentials
  of that tenant.
- Handle ids are `MAC_{k_tenant}(random)`: unguessable, verifiable as the tenant's without a lookup, and
  useless to another tenant.

### 6.7 Label namespaces

- `DataClass` gets an **owner** (`Platform` or `Tenant(T)`), as in the decentralized label model: only the
  owner declassifies its classes, and a tenant can define classes only under its own owner. Adapters and
  published artifacts can't mint classes of another owner.
- The provider-side label store (design §4.2) is keyed by tenant. The same GitHub issue written by two
  tenants' agents gets two label entries, never one shared entry.
- **No cross-tenant handles**: dereferencing a handle of another tenant is impossible without an active
  share (§7).

### 6.8 Ledger and audit

Ledger rows, grants, ratchet counters, fatigue stats and policy epochs are partitioned by tenant. Each
tenant has its own chain (§5.7). The ledger is the place where a revocation takes effect, so revocation
latency is one transaction, not a token lifetime.

### 6.9 LLM proxy

- **Keys.** The platform's key, mapped to **one provider workspace or project per tenant**, or the
  tenant's BYO key or endpoint. With a platform key, the tenant's spend cap is enforced in wicket first
  and in the provider workspace second.
- **Prompt caching.** Anthropic isolates caches per workspace on its own API (but only per organization on
  Bedrock and Vertex); OpenAI isolates per organization, and `prompt_cache_key` is not an isolation
  boundary [H]. So **a platform that sends all tenants through one workspace or project shares one prompt
  cache across tenants**. That is a timing side channel (Gu et al.) [H].
  - Rule: one provider workspace or project per tenant where the provider isolates by workspace.
  - On Bedrock and Vertex, an org- or account-level split for tenants that need it.
  - For self-hosted vLLM, `cache_salt = H(tenant)`, carried on every path, including tool continuations.
  - Never return cached-token counts to a tenant except for its own requests.
  - The shared platform system-prompt prefix may still be cached per tenant (it isn't secret).
- **Rate limits** per tenant, ahead of the provider's per-account limits (§5.5).

### 6.10 MCP servers

Per-task instances stay the default (design §8.2). `InstanceScope::Shared` becomes `Shared { tenant }`: a
server instance never serves two tenants. A vetted platform service shared by everyone is a platform
component, in the platform's TCB, and must itself be tenant-aware. A tenant that wants to offer a service
to others does so through a `Share::Service` (§7.5), running in its own tenancy.

### 6.11 Kubernetes

- The official docs: namespaces don't isolate cluster-scoped objects; DNS allows cross-namespace lookups;
  "the kubelet and … the API service are still shared services" even with dedicated nodes [H]. EKS:
  Kubernetes is "a single tenant orchestrator… the cluster is the only construct that provides a strong
  security boundary" [H]. vCluster's own table marks only **Private Nodes** (own CNI, CSI, compute) as
  suitable for untrusted tenants [H]. HNC is archived [H]; Capsule is soft multi-tenancy [M].
- **wicket's position:** tenants are **wicket principals, never Kubernetes principals**. They get no
  kubeconfig, no namespace, no CRD access, and their workloads are direct-launched sandboxes rather than
  pods. So Kubernetes multi-tenancy tooling (vCluster, Capsule) solves a problem wicket doesn't have. The
  cluster is wicket's own infrastructure: one cluster per cell, node pools per tier and for dedicated
  tenants, and Silo = a separate cluster or account. The rules from design §8.3 stay: cluster-admin is
  TCB, there is no tenant pod with a service-account token, and the operator has no cluster-wide Secret
  read.

### 6.12 Blast radius

See §11a. The two components whose compromise reaches many tenants are **wicketd in a cell** and **the
KMS root**. Cells, per-tenant keys, BYOK and the Silo tier are the containment.

---

## 7. Cross-tenant sharing

*Owner refinement, 2026-11-08: tenants aren't hermetically sealed. Isolation is the default; sharing is an
explicit, policy-governed exception.*

### 7.1 What tenants might share

| Kind | Example | Default | Mechanism |
|---|---|---|---|
| **Data / results** | A shares a triage report (handle) or a dataset with its contractor B | off | `Share::Data` (reference by default) through a cross-tenant gate |
| **Published artifacts** | manifest templates, adapters, skills, MCP server images, published by A for everyone | off; consumers opt in per digest | `Share::Artifact`: read-only, pinned by digest, reviewed, run in the *consumer's* tenancy |
| **Services** | A operates an MCP service or an agent that B's agents call | off | `Share::Service`: B's gateway → cross-tenant gate → A's service workload in A's tenancy |
| **Capacity** | subsidiaries of one group share a dedicated pool | off | `Share::Capacity`: placement change only; sandboxes stay per workload |
| **Collaboration spaces** | A and B run a joint zone on a shared project | off | `Share::JointZone`: a zone with two parties, each controlling its own resources and data |
| **Delegation** | B lets A's agent comment on B's issues | off | `Share::Delegation` with a `CrossTenantGrant`: a cross-account role with an external id |

### 7.2 Prior art for policy-controlled cross-boundary sharing

| System | Consent | Shared as | Revocation | Who pays | Deletion / offboarding | Lesson |
|---|---|---|---|---|---|---|
| **AWS RAM** | inside an Organization: no invitation once enabled; outside: an invitation the consumer accepts, expiring after 12 h or 7 d [H]. Two layers on the consumer side: the consumer admin delegates in IAM within the owner's managed permission [H] | reference; can't be reshared [H] | "a few minutes" [H]; leaving the org revokes [H] | varies by service [M] | remove resources from shares before deleting [H] | the owner sets a ceiling and the consumer delegates within it; RAM's `"Principal": "*"` admits the owner's whole account [H], so bypass paths matter |
| **Cross-account roles + ExternalId** | the vendor generates a per-customer id, "controlled by Example Corp, not its customers", not a secret [H] | assumed role | delete the role | the role owner pays ("their use … is billed to you") [H] | — | **37 % of 90 vendors got ExternalId wrong**, 15 % more validated only in the UI [M]; validate on the backend for create and update |
| **aws:SourceArn / SourceAccount / SourceOrgID**, RCPs, data perimeters | central caps that never grant [H] | — | — | — | — | the platform stamps the on-behalf-of tuple; the caller can't set it |
| **KMS cross-account** | the key policy (owner) **and** the IAM policy (consumer): "neither alone is sufficient"; logged in both accounts [H] | use, not key | grants revoke in "typically under 5 minutes" [H] | — | key deletion waits 7–30 days and "might not immediately affect" cached data keys [H] | bilateral by construction; bound key caches |
| **Snowflake Secure Data Sharing** | the provider grants unilaterally; the consumer creates a DB from the share [H/M] | **reference, no copy**, read-only, secure views only [H] | "instantly invalidates" [H] | **the consumer pays compute, the provider pays storage** [H] | dropping the share invalidates consumers [H]; consumers can CTAS a copy that escapes revocation [M] | cross-region = **replication** (auto-fulfillment) paid by the provider [H]; Business Critical data can't be shared down to lower editions by default [H] |
| **Snowflake clean rooms** | changes need the affected collaborators' approval [H] | templates only (JinjaSQL) over live views | — | the analysis runner pays [H] | — | the closest analogue to a joint zone with typed gates |
| **Databricks Delta Sharing** | recipient objects; open (bearer token ≤ 1 y), Databricks-to-Databricks, or OIDC federation [H] | reference via pre-signed URLs / temporary STS credentials [H] | on demand, but **issued URLs live until they expire** [M] | recipient pays its compute on D2D [H] | — | bearer artifacts outlive revocation; tokens with no expiry are being force-expired [H] |
| **Slack Connect** | each side's admins gate their own side [H/M] | channel owned by the creating org [H] | disconnect [H] | — | the owner keeps the channel; the removed org gets an archive [H] | **sender's org retention and EKM apply to its own messages** [H] |
| **Teams shared channels / Entra B2B direct connect** | blocked by default; **mutual** inbound + outbound configuration [H] | host tenant stores everything [H] | — | — | SharePoint file grants outlive channel removal [H] | **host's policies apply; "the external organization's policies aren't used"** [H]; cross-tenant sync abused for persistence [M] |
| **Google Workspace** | trusted-domain allowlist (≤ 5,000), warnings, badges [H] | per object | removing a domain revokes within 24 h [H] | — | — | **Google Groups bypass the domain allowlist** [H] |
| **GitHub** | fine-grained PATs need org approval by default; App installs by org owners; new App permissions need each installer's approval, removals are immediate [H/M] | — | — | — | — | widening needs fresh consent, narrowing doesn't; classic PATs skip approval |
| **Zanzibar / OpenFGA** | one tuple space; cross-org relations are native [M]; OpenFGA's own guide shares cross-tenant by direct grants "same model, no special case" [H] | relation | tuple delete | — | — | isolation lives in the model; easy to share by accident |
| **SPIFFE federation, GCP WIF** | `federates_with` configured on both sides, opt-in per workload [H]; WIF attribute conditions "help avoid the confused deputy problem" [H] | identity | bundle removal | — | — | pin the tenant claim on multi-tenant issuers |
| **K8s Gateway API ReferenceGrant** | **the target namespace creates the grant** listing allowed `from`/`to` [H] | reference | deleting the grant revokes; implementations must recompute [H] | — | — | exists to stop confused deputies (CVE-2021-25740) [H]: the target opts in |
| **Marketplaces** (AWS Marketplace, Workers for Platforms, AppExchange, Shopify) | review before listing, re-review on risk [H/M]; AWS meters on behalf of the buyer, idempotent hourly records that can't be amended [H] | artifact or SaaS | — | buyer, via the marketplace | — | third-party code runs untrusted (WfP: no shared cache, platform outbound, platform-set limits) [H]; **none documents digest pinning** |

### 7.3 Principles for wicket (from §7.2)

1. **Isolation by default; every share is an object.** A `Share` names a provider tenant, a consumer, a
   kind, a scope, a label policy, an expiry and a payer. Nothing else creates a cross-tenant path.
2. **Bilateral, two-layer consent.** The provider's admin sets a ceiling: what may be shared, with whom,
   for how long. The consumer's admin accepts, and delegates inside it to specific zones or templates.
   The platform's `SharingCeiling` on both plans must allow it, along with residency and compliance class.
   Neither side alone grants anything; platform policy can deny but never grant. Both admin decisions are
   `WicketPasskey`, and `TwoPerson` where either side's plan says so.
3. **The target opts in, in its own ledger** (ReferenceGrant). A delegation lives in the grantor's ledger
   partition; a service exposure lives in the service owner's. Deleting it revokes, and decisions are
   recomputed per `Op`.
4. **Reference, not copy**, by default. Transfers (copies) are an explicit mode, with the consequence
   spelled out on the approval card.
5. **Revocation is per `Op` in the ledger**, so it is immediate (target ≤ 1 s). No bearer artifacts outlive
   it: no pre-signed URLs and no long-lived tokens cross tenants. Key caches have a stated bound.
6. **Always time-bounded.** Expiry is mandatory, and renewal is a new decision. Invitations expire.
7. **The platform stamps the on-behalf-of tuple** `(tenant, zone, task, share, external_id)` on every
   cross-tenant call. The caller can't set it (ExternalId, SourceArn). It is validated on create *and*
   update.
8. **Widening needs fresh consent; narrowing is immediate** (GitHub App permissions).
9. **Close bypass paths.** Every route into shared content (handles passed on, gate fields, joint-zone
   stores, nested shares, published artifacts) hits the same check. No resharing by default (RAM,
   Snowflake).
10. **Audit on both sides** under one share and request id. Changes to sharing are protected, alertable
    actions. Admin-configured trust is itself a persistence vector, as the cross-tenant sync abuse showed.

### 7.4 Labels and keys for shared data

- **Owner tags travel** (decentralized label model). Data A shares keeps A's classes (`t:A/…`). B's agent
  that reads it gets `t:A/…` in its label. Every later flow of that label must be permitted by **A's**
  policy: the share's `permitted_sends`, or A's own destination clearances. So B can analyse A's data but
  can't send it anywhere A didn't allow, including to a third tenant C. Joins with B's own classes need
  both owners' permission to flow.
- **Relabelling into the receiver's namespace** is a *declassification by the owner*:
  `SharedLabelPolicy::Declassify{to: t:B/…}`, decided on A's side. Only then does B own the result, and
  A's later erasure no longer reaches it. This is the "transfer" mode, and the approval card says so.
- **Gates.** A cross-tenant gate is an ordinary gate (`TypedFields`, `HandlesOnly`, `QuarantinedReader`,
  `Declassify`) with `GateRule::CrossTenant{share}` added. Free text never crosses it. Typed fields that
  cross are relabelled with the sender's owner tag.
- **Keys.** Reference shares are read through the owner's key: wicketd unwraps with A's KEK on B's behalf
  while the share is active, so A's key policy (or A's BYOK revocation) cuts B off. Transfers are
  re-encrypted under B's KEK at transfer time. For **derived content carrying two owners' tags**, the
  content DEK is split 2-of-2 (XOR shares wrapped by each owner's KEK), so **either owner can
  crypto-shred** it. This is a proposal; no product does it (§7.2, KMS row). Proxy re-encryption isn't
  needed: wicketd mediates every read.

### 7.5 Mechanisms per kind

- **Data.** `Share::Data{objects, mode: Reference}` makes handles and datasets readable by named consumer
  zones (or templates) through a cross-tenant gate. Stores stay in the provider's cell. The consumer pays
  the compute it uses; the provider pays storage, and any residency replica if allowed (Snowflake split).
- **Published artifacts.**
  - Publisher A submits an artifact. The platform reviews it: static checks, and for adapters symcc
    "narrower than the default and disjoint from the dangerous list", the same as generated adapters.
  - The artifact is **pinned by digest** and signed by the platform.
  - Consumers reference the digest in their manifests and run it in **their own** tenancy, sandbox and
    labels. No data flows to the publisher.
  - Skills and templates are taint for the consumer's zones until the consumer's admin approves that
    digest. MCP images run under design §8.2 like any third-party server.
  - New versions need the consumer's fresh approval if they widen anything; narrowing updates can be
    automatic.
  - Usage can be metered to the publisher for marketplace billing (idempotent hourly records, as AWS
    Marketplace does).
- **Services.** B's agent calls `a.tool` through B's gateway:
  1. **Gate out of B.** The arguments become typed fields and handles labelled `t:B/…`. B's consent must
     list A's service as a destination cleared for those classes.
  2. **A's service runs in A's tenancy**, on A's nodes and A's bill for compute, with **A's own
     credentials** for A's resources. It never receives B's credentials (no token passthrough).
  3. **Labels inside A.** B's data inside A's service keeps B's owner tag, so A's service zone can't send
     it anywhere B didn't clear.
  4. **Gate back into B.** The results come back labelled `t:A/…` (or declassified by A).
  5. If A's service needs B's resources, that is a separate delegation.
  6. **Metering.** A `CrossTenantCalls` usage record goes to both tenants. A can charge B through
     platform metering.
- **Capacity.** `Share::Capacity{pool}` lets B place workloads on A's dedicated pool. Both admins accept
  (B's data then sits on A's hosts, and A's hosts carry B's tenant). It changes only placement: sandboxes,
  enforcement workers, leases and keys stay per tenant. For a group of affiliated tenants (subsidiaries),
  not strangers.
- **Joint zones.** `Share::JointZone{zone}` creates a zone with `parties: [A, B]`.
  - **Reach** is the union of what each party grants it on *its own* resources, each part ⊆ that party's
    ceiling. This is per owner, not the intersection of the two ceilings: B's ceiling may not mention A's
    repos at all.
  - **Clearance** is the union of the shared classes. **Sends** are per owner tag (§7.4).
  - **Isolation floor, kernel and attestation**: the stricter of the two parties'.
  - **Residency**: the intersection of the parties' allowed regions. An empty intersection means the zone
    can't be formed.
  - **Placement**: a neutral platform pool by default, or one party's pool if both accept.
  - **Escalations**: an `Op` on A's resources is decided by A's approvers, on B's by B's.
  - **Ledger and records**: the joint zone has its own ledger partition and chain, with commitments
    mirrored into both tenants' chains. Retention follows the **sender's** tenant for each record (Slack's
    rule, which matches per-owner keys), not the host's (Teams' rule).
  - **Billing**: the joint zone's compute is billed by a declared split.
- **Delegation.** `CrossTenantGrant{grantor: B, grantee: A, grantee_zones, capability, budget,
  conditions, external_id}`, held in B's ledger.
  - A's task binding must carry the external id, which the platform minted and A can't choose.
  - A's agent's `Op` on B's resource is decided by **B's chain**: B's ceiling ∧ the grant ∧ the grant's
    conditions (A's taint, A's task class, A's isolation floor) ∧ the usual sink provenance, which must
    trace to A's task text *and* fall inside the grant.
  - The credential is **B's**, leased from B's vault partition to the enforcement worker serving A's task.
    B's consent therefore names A's minimum isolation tier, and the lease is audience-bound to that worker.
  - Escalations under the grant go to B's approvers.
  - Data read from B carries `t:B/…`.
  - Both ledgers record each use.
  - B can revoke at any time, effective on the next `Op`.

### 7.6 How sharing shows up in `explain`

- Each tenant's zone view shows shares as **"external tenant" nodes**. They show only the counterparty's
  display name and the interface it exposes (tool names, typed fields, the classes it may receive), never
  the counterparty's internal zones.
- The blast radius of `--compromised <zone>` includes every outbound share and delegation the zone can
  use, and what the counterparty's triggers turn that into. B's view of A's delegation answers "if A is
  compromised, what can happen to B": exactly the grant.
- The timeline shows share proposals, acceptances, uses (aggregated) and revocations on both sides.

### 7.7 Residency, erasure and offboarding

- **Residency.** A share whose consumer is in another jurisdiction is denied by default. Platform policy
  may allow particular pairs, which makes it a Chapter V transfer the tenants must cover. Reference reads
  across cells are remote reads, so the data stays in the provider's cell. Replicas are explicit,
  provider-paid and residency-checked (Snowflake auto-fulfillment).
- **When a tenant erases data or leaves:**
  - **References** it gave die: the owner key is destroyed, or the share is revoked.
  - **Derived content** under 2-of-2 keys dies with it.
  - **Transfers** made earlier remain the consumer's: that is what transfer means, and the card said so.
  - **Joint-zone records** remain in the other party's chain as commitments only.
  - **Published artifacts** are unlisted. Consumers keep running the pinned digest until their admin
    removes it, because removing it under them would break their manifests. The platform can force removal
    for security reasons.
- **When a consumer leaves**, its acceptances are revoked, and the provider's view updates.

---

## 8. Compliance, only where it constrains the architecture

| Regime | Constraint | Where it lands in wicket |
|---|---|---|
| **SOC 2** (CC6 logical access, CC7.2 monitoring, CC8.1 change management) [M] | access reviews, logged admin actions, change control | control-plane audit in the tenant and platform chains; policy changes are epochs with deciders; break-glass logged in both chains |
| **ISO 27001:2022** (A.8.15 logging, A.8.16 monitoring, A.8.17 clock sync, A.8.24 crypto, A.5.23 cloud services, A.5.33 records); **ISO 42001** AI event logging [M] | key management policy, synchronised clocks, records protection | KMS hierarchy (§4.5); timestamps from a synchronised source in every chain record; WORM anchoring |
| **HIPAA** (§164.312(b) audit controls, (c) integrity, (e) transmission security; §164.316 documentation kept 6 years) [H] | BAA chain to every sub-processor touching PHI; audit controls; long documentation retention | a HIPAA plan class: only BAA-covered model routes and clouds (Managed Agents and the OpenAI Agents API are not HIPAA/ZDR eligible [H]); PHI-labelled data can't be shared to non-HIPAA tenants (`SharingCeiling`) |
| **GDPR** (Art. 17 erasure with (3)(b)/(e) exceptions; Art. 28 processor terms, sub-processor authorisation, delete or return at end; Art. 30 records; Chapter V transfers) [H]; EDPB 01/2025: pseudonymised data stays personal data [M] | erasure vs audit retention; sub-processor lists; residency | crypto-shredding with per-user keys and salts, erasure receipts, export-then-erase offboarding, sub-processor list per cell, cross-jurisdiction sharing denied by default; EU-US DPF upheld by the General Court in Sept 2025, appeal pending [M], so keep SCCs |
| **EU AI Act** (Art. 12 automatic event logging for high-risk systems; Art. 19 provider and Art. 26(6) deployer log retention ≥ 6 months) [H]; the Digital Omnibus (Reg. (EU) 2026/1744) moves Annex III high-risk obligations to 2 Dec 2027 and Annex I to 2 Aug 2028 [H, recitals only] | wicket is usually infrastructure for the provider or deployer, not itself the high-risk system; tenants building high-risk systems need logs they control | per-tenant export of the full event and decision log; a retention floor ≥ 6 months configurable per tenant; logs "under their control" = the tenant's sink |
| **DORA** (Art. 30 contract terms: data locations with notice of change, access and return, audit rights, exit strategies) [H]; **NIS2** Art. 21/23 [M] | financial tenants push these down to the platform | residency as data, exit exports of ledger and audit, incident hooks per tenant |
| **FedRAMP** (NIST 800-53 AU-9/AU-11; OMB M-21-31 retention) [M] | separate authorised boundary | a Silo cell only; out of scope for v1 |

Architectural takeaways: (1) **audit logs are per tenant, exportable, retained per tenant, immutable but
erasable by key**; (2) **key management is a first-class component** with per-tenant keys and BYOK;
(3) **residency and sub-processors are data** the placement compiler and model router read; (4) **plan
classes encode compliance** (HIPAA, regulated finance), which narrow routes and sharing.

---

## 9. Recommendations in one place

1. **Tenant id everywhere, from M0.** Single-tenant is tenant zero. One code path.
2. **Ceiling chain** `platform ∧ plan ∧ tenant ∧ workspace ∧ zones ∧ grant ∧ labels ∧ ledger`, with tenant
   policy proved ⊆ plan for UX and AND-ed at evaluation for safety.
3. **gVisor floor for all tenant workloads; `process` and `vendor_rc` off in MultiTenant mode.**
4. **Split sandbox nodes from enforcement nodes in shared cells**, so no tenant secret ever sits on a node
   that runs other tenants' code; tenant-sharded enforcement workers; tenants-per-node cap.
5. **Isolation tiers by plan** (Pooled → PooledHardened → Dedicated → Silo), matrix in §11.
6. **Vault keyed by (tenant, subject, provider, connection)**; workspaces as policy edges; per-purpose
   consent through a wicket-owned `/connect` page that proves consenting user = initiating user; narrowest
   native credential per task; envelope encryption with tenant KEKs and BYOK.
7. **One provider workspace or project per tenant** for LLM keys: spend caps, rate limits and prompt-cache
   isolation; `cache_salt` for self-hosted models.
8. **Per-tenant static egress IPs** bound by the egress proxy on enforcement nodes.
9. **End users approve in the SaaS product** through an embeddable, passkey-backed approval component
   served from wicket's origin; the embedder never decides above R2.
10. **Owner-tagged labels (DLM)** make both tenant isolation and cross-tenant sharing one mechanism.
11. **Cross-tenant sharing only through `Share` objects**: bilateral consent, target opt-in in its own
    ledger, reference not copy, per-`Op` revocation, mandatory expiry, platform-stamped on-behalf-of
    tuples, both ledgers audited.
12. **Cells** for residency and blast radius, a global directory with nothing else in it, and Silo/BYOC
    cells for tenants that need them.

---
## 10. Recommended types

New crate `wicket-tenancy` (types in `wicket-core`, no I/O, like the rest of the model). The rule that
makes everything else work: **a `TenantId` is part of every identifier and every store key, from M0**,
even in single-tenant mode, where it is the fixed "tenant zero". There is one code path, not two.

```rust
// ---------- hierarchy ----------
pub struct PlatformId(Ulid); pub struct TenantId(Ulid); pub struct WorkspaceId(Ulid);
pub struct EndUserId(Ulid); pub struct PlanId(SmolStr); pub struct CellId(SmolStr);

pub enum PlatformMode {
    SingleTenant,   // today's developer tool: tenant zero, process tier allowed for dev
    MultiTenant,    // ⇒ isolation floor ≥ UserspaceKernel for every tenant workload, no `process` tier,
                    //   no vendor_rc, tenant-scoped everything; checked at startup and by the zone compiler
}

pub struct Platform {
    pub id: PlatformId,
    pub mode: PlatformMode,
    pub ceiling: Ceiling,                     // providers, backends, regions, label owners the platform supports
    pub cells: Vec<Cell>,                     // regional deployments (control plane + nodes + stores)
    pub directory: DirectoryRef,              // global: TenantId → Cell, nothing else
    pub root_key: KmsKeyRef,                  // wraps per-tenant KEKs that are not BYOK
}

pub struct Cell { pub id: CellId, pub region: RegionId, pub jurisdiction: Jurisdiction,
                  pub kind: CellKind /* Shared | DedicatedTo(TenantId) | Byoc(TenantId) */ }

pub struct Plan {
    pub id: PlanId,
    pub ceiling: TenantCeiling,               // the most any tenant on this plan can be configured to do
    pub tier: IsolationTier,
    pub quotas: QuotaSet,                     // defaults; tenant overrides must be ≤
}

#[derive(PartialOrd, Ord)]
pub enum IsolationTier {
    Pooled,           // shared gVisor sandbox nodes (≤ K tenants each) holding no tenant secrets; enforcement
                      // on cell enforcement nodes, tenant-partitioned workers; shared platform egress IPs
    PooledHardened,   // + one enforcement worker process per tenant, whole-core CPU allocation, own egress IPs
    Dedicated,        // + node pools tainted to the tenant (enforcement may be node-local), dedicated
                      //   cores/hosts, microVM where KVM exists, per-tenant KMS key
    Silo,             // + own cell (control plane, stores, cluster) or BYOC in the tenant's cloud account
}

/// The ceiling a plan imposes. Tenant and workspace admins can only narrow inside it.
pub struct TenantCeiling {
    pub reach: CapabilitySet,                       // providers, verbs, max risk that exist for this tenant
    pub auto_max_risk: RiskClass,                   // no tenant policy can auto-grant above this
    pub isolation_floor: IsolationLevel,            // ≥ UserspaceKernel in MultiTenant mode
    pub backends: BTreeSet<BackendKind>,
    pub agents: BTreeSet<AgentKind>, pub models: BTreeSet<ModelRef>,
    pub regions: BTreeSet<RegionId>,                // residency choices offered
    pub operator_modes: BTreeSet<OperatorMode>,     // vendor_rc never in MultiTenant
    pub byo: ByoAllowance,                          // { llm_keys, oauth_clients, kms_keys, mcp_images, egress_ips, idp }
    pub approval_floor: BTreeMap<RiskClass, ApprovalAssurance>, // minimum assurance per risk (§5.6)
    pub sharing: SharingCeiling,                    // which cross-tenant share kinds are possible at all (§7)
    pub retention: RetentionBounds,                 // min/max for audit, transcripts, handles, snapshots
    pub quotas: QuotaSet,                           // hard upper bounds
}

pub struct Tenant {
    pub id: TenantId, pub plan: PlanId, pub cell: CellId, pub display_name: String,
    pub residency: Option<Jurisdiction>,            // pins cell, placement, stores, model endpoints
    pub policy: TenantPolicy,                       // Cedar, namespace-confined; proved ⊆ ceiling; also AND-ed at eval
    pub label_owner: LabelOwner,                    // = LabelOwner::Tenant(id); owns "t:<id>/…" classes
    pub data_classes: Vec<DataClass>,
    pub keys: TenantKeys,
    pub idp: Option<IdpFederation>,                 // tenant's own OIDC/SAML for admins and end users
    pub egress: EgressIdentity,                     // SharedPlatform | Dedicated{ips: Vec<IpAddr>, region}
    pub approvers: ApproverPolicy,                  // who decides what (§5.6)
    pub retention: RetentionPolicy,                 // within plan bounds
    pub state: TenantState,                         // Active | Suspended{why} | Offboarding{export_until} | Erased{at, receipt}
}

pub struct Workspace {                              // org/team/project inside a tenant; may nest
    pub id: WorkspaceId, pub tenant: TenantId, pub parent: Option<WorkspaceId>,
    pub policy: NarrowingPolicy,                    // ⊆ tenant policy (same proof + eval-chain rule)
    pub quotas: QuotaSet,                           // Σ children ≤ parent is NOT required; each ≤ parent
}

pub struct EndUser {
    pub id: EndUserId, pub tenant: TenantId,
    pub external_id: SmolStr,                       // the embedder's user id, unique per tenant
    pub idp_subject: Option<(Issuer, Subject)>,     // when the tenant federates its IdP
    pub approver_keys: Vec<WebAuthnCredentialId>,   // passkeys registered with wicket's approval RP
    pub workspaces: BTreeSet<WorkspaceId>,
    pub state: EndUserState,                        // Active | Disabled | Erased{at}
}

pub enum Principal {                                // control-plane principals (Cedar entities)
    PlatformOperator(OperatorId),
    Embedder { key: ApiKeyId, tenants: TenantScope },     // the SaaS backend; can start tasks, never decide
    TenantAdmin { tenant: TenantId, who: EndUserId },
    WorkspaceAdmin { workspace: WorkspaceId, who: EndUserId },
    EndUser { tenant: TenantId, who: EndUserId },
    Agent(AgentId),                                 // data plane only; identity from transport
}

// ---------- labels: owners, as in the decentralized label model ----------
pub enum LabelOwner { Platform, Tenant(TenantId) }
pub struct DataClass { pub owner: LabelOwner, pub name: SmolStr }    // rendered "t:01J…/source"
// Only `owner` may declassify a class. A tenant can define classes only under its own owner.
// A label with classes of two owners needs BOTH owners' permission to flow anywhere (§7.4).

// ---------- store discipline ----------
pub struct Scoped<T> { pub tenant: TenantId, pub inner: T }  // every store API takes and returns Scoped<…>;
                                                             // no store method exists without a TenantId
pub struct HandleId([u8; 32]);  // = MAC_k(tenant)(random) — unguessable and verifiable as T's without a lookup

// ---------- credentials (§4) ----------
pub struct CredentialKey {
    pub tenant: TenantId,
    pub subject: CredSubject,                       // whose authority this is
    pub provider: ProviderId,
    pub connection: ConnectionId,                   // several accounts per (subject, provider) are allowed
}
pub enum CredSubject { Tenant, EndUser(EndUserId), Service(ServiceAccountId) }
pub enum OAuthClientRef {
    WicketDev(ProviderId),                          // development only
    Platform(ProviderId),                           // the SaaS operator's app: production default
    TenantByo { tenant: TenantId, client: ClientId },   // tenant's own app (own name on consent)
}
pub struct WorkspaceGrant {                         // workspaces are a policy edge, not part of the key
    pub workspace: WorkspaceId, pub connection: ConnectionId,
    pub tools: BTreeSet<ToolRef>, pub hosts: BTreeSet<HostPattern>, pub scopes: NativeScopes,
}
pub struct Connection {
    pub key: CredentialKey, pub client: OAuthClientRef,
    pub provider_subject: SmolStr,                  // GitHub user id, Google sub: detects wrong-account connects
    pub granted_scopes: NativeScopes,               // what the provider actually granted
    pub consent: ConsentRecord,
    pub status: ConnectionStatus,                   // Active | NeedsReauth{since} | Revoked{by, at}
}
pub struct ConsentRecord {
    pub by: EndUserId, pub at: Timestamp, pub scopes: NativeScopes,
    pub purposes: BTreeSet<TaskClass>,              // consent is per purpose, not blanket
    pub evidence: ConsentEvidence,                  // provider grant id + wicket passkey assertion, if any
}
pub struct SealedCredential {                       // at rest
    pub key: CredentialKey,
    pub binding: InjectionBinding,                  // (hosts, header slot, format) sealed with the secret
    pub ciphertext: Vec<u8>,                        // AEAD; AAD = (tenant, subject, provider, connection)
    pub dek: WrappedKey,                            // DEK wrapped by the tenant KEK (KMS / BYOK)
}
pub struct CredentialLease {                        // what a node ever sees, in memory only
    pub cred: CredentialKey, pub task: TaskId, pub zone: ZoneId,
    pub worker: EnforcementWorkerId, pub audience: NodeIdentity,   // never a sandbox node in shared cells
    pub scopes: NativeScopes,                       // ⊆ granted ∩ solver's per-task native scopes
    pub expires_at: Timestamp,                      // ≤ min(task end, provider token expiry, 1 h)
}

pub struct TenantKeys {
    pub kek: KekRef,                                // PlatformManaged{context} | TenantKmsKey | Byok{external}
    pub user_deks: KeyDerivation,                   // per-end-user content keys, for per-user crypto-shredding
    pub audit_salt: SaltRef,                        // per-tenant HMAC salt for audit commitments
}

// ---------- quotas, metering, money ----------
pub struct QuotaSet {
    pub concurrent_tasks: u32, pub concurrent_sandboxes: u32, pub concurrent_mcp_instances: u32,
    pub vcpu_milli: u64, pub mem_mib: u64, pub disk_gib: u32,
    pub task_starts: Rate, pub ops: Rate, pub escalations: Rate, pub llm_tokens: Rate, pub api_calls: Rate,
    pub egress_bytes: PerPeriod<u64>, pub storage_gib: u32,
    pub spend: SpendCaps,
}
pub struct SpendCaps { pub per_task: Money, pub daily: Money, pub monthly: Money, pub hard_stop: bool }

pub struct UsageRecord {
    pub id: UsageId,                // idempotency key = H(source, source_instance, seq); duplicates are dropped
    pub tenant: TenantId, pub workspace: Option<WorkspaceId>, pub end_user: Option<EndUserId>,
    pub task: Option<TaskId>, pub zone: Option<ZoneId>,
    pub meter: Meter, pub quantity: Decimal, pub window: (Timestamp, Timestamp),
    pub source: MeterSource,        // LlmProxy | Node | Egress | Gateway | Store | Provisioner
    pub cost_basis: Option<Money>,  // what it cost the platform (provider list price / invoice line)
    pub counterparty: Option<TenantId>, // cross-tenant service calls and shares (§7)
}
pub enum Meter {
    LlmTokens { model: ModelRef, kind: TokenKind /* Input | Output | CacheRead | CacheWrite */ },
    SandboxCpuSeconds { tier: IsolationTier }, SandboxMemGibSeconds { tier: IsolationTier },
    SandboxWallSeconds { backend: BackendKind }, ParkedGibHours,
    EgressBytes { dest: DestClass }, Ops { surface: Surface }, McpCalls { server: McpServerRef },
    HumanEscalations, StorageGibHours { kind: StoreKind },
    DedicatedHostHours { class: HostClassId }, StaticIpHours, CrossTenantCalls,
}
pub struct Reservation { pub tenant: TenantId, pub task: TaskId, pub amount: Money, pub expires_at: Timestamp }
// The design §8.5 rule ("reserve the worst case in the ledger before acting") becomes per tenant: an LLM call
// reserves max_tokens × price, a sandbox reserves lease × rate; the reconcile releases the difference.

// ---------- approvals ----------
#[derive(PartialOrd, Ord)]
pub enum ApprovalAssurance {
    EmbedderAttested,        // the SaaS backend says user U approved (U's session in the SaaS). SaaS is TCB.
    TenantIdpStepUp,         // CIBA / OIDC step-up at the tenant's IdP, acr + auth_time checked by wicketd
    WicketPasskey,           // WebAuthn assertion over the request digest, verified by wicketd (default R3+)
    TwoPerson,               // two distinct WicketPasskey approvers (R4, money, cross-tenant shares)
}
pub enum ApproverRule {
    CredentialSubject,       // the Op uses U's credential ⇒ U decides (or U's delegate)
    Role { workspace: Option<WorkspaceId>, role: RoleId },   // tenant resources ⇒ tenant approvers
    Both,                    // e.g. a user-credential Op on a tenant-classified repo
}

// ---------- cross-tenant sharing (§7) ----------
pub struct Share {
    pub id: ShareId, pub kind: ShareKind,
    pub provider: TenantId, pub consumer: Consumer,        // Tenant(T) | Listing(ListingId)
    pub labels: SharedLabelPolicy,
    pub consent: BilateralConsent,
    pub platform_epoch: PolicyEpoch,                       // platform sharing policy it was checked against
    pub expires_at: Timestamp,                             // always bounded; renewal is a new decision
    pub residency: ResidencyRule,                          // ProviderRegionOnly | Both(jurisdictions) | …
    pub payer: Payer,                                      // Provider | Consumer | Split
    pub state: ShareState,                                 // Proposed | Active | Suspended | Revoked{at} | Expired
}
pub enum ShareKind {
    Data { objects: ObjectSet /* handles, datasets, stores */, mode: ShareMode /* Reference | Transfer */ },
    Artifact { digest: Digest, kind: ArtifactKind /* Template | Adapter | Skill | McpImage */, review: ReviewRef },
    Service { service: ServiceRef, interface: Vec<GateRule> },   // A's MCP service / agent that B calls
    Capacity { pool: PoolId },
    JointZone { zone: ZoneId },
    Delegation { grant: CrossTenantGrant },
}
pub struct BilateralConsent {
    pub provider_side: SignedDecision,     // provider tenant admin, ≥ WicketPasskey
    pub consumer_side: SignedDecision,     // consumer tenant admin, ≥ WicketPasskey
    pub platform: PlatformCheck,           // both plans' SharingCeiling, residency, compliance class
}
pub enum SharedLabelPolicy {
    KeepOwnerTag { permitted_sends: Vec<Destination> },   // default: data stays the provider's (DLM)
    Declassify { to: DataClass /* consumer-owned */, decider: SignedDecision /* provider side */ },
}
pub struct CrossTenantGrant {              // B lets A's agents act on B's resources (cross-account role)
    pub grantor: TenantId, pub grantee: TenantId,
    pub grantee_zones: ZoneTemplateDigestSet,   // which of A's zone templates may use it
    pub capability: Capability, pub budget: Budget,
    pub conditions: GrantConditions,            // max taint, task classes, isolation floor on A's side
    pub external_id: Nonce,                     // confused-deputy defence: must appear in A's task binding
    pub decided_by: ApproverRule,               // escalations under it go to B's approvers
}
```

## 11. Tenant isolation matrix

Columns are `IsolationTier`s. The last column says what cross-tenant sharing (§7) may change.
"Never" means no policy, plan or share can turn it on.

| Layer | Pooled | PooledHardened | Dedicated | Silo / BYOC | Shareable by policy? |
|---|---|---|---|---|---|
| Control plane (API, wicketd, escalation broker) | shared cell; tenant-scoped authz on every call | shared cell | shared cell or dedicated cell | own cell / own account | No (shares are objects *in* it) |
| Ledger + audit store | shared DB, per-tenant partition and hash chain; global chain holds only partition heads | same | same, per-tenant KMS key | own DB | Joint zones and shares get their own partition, mirrored as commitments into both tenants' chains |
| Vault records | per-tenant partition, KEK = platform KMS key + encryption context {tenant} | same | per-tenant KMS key; BYOK option | BYOK / HYOK in tenant account | Never (a delegation shares *use*, never the credential) |
| Where credential leases live | enforcement nodes only, never sandbox nodes | same, one worker process per tenant | tenant's own nodes (node-local allowed) | own | Delegation leases B's credential to the worker serving A's task, audience-bound |
| Content (handles, transcripts, snapshots) | per-tenant DEKs, per-end-user subkeys | same | per-tenant KMS key | BYOK | Reference shares read through the owner's key; transfers re-encrypt to the consumer |
| Label namespace | `t:<id>/…`, owner-checked | same | same | same | Owner tag travels with shared data (KeepOwnerTag) or is declassified by its owner |
| LLM provider account | platform key, **one provider workspace/project per tenant** (spend limit, cache isolation) | same | same, or tenant BYO key | tenant BYO key / own endpoint | No |
| Prompt / prefix cache | provider cache per workspace; self-hosted: `cache_salt` = tenant | same | same | own | Never |
| Egress proxy process | cell enforcement nodes, tenant-partitioned workers, shuffle-sharded | **one worker process per tenant** (per enforcement node) | node-local on tenant-only nodes, or dedicated workers | own | No |
| Egress source IP | shared platform pool (published) | **dedicated static IPs per tenant per region** | dedicated | tenant's own NAT | No |
| Per-box CA | per box (already); key only in the enforcement worker | same | same | same | No |
| MCP gateway | enforcement tier, sessions keyed (tenant, agent, route) | per-tenant worker | tenant-only | own | Service shares are routed by the gateway through a cross-tenant gate |
| Third-party MCP servers | per task (already); `Shared` scope only within a tenant | same | same | same | Never across tenants as a shared instance; tenant A may *offer* a service (§7) |
| Sandbox kernel | gVisor floor | gVisor or microVM | microVM where KVM exists | tenant's choice ≥ gVisor | No |
| Warm pool | pristine, unbound, shared across tenants; destroyed after use, never returned | same | per-tenant pools | own | — |
| Snapshot templates | platform templates (no tenant data) shared read-only; **tenant templates per tenant** | same | same | own | Published artifact (pinned, reviewed) only |
| Memory CoW sharing / KSM | KSM off across tenants; snapshot CoW only from platform templates | KSM off | KSM off | tenant's choice | Never |
| Image layer cache | platform layers shared; tenant layers per tenant (no cross-tenant dedup) | same | per node | own | Published artifacts only |
| CPU | cgroup quotas; no SMT-sibling sharing between tenants (core scheduling or whole-core allocation) | whole cores per tenant | dedicated hosts | own | Capacity share (opt-in pool) only between consenting tenants |
| Node / host | shared; ≤ K tenants per node (spread cap); host anti-affinity for marked pairs | same, smaller K | taint `wicket.dev/tenant=T` | own cluster | Capacity share |
| Kubernetes | one cluster per cell; tenants are **not** Kubernetes users | same | node pools | own cluster | No |
| Network fabric | interface-less netns; WireGuard between nodes; no tenant-to-tenant path | same | same | own | Only gateway-mediated service calls |
| Console / approval domain | `approve.<platform>` or tenant CNAME (related origins) | same | custom domain | own | No |
| Metering + quotas | per tenant, workspace, user | same | same | same | Cross-tenant calls metered to both with a counterparty field |
| Region / residency | tenant's chosen cell | same | same | same | Cross-jurisdiction sharing denied by default |

## 11a. Blast radius by component

| If this is compromised | What an attacker gets | Containment |
|---|---|---|
| A sandbox | its own zone's reach (as today) | gVisor/microVM, no secrets inside, per-box CA |
| A third-party MCP server | its server zone ⊆ caller's reach, one task | per-task instance, never shared across tenants |
| A sandbox node / `wicket-node` (privileged) | the sandboxes on it, and the ability to *use* (not read) the grants of boxes placed on it | no leases, CA keys or model keys on sandbox nodes in shared cells; ≤ K tenants per node; the ledger rejects identity claims for boxes placed elsewhere |
| An enforcement worker (Pooled, shared process) | leases of the tenants that worker serves | shuffle sharding, leases ≤ 1 h and audience-bound, PooledHardened gives each tenant its own process |
| An enforcement node | leases and CA keys of tenants sharded onto it | attestation before leases, shard spread, short leases, Dedicated tier |
| Embedder (the SaaS backend) | start tasks as any user of any tenant it serves; `EmbedderAttested` approvals | per-tenant embedder keys, end-user assertions from the tenant IdP, R3+ needs `WicketPasskey` |
| Console / approval front end | can show wrong things | wicketd verifies passkey over the digest (unchanged); typed request rendered from wicketd data |
| wicketd in a cell | every tenant in the cell | cells, per-tenant KMS keys (a DB dump alone is ciphertext), BYOK lets a tenant cut access, Silo tier |
| KMS root / platform operator | everything not BYOK | HSM-backed root, two-person operator actions, BYOK/HYOK for those who need it |
## 12. Embedding API sketch

HTTP + JSON, the same API-first rule as §13.1.3: the console, the CLI and the embedding SaaS are all clients.
Every path is tenant-scoped; a token for tenant A gets `404` (not `403`) for any id of tenant B.

**Authentication of the embedder.** The SaaS backend holds an `Embedder` key. Recommended shape:
one key per (embedder, tenant), or a platform key that can only be *exchanged* (RFC 8693) for a
short-lived tenant-scoped token. Either way one HTTP call is bound to one tenant, so a SaaS bug that mixes
tenant ids fails closed. **End-user identity** arrives as an assertion:
- `user_assertion` — a short-lived JWT the embedder signs (`iss` = embedder, `sub` = external user id,
  `aud` = wicket, `tenant`, `exp` ≤ 5 min, `jti` single-use); or
- an ID token / ID-JAG from the **tenant's own IdP** when the tenant federates (enterprise). Then the
  embedder is no longer trusted to say who the user is.

**Endpoints**

```
# platform operator
POST   /v1/tenants                                  {plan, cell|region, display_name, idp?, keys?}
PATCH  /v1/tenants/{t}                              plan change (narrowing is immediate; widening is a platform decision)
POST   /v1/tenants/{t}:suspend | :offboard | :erase

# tenant admin (console or API)
PUT    /v1/tenants/{t}/policy                       Cedar, namespace-confined; response carries the symcc
                                                    verdict "⊆ ceiling" or the counter-example
POST   /v1/tenants/{t}/workspaces
PUT    /v1/tenants/{t}/approvers                    ApproverRule per (risk, data class, credential subject)
POST   /v1/tenants/{t}/oauth-clients                BYO OAuth client (white-label consent screens)
PUT    /v1/tenants/{t}/egress                       request dedicated IPs (plan-gated); returns the IP list
GET    /v1/tenants/{t}/explain?zone=…               zone view, blast radius, incl. shares (§7.6)

# embedder (SaaS backend), tenant-scoped token
PUT    /v1/tenants/{t}/end-users/{external_id}      upsert; optional idp_subject
POST   /v1/tenants/{t}/connect-sessions             {end_user, provider, scopes?, purposes, return_url}
                                                    → {connect_url, expires_at}   # Nango/Pipedream-style
GET    /v1/tenants/{t}/connections?end_user=…       status only, never tokens
DELETE /v1/tenants/{t}/connections/{c}              revoke at provider + crypto-delete

POST   /v1/tenants/{t}/tasks                        Idempotency-Key header
  { template: "github-issue-triage@3",              # tenant- or platform-published, pinned by digest
    workspace, on_behalf_of: <user_assertion>,
    instructions: "…",                              # authored by U → trusted text at U's authority
    params: { repo: "acme/api", label: "bug" },     # typed by the template schema → trusted, sink-eligible
    attachments: [ {kind: "text", data: "…"} ],     # untrusted data → labelled handles, never sink sources
    budget: {usd: 2.00, wall: "30m"}, callback: {webhook_endpoint_id} }
  → 202 {task_id, status_url, events_url}
GET    /v1/tenants/{t}/tasks/{id}                   typed result fields + handle ids
GET    /v1/tenants/{t}/tasks/{id}/events            SSE, resumable (Last-Event-ID); content as handles
POST   /v1/tenants/{t}/tasks/{id}:cancel | :amend   amend = typed AmendTask, needs U's assurance level
GET    /v1/tenants/{t}/handles/{h}                  dereference: needs a cleared human principal; logged

GET    /v1/tenants/{t}/escalations?end_user=…&state=pending
POST   /v1/tenants/{t}/escalations/{r}/approval-sessions  {end_user}
                                                    → {embed_token, approval_url, expires_at}
POST   /v1/tenants/{t}/escalations/{r}/decisions    only for EmbedderAttested-level requests;
                                                    otherwise 409 "assurance_required: WicketPasskey"

GET    /v1/tenants/{t}/usage?group_by=workspace,end_user,meter&from=…&to=…
GET    /v1/tenants/{t}/quotas
POST   /v1/tenants/{t}/audit-exports                {from, to, format: ocsf|jsonl, sink}
PUT    /v1/tenants/{t}/audit-sinks/{s}              continuous export (S3/GCS with tenant role, HTTPS)
DELETE /v1/tenants/{t}/end-users/{external_id}      GDPR erasure → erasure receipt (async)

# cross-tenant sharing (§7)
POST   /v1/tenants/{t}/shares                       propose (provider side)
POST   /v1/tenants/{t}/shares/{s}:accept | :reject  consumer side (passkey)
DELETE /v1/tenants/{t}/shares/{s}                   either side may revoke, effective on the next Op
```

**Webhooks.** Signed per the Standard Webhooks spec (`webhook-id`, `webhook-timestamp`,
`webhook-signature`, HMAC, replay window). **Thin events**: ids, types, states and typed fields only;
never transcript content, never handle contents (consistent with "push payloads carry no data").
Tenant-configured endpoints are an egress `Op` of the platform: they go through the SSRF classifier and
are verified by a challenge before first use.

| Event | Payload (beyond ids) |
|---|---|
| `task.started` / `task.completed` / `task.failed` / `task.cancelled` | status, typed result fields, cost |
| `escalation.pending` | end user, risk class, required assurance, binding code, expiry — **no** justification text |
| `escalation.decided` / `escalation.expired` | decision, decider principal kind |
| `connection.needs_reauth` / `connection.revoked` | provider, end user |
| `usage.threshold` / `quota.exceeded` / `spend.cap_reached` | meter, value, cap |
| `share.proposed` / `share.accepted` / `share.revoked` | counterparty display name, kind |
| `audit.export.ready`, `erasure.completed` | receipt id |

**Embeddable approval flow (CIBA-shaped, end user decides inside the SaaS product).**

```
agent Op ─► gate: Pending R-123 (needs U, ≥ WicketPasskey)
wicketd ─► webhook escalation.pending {R-123, end_user=U, binding_code=K7Q2}
SaaS     ─► shows "Your agent needs approval" in its own UI / push / email
U clicks ─► SaaS backend POST …/escalations/R-123/approval-sessions {end_user: U}
           ◄─ embed_token (single use, 5 min, bound to (R-123, U, request digest))
SaaS UI  ─► renders <wicket-approval token=…> : a cross-origin iframe served from
           approve.<platform> or the tenant's white-label CNAME (WebAuthn related origins)
iframe   ─► fetches the TYPED request from wicketd (not from the SaaS page), renders
           provider·verb·resource·budget·blast-radius delta·binding code; justification folded, untrusted
U        ─► "Narrow and approve" → navigator.credentials.get() with challenge = H(digest ‖ narrowing)
           (iframe allow="publickey-credentials-get"; first use: passkey enrolment gated by the
            user assertion, or by the tenant IdP for federated tenants)
wicketd  ─► verifies assertion against U's registered key, writes the grant, webhook escalation.decided
agent    ◄─ await_grant returns / retry succeeds
```

Fallbacks, chosen by `ApprovalAssurance` and tenant policy: a hosted approval page (link in the SaaS's
email/push, same iframe content top-level), CIBA through the tenant's IdP (`binding_message` = binding
code), or `EmbedderAttested` for ≤ R2 when the tenant allows it. The SaaS controls the page around the
iframe, so the iframe never trusts anything the parent page sends except the embed token; clickjacking
defences are an approval-card requirement (a deliberate hold-to-confirm, `IntersectionObserver` v2
visibility checks where available, frame-ancestors limited to the tenant's registered origins).

**White-labelling.** Tenant CNAMEs for the approval and connect pages (`approve.saas.example` →
platform), tenant-branded OAuth consent screens via BYO OAuth clients, a theming API for the iframe.
What is never themable: the typed-request block, the binding code, the "untrusted" fold and the
assurance prompt, so a tenant cannot make a dangerous request look benign.

## 13. Changes to design.md, section by section

| § | Change |
|---|---|
| Header / §1 | Add a row: "Developer tool" → "also a multi-tenant platform for agentic SaaS (owner, 2026-11-08); tenants are hostile to each other; isolation by default, sharing only through cross-tenant gates". Cite research 14. |
| §2 Principles | **10. The tenant is the outermost boundary.** Every id, key, label class, store row, cache, pool binding and log chain is tenant-scoped; nothing mutable is shared across tenants except through a cross-tenant gate that both tenants and the platform approved. **11. One code path.** Single-tenant mode is tenant zero, not a different build. |
| §3 Architecture | Split `wicketd` into a **global directory** (TenantId → cell, nothing else) and **regional cells** (full control plane + nodes + stores). Add the embedding API and webhook dispatcher as clients of the API. In shared cells, **split sandbox nodes (tenant code, a forwarder, no secrets) from enforcement nodes** (egress/LLM/gateway as tenant-sharded workers, leases, CA keys, tenant egress IPs); node-local enforcement stays for single-host and Dedicated. |
| §4.1 | The ceiling chain becomes `platform ∧ plan ∧ tenant ∧ workspace ∧ every ancestor zone ∧ grant ∧ labels ∧ ledger`. Tenant/workspace Cedar is namespace-confined (validator rejects references to other tenants' entities; a `resource in Tenant::"T"` guard is injected), proved ⊆ ceiling with symcc for UX, and AND-ed at evaluation so a proof bug never widens. |
| §4.2 Labels | `DataClass` gains an owner (`Platform` or `Tenant(T)`); only the owner declassifies (Myers–Liskov DLM). Multi-owner labels need every owner's permission to flow. Handles carry `tenant` and use tenant-MACed ids. |
| §4.3 | `Zone` gains `tenant` and optional `parties` (joint zones, §7). `GateRule::CrossTenant { share: ShareId }` added. |
| §5 Manifests | Manifest gains `tenant`, `workspace`, `on_behalf_of: EndUserId`. Trusted text = template text + typed params + end-user instructions (at U's authority); embedder attachments are untrusted data. Templates come from the platform, the tenant, or a reviewed published artifact. |
| §6 Inner agents | LLM credentials resolve per tenant (platform key in the tenant's provider workspace, or BYO). `vendor_rc` is impossible in `MultiTenant` mode. |
| §7 Sandboxes | `MultiTenant` ⇒ floor ≥ gVisor; `process` disabled. Warm pools: pristine and shareable, bound once, **destroyed after use, never returned**. Snapshot images carry `tenant`; restore refuses a different tenant. KSM off across tenants; no SMT-sibling sharing between tenants. |
| §7.1 | Budgets per tier: add the forwarder hop latency (target ≤ 2 ms p95 in-region), per-tenant enforcement-worker overhead (target ≤ 30 MiB per tenant per enforcement node) and the tenants-per-node cap K to `wicket-bench`. |
| §8.1/8.2 | `InstanceScope::Shared` becomes `Shared { tenant }`; cross-tenant shared instances do not exist. A tenant-offered service is a `Share::Service`, run in the provider tenant's tenancy. |
| §8.3 | Tenants are not Kubernetes users; no tenant API access to clusters. Placement adds `TenantSpread { max_tenants_per_node }`, `Dedicated { tenant }` (exists), `CoreExclusive`, and derived host anti-affinity for tenant pairs a tenant marks as competitors. One cluster per cell; Silo = own cluster/account. |
| §8.4 | Residency pins a tenant to a cell; placement, stores, snapshots, model endpoints and egress IPs all derive from it. "Credentials to nodes" becomes "credentials to enforcement nodes": sandbox nodes in shared cells never receive leases; the vault releases a lease only to an attested enforcement worker serving a task the ledger placed. |
| §8.5 Money | Money envelope and worst-case reservation per tenant (and per workspace / user); the platform envelope remains above. Daily reconcile attributes provider charges to tenants (LLM per workspace/project, compute by usage records). |
| §9.1 Egress | Credential binding is `(tenant, subject, provider, connection) → (hosts, slot, format)`; the proxy resolves the box's transport identity (relayed by the node forwarder over mTLS, checked against the ledger's placement) → task → tenant → only that tenant's leases. Per-tenant source IP selection when dialling upstream. Internal hops carry a Transaction-Token-shaped context `{txn, sub, tctx}`. |
| §9.2 Gateway | Sessions keyed by (tenant, agent, route). Remote MCP OAuth tokens keyed by (tenant, end user, upstream). Cross-tenant service calls go through a `CrossTenant` gate. |
| §9.3 LLM proxy | Per-tenant provider workspace/project, per-tenant spend caps and reservation, prompt-cache isolation per tenant (provider workspace or `cache_salt`), BYO keys. |
| §9.4 Upstream creds | Vault becomes tenant- and subject-scoped, envelope-encrypted with tenant KEKs (BYOK option); end-user OAuth connections with per-purpose consent; prefer installation/tenant credentials, user credentials only when actions must be attributed to the user. |
| §11 Escalation | Approver resolution by `ApproverRule` (credential subject vs tenant role); `ApprovalAssurance` per risk; the embedder can never decide above `EmbedderAttested`. Ratchet and fatigue metrics per (tenant, approver). |
| §12 Memory | Task memory per tenant; persistent memory needs the tenant's decider; **erasure**: per-user and per-tenant crypto-shredding, provider-side token revocation, erasure receipts, backup tombstones. |
| §13.1 | New channel kind `Embedded { tenant }` (the iframe) and `TenantIdpCiba`. Console gains tenant-admin and platform-operator views; platform operators see tenant metadata, not tenant content, unless break-glass (two-person, announced to the tenant, logged in both chains). |
| §13.2 | `explain` and the zone view are tenant-scoped and include inbound and outbound shares as "external tenant" nodes showing only the interface the other side exposed. Audit: per-tenant chains, per-tenant salts, OCSF export, retention per tenant within plan bounds. |
| §14 Crates | Add `wicket-tenancy` (types), `wicket-api` (embedding API, webhooks), `wicket-meter` (usage records, quotas, reservations), `wicket-kms` (envelope encryption, KEK providers, BYOK), `wicket-share` (shares, cross-tenant gates). `wicket-store` gains `Scoped<T>`. Fix the duplicate `wicket-operator` name (kube operator vs operator channels → rename the latter `wicket-channels`). |
| §15 Milestones | Add T0–T8 below; T0 lands with M0 so tenant ids are never retrofitted. |
| §16 Decisions | Add: cells; tenants are not Kubernetes principals; gVisor floor in MultiTenant; tenant-sharded enforcement from PooledHardened; DLM owner labels; reference-not-copy sharing; Cedar (not OpenFGA) for the control plane in v1. |
| §17 Open questions | Add the questions in §16 of this note. |

## 14. Conformance and red-team tests for cross-tenant isolation

Every test runs with two tenants A and B on the same node, cell and pool, at each tier. A test passes only if
the attack fails **and** the attempt appears in A's audit chain (and in B's, where B was targeted).

**Control plane**
1. **Authorization matrix (IDOR sweep).** For every endpoint × every id kind, a token of A addressing B's id
   returns 404 and leaks nothing in timing or error shape. Generated from the OpenAPI spec, run in CI.
2. **Embedder confusion.** A per-tenant embedder key for A cannot start a task, read a handle or create an
   approval session for B; a user assertion with `tenant=B` signed by A's embedder is rejected.
3. **Delegated admin can't widen.** A tenant admin uploads policies that try to widen (permit outside the
   ceiling, reference `Tenant::"B"`, raise `auto_max_risk`, enable `process`); each is rejected with a symcc
   counter-example, and a deliberately broken symcc still yields no wider decision (evaluation chain).
4. **Approval assurance.** An `EmbedderAttested` decision for an R3 request is refused; an approval-session
   token for (R-1, U) cannot approve (R-2, U) or (R-1, V); replay fails.

**Data plane**
5. **Credential isolation.** A's box presents B's placeholder in the declared slot: no injection, anomaly
   raised in both chains. A's proxy worker has no B leases in memory (PooledHardened: different process;
   Pooled: partition check fuzzed).
6. **Handle forgery.** Random, guessed, replayed and B-issued handle ids passed by A's agent as tool
   arguments, gate inputs and `read_handle` calls: all refused without an existence oracle.
7. **Label namespace spoofing.** A defines `t:B/source`, or an adapter labels A's data with B's owner:
   rejected at load.
8. **Warm pool and snapshot reuse.** A claimed sandbox is never seen again by any tenant (pool sequence
   numbers); restoring A's snapshot into B's zone is refused; platform templates restored for B carry no A
   bytes (canary file and memory canary from A's earlier use).
9. **Memory and CPU side-channel hygiene.** KSM is off or excludes tenant workloads (`/sys/kernel/mm/ksm`
   check per node); no two tenants on SMT siblings (topology check of pinned cpusets); a Flush+Reload /
   Prime+Probe covert-channel probe between A and B boxes measured and reported per tier.
10. **Prompt-cache isolation.** A seeds a long unique prefix; B sends the same prefix: B's response shows no
    cache-read tokens and no TTFT difference (statistical test, Gu et al. method) — run against each
    upstream route (provider workspace per tenant, self-hosted vLLM with `cache_salt`).
11. **MCP instance sharing.** A manifest asking for `Shared` scope on a server already serving B is rejected;
    an MCP server instance's state written for A is absent for B.
12. **Network.** From A's box: no route to B's box, B's MCP servers, node services, metadata, DNS (existing
    M4b probes, now with two tenants); A's egress leaves from A's IPs only (echo service sees the source IP);
    B's dedicated IPs are never used for A.
13. **Noisy neighbour.** A runs fork bombs, memory balloons, disk fill, egress floods, escalation storms and
    LLM-token floods at its quota; B's task p95 latency, warm-pool claim latency and LLM-proxy latency stay
    within an agreed delta (e.g. +10 %); A's overrun is refused by quota, not by capacity exhaustion.
14. **Metering attribution.** Over a seeded workload, Σ usage per tenant reconciles with provider invoices
    and node accounting to within rounding; duplicate usage events (retries) are dropped by idempotency key.
15. **Node compromise drill.** Dump a shared sandbox node's memory: no credential leases, CA keys or model
    keys at all; tenants on the node ≤ K; forged box-identity claims for boxes placed elsewhere are rejected
    by the ledger. Dump an enforcement node: only leases for its shards, audience-bound, ≤ 1 h, useless
    from any other worker.
16. **Erasure.** Erase end user U: vault records undecryptable, provider tokens revoked (verified at the
    provider), handles and transcripts tagged with U's key unreadable, audit commitments unlinkable,
    receipt issued; restore an older backup and verify tombstones re-apply.
17. **Residency.** A UK-resident tenant's sandboxes, stores, snapshots, model calls and egress all stay in
    UK cells; a placement override is refused.

**Cross-tenant sharing (§7)**
18. **Consent.** A share without both admins' passkey decisions, or past either plan's `SharingCeiling`, or
    across jurisdictions without platform policy, never activates.
19. **Revocation latency.** After either side revokes, the next `Op` using the share is denied (target: ≤ 1 s,
    ledger-side); in-flight handles from the share become unreadable.
20. **Owner tags hold.** B's agent reads A's shared data (`KeepOwnerTag`) and tries to send it to a
    destination A did not permit, via a GET URL, a PR body, a webhook and a cross-tenant call back to a
    third tenant C: all denied.
21. **Delegation confused deputy.** C's agent tries to use B's grant to A (wrong grantee), A's agent from an
    unlisted zone template, or without the external id: all denied. Sink provenance must trace to A's task
    text *and* fall inside B's grant.
22. **Service calls.** B calls A's MCP service: A's service never receives B's credentials; B's arguments
    arrive labelled `t:B` and A's service zone cannot send them anywhere B didn't clear; A's results arrive
    in B labelled `t:A`.
23. **Offboarding.** A leaves: references held by B die, transfers made earlier remain B's, joint-zone
    records stay in both chains as commitments, and both tenants' explain views update.

## 15. Milestones

Inserted into design.md §15. T0 must land with M0; the rest can follow M3b without blocking the security
core.

| # | Milestone | Done when |
|---|---|---|
| **T0** | `TenantId` in every id, `Scoped<T>` store API, owner-tagged `DataClass`, tenant-MACed handle ids, per-tenant ledger partition and hash chain; single-tenant mode = tenant zero | Property tests: no store method compiles without a tenant; label join with two owners needs both owners' flow permission; a handle id from tenant A fails verification under B. |
| **T1** | Control-plane authz (Cedar entities Platform > Plan > Tenant > Workspace > EndUser), tenant policy ⊆ plan ceiling via symcc + evaluation chain, tenant admin console views, embedder keys, embedding API v0 (tasks, events, escalations), Standard-Webhooks dispatcher | Tests 1–4 pass; the IDOR sweep is a CI gate. |
| **T2** | Vault per tenant and subject: envelope encryption (`wicket-kms`, platform KMS + encryption context; BYOK behind a feature), end-user connections with connect sessions and per-purpose consent, BYO OAuth clients, credential leases audience-bound to nodes | Test 5 and 15; a GitHub-issue-triage task runs for two tenants and two end users on one node with no credential crossing. |
| **T3** | Embeddable approval: iframe + passkeys (related origins for tenant CNAMEs), approval sessions, `ApprovalAssurance`, CIBA via a tenant IdP, white-label theming with fixed security blocks | An end user approves an R3 escalation inside a demo SaaS page; E-OP1 phishing red-team rerun against the embedded card (malicious parent page). |
| **T4** | Metering and quotas: usage records from every enforcement point, per-tenant reservations and spend caps in the LLM proxy and provisioner, rate limits, weighted fair queueing for warm-pool claims | Tests 13–14. |
| **T5** | Placement tiers: sandbox/enforcement node split with the box forwarder, tenant spread cap, tenant-sharded enforcement workers (shared and per-tenant process), whole-core cpusets respecting SMT siblings / core scheduling, KSM and swap off, preflight of CPU mitigations, dedicated pools, per-tenant static egress IPs, per-tenant LLM provider workspaces and cache salts | Tests 6–12 and 15, measured per tier in `wicket-bench`: the extra forwarder hop and per-tenant worker overhead within budget. |
| **T6** | Cells and residency: global directory, two regional cells, residency-derived placement, regional stores and model endpoints | Test 17; a cell outage leaves other cells' tenants unaffected. |
| **T7** | Audit export (OCSF, tenant sinks), retention policies, erasure (per user, per tenant) with receipts and backup tombstones, break-glass with dual logging | Test 16; an auditor-style export reproduces a task's grant timeline from the tenant's chain alone. |
| **T8** | Cross-tenant sharing: `wicket-share`, bilateral consent, cross-tenant gates, reference shares with owner tags, artifact publication with review and pinning, service shares, delegation grants with external ids, explain views for both sides | Tests 18–23. |
| **T9** | Cross-tenant red team: an adaptive attacker controlling tenant A (admin, end users, agents, MCP servers, published artifacts) against tenant B on shared infrastructure | Escapes found ≤ 3, each turned into a rule or a test; zero credential or content crossings. |
---

## 16. Open questions

1. **Enforcement-node hop.** Does the sandbox → enforcement-node forwarder stay within budget for chatty
   agents (git store-and-forward, SSE streams)? Measure in T5; if not, PooledHardened could run per-tenant
   enforcement workers on sandbox nodes that host only that tenant's boxes.
2. **K (tenants per node)** and the shuffle-shard shape: a cost model is needed per provider and node
   size.
3. **Who is the user, really?** For tenants that do not federate their IdP, the embedder is in the TCB for
   end-user identity. Is `EmbedderAttested` ≤ R2 the right default, or should passkey enrolment require
   an out-of-band proof (email to the tenant's verified domain)?
4. **Cross-origin passkeys in iframes** across browsers, and WebAuthn related origins for tenant CNAMEs:
   verify current browser support before T3 [M].
5. **2-of-2 content keys for multi-owner data**: cost and complexity versus simply refusing multi-owner
   derived content in pooled tiers.
6. **Provider workspace limits**: Anthropic allows 100 workspaces per organization by default [H]. At
   thousands of tenants, tenants share workspaces in buckets (and so share caches), or the platform runs
   several organizations. Which tenants get exclusive workspaces?
7. **Model residency** for EU tenants: Bedrock/Vertex/Foundry regional endpoints vs self-hosted, and what
   that does to the prompt-cache isolation rule (Bedrock and Vertex isolate per organization or account
   only).
8. **Published-artifact review**: who reviews (the platform operator, automated checks, both), and what
   evidence lowers a published adapter's risk below R4 for consumers.
9. **OpenFGA later?** If object-level cross-tenant sharing grows into a large relationship graph, does
   wicket add a relationship engine beside Cedar?
10. **Erasure vs audit**: legal sign-off on "crypto-shredded commitments are beyond use" for EU tenants.
11. **Billing for services and joint zones**: platform-mediated settlement between tenants, or out of
    scope (metering only)?
12. **BYOC cells**: which parts stay with the platform operator (directory, artifact registry, updates),
    and what flows back (metrics only, as E2B BYOC does [H])?

## 17. Sources

**Sandbox platforms.** E2B: https://e2b.dev/security.md · https://docs.e2b.dev/sandbox/rate-limits ·
https://docs.e2b.dev/faq/egress-ip-ranges · https://docs.e2b.dev/sandbox/internet-access ·
https://docs.e2b.dev/byoc.md. Daytona: https://www.daytona.io/docs/en/isolation ·
https://www.daytona.io/docs/en/limits · https://www.daytona.io/docs/en/network-limits ·
https://www.daytona.io/docs/en/bring-your-own-compute.md. Modal: https://modal.com/docs/guide/sandbox-networking ·
https://modal.com/docs/guide/security · https://modal.com/docs/guide/environments ·
https://modal.com/docs/guide/proxy-ips · https://modal.com/docs/guide/region-selection. Fly:
https://docs.fly.io/networking/private-networking · https://docs.fly.io/networking/egress-ips ·
https://fly.io/sprites-blog/running-untrusted-code/. Cloudflare:
https://developers.cloudflare.com/workers/reference/security-model/ ·
https://developers.cloudflare.com/cloudflare-for-platforms/workers-for-platforms/reference/how-workers-for-platforms-works/ ·
https://developers.cloudflare.com/cloudflare-for-platforms/workers-for-platforms/configuration/outbound-workers/ ·
https://blog.cloudflare.com/dynamic-workers · https://developers.cloudflare.com/sandbox/concepts/security/.
Vercel: https://vercel.com/docs/sandbox/concepts · https://vercel.com/docs/sandbox/concepts/firewall.md ·
https://vercel.com/docs/vercel-sandbox. Browserbase: https://docs.browserbase.com/account/enterprise/security.md ·
https://docs.browserbase.com/platform/browser/core-features/contexts.md. Replit:
https://docs.replit.com/build/code/security. Lovable: https://modal.com/blog/lovable-case-study ·
https://www.tenable.com/cve/CVE-2025-48757. Devin: https://docs.devin.ai/enterprise/vpc/overview.md. Cursor:
https://cursor.com/docs/cloud-agent/security · https://cursor.com/docs/cloud-agent/self-hosted.

**Incidents.** https://www.wiz.io/blog/wiz-and-hugging-face-address-risks-to-ai-infrastructure ·
https://www.wiz.io/blog/wiz-research-discovers-critical-vulnerability-in-replicate ·
https://www.wiz.io/blog/sapwned-sap-ai-vulnerabilities-ai-security ·
https://www.wiz.io/blog/chaosdb-how-we-hacked-thousands-of-azure-customers-databases ·
https://www.wiz.io/blog/wiz-research-critical-nvidia-ai-vulnerability ·
https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape ·
https://therecord.media/sandbox-vulnerability-gives-rogue-ai-agents-path-out.

**Hosted runtimes.** AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-sessions.html ·
…/runtime-security-best-practices.html · …/bedrock-agentcore-limits.html · …/identity-terminology.html ·
…/get-workload-access-token.html · …/oauth2-authorization-url-session-binding.html · …/identity-consent-portal.html ·
…/gateway.html · …/gateway-interceptors.html · …/policy.html · …/data-encryption.html · …/memory-organization.html ·
https://aws.amazon.com/blogs/machine-learning/building-multi-tenant-agents-with-amazon-bedrock-agentcore/ ·
https://aws.amazon.com/blogs/machine-learning/shared-infrastructure-isolated-tenants-pool-model-multi-tenancy-with-amazon-bedrock-agentcore.
Google: https://docs.cloud.google.com/vertex-ai/generative-ai/docs/agent-engine/overview ·
https://docs.cloud.google.com/agent-builder/agent-engine/agent-identity · https://docs.cloud.google.com/iam/docs/auth-with-3lo-v2 ·
https://docs.cloud.google.com/agent-builder/agent-engine/sessions/iam-conditions. Anthropic:
https://platform.claude.com/docs/en/managed-agents/overview · …/managed-agents/secure-deployment-risks ·
…/managed-agents/self-hosted-sandboxes · …/managed-agents/vaults · …/managed-agents/mcp-connector ·
…/manage-claude/workspaces · …/manage-claude/data-residency · …/build-with-claude/prompt-caching. OpenAI:
https://developers.openai.com/api/docs/deprecations · …/guides/agents-api/overview.md ·
…/guides/agents-api/environments/security.md · …/guides/spend-limits.md · …/guides/your-data ·
…/guides/prompt-caching. Microsoft: https://learn.microsoft.com/azure/foundry/agents/concepts/standard-agent-setup ·
https://learn.microsoft.com/azure/foundry/agents/concepts/hosted-agents. Cache side channel:
https://arxiv.org/html/2502.07776v2 · https://arxiv.org/abs/2411.18191 · https://docs.vllm.ai/en/latest/design/prefix_caching.html.

**Credential brokering.** https://pipedream.com/docs/connect/api-proxy · …/managed-auth/tokens ·
…/managed-auth/oauth-clients · https://docs.arcade.dev/en/operate/deploy/architecture ·
https://docs.arcade.dev/en/home/auth/secure-auth-production ·
https://arcade.dev/blog/arcade-proactively-addressed-coat-vulnerability-in-agentic-ai ·
https://docs.composio.dev/docs/authentication · https://docs.composio.dev/docs/auth-configuration/white-labeling ·
https://nango.dev/docs/reference/backend/http-api/connect/sessions/create.md · https://www.nango.dev/docs/guides/platform/security ·
https://auth0.com/ai/docs/intro/token-vault · https://auth0.com/ai/docs/intro/asynchronous-authorization ·
https://workos.com/docs/pipes/token-proxy · https://workos.com/blog/workos-pipes-where-your-users-tokens-actually-live ·
https://docs.descope.com/agentic-identity-hub/core-components/connections · https://developer.okta.com/blog/2026/07/06/submit-oin-xaa.
MCP: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization ·
https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices ·
https://modelcontextprotocol.io/specification/2026-07-28/changelog ·
https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation · https://github.com/modelcontextprotocol/ext-auth.
Standards: https://www.rfc-editor.org/rfc/rfc8693.html · https://www.rfc-editor.org/rfc/rfc9396.html ·
https://www.rfc-editor.org/rfc/rfc9449.html · https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html ·
https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/ ·
https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/ ·
https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/ ·
https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow ·
https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app ·
https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app. Keys:
https://docs.aws.amazon.com/kms/latest/developerguide/resource-limits.html · …/requests-per-second.html ·
…/encrypt_context.html · …/keystore-external.html · …/grants.html · …/deleting-keys.html ·
…/key-policy-modifying-external-accounts.html ·
https://aws.amazon.com/blogs/architecture/simplify-multi-tenant-encryption-with-a-cost-conscious-aws-kms-key-strategy/ ·
https://developer.hashicorp.com/vault/docs/secrets/transit.

**Kubernetes, side channels, authz, metering.** https://kubernetes.io/docs/concepts/security/multi-tenancy/ ·
https://docs.aws.amazon.com/eks/latest/best-practices/tenant-isolation.html ·
https://docs.cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods · https://gvisor.dev/docs/architecture_guide/security/ ·
https://vcluster.com/docs/vcluster/configure/tenancy-model · https://github.com/kubernetes-retired/hierarchical-namespaces ·
https://docs.cilium.io/en/stable/network/egress-gateway/egress-gateway/ ·
https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md ·
https://docs.kernel.org/admin-guide/hw-vuln/core-scheduling.html · https://docs.kernel.org/admin-guide/hw-vuln/attack_vector_controls.html ·
https://docs.kernel.org/admin-guide/hw-vuln/vmscape.html · https://arxiv.org/abs/2405.12469 ·
https://docs.aws.amazon.com/whitepapers/latest/security-design-of-aws-nitro-system/the-ec2-approach-to-preventing-side-channels.html ·
https://docs.cloud.google.com/compute/docs/nodes/sole-tenant-nodes ·
https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/design-multi-tenancy-considerations.html ·
https://docs.cedarpolicy.com/policies/templates.html · https://docs.rs/cedar-policy-symcc ·
https://openfga.dev/docs/use-cases/multi-tenant-saas · https://authzed.com/docs/spicedb/concepts/caveats ·
https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/silo-pool-and-bridge-models.html ·
https://builder.aws.com/content/3Eupj3d2bo4fEvlzYbICMZNhQ3B/fairness-in-multi-tenant-systems ·
https://builder.aws.com/content/3F06NpJ8YeoIGP8VHTw4n81pFn8/workload-isolation-using-shuffle-sharding ·
https://github.com/cloudevents/spec/blob/main/cloudevents/spec.md · https://github.com/openmeterio/openmeter ·
https://docs.stripe.com/billing/subscriptions/usage-based/recording-usage-api ·
https://schema.ocsf.io/classes/api_activity · https://schema.ocsf.io/1.9.0/profiles/ai_operation.

**Compliance.** https://artificialintelligenceact.eu/article/12/ · …/article/19/ · …/article/26/ ·
https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng · https://gdpr-info.eu/art-17-gdpr/ · https://gdpr-info.eu/art-28-gdpr/ ·
https://www.law.cornell.edu/cfr/text/45/164.312 · https://www.law.cornell.edu/cfr/text/45/164.316 ·
https://www.digital-operational-resilience-act.com/Article_30.html.

**Sharing.** https://docs.aws.amazon.com/ram/latest/userguide/getting-started-sharing.html ·
https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html ·
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html ·
https://www.praetorian.com/blog/aws-iam-assume-role-vulnerabilities/ ·
https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html ·
https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_data-perimeters.html ·
https://docs.snowflake.com/en/user-guide/data-sharing-intro · https://docs.snowflake.com/en/user-guide/data-sharing-provider ·
https://docs.snowflake.com/en/collaboration/provider-understand-cost-auto-fulfillment ·
https://docs.snowflake.com/en/user-guide/cleanrooms/introduction · https://docs.databricks.com/aws/en/delta-sharing/ ·
https://github.com/delta-io/delta-sharing/blob/main/PROTOCOL.md · https://docs.databricks.com/aws/en/delta-sharing/create-recipient-token ·
https://slack.com/help/articles/115005912706 · https://slack.com/intl/en-gb/help/articles/115004152843 ·
https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview ·
https://learn.microsoft.com/en-us/microsoftteams/shared-channels ·
https://knowledge.workspace.google.com/admin/domains/allow-external-sharing-with-only-trusted-domains ·
https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization ·
https://spiffe.io/docs/latest/architecture/federation/readme/ · https://docs.cloud.google.com/iam/docs/workload-identity-federation ·
https://gateway-api.sigs.k8s.io/reference/api-types/referencegrant/ ·
https://docs.aws.amazon.com/marketplace/latest/userguide/metering-for-usage.html ·
https://shopify.dev/docs/apps/launch/app-store-review/review-process.
