# 18 — Authorization landscape: policy engines, distribution, capability tokens, relationship stores

Research date: 2026-11-10. Prompted by the owner's view that the picks in #51 and #57 (cedar-local-agent as
the node decision point, OPAL for distribution, Amazon Verified Permissions and Janssen as optional backends)
showed a poor grasp of the landscape. This is a fresh survey that doesn't start from those picks. It covers what
exists, what each thing actually does, how healthy it is, and how the pieces could fit together for wicket.

Context read first: design §2, §2.1, §3.2, §5.1, §11; issues #5, #11, #27, #34, #50, #51, #56, #57; research
[03] and [08].

Confidence tags, as in [03], [10], [14], [15]:
- **[H]** verified in this session against a primary source: the project's repo, source code, docs, release
  page, or the GitHub and crates.io APIs;
- **[M]** from a reputable secondary source, or from the author's knowledge of primary sources, not re-read
  in this session;
- **[L]** unverified, or likely to have changed.

Repository figures (last release, commits, contributors) come from the GitHub and crates.io APIs on
2026-11-10. "Commits in 3 months" counts commits on the default branch since 2026-08-10, capped at 100 by the
API. "Regulars" counts contributors with at least 5 commits.

---

## 0. Summary: the five things that matter

1. **No single product fits, because wicket's problem is really three problems.** The market has three
   kinds of thing:
   - *policy engines* (Cedar, OPA/Rego, Cerbos, Casbin) check one request against rules and data you hand
     them;
   - *relationship stores* (SpiceDB, OpenFGA, Keto, Permify) are central servers that answer "is X related
     to Y";
   - *capability tokens* (Biscuit, UCAN, macaroons, ZCAP) carry authority that has been delegated and
     narrowed, and can be checked offline.

   Runtime delegation that only narrows (R2, R3) is a capability problem. Org rules (R5) are a
   policy-engine problem. wicket's relationship data (R6) is small and mostly tree-shaped, and a Zanzibar
   server in the request path would break R1. **Nothing in the relationship-store family decides on the
   node** except Topaz, whose company closed in 2025, and AuthZed Materialize, which is a commercial
   early-access product. [H]

2. **Every system that really guarantees "children can't exceed parents" does it by intersection, not by
   proof.** The examples:
   - AWS session policies and permission boundaries: effective permissions are the *intersection* [H];
   - Biscuit attenuation blocks can only add checks [H];
   - Cerbos scopes with `REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS`: "leaf nodes can only restrict access" [H];
   - Kubernetes RBAC refuses to create a role or binding unless the creator already holds every permission
     in it, the exact rule #50 wants for granting [H].

   A solver is useful for explaining a refusal before spawn, and for reviewing org policy. It shouldn't be
   the guarantee.

3. **Cedar is the right language for org rules, but the "templates plus entities" plan in #51 doesn't work
   as written.** Read in the source [H]:
   - SymCC **rejects template-linked policies**: "template-linked policies are not supported".
   - SymCC proves properties for *all* entity stores, so authority stored as entity data isn't covered by
     the proof.
   - Cedar's `like` pattern **must be a literal in the policy text**.
   - Templates have only two slots (`?principal`, `?resource`). Generalised templates are still an open
     RFC (#98).
   - Cedar can't quantify over a set of records.

   So a grant like "GET api.github.com/repos/x/*" can't be data matched by one fixed template. It has to be
   policy text generated per grant or zone, or live outside Cedar.

4. **cedar-local-agent, avp-local-agent, OPAL and Cedarling add little and cost a dependency.** The
   evidence [H]:
   - cedar-local-agent is about 4,000 lines of file loaders, polling and OCSF logging around the
     `cedar-policy` crate. Its last release was 3.0.0 on 2025-04-29, with no code commits since.
   - avp-local-agent ties wicket to AWS and needs refreshes of at least 15 s.
   - OPAL is Python, still on 0.10 release candidates, and its docs say nothing about signing.
   - Cedarling is built around principals derived from JWTs, and its signed policy stores are still a
     draft (jans#15414, open).

   **None of them signs incremental updates or fails narrow when it can't refresh.** OPA, the most mature
   distribution system, keeps serving its last good bundle, and its delta bundles *cannot* be signed [H].
   Freshness and fail-narrow therefore have to be wicket's own code, about 1–2k lines. TUF's design is the
   model to borrow.

5. **Recommendation: Architecture A (§5.1).**
   - Zone ceilings and leases are **Biscuit** chains: Rust, Apache-2.0, Eclipse Foundation, offline
     verification, narrowing by construction, revocation IDs, third-party blocks for approvals.
   - Org rules are **Cedar**, using the `cedar-policy` crate directly, with SymCC in CI.
   - **wicket's own signed snapshot and delta feed** carries a freshness lease to each node.
   - Relationship data stays in wicketd and becomes Cedar entities on each node. **OpenFGA** is an optional
     source later, for sharing in platform mode.

   Biscuit is the one dependency with thin maintenance: 6 regulars, last release 2025-07-16, but active
   commits this month. It's about 20k lines, Apache-2.0, and wicket uses a small part of it, so forking
   is a realistic fallback.

---

## 1. Requirements (columns of the comparison)

| | Requirement | Short form in the tables |
|---|---|---|
| R1 | Decides on the node with no per-request round trip; revocation within a known bound; fails narrow when the node can't refresh | local / revoke / narrow |
| R2 | Highly dynamic authority: zones spawned many times an hour; grants per approval as time-limited, possibly single-use leases on any resource | dynamic |
| R3 | Delegation only narrows; children can't exceed parents; humans default to everything; ideally by construction and checkable offline | narrowing |
| R4 | Signed policy and grant artifacts; audit and decision logs | integrity / logs |
| R5 | Org rules (images, hosts, escalation rights, inspection rights, operator roles) reviewable and ideally analysable (containment, equivalence) | analysable |
| R6 | Relationship data: who owns which agent, tenant sharing, chains back to a human | relationships |
| R7 | Rust-native or embeddable in a Rust daemon; multi-tenant; self-hostable on any cloud | Rust / self-host |
| R8 | Maintenance health, licence, and whether forking or vendoring is viable | health |

---

## 2. Comparison table

Key: **yes** = meets it out of the box; **part** = meets some of it, or with work wicket must do; **no** =
doesn't, or works against it; **n/a** = not that kind of component.

### 2.1 Against the requirements

| Candidate | R1 local / revoke / narrow | R2 dynamic | R3 narrowing | R4 integrity / logs | R5 analysable | R6 relationships | R7 Rust / self-host | R8 health |
|---|---|---|---|---|---|---|---|---|
| **Cedar** (`cedar-policy` + SymCC) | part: evaluates in-process; no distribution or revocation | part: entities and tags are data, but patterns must be literal policy text | part: no delegation concept; intersection of policy sets works; SymCC proves `implies` for static policies | no: bring your own | **yes**: validator, SymCC, Lean-modelled semantics | part: entity hierarchy (`in`) | **yes**: Rust crate, Apache-2.0 | **strong** |
| cedar-local-agent | part: file polling, no push, no signing | part | no | part: OCSF logs | (Cedar's) | (Cedar's) | yes | **weak**: no code commits since 2025-04 |
| Amazon Verified Permissions + avp-local-agent | part: cache refreshed at least every 15 s | part | no | part: CloudTrail | (Cedar's) | part | **no**: AWS only | part: service yes, local agent stale |
| Janssen Cedarling + Lock | part: local; refresh; OAuth status lists | part: JWT-centred | no | part: Sigstore store signing on a branch; signed decision evidence | (Cedar's) | part: from JWT claims | part: Rust crate, Janssen-shaped | active |
| **OPA** | part: local; long polling; keeps last good (no fail-narrow) | part: push API, delta bundles | no | **yes**: signed snapshot bundles, decision logs with masking (deltas unsigned) | part: tests and coverage only | part: JSON data | part: Go sidecar or Wasm; Rust only via regorus | strong code; governance changed 2025 |
| regorus (Rust Rego) | part: engine only | part | no | no | part: coverage | part | **yes**: Rust, `no_std`, MIT | strong (Microsoft) |
| Cerbos PDP (+ Hub) | part: local PDP; Hub pushes | part: policy files | part: narrow-only scopes, but static | part: Hub signs and encrypts bundles, collects audit (commercial) | part: policy tests | part: derived roles | part: Go service; Rust SDK is a client | active; one vendor |
| Casbin (casbin-rs) | part | part | no | no | no | part: role graph | yes | ok; Apache podling |
| Oso (Polar) | no | — | — | — | — | — | — | **archived** |
| OPAL | part: websocket push | yes: data push | n/a | **no signing** documented | n/a | n/a | part: Python | 0.10 still RC |
| **SpiceDB** | **no**: central server | **yes**: expiring relationships (GA), caveats | no | no | part: schema tests | **yes** | part: Go + DB; no official Rust client | active; one vendor |
| **OpenFGA** | **no**: central server | yes: CEL conditions, time windows | no | no | part: model tests | **yes** | part: Go + DB | active; CNCF incubating |
| Ory Keto / Oathkeeper | no | part | no | no | part | yes | part: Go | slower |
| Permify | no | yes | no | no | part | yes | part: Go; **AGPL-3.0** | active; owned by FusionAuth |
| Topaz | **yes**: local embedded directory + OPA | part | no | part: decision logs | part | yes | part: Go | company closed 2025 |
| **Biscuit** | **yes**: verify with the root public key; revocation list pushed | **yes**: short-lived tokens; ledger facts for use counts | **yes, by construction**; third-party blocks | **yes**: signed by design; revocation IDs | part: Datalog, no analyser | no | **yes**: Rust, Apache-2.0 | moderate; forkable |
| Macaroons | yes | yes | yes | part: HMAC, so any verifier can mint | no | no | part: crate stale | stale |
| UCAN 1.0 | yes | yes | yes | yes | part: small policy language | no | part: DID/IPLD; Rust implementation stale | spec active; Rust not |
| ZCAP-LD | yes | yes | yes | yes | no | no | no: JSON-LD, JavaScript | W3C CCG work item |
| SPIFFE/SPIRE | n/a: identity | — | — | yes: SVIDs | — | — | yes: `spiffe` crate | strong (CNCF) |
| Envoy ext_authz | **no**: remote call per request | — | — | — | — | — | — | strong |
| AuthZEN 1.0 | n/a: PEP↔PDP API standard | — | — | — | — | — | — | Final since 2026-01 |
| Kubernetes RBAC / ValidatingAdmissionPolicy | n/a: precedent | — | escalate/bind rule | — | — | — | — | — |

### 2.2 Maintenance facts (R8) [H, GitHub and crates.io APIs, 2026-11-10]

| Project | Latest release | Commits in 3 months | Regulars | Stars | Licence | Backing |
|---|---|---|---|---|---|---|
| cedar-policy/cedar | v4.14.1, SymCC 0.8.1 (2026-11-02) | 92 | 20 | 1.9k | Apache-2.0 | AWS staff; CNCF Sandbox since 2025-10-08 |
| cedar-policy/cedar-local-agent | 3.0.0 (2025-04-29) | 0 | 5 | 33 | Apache-2.0 | AWS; dormant |
| awslabs/avp-local-agent | 3.0.0 (2025-04-30) | 0 | — | 21 | Apache-2.0 | AWS; dormant |
| cedar-policy/cedar-for-agents | mcp schema generator 0.7.0 (2026-10-22) | 62 | 5 | 59 | Apache-2.0 | AWS |
| cedar-policy/cedar-access-control-for-k8s | none | 1 | 1 | 149 | Apache-2.0 | "no longer maintained" |
| JanssenProject/jans (Cedarling) | v2.6.1; `cedarling` crate 2.6.1 (2026-11-10) | 100+ | 69 | 657 | Apache-2.0 | Janssen Project, Linux Foundation [M] |
| open-policy-agent/opa | v1.22.2 (2026-11-06) | 100+ | 56 | 12.5k | Apache-2.0 | CNCF graduated [M]; core maintainers at Apple |
| microsoft/regorus | 0.15.0 (2026-11-09) | 100+ | 12 | 369 | MIT | Microsoft |
| permitio/opal | 0.10.0-rc.6 (2026-11-10, pre-release) | 31 | 27 | 5.5k | Apache-2.0 | Permit.io |
| permitio/cedar-agent | 0.2.2 (2025-10-16) | 0 | 5 | 205 | Apache-2.0 | Permit.io |
| cerbos/cerbos | v0.57.0 (2026-10-23) | 100+ | 12 | 4.7k | Apache-2.0 | Cerbos (one vendor) |
| apache/casbin-rs | 2.20.0 (2026-02-04) | 11 | 8 | 1.2k | Apache-2.0 | ASF Incubator since 2026-02-07 |
| osohq/oso | 0.27.3 (2024-01-13) | — | 12 | 3.5k | Apache-2.0 | **archived**: "Legacy Oso open source library" |
| authzed/spicedb | v1.57.0 (2026-10-20) | 100+ | 18 | 7.2k | Apache-2.0 | AuthZed (one vendor) |
| openfga/openfga | v1.22.1 (2026-10-28) | 52 | 23 | 6.1k | Apache-2.0 | CNCF Incubating since 2025-10-28; Okta/Auth0 staff [M] |
| ory/keto | v26.2.0 (2026-03-20) | 0 (last 2026-07-29) | 20 | 5.4k | Apache-2.0 | Ory |
| Permify/permify | v1.7.6 (2026-11-05) | 100+ | 21 | 6.0k | **AGPL-3.0** | FusionAuth (acquired 2025-11) |
| aserto-dev/topaz | v0.33.26 (2026-11-06) | 29 | 8 | 1.4k | Apache-2.0 | community; Aserto wound down 2025 |
| warrant-dev/warrant | v1.15.1 (2024-06-10) | 0 | 4 | 1.3k | Apache-2.0 | WorkOS; dormant [M] |
| eclipse-biscuit/biscuit-rust | biscuit-auth 6.0.0 (2025-07-16) | 40 | 6 | 254 | Apache-2.0 | Eclipse Foundation |
| ucan-wg/rs-ucan | ucan 0.4.0 (2023-06-28) | 0 | 5 | 93 | Apache-2.0 | dormant |
| macaroon (crate) | 0.3.0 (2022-10-13) | — | — | — | MIT | dormant |
| spiffe/spire | v1.16.0 (2026-11-05) | 100+ | 57 | 2.6k | Apache-2.0 | CNCF graduated [M] |
| `spiffe` crate (maxlambrecht/rust-spiffe) | 0.19.0 (2026-10-28) | — | — | — | Apache-2.0 | community |
| awslabs/tough (TUF) | 0.24.0 (2026-07-10) | — | — | 235 | Apache-2.0 / MIT | AWS (Bottlerocket) |

---

## 3. Per-candidate notes

### 3.1 Policy engines

#### Cedar: the `cedar-policy` crate, SymCC and Cedar Analysis

- **Health.**
  - 4.14.1 (Cedar language version 4.6) and `cedar-policy-symcc` 0.8.1, both 2026-11-02. 92 commits in the
    last three months, 20 regulars [H]. https://github.com/cedar-policy/cedar
  - Accepted into the CNCF at Sandbox level on 2025-10-08 [H]. https://www.cncf.io/projects/cedar/
  - The Go port, `cedar-go`, is active too [H].
- **What it is good at.**
  - A small, validated PARC language: `forbid` beats `permit`, deny by default, schema validation.
  - Entity hierarchies through `in`, entity tags (`hasTag`/`getTag`, stable) and `datetime`/`duration`
    (default features) [H, Cargo features and parser].
  - Formal analysis. SymCC can check that a policy set:
    - never errors;
    - always allows or always denies;
    - **implies** another set, is **equivalent** to it, or is **disjoint** from it;

    each with a counterexample, using cvc5 1.3.1 as an external binary [H, SymCC README]. The Cedar
    Analysis CLI turns this into a "more or less permissive" policy diff [H, per 03].
  - Industry use for agents. AWS Bedrock AgentCore Policy, GA 2026-03-03, puts Cedar in front of agent tool
    calls at a gateway [H]. https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available
  - `cedar-for-agents` generates Cedar schemas from MCP tool descriptions, and ships an MCP server exposing
    Cedar analysis (0.7.0, 2026-10-22) [H]. That bears directly on wicket's gateway (#9).
    https://github.com/cedar-policy/cedar-for-agents
- **Limits that matter for wicket**, all read in source on 2026-11-10 [H]:
  - **SymCC refuses template-linked policies** (`well_typed_policies`: "template-linked policies are not
    supported"). To analyse grants made from templates, wicket would have to expand them to static
    policies first.
  - **SymCC quantifies over every entity store** that fits the schema; its counterexamples include a
    synthesised store. It proves "policy set A implies B for all data", not "zone X's data is within
    zone Y's data". If zones and grants are *entities*, SymCC can't say anything about one particular
    child being inside one particular parent.
  - **`like` takes a literal pattern only.** The parser rejects a variable, name or expression as the
    pattern (`InvalidPattern`). A path glob can't come from an entity attribute or the context.
  - **Templates have two slots**, `?principal` and `?resource`, both entity UIDs (`ValidSlotId`).
    Generalised templates are RFC #98, still open. https://github.com/cedar-policy/rfcs/pull/98
  - **No quantifiers over a set of records.** Only `contains`, `containsAll`, `containsAny` and `isEmpty`
    exist, so "some grant in `principal.grants` covers this host and path" can't be written [H, operator
    docs]. Exact-match grants can use tags, e.g. `principal.hasTag(context.host)`; pattern grants can't.
  - Experimental features (`partial-eval`, `tpe`, `entity-manifest`, …) sit behind an `experimental`
    feature and may break in patch releases [H, Cargo.toml; 03].
- **What follows.** Cedar is excellent for *who may do what kind of thing*: operator roles (#11),
  escalation rights (#50), inspection rights (#34), image and host allowlists, tenant rules. Reach rules
  with globs and grants with patterns are a poor fit *as data*. They work only as policy text generated
  per zone or grant, or as wicket's own capability algebra outside Cedar.
- **Vendoring.** Not needed. The crate is healthy, and wicket should depend on it directly.

#### cedar-local-agent

- About 4,000 lines of Rust [H, cloned]. It has:
  - `SimplePolicySetProvider`, `SimpleEntityProvider` and `UpdateProviderData` traits;
  - file-based providers refreshed by a clock-tick task;
  - an authorizer wrapper that writes OCSF 1.0.0 log records.
- Depends on `cedar-policy = "4.2.0"`, which is semver-compatible with 4.14. Last release 3.0.0 on
  2025-04-29. Since then there are only security-contact and code-of-conduct commits, the last on
  2026-05-07 [H]. https://github.com/cedar-policy/cedar-local-agent
- There's no push, no signing, no revocation and no fail-narrow. Everything wicket needs from a node
  decision point is missing; what it does have is a thin wrapper.
- **Verdict:** don't depend on it. Use `cedar-policy` directly. Copy the provider-trait shape and the OCSF
  mapping if they're useful (Apache-2.0).

#### Amazon Verified Permissions (AVP) and avp-local-agent

- AVP is a managed Cedar service with a per-request API [M].
- avp-local-agent adds AVP-backed providers to cedar-local-agent. Its README asks for a refresh rate of
  **at least 15 seconds** "since any more risks overwhelming AVP" [H]. Last release 3.0.0 on 2025-04-30
  [H]. https://github.com/awslabs/avp-local-agent
- It ties an installation to one cloud (against R7), and still needs wicket's own signing and
  fail-narrow on top.
- **Verdict:** drop it as a backend. An AWS customer who wants Cedar policies authored in AVP could export
  them into wicket's pipeline instead.

#### Janssen Cedarling and Lock

- Cedarling is a Cedar policy decision point, published as the Rust crate `cedarling` (2.6.1,
  2026-11-10), with WASM, mobile and other bindings [H].
- Its model:
  - principals are built from **validated JWTs** checked against trusted issuers;
  - revocation uses the OAuth Status List spec;
  - with TRACE it **signs a record of each decision** as evidence [H].
  https://docs.jans.io/stable/cedarling/
- Lock Server collects logs and evidence and can serve the policy store [H].
- **Signed policy stores aren't released.** Sigstore verification of `.cjar` stores lives on a branch "not
  yet in main", and the single-envelope format `.cjarsig` is an open draft (jans#15414) [H].
  https://github.com/JanssenProject/jans/issues/15414
- **Fit.** wicket's identity is the transport (design §3.2), not a JWT presented by the agent. So
  Cedarling's central feature, turning tokens into principals, is beside the point. Its signed decision
  evidence and Sigstore store signing are worth copying as ideas.
- **Verdict:** don't adopt.

#### OPA (Open Policy Agent)

- **Distribution is the most complete anywhere** [H]:
  https://www.openpolicyagent.org/docs/management-bundles
  - bundles with `.manifest` and revision;
  - **signed bundles**: `.signatures.json` holds JWTs listing each file's hash, and OPA "activates the new
    bundle only if all the verification steps succeed";
  - long polling;
  - `persist: true`, to start from the last bundle when the server is down;
  - a status API and discovery [M].
- **Gaps that matter.**
  - Delta bundles change data only, and **"do not support signature verification"**. A bundle source
    configured to verify rejects them.
  - Activated deltas aren't persisted.
  - When downloads fail, OPA keeps the last good bundle. The docs describe no expiry. That's fail-*stale*,
    not fail-narrow [H for deltas; inference for staleness].
- **Decision logs are the reference design** [H]:
  https://www.openpolicyagent.org/docs/management-decision-logs
  - `decision_id`, input, result, and the revision of each bundle used;
  - masking rules (`system.log.mask`) and drop rules;
  - chunked gzip upload with requeue and backoff;
  - a rate limit that **drops** events when exceeded. That's something wicket's audit must not do.
- **Wasm.** `opa build -t wasm` compiles policy to Wasm. The host must supply builtins Wasm doesn't
  cover, and `http.send` is never supported [H]. Rust host: `opa-wasm` (matrix-org) 0.3.4, 2026-10-27 [H].
- **Governance.** In August 2025 the core maintainers (Teemu Koponen, Tim Hinrichs, Torin Sandall) joined
  Apple and Styra wound down. OPA stayed under the CNCF with the same maintainers [M, maintainers' post
  and press].
  https://openpolicyagent.org/blog/note-from-teemu-tim-and-torin-to-the-open-policy-agent-community-2dbbfe494371
  - The donated Enterprise OPA repo (`open-policy-agent/eopa`) is now **archived** [H].
  - A new OPA Control Plane (OCP) builds bundles from git and pushes them to object storage, with no
    signing mentioned [H]. https://github.com/open-policy-agent/opa-control-plane
  - Code activity on OPA itself is high: v1.22.2 on 2026-11-06, 56 regulars [H].
- **Analysis.** Rego has tests and coverage, but no containment or equivalence analysis [M, 03].
- **Verdict:** borrow the bundle and decision-log *designs*. Don't adopt Rego, because R5's analysis isn't
  available and Rego's document-query style isn't what wicket needs.

#### regorus (Microsoft, Rust Rego)

- MIT [H, LICENSE]. 0.15.0 on 2026-11-09; 100+ commits in three months [H].
  https://github.com/microsoft/regorus
- It passes OPA v1.2.0's tests apart from missing builtins (JWT, glob, net, …). Cryptographic builtins
  are excluded by design. It supports `no_std` and Wasm, has a register VM, and includes Azure Policy and
  Azure RBAC front ends [H].
- Its README claims the RVM is 1.35–2.15× faster than Cedar on the OOPSLA'24 benchmark, with a
  reproduction repo [H that the claim is made; not reproduced here].
- It uses Verus to verify its *numeric* code, not policies [H, `src/verify`].
- It has no bundles, signing or decision logs [H, README silent; M].
- **Verdict:** the only serious way to run Rego inside a Rust daemon. It doesn't change the Rego
  analysability problem.

#### Cerbos (PDP, Hub, embedded PDP)

- PDP: Go, Apache-2.0, v0.57.0 on 2026-10-23 [H].
- Policies are YAML with CEL conditions: resource, principal, role and derived-role policies.
- **Scoped policies** with `SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS`: "leaf nodes can only
  restrict access and must conform to parent permissions" [H]. That's narrow-only hierarchy built into
  the engine. But scopes are policy files compiled into a bundle, so each spawn would mean a new policy
  file and a rebuild. https://docs.cerbos.dev/cerbos/latest/policies/scoped_policies
- **Hub** "validates, tests, signs, and distributes every policy change", pushes to PDPs, builds
  "encrypted" bundles, runs the embedded PDP (WASM) and collects audit logs [H].
  https://docs.cerbos.dev/cerbos-hub/
  - Hub is a hosted, proprietary control plane, with on-premises deployment for enterprise customers
    [M, vendor blog]. https://www.cerbos.dev/blog/cerbos-hub-now-available-on-premise
  - The Rust crate `cerbos` (0.5.0) is a client of the Go PDP, not an engine [H].
- **Verdict:** not a fit (a Go service, signing only in the commercial product, static scopes). The
  parental-consent scope semantics are a good precedent for R3.

#### Casbin (casbin-rs) and Oso

- **Casbin.**
  - PERM model files with RBAC and ABAC; `casbin-rs` 2.20.0 (2026-02-04) [H].
  - Moved into the Apache Incubator on 2026-02-07, with no Apache release yet, and the IPMC is querying
    software grants [M, incubator pages]. https://incubator.apache.org/clutch/casbin.html
  - No analysis, no delegation semantics, no signing. Not a fit.
- **Oso.**
  - The open-source library (Polar) is **archived**: "Legacy Oso open source library (archived)". Last
    release 0.27.3 in 2024-01 [H].
  - Oso Cloud is proprietary. Its "local authorization" returns SQL to run against your own database, and
    can't mix some local and central facts [H].
    https://www.osohq.com/docs/authorization-data/local-authorization
  - Drop.

### 3.2 Distribution layers

- **OPAL** (Permit.io):
  - Python server and client. Clients keep a websocket subscription, with a backbone pub/sub (Postgres,
    Redis or Kafka) to scale servers; they fetch updates over REST and pull data from sources directly
    [H]. https://docs.opal.ac/overview/architecture
  - Engines are OPA, plus Cedar through `permitio/cedar-agent`, whose last release was 0.2.2 on 2025-10-16
    with no commits since [H].
  - The architecture docs don't mention **signing** [H]; I found no end-to-end signing feature [M].
  - Still on 0.10.0 release candidates as of 2026-11-10 [H].
  - Its data path means nodes reaching data sources directly, which wicket's nodes shouldn't do.
  - **Verdict:** drop. It adds a Python service, solves only push, and isn't signed.
- **OPA bundles and OCP:** see OPA above. The best snapshot signing, but no signed deltas and no freshness
  expiry.
- **Cerbos Hub:** signs and encrypts; commercial.
- **Janssen Lock:** policy-store serving plus log collection; signing is still a draft.
- **TUF (The Update Framework)**: the design to copy.
  - **Not an authorization product**, but the standard design for signed distribution that resists
    rollback, freeze and mix-and-match attacks. Its *timestamp* role is short-lived signed freshness
    metadata: a client that can't get a fresh one knows it is stale [M].
  - That is exactly R1's "fail narrow when the node can't refresh". Rust: `tough` (awslabs, 0.24.0,
    2026-07-10) [H]. CNCF graduated [M]. https://theupdateframework.io/
  - wicket probably wants only the *ideas*: monotonic version, short-expiry freshness, a root that
    rotates the signing keys. Pulling in the TUF repository model for a single stream of grants is
    heavier than needed.

### 3.3 Relationship stores (Zanzibar family)

None of these decides on the node. Each is a networked server with its own database. The question for wicket is
only whether one should be the *source* of relationship data that is then turned into local decision data.

- **SpiceDB** (AuthZed):
  - Apache-2.0, v1.57.0 on 2026-10-20 [H].
  - Strong consistency through ZedTokens, and caveats (CEL) [M].
  - **Expiring relationships**: experimental in v1.40, **GA in v1.48** (December 2025 changelog) [M,
    AuthZed docs and changelog via search].
    https://authzed.com/docs/spicedb/concepts/expiring-relationships
  - **Materialize** precomputes permission sets and streams them to the client. It is "Available on
    Dedicated only", and Event Streams is early access [H].
    https://authzed.com/docs/authzed/concepts/authzed-materialize
  - No official Rust client; the community crates are small and stale (`spicedb-client` 0.1.1 from 2024,
    `spicedb-rust` 0.3.4) [H].
- **OpenFGA**:
  - Apache-2.0, v1.22.1 on 2026-10-28.
  - **CNCF Incubating** since 2025-10-28 [H, CNCF blog].
    https://www.cncf.io/blog/2025/11/11/openfga-becomes-a-cncf-incubating-project/
  - Conditions in CEL, with context stored on the tuple (up to 32 KB) and merged at check time. The docs'
    temporal-access example grants for 10 minutes [H]. https://openfga.dev/docs/modeling/conditions
  - Checks go only through the server API [H].
  - Rust client: `openfga-client` 0.6.1 (2026-08-06, community) [H].
  - The most neutral governance of the family.
- **Ory Keto**: Go, Apache-2.0, v26.2.0 on 2026-03-20. Last commit 2026-07-29 [H]. **Oathkeeper** is an
  identity and access proxy, similar cadence [H]. Slower than SpiceDB or OpenFGA.
- **Permify**: Go, **AGPL-3.0** [H], acquired by FusionAuth in November 2025 and said to stay open source
  [M]. The AGPL rules out vendoring into an MIT project and complicates hosted platform mode.
- **Topaz** (Aserto):
  - OPA plus a Zanzibar-model directory in an **embedded local database**, so it does decide locally [H].
    https://www.topaz.sh/docs/intro
  - **Aserto wound down as a company in 2025** (SaaS off by 2025-05-31) [H, Aserto blog]. Topaz still
    releases (v0.33.26, 2026-11-06) with 8 regulars [H].
    https://www.aserto.com/blog/the-final-chapter-for-aserto
  - Go and Rego. Interesting as proof that "local ReBAC plus policy" works, not as a dependency.
- **Warrant**: dormant since 2024-06 [H]; acquired by WorkOS [M]. Drop.

**What wicket's relationship data actually is** (R6):
- the spawn tree, already in every identity's `act` chain (§3.2);
- tenant membership and groups from the IdP;
- operator roles;
- grants between tenants (§15).

The first three are tree-shaped and small per node, and Cedar's `in` hierarchy handles them. Only the
fourth, between end users of a platform tenant, looks like Zanzibar's problem. Even then wicket can
*materialise* the answer into node data when a grant is made, so a stale relationship store only delays new
sharing, which fails narrow. Withdrawing sharing must go out as a revocation.

### 3.4 Capability tokens and delegation formats

- **Biscuit** (`biscuit-auth`) [H, spec and source]
  https://doc.biscuitsec.org/reference/specifications, https://github.com/eclipse-biscuit/biscuit-rust
  - Ed25519 or P-256 chained blocks. A holder can add a block that restricts the token, but can't remove
    one. By default only the authority block, the current block and the authorizer are trusted.
  - **Third-party blocks** carry an extra signature, and are trusted via `trusting ed25519/<key>`. A
    `ThirdPartyBlockRequest` binds them to `previousSignature`.
  - **Revocation IDs**, one per block: the block's signature. Revoking a parent's block kills every token
    derived from it.
  - **Sealed tokens** stop further attenuation. Time is an ambient fact the authorizer supplies.
  - Datalog v3.3, adding `reject if`, arrays, maps and more.
  - The Rust authorizer has `RunLimits`: max facts (default 1000), iterations, time, and new step
    counting, merged in November 2026.
  - **No use counts**: Biscuit is stateless, so wicket's ledger supplies facts.
  - CVE-2024-42350, about third-party block requests, was fixed in v4+ of the spec, so use 6.x [H, 03].
  - Health: 6.0.0 on 2025-07-16; 40 commits since 2026-08-10, including the Sync authorizer and step
    counter on 2026-11-09; 6 regulars; Eclipse Foundation; spec repo last touched 2025-10 [H].
  - About 19.6k lines in the core crate [H].
  - **Fork viability: good.** Apache-2.0, a spec independent of the code, and several implementations
    (Rust, Go, Java, Python/JS through Rust bindings [M]). wicket would use a subset: Ed25519, generated
    blocks, no hand-written Datalog.
- **Macaroons**: HMAC chains. A verifier must hold the root secret, so **every node could mint
  authority**, which defeats R4 across nodes. The `macaroon` crate 0.3.0 dates from 2022 [H]. Drop.
- **UCAN 1.0**:
  - The spec README lists version 1.0.0, with Delegation and Invocation (required) and Promise and
    Revocation (recommended) sub-specs [H]. [03] recorded rc.1, so it has moved since.
    https://github.com/ucan-wg/spec
  - Built on DIDs and IPLD.
  - The Rust `ucan` crate's last release was in 2023 (0.4.0 stable; 0.7.0-alpha.1) [H]. Active 1.0 work is
    in Go/JS (`ucantone`, ucanto) [M].
  - Adopting it means writing a Rust 1.0 implementation. Drop for now.
- **ZCAP-LD**: a W3C CCG *work item*, not on the standards track [H]. JSON-LD, with a JavaScript reference
  implementation from Digital Bazaar [H]. Drop.
- **rcan** (n0-computer): Rust ed25519 delegation chains; 0.4.1, 2026-10-16; 221k downloads [H]. Minimal,
  with no policy language. Interesting as a "write our own" reference.
- **Meadowcap** (Willow): capabilities over *areas*, where an area is a path prefix × time range ×
  subspace with built-in containment [M]. The Rust code moved to Codeberg (`willow25` 0.7.11,
  `meadowcap` 0.6.0) and the GitHub repo is archived [H]. Not a dependency, but **a good model for
  wicket's capability algebra**: a product of simple lattices whose containment is decidable by
  structure, with no solver.
- **Keyhive** (Ink & Switch): Rust, Apache-2.0, delegation and revocation certificates plus group key
  agreement. Its README says "DO NOT use this release in production", and it hasn't been audited [H].
  Research only.
- **draft-niyikiza-oauth-attenuating-agent-tokens**: JWT chains with a closed constraint vocabulary and a
  rule that each extension must define a sound subsumption check [H, 03]. It's the closest standards-track
  shape to wicket's grants. Individual draft.
- **OAuth Transaction Tokens** (draft-ietf-oauth-transaction-tokens-11, 2026-07-30, "Waiting for
  Write-Up"): short-lived signed JWTs carrying immutable context (`txn`, `tctx`, `scope`) through a call
  chain inside one trust domain [H].
  https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/
  The right format if wicket ever passes context to *internal* downstream services. Not a grant format.

### 3.5 Identity and enforcement plumbing

- **SPIFFE/SPIRE**: identity, not authorization. SPIRE v1.16.0 on 2026-11-05, 57 regulars [H]. Rust
  `spiffe` crate 0.19.0 on 2026-10-28 [H]. Design §2.1 already plans SPIFFE IDs, with SPIRE as an optional
  issuer. Nothing changes here.
- **Envoy ext_authz**: calls an external gRPC or HTTP service *per request* [H]. That's the opposite of
  R1, and wicket is its own enforcement point anyway.
  https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter
- **AuthZEN Authorization API 1.0**: an OpenID **Final** spec since 2026-01-12, defining a standard JSON
  API between enforcement and decision points; an MCP binding is a working-group draft [H, OpenID
  announcement via search]. Cerbos and others implement it [M].
  https://openid.net/authorization-api-1-0-final-specification-approved/
  A cheap interop seam later: wicket could expose its decisions over AuthZEN to external enforcement
  points, or call an organisation's PDP for advice. Not a core dependency.
- **Kubernetes**:
  - RBAC's escalation prevention: "You can only create/update a role if … You already have all the
    permissions contained in the role", or hold `escalate`; bindings need the permissions or `bind` [H].
    That's #50's grant rule, battle-tested.
    https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping
  - ValidatingAdmissionPolicy (CEL) has been stable since v1.30 [H]. It's relevant only if wicket runs
    boxes on Kubernetes (#45).
  - Cedar's Kubernetes authorizer says "This repository is no longer maintained"; it's moving to an
    unnamed Rust implementation [H]. Not a dependency.

---

## 4. What the landscape teaches

1. **Narrowing by construction means intersection at decision time.** The node checks the request against
   the org policy, *every* ancestor's ceiling, and the grant, and allows only if all agree. Then a child
   can't exceed its parent even if the spawn-time check has a bug. The spawn-time subset check, or SymCC,
   becomes an *early, explainable refusal*, not the guarantee. This is cheap: spawn depth is small and
   each check is microseconds [M]. It also matches design §3's formula: `Cedar(org ∧ zone ∧ forbids) ∧
   ∃grant ⊇ op ∧ label rules ∧ ledger`.
2. **Grant permission is "only within your own authority", checked when the grant is made.** Kubernetes
   (escalate/bind), AWS (session policies) and Cerbos (parental consent) all do this. For wicket: approval
   is valid only if Cedar says the approver may approve this kind of thing (#11, #50) *and* the capability
   algebra says the grant ⊆ the approver's own authority. A human's default authority is "everything in
   the tenant", so the algebra check always passes for an unrestricted human.
3. **Nobody ships fail-narrow.**
   - OPA, cedar-local-agent, OPAL and Cedarling all keep the last policy indefinitely, or until a refresh
     succeeds.
   - Only TUF-style freshness, a signed statement that expires, gives a node a *bounded* notion of
     "stale".
   - Revocation latency is then at most the freshness interval, and usually just the push latency.
4. **Nobody signs fine-grained updates.** OPA signs snapshots and not deltas. Cerbos signs inside a
   commercial product. Janssen is a draft. wicket's updates are mostly small (a grant, a revocation, a new
   zone), so it needs a signed, hash-chained *delta* log anyway.
5. **Use counts and divisible budgets are always server-side state.** No token format or engine does
   them. The MCP MRTR spec and the niyikiza draft both say so [03]. wicket's design already puts the
   single-use counter on the node that holds the box (#57). Keep that.
6. **Relationship stores answer a question wicket mostly doesn't have yet.** Keep relationships in
   wicketd's database and push the per-node part as Cedar entities. Add OpenFGA (neutral governance,
   conditions) only when platform mode needs end-user sharing it can't express, and then only as a source
   that is materialised.

---

## 5. Candidate architectures

### 5.1 Architecture A: capability chains for zones and leases, Cedar for org rules, wicket's own signed feed (recommended)

**Pieces**
- **Capability algebra** (wicket-core, largely exists in `subset.rs`). Reach (host/method/path patterns),
  injections, budgets, limits, isolation, images, `accept_from`, `inspect`, and the escalation flags
  `request`/`grant`. It's a product of simple lattices with containment decided by structure, Meadowcap
  style. Its jobs:
  - the spawn-time and grant-time ⊆ checks, with readable violations;
  - compiling ceilings and grants to Biscuit checks.
- **Zone chain = one Biscuit per box.**
  - The control plane mints an authority block for the root principal: a human gets an unrestricted
    tenant scope; a trigger gets its own ceiling.
  - Each spawn appends a block whose checks are the child zone's ceiling. The node holds the token; **no
    token enters the box** (principle 2).
  - Effective authority is the intersection of all blocks, by Biscuit's semantics.
  - A child placed on another node brings its chain, and that node verifies it with the root public key
    alone.
- **Leases = short-lived Biscuits or third-party blocks**, bound to box id and epoch:
  - `check if time($t), $t < not_after`;
  - `check if uses_left($g, $n), $n > 0`, with `uses_left` injected by the node's ledger;
  - one lease model for every resource kind (#56).
- **Approvals.**
  - Human: the console verifies the passkey assertion over the request digest. The approval service then
    signs a third-party block `approved(req_digest, approver, assertion_digest)`.
  - Agent (#50): the parent's node signs the third-party block, after checking that the grant is within
    the parent's effective authority. This can happen **on the node with no control-plane round trip**,
    and is audited.
- **Org rules = Cedar**, through the `cedar-policy` crate directly.
  - Entities: tenant, human, group (from the IdP), operator role, agent, zone. Zones link to their parent
    with `in`, so the chain back to the human is plain Cedar.
  - Actions: `approve`, `inspect`, `spawn`, `request_escalation`, `use_image`, `reach_host_class`, `operate`, …
  - Policies are **static and reviewed** (no templates), so SymCC applies in full.
  - CI runs Cedar Analysis diffs on every org-policy change, and checks *floor ⊆ manifest ⊆ ceiling* for
    task classes (§5.2). There, manifests are compiled to static policies for the check only.
- **Distribution, owned by wicket.**
  - A per-node feed over the existing node channel (SSH or mTLS): a signed snapshot plus a signed,
    hash-chained delta log (epoch, sequence number, previous hash).
  - Contents: org policy, entities for that node's boxes, revocation IDs, identity revocations.
  - A **freshness statement** signed every few seconds with a short expiry, e.g. 30 s.
  - When it expires the node goes narrow: no new leases, no spawns, no approvals, and only ops that the
    zone ceiling plainly allows at low risk (R1 or below).
  - TUF ideas: monotonic version, a root that certifies short-lived signing keys (design §3.2 already
    plans this), rollback rejection.
- **Audit.** A per-node hash-chained decision log recording:
  - `decision_id`, epoch and feed sequence;
  - the revocation IDs of the blocks used;
  - the Cedar policy IDs that decided;
  - masked arguments.

  Shipped to the control plane; `audit --verify` checks the chains. Copy OPA's masking and buffering
  design but never drop events: back-pressure instead. OCSF export is optional.
- **Relationships.** wicketd's database is the source. Nodes get Cedar entities only for their own boxes.
  OpenFGA is an optional source for platform-mode sharing, materialised when a grant is made.

**Against R1–R8**
- R1 **yes**: Cedar and Biscuit checks are both in-process. Revocation latency is about push latency, at
  worst one freshness interval. Fail-narrow is explicit.
- R2 **yes**: spawns and grants add blocks or tokens. No policy text is recompiled. Org policy changes
  rarely.
- R3 **yes, by construction**: blocks only add checks, and anyone with the root public key can check the
  chain offline. Humans default to everything. Grant-time ⊆ follows the Kubernetes rule.
- R4 **yes**: every artifact is signed (feed, freshness, tokens, third-party approvals) and logs are
  hash-chained.
- R5 **yes for org rules** (Cedar + SymCC). Zone ceilings are checked by the algebra's structural subset,
  not by a solver.
- R6 **part**: Cedar entities plus wicketd's database; OpenFGA later if needed.
- R7 **yes**: all Rust crates (`cedar-policy`, `biscuit-auth`), no cloud dependency.
- R8 Cedar strong. Biscuit moderate, but forkable.

**Build / fork / vendor**
- Build:
  - algebra → Biscuit compiler;
  - feed and freshness, about 1–2k lines;
  - node ledger for use counts;
  - approval signer;
  - the Cedar schema and policies for #11, #34, #50.
- Depend: `cedar-policy`, `cedar-policy-symcc` (CI and control plane only, plus cvc5), `biscuit-auth` 6.x
  pinned.
- Vendor or fork: none now. Be ready to fork `biscuit-auth`, since only the Ed25519 / third-party /
  authorizer subset is used.
- Don't use: cedar-local-agent, avp-local-agent, OPAL, Cedarling.

**Risks**
- *Two languages.* Cedar for org rules, Datalog inside Biscuit. Mitigation: wicket generates every Biscuit
  block from the algebra from a fixed vocabulary. Nobody writes Datalog, and denials are explained in
  algebra terms before Datalog runs.
- *Biscuit maintenance* (6 regulars). Mitigation: a subset, a pinned version, a fork plan, and a format
  kept at arm's length. The algebra should also compile to a plain signed-record chain (niyikiza-style
  JWS or COSE), so Biscuit can be swapped out.
- *Token size and verification cost* grow with spawn depth. Mitigation: a depth limit, `RunLimits` tuned
  (the default `max_facts` of 1000 may be too low), and benchmarks.
- *Keys for third-party signers* (approval service, node keys) widen key management. Mitigation: short-lived
  issuing keys under the root, as §3.2 already plans.
- Building the feed and freshness is wicket's own code inside the TCB. Mitigation: it's small and fuzzed,
  and modelled on TUF.

### 5.2 Architecture B: Cedar for everything, no tokens (#51 and #57, corrected)

**Pieces**
- Each zone is compiled to a **static** Cedar policy set, with patterns as literals.
- Each grant is a generated static policy with a `context.now < expiry` condition. Exact-match grants can
  be entity tags.
- Decision = org ∧ every ancestor zone's policy set ∧ grants, evaluated as separate `is_authorized` calls
  and ANDed.
- At spawn, `check_implies(child, parent)` per request environment, through SymCC and cvc5, gives the
  early refusal, with counterexamples as explanations. Intersection at runtime remains the guarantee.
- Distribution: the same signed snapshot, delta feed and freshness as A, but carrying policy text and
  entities.
- Revocation: delete policies and bump the epoch.
- Relationships: as in A.

**Against R1–R8**
- R1 yes, with wicket's feed.
- R2 part. Every spawn and every grant is new policy text pushed to nodes. That's fine at "many an hour"
  per node, but policy sets grow, and each grant needs a SymCC-friendly shape.
- R3 by intersection. The proof of *who delegated what* lives in wicket's ledger, not in a portable
  artifact. It can be checked offline with the ledger plus the snapshot.
- R4 yes for snapshots and deltas. Approvals are proven by the ledger's signed records, which wicket
  already writes.
- R5 **strongest**: everything, ceilings included, is one analysable language.
- R6 part; R7 yes; R8 **best**: one healthy dependency.

**Build / fork / vendor:** the manifest → Cedar compiler; feed and freshness; SymCC in the spawn path;
cvc5 packaged with the control plane. No Biscuit.

**Risks**
- *Solver in the spawn path.* cvc5 is an external C++ binary pinned at 1.3.1. Solve times for
  wicket-sized policies are unknown [L]: measure them.
- *Patterns.* SymCC's handling of `like` and of tags at scale isn't documented [L]. Keep to a
  SymCC-friendly subset and test it in CI.
- *No portable delegation proof.* That makes cross-node and later cross-installation delegation (§15
  federation) harder.
- *Agents granting on the node (#50)* means generating and signing policy text on the node, or a
  control-plane round trip.

### 5.3 Architecture C: the OPA ecosystem

**Pieces**
- Rego policies evaluated by regorus inside wicketd, or by an OPA sidecar per node.
- OPA bundle format: signed snapshots, OCP to build them, OPA-style decision logs.
- Grants as data, through the push API or delta bundles.
- Relationships from OpenFGA, or Topaz's directory.

**Against R1–R8**
- R1 part: local, but delta bundles are unsigned and there's no freshness expiry, so wicket adds both.
- R2 part.
- R3 no: intersection must be hand-written in Rego, with no analysis.
- R4 the best *off-the-shelf* (signed bundles, decision logs).
- R5 weak: no containment or equivalence analysis.
- R6 good with OpenFGA or Topaz.
- R7 part: regorus is Rust but has no bundle loader, so that's reimplemented; otherwise Go sidecars.
- R8 OPA strong in code, with governance in flux since 2025; regorus strong.

**Verdict:** the most mature operations story, and the weakest on the two things that make wicket
distinctive, R3 and R5. Listed for honesty, not recommended.

*(Rejected without a full write-up: a Zanzibar-centred design, with SpiceDB or OpenFGA as the source of
truth for grants as expiring relationships. It fails R1, since every check is a network call, unless the
commercial Materialize streams are used.)*

---

## 6. Ranked recommendation

1. **Architecture A.** It's the only design where narrowing, signatures, offline verification and subtree
   revocation are properties of the *artifact*, rather than of wicket code paths that must be right
   everywhere. It keeps Cedar for what Cedar is best at: reviewed, static org rules, which keeps SymCC
   usable without templates. It's all Rust and needs no cloud. It lets a parent agent grant on its own
   node (#50) with no control-plane round trip, and a spawned child carry its authority to another node
   (#57). Its weak point is one moderately maintained dependency, Biscuit, which can be forked and is
   swappable by design.
2. **Architecture B**, if the owner prefers one language and the healthiest single dependency. It's
   simpler to explain. It costs a solver in the spawn path, delegation proofs that live in the ledger
   rather than in a portable artifact, and harder cross-node and federated delegation. It's a reasonable
   0.0.1 path *if* A's algebra-first structure is kept, so Biscuit can be added later without changing
   the decision formula.
3. **Architecture C.** Mature operations, but no analysis (R5) and no narrowing by construction (R3).

**What this changes in the current plans** (suggestions; no issue was edited):
- #51: drop "templates plus entities, proved by SymCC". SymCC rejects template-linked policies and can't
  see entity data. Use SymCC for org policy diffs and the *floor ⊆ manifest ⊆ ceiling* band, on static
  policies. Keep the zone-containment guarantee in the capability algebra plus runtime intersection.
- #57: drop cedar-local-agent, OPAL, avp-local-agent and Cedarling. The node embeds `cedar-policy` and
  `biscuit-auth`. Distribution is wicket's own signed snapshot and delta feed with a TUF-style freshness
  lease; that's the piece that makes "bounded revocation" and "fail narrow" true. Grants as Biscuit, which
  the issue already mentions, becomes the main path, not an option.
- §2.1 table: "OpenFGA or Cedar for sharing between tenants" becomes "Cedar entities, materialised from
  wicketd; OpenFGA as an optional source in platform mode".

**Experiments before committing** (each about a day):
1. SymCC on a realistic parent and child zone compiled to static Cedar: solve time and counterexample
   quality. This decides whether B's spawn-time proof is viable at all.
2. Biscuit verification with a spawn depth of 5, about 50 checks and a third-party approval block:
   latency, token size, and the `RunLimits` needed.
3. The feed and freshness kill test: stop the control plane, confirm that allowed ops continue and that
   new leases, spawns and approvals stop at expiry, and measure revocation latency with push on and off.
4. The Cedar org schema for #11, #34 and #50 (roles, inspection, request/grant flags), with a Cedar
   Analysis diff in CI.

---

## 7. Sources (primary unless marked)

- Cedar: https://github.com/cedar-policy/cedar ·
  SymCC README https://github.com/cedar-policy/cedar/blob/main/cedar-policy-symcc/README.md ·
  template limitation in `cedar-policy-symcc/src/symcc.rs` (`well_typed_policies`) ·
  literal `like` patterns in `cedar-policy-core/src/parser/cst_to_ast.rs` (`InvalidPattern`) ·
  template slots in `cedar-policy-core/src/ast/name.rs` (`ValidSlotId`) ·
  operators https://docs.cedarpolicy.com/policies/syntax-operators.html ·
  RFC 98 https://github.com/cedar-policy/rfcs/pull/98 ·
  CNCF https://www.cncf.io/projects/cedar/ ·
  Cedar Analysis https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/
- cedar-local-agent https://github.com/cedar-policy/cedar-local-agent ·
  avp-local-agent https://github.com/awslabs/avp-local-agent ·
  cedar-for-agents https://github.com/cedar-policy/cedar-for-agents ·
  Cedar for Kubernetes https://github.com/cedar-policy/cedar-access-control-for-k8s ·
  AgentCore Policy GA https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available
- Janssen Cedarling https://docs.jans.io/stable/cedarling/ ·
  signed store draft https://github.com/JanssenProject/jans/issues/15414
- OPA bundles https://www.openpolicyagent.org/docs/management-bundles ·
  decision logs https://www.openpolicyagent.org/docs/management-decision-logs ·
  Wasm https://www.openpolicyagent.org/docs/wasm ·
  maintainers' note https://openpolicyagent.org/blog/note-from-teemu-tim-and-torin-to-the-open-policy-agent-community-2dbbfe494371 ·
  EOPA (archived) https://github.com/open-policy-agent/eopa ·
  OCP https://github.com/open-policy-agent/opa-control-plane ·
  regorus https://github.com/microsoft/regorus ·
  opa-wasm https://github.com/matrix-org/rust-opa-wasm
- OPAL https://docs.opal.ac/overview/architecture · cedar-agent https://github.com/permitio/cedar-agent
- Cerbos Hub https://docs.cerbos.dev/cerbos-hub/ ·
  scoped policies https://docs.cerbos.dev/cerbos/latest/policies/scoped_policies ·
  on-premises (vendor blog) https://www.cerbos.dev/blog/cerbos-hub-now-available-on-premise
- Casbin incubator https://incubator.apache.org/clutch/casbin.html ·
  Oso https://github.com/osohq/oso ·
  Oso local authorization https://www.osohq.com/docs/authorization-data/local-authorization
- SpiceDB expiring relationships https://authzed.com/docs/spicedb/concepts/expiring-relationships ·
  changelog https://authzed.com/changelog/december-2025-release ·
  Materialize https://authzed.com/docs/authzed/concepts/authzed-materialize
- OpenFGA conditions https://openfga.dev/docs/modeling/conditions ·
  incubation https://www.cncf.io/blog/2025/11/11/openfga-becomes-a-cncf-incubating-project/
- Ory Keto https://github.com/ory/keto ·
  Permify acquisition (press) https://builtin.com/articles/fusionauth-acquires-permify-20251125 ·
  Topaz https://www.topaz.sh/docs/intro ·
  Aserto https://www.aserto.com/blog/the-final-chapter-for-aserto
- Biscuit spec https://doc.biscuitsec.org/reference/specifications ·
  biscuit-rust https://github.com/eclipse-biscuit/biscuit-rust ·
  CVE-2024-42350 https://nvd.nist.gov/vuln/detail/CVE-2024-42350
- UCAN https://github.com/ucan-wg/spec · rs-ucan https://github.com/ucan-wg/rs-ucan ·
  ZCAP https://github.com/w3c-ccg/zcap-spec · rcan https://github.com/n0-computer/rcan ·
  Willow (Rust) https://codeberg.org/worm-blossom/willow_rs ·
  Keyhive https://github.com/inkandswitch/keyhive
- Attenuating agent tokens https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-01 ·
  Transaction Tokens https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/ ·
  AuthZEN 1.0 https://openid.net/authorization-api-1-0-final-specification-approved/
- SPIRE https://github.com/spiffe/spire · rust-spiffe https://github.com/maxlambrecht/rust-spiffe ·
  Envoy ext_authz https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter
- Kubernetes RBAC escalation prevention https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping ·
  ValidatingAdmissionPolicy https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/ ·
  AWS session policies https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session
- TUF https://theupdateframework.io/ · tough https://github.com/awslabs/tough
- Earlier wicket research: [03] policy, authority and IFC; [08] gateways and policy.
