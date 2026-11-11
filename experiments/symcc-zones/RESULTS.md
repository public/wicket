# Experiment #58: SymCC on realistic parent and child zones

Date: 2026-11-11. Ticket: public/wicket#58 (refs #51, #57; research 18 §5.1, §5.2, §6).

**Question.** Can Cedar's symbolic compiler (`cedar-policy-symcc`, backed by cvc5) prove "child zone ⊆
parent zone" fast enough, with counterexamples that can be made readable? That decides whether
architecture B (Cedar for everything, with SymCC in the spawn path) is viable at all, and how A should
use SymCC in CI (org policy diffs; org floor ⊆ manifest ⊆ ceiling).

**Short answer.**
- **B passes on speed but fails on robustness.**
  - On realistic zones SymCC decides containment in 0.06–0.3 s (median 0.13 s), and 0.1–3.2 s with the
    exact encoding.
  - cvc5 peaks at 74 MiB. Once a small wicket-side translator rewrites the counterexamples, they read
    well.
  - But the obvious encoding (the path as one string) is inexact for globs such as
    `/v1/code/sessions/*/worker/**`. On those, cvc5 returns `unknown` after 10 s and after 60 s, on both
    1.3.1 and 1.4.2.
  - An exact encoding exists (the path as segment attributes, depth ≤ 8). It decides all 28 cases
    correctly, but the cost grows faster than linearly: 2.6 s at 100 reach rules and 30 s at 300.
  - It is 10³–10⁵ times slower than `subset.rs` (0.4–300 µs). It returns one counterexample per Cedar
    action, not every violation. And the zone-to-Cedar compiler would be new code inside the trusted
    computing base.
  - So B would still need a structural fallback for `unknown` and for listing every violation, which
    is A's algebra. **Decision: B is not worth adopting. Keep A.**
- **For A, SymCC works well in CI.**
  - Org-policy diff queries take 0–9 ms each, and the counterexamples replay against
    `Authorizer::is_authorized`.
  - floor ⊆ manifest ⊆ ceiling takes 0.05–0.7 s per check, using the same zone compiler with the
    segment path model.
  - SymCC also turned out to be a good **test oracle for `subset.rs`**. It found two gaps (§6).

---

## 1. What was built

`experiments/symcc-zones/` is a standalone Cargo project with its own `[workspace]`. It depends on
`wicket-core` by path, so it uses the real `ZoneSpec`, `subset::check`, glob and host matching, and
`canonical_path`.

| File | What it does |
|---|---|
| `src/compile.rs` | `ZoneSpec` plus the spawn parameters (image, remaining budgets, child slots, time left) → **static** Cedar policies, one small policy set per Cedar action (request environment). Defines the schema. |
| `src/glob.rs` | wicket path globs → Cedar `like` on a string path, with over- and under-approximations where the glob can't be written exactly. |
| `src/seg.rs` | The alternative path model: the path as `depth` plus segment attributes `s0..s7`. Exact for every glob without `?`/`[...]`. |
| `src/oracle.rs` | A concrete evaluator for the modelled request space: `op::evaluate`, with the risk class replaced by a free `dangerous` flag and wicket's own globset/host code. It replays SymCC counterexamples and difference-tests the compiler. |
| `src/cases.rs` | 6 parents, 28 children, and a synthetic generator for N reach rules. |
| `src/org.rs` | A hand-written org policy in three versions, for A's CI diff. |
| `src/main.rs` | The harness: `probe`, `difftest`, `zones`, `scale`, `band`, `org`, `policies`. |
| `run-all.sh`, `run-all2.sh` | The runs whose logs are in `logs/` (second pass after a segment-encoding simplification). |

### 1.1 Schema and compilation

```
entity Agent;  entity Url { host: String, path: String };     // string path model
               // segment model: entity Url { host: String, depth: Long, s0: String, …, s7: String };
entity Image;  entity Zone;  entity Secret;  entity Route;
action "GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"
  appliesTo { principal: [Agent], resource: [Url], context: { dangerous: Bool } };
action "run_with"       appliesTo { …, resource: [Zone], context: { memory_mb, millicpus, pids, timeout_s, isolation, children: Long } };
action "start_image"    appliesTo { …, resource: [Image] };
action "accept_message" appliesTo { …, resource: [Zone] };
action "inject"         appliesTo { …, resource: [Secret], context: { host, header, format: String } };
action "use_model"      appliesTo { …, resource: [Route], context: { requests, output_tokens: Long, server_tools: Bool } };
action "ask_unlisted"   appliesTo { …, resource: [Zone] };
```

That gives 13 request environments. How each part of a zone is compiled:

- **Reach rule *i*** becomes one `permit` per method, `when { host && (path glob || …) && <danger> }`.
  - `<danger>` is `!context.dangerous`, or, with `allow_dangerous`, "not dangerous, or no earlier rule
    for this method matches". This keeps `evaluate`'s first-match semantics, where an earlier matching
    rule without `allow_dangerous` returns NeedsGrant.
  - `*.example.com` becomes `host like "*.example.com" && host != ".example.com"`.
- **Forbid rule** becomes a `forbid` on every HTTP action.
- **Envelope.** Two shared `forbid`s in every zone remove requests the proxy never evaluates, so analyses
  only range over real requests:
  - non-canonical paths: not starting with `/`, `//`, dot segments, `%2f %5c %2e %00 %25`, `?`, `\`;
  - malformed hosts;
  - `localhost`, `*.localhost` and the metadata hosts.
- **Limits, images, accept_from, injections, the model route and `unlisted_hosts`** become one `permit`
  each, with the parent side using what it has *left*: `time_remaining`, `child_slots − 1`, and
  `llm_remaining`.
- **Two checks per case:**
  - `child ⇒ parent` over the 13 environments (what each allows);
  - `notForbidden(child) ⇒ notForbidden(parent)` over the 7 HTTP environments (a parent forbid must stay
    forbidden in the child, even where no reach rule covers it).

  So one containment check is **20 SymCC queries** (`check_implies_with_counterexample_opt`).

The policies are static, with no templates. Run `symcc-zones policies <child>` to print them. A sample is
in `logs/policies-*.log`.

### 1.2 Path globs: the central encoding problem

Cedar `like` has one wildcard, `*`, and it **matches `/`**. wicket's `*` stays inside one segment, while
`**` crosses segments (globset with `literal_separator`). The `probe` subcommand recorded globset's
behaviour:
- `/x/**` matches `/x/` and `/x/a/b`, but not `/x`;
- `/a/**/b` matches `/a/b`;
- `/a/*` matches `/a/`.

**String model (`glob.rs`).**
- `**` becomes `*`, which is exact.
- One or more one-segment `*`s with no `**` are made exact by also requiring exactly as many `/` as the
  glob's literal text has: `!(path like "*/*/*/*/*")` with one more `/`.
- `*` together with `**`, as in `/v1/code/sessions/*/worker/**`, couldn't be written exactly with `like`
  and boolean connectives.
  - The child side gets an over-approximation (drop the constraint).
  - The parent side gets an under-approximation: `!(path like P_i)`, where `P_i` replaces the *i*-th
    `*` with `*/*`. This removes any string with *some* split that puts a `/` into that star, which also
    removes some legitimate strings.
- `?` and `[...]` are over-approximated by `*` and under-approximated by `false`. Cedar has no
  single-character wildcard and no string length.
- Using child-over and parent-under is sound: "within" is a proof. "Not within" may be spurious, so every
  HTTP counterexample is replayed through `oracle.rs`.

**Segment model (`seg.rs`).**
- The URL carries `depth` and `s0..s7`. The envelope adds: segments have no `/`, aren't `.`/`..`, only
  the last may be empty, and `1 ≤ depth ≤ 8`.
- Each glob becomes a disjunction over depths of per-segment `==` or `like` conditions (`**` enumerates
  the possible alignments), with identical depths merged into `depth >= k`.
- This is exact for every glob without `?`/`[...]`, for paths of up to 8 segments. Deeper paths would
  have to be refused by the proxy, or matched by a `rest` attribute, which isn't modelled here.

**Difference test** (`difftest`). The test generated about 645k (zone, mode, method, host, path,
dangerous) evaluations from every zone's own literals, with wildcards filled by "", `x`, `x/y` and
`abc/worker/q`. It compared concrete Cedar `is_authorized` on both encodings against the oracle:

| model | evaluations | Over ⊉ oracle | Under ⊈ oracle | mismatches where the encoding claims exactness | allowed differences where it's approximate |
|---|---|---|---|---|---|
| string | 646,744 | 0 | 0 | 0 | 162 (all in remote-control's `*` + `**` globs) |
| segment | 643,776 | 0 | 0 | 0 | 0 |

## 2. Environment

| | |
|---|---|
| Machine | a Vultr VPS in London, **4 vCPU shared** (Broadwell), 8 GB RAM. Shared with other jobs (a Biscuit benchmark ran at the same time), so expect ±30% noise. Every run had one CPU slot and a 2 GiB memory cap. |
| Rust | cargo/rustc 1.99.1, release profile, `CARGO_BUILD_JOBS=1` |
| Cedar | `cedar-policy` **4.14.1** and `cedar-policy-symcc` **0.8.1** (crates.io, pinned `=`; both released 2026-11-02) |
| Solver | **cvc5 1.3.1**, the version the SymCC README pins: `cvc5-Linux-x86_64-static.zip` from the official GitHub release (sha256 `1a1cda20…be3ed1`), symlinked at `tools/cvc5`. For comparison, **cvc5 1.4.2** (the latest, sha256 `7eb18f8c…cc61d8`) in `tools/dl-cvc5-1.4.2/`. Nothing is installed system-wide. |
| How SymCC finds cvc5 | `LocalSolver::cvc5()` runs `$CVC5`, or `cvc5` on `PATH`, as a child process speaking SMT-LIB over stdin/stdout (`--lang smt`). The harness sets `CVC5=$PWD/tools/cvc5`. |

**A SymCC pitfall.** `LocalSolver::cvc5()` passes `--tlimit=60000`. cvc5 applies `--tlimit` to the
**whole process lifetime**, idle time included (verified directly: `--tlimit=2000`, one query, 3 s idle,
then "cvc5 interrupted by timeout", abort).
- A reused solver, which is what a long-lived control-plane service would keep, therefore dies 60 s
  after it starts.
- The harness uses `LocalSolver::cvc5_with_args(["--tlimit-per=<ms>"])`, a per-query limit, which works
  with SymCC's `(reset)` between queries.
- Starting a fresh cvc5 for each check costs almost nothing: the "cold" column is within noise of the
  warm median.

## 3. Method

- **Cases.** 28 children of 6 parents:
  - **self-hosting**: `examples/self-hosting/manifest.yaml`;
  - **research**: the `research` zone of `examples/hello-github.yaml`;
  - **remote-control**: `examples/remote-control/manifest.yaml`, which has forbids and the
    `*`-next-to-`**` worker globs;
  - **subset-rs** and **subset-rs-hide**: the parent from `subset.rs`'s tests;
  - **forbid-parent**: reach `/**` with a forbid on `/private/**` and `mcp.example.com`.

  Children are either genuinely within, or wider in one way each: an extra host, method, wider path,
  wildcard host, push path, `allow_dangerous`, memory, credential, isolation, dropped forbids, or
  unlisted hosts. They include all three zone cases from `subset.rs`'s tests.
- **Timing.** Each case ran 5 times on a warm solver (median reported), plus once with a fresh cvc5
  process ("cold"). Time includes generating the Cedar text, parsing, SymCC compilation and solving.
  `subset::check` was timed over 200 iterations for comparison.
- **Memory.** cvc5's peak RSS was sampled from `/proc/<child>/status` VmHWM. The harness's own RSS came
  from `/usr/bin/time -v`.
- **Time limits.** 10 s per query for the string model's full run (the hard queries were then rerun at
  60 s, on both cvc5 versions), and 60 s per query elsewhere.
- **Counterexamples.** Each was turned into a sentence: the request, plus what the child and the parent
  each decide and why. HTTP counterexamples were replayed concretely ("confirmed" means the oracle agrees
  the child allows and the parent doesn't).
- **Per-rule pass.** Whenever a case failed, a second pass checked each child reach rule on its own,
  to name every offending rule the way `subset.rs` does.

## 4. Results: zone containment (the B question)

Times are the median total for all 20 queries of one check, in ms. `subset.rs` µs is the hand-written
check, for comparison.

| # | child | parent | expected | SymCC, string path | ms | SymCC, segment path | ms | subset.rs |
|---|---|---|---|---|---|---|---|---|
| 1 | sh-crates-only | self-hosting | within | within | 79 | within | 150 | within (1.1 µs) |
| 2 | sh-issues-reader | self-hosting | within | within | 131 | within | 269 | within (132 µs) |
| 3 | sh-brace-star | self-hosting | within | within | 120 | within | 206 | within (2.7 µs) |
| 4 | sh-copy | self-hosting | within (the parent's own zone) | within | 59 | within | 109 | within (4.9 µs) |
| 5 | sh-extra-host | self-hosting | wider: extra host | 2 cex, confirmed | 116 | 2 cex, confirmed | 286 | 2 violations (3.1 µs) |
| 6 | sh-extra-method | self-hosting | wider: POST | 1 cex, confirmed | 109 | 1 cex, confirmed | 242 | 1 violation (121 µs) |
| 7 | sh-wider-path | self-hosting | wider: /repos/public/** | 2 cex, confirmed | 183 | 2 cex, confirmed | 329 | 2 violations (4.3 µs) |
| 8 | sh-wildcard-host | self-hosting | wider: *.github.com | 2 cex, confirmed | 218 | 2 cex, confirmed | 493 | 2 violations (1.9 µs) |
| 9 | sh-push | self-hosting | wider: git-receive-pack | 1 cex, confirmed | 122 | 1 cex, confirmed | 230 | 1 violation (64 µs) |
| 10 | sh-dangerous | self-hosting | wider: allow_dangerous | 2 cex, confirmed | 155 | 2 cex, confirmed | 297 | 2 violations (5.0 µs) |
| 11 | sh-memory | self-hosting | wider: memory 4g > 3g | 1 cex | 138 | 1 cex | 229 | 1 violation (2.1 µs) |
| 12 | sh-inject-secret | self-hosting | wider: another credential | 1 cex | 132 | 1 cex | 221 | 1 violation (4.0 µs) |
| 13 | sh-runc | self-hosting | wider: isolation runc | 1 cex | 150 | 1 cex | 211 | 1 violation (1.6 µs) |
| 14 | rs-commits | research | within | within | 118 | within | 199 | within (1.2 µs) |
| 15 | rs-refs | research | within | within | 97 | within | 172 | within (0.8 µs) |
| 16 | rs-owner | research | wider: /repos/octocat/** | 2 cex, confirmed | 232 | 2 cex, confirmed | 324 | 2 violations (1.9 µs) |
| 17 | rs-put | research | wider: PUT | 1 cex, confirmed | 142 | 1 cex, confirmed | 229 | 1 violation (1.9 µs) |
| 18 | rs-git-glob | research | wider: glob over exact paths | 1 cex, confirmed | 160 | 1 cex, confirmed | 218 | 1 violation (0.8 µs) |
| 19 | rc-one-session | remote-control | within (`…/abc123/worker/**` ⊆ `…/*/worker/**`) | **unknown** (3 queries hit the limit) | 30,090 | within | 341 | **3 violations (false)** (213 µs) |
| 20 | rc-messages | remote-control | within | within | 66 | within | 181 | within (0.4 µs) |
| 21 | rc-copy | remote-control | within (the parent's own zone) | **unknown** (3 queries hit the limit) | 30,105 | within | 135 | within (270 µs) |
| 22 | rc-missing-forbid | remote-control | wider: forbids dropped | 7 cex + 3 unknown | 30,290 | 7 cex, confirmed | 2,967 | **within (missed)** (265 µs) |
| 23 | rc-delete | remote-control | wider: DELETE on worker path | 1 cex, confirmed | 117 | 1 cex, confirmed | 217 | 1 violation (1.1 µs) |
| 24 | t-narrower | subset-rs | within (`a_narrower_zone_passes`) | within | 177 | within | 393 | within (134 µs) |
| 25 | t-every-widening | subset-rs | wider ×16 (`every_widening_is_named`) | 8 cex, confirmed | 201 | 8 cex, confirmed | 441 | 21 violations (8.5 µs) |
| 26 | t-hidden | subset-rs-hide | wider (`hidden_hosts_stay_hidden`) | 2 cex | 68 | 2 cex | 130 | 3 violations (1.1 µs) |
| 27 | f-no-forbid | forbid-parent | wider: parent's forbids missing | 9 cex, confirmed | 326 | 9 cex, confirmed | 3,175 | **within (missed)** (1.2 µs) |
| 28 | f-inherited | forbid-parent | within (forbids inherited as `spawn.rs` does) | within | 105 | within | 128 | within (0.8 µs) |

**Summary.**
- **String model**: 25 of 28 cases decided correctly, with a median of 131 ms (59–326 ms). The slowest
  single query took 76 ms.
  - The 3 cases with remote-control's `*`+`**` globs came back `unknown`. At 60 s per query the result
    is the same on cvc5 1.3.1 and 1.4.2 (`logs/hard-cvc5-*.log`). For these queries the true answer is
    SAT, with a spurious counterexample such as `/v1/code/sessions/abc123/worker/x/worker/y`. cvc5's
    string solver can't find it: negated `like` over unbounded strings is its weak spot.
- **Segment model**: 28 of 28 correct, with a median of 229 ms (109–3,175 ms). The slowest single query
  took 445 ms.
  - The two slow cases (rows 22 and 27, about 3 s) are the not-forbidden checks over `/**` forbids. The
    solver has to build a full-depth path.
  - With cvc5 1.4.2, the earlier, unmerged segment encoding gave a median of 270 ms and a maximum of
    1,951 ms: no better than 1.3.1.
- **Memory**: cvc5 peaks at 64 MiB (string) and 74 MiB (segment). The harness itself uses 12 MiB.
- **Cold vs warm**: starting cvc5 per check adds nothing measurable (cold median 86 ms vs warm 131 ms for
  the string model: noise).

### 4.1 Scaling (synthetic parents, N reach rules; the child narrows every rule)

A third of the rules have one-segment `*` and a tenth have wildcard hosts. "Sliced" checks each child
rule on its own against only the parent rules whose host can overlap: a sound structural pre-filter that
would be wicket code. Medians of 3 runs; sliced is 1 run.

| N | child | string: whole zone | segment: whole zone | string: sliced per rule | segment: sliced per rule |
|---|---|---|---|---|---|
| 10 | within | 89 ms | 138 ms | 138 ms (10 queries) | 350 ms |
| 10 | 1 rule widened | 162 ms, cex | 183 ms, cex | 185 ms | 446 ms |
| 30 | within | 556 ms | 383 ms | 505 ms | 1.5 s |
| 30 | 1 rule widened | 114 ms, cex | 350 ms, cex | 476 ms | 1.4 s |
| 100 | within | 13.2 s | 2.6 s | 2.0 s | 5.1 s |
| 100 | 1 rule widened | 2.0 s, cex | 1.8 s, cex | 1.7 s | 5.2 s |
| 300 | within | **unknown (60 s limit)** | 30.2 s | 4.7 s (slowest query 41 ms) | 16.0 s |
| 300 | 1 rule widened | 2.2 s, cex | 20.9 s, cex | 5.5 s | 17.0 s |

Whole-zone queries grow faster than linearly. Proving "within", which is UNSAT, is the expensive
direction, because every parent rule participates. Host slicing makes each query small, so the total
becomes roughly linear in the number of child rules, but it moves part of the reasoning back into wicket
code.

## 5. Counterexamples and readability

What SymCC returns is a synthesised request plus an entity store. Raw, for `sh-wider-path`:

```
principal: Agent::"", action: Action::"GET", resource: Url::""
context: {dangerous: false}
entities: [ Agent::"", Action::"PATCH", …(all 13 action entities)…,
  Url::"" { host: "api.github.com", path: "/repos/public/AAAAAA" } ]
```

That's usable but noisy: empty entity ids, every action entity listed, and cvc5's filler strings (`A`,
`AAAA`). The harness turns it into a sentence by reading the host, path and flags, and replaying them
through wicket's own matching. These are verbatim outputs (segment model):

- `GET https://api.github.com/repos/public/: the child allowed by reach rule 2 (api.github.com ["GET", "HEAD"] ["/repos/public/**"]); the parent needs a grant: outside reach`
- `GET https://AAAA.github.com/: the child allowed by reach rule 2 (*.github.com …); the parent needs a grant: outside reach`
- `GET https://api.github.com/repos/public/wicket/ (rated dangerous, R3+): the child allowed by reach rule 2 (… allow_dangerous); the parent needs a grant: matches reach rule 3 but is dangerous and that rule lacks allow_dangerous`
- `GET https://api.example.com/private/: the child allowed by reach rule 0 (api.example.com ["GET", "POST"] ["/**"]); the parent forbidden by forbid rule 0 (api.example.com ["/private/**"])`
- `DELETE https://api.anthropic.com/mcp-registry/FA/EA/DA/CA/BA/AA/ is not forbidden in the child (needs a grant: outside reach), but the parent forbidden by forbid rule 1 (… "/mcp-registry/**")` (the segment model fills free segments with junk)
- `inject secret "github-admin" into api.github.com Authorization as "Bearer {secret}": the child does, the parent doesn't`
- `start image "img:root": the child may, the parent may not` · `accept messages from zone "anyone": …`
- `run with memory 4096 MiB, -1 millicpus, -1 pids, timeout -1 s, isolation level 9223372036854775807, -1 children: allowed by the child, not by the parent`

**Judgement.**
- **HTTP counterexamples are good** once translated. They name a concrete request a human or agent
  understands. They tend to be the *minimal* witness (`/repos/public/`, `/tokio/AA/`), which is exactly
  the boundary that was crossed. The translator is about 60 lines, but it needs the zone's own rule list
  to say *which* rule allows it. SymCC knows nothing about rule numbers, so wicket replays the request to
  find out.
- **Numeric counterexamples need interpretation.** The solver sets every unconstrained field to an
  extreme (`-1`, `i64::MAX`) and violates only one limit. A user has to compare the values with the
  parent's limits to see that "memory 4096 > 3072" is the point. The schema can't express ranges, so
  avoiding the extremes needs extra assumption policies.
- **One counterexample per query.** For `every_widening_is_named`, SymCC reports 8 (one per failing
  action), where `subset.rs` lists 21 violations. The per-rule pass recovers the HTTP part (9 findings,
  matching `subset.rs`'s reach lines exactly) in about 0.7–1 s. Listing every limit, model and image
  violation would need one query per field: in effect, rebuilding the structural check.

## 6. What SymCC found that the hand-written check misses

1. **`subset.rs` ignores forbid rules** (rows 22 and 27). A child with the parent's reach and no forbids
   passes `subset::check`. It's safe today only because `crates/wicket-cli/src/spawn.rs` prepends the
   parent's forbids to every child zone (`z.forbid = p.zone.forbid…chain(z.forbid)`). If any other path
   constructs zones, the property is lost. Suggestion: make `subset.rs` require `parent.forbid ⊆
   child.forbid` structurally, or document the dependency on spawn.rs.
2. **`subset.rs` is incomplete for one-segment `*` in a parent glob** (row 19). `…/abc123/worker/**` ⊆
   `…/*/worker/**` is true, but `path_covered` only proves containment under literal `Q/**` parents, so
   it reports 3 false violations. The segment-model SymCC check proves it in 0.34 s. This is a
   conservative failure (it refuses, it doesn't over-allow).
3. Minor: `canonical_path("//")` is accepted. The body `"/"` is stripped to empty, so `//` counts as
   canonical, while every other empty segment is rejected. The envelope and oracle here treat `//` as
   invalid.

## 7. A's uses

### 7.1 Org policy diff in CI (`src/org.rs`, `logs/org.log`)

The test policy has 12 policies over 5 actions and 6 request environments:
- tenant isolation;
- owners approve up to R3, the `approvers` group up to R4, no self-approval;
- owners and operators inspect; agents inspect their descendant zones (`resource in principal.zone`);
- trusted images only;
- agents grant up to R2 under their own zone (#50).

There were three versions:
- **v2** is a plausible PR: owners may approve R4; agent inspection is dropped; and the self-approval
  forbid is "simplified" to `risk >= 2`.
- **v3** is a refactor of v1 that should change nothing.

| question | result | time per environment |
|---|---|---|
| v2 ⇒ v1 (does v2 allow anything new?) | **no**: `Human approve Zone` | 0–9 ms |
| v1 ⇒ v2 (does v2 remove anything?) | **no**: `Agent inspect Zone` | 0–5 ms |
| v3 ≡ v1 | yes, in all 6 environments | 0–6 ms |

SymCC compiles v1 for every environment in 1.6 ms.

The counterexamples replay with `Authorizer::is_authorized` and name the deciding policies:

```
v2 ⇒ v1 fails: principal Human::"" approve Zone::"", context {requester: Human::"", risk: -1};
  Human::"" in [Group::"approvers"]; Zone::"" { owner: Human::"A", tenant: Tenant::"" } …
  replay: v2 Allow by ["approvers-approve"], v1 Deny by ["no-self-approval"]
v1 ⇒ v2 fails: Agent::"" { zone: Zone::"A" } inspect Zone::"" in [Zone::"A"]
  replay: v1 Allow by ["agents-inspect-descendants"], v2 Deny by []
```

That's readable for a policy reviewer, especially with the policy ids from the replay.

Two caveats:
- It shows **one** loosening per environment. Here it found the subtle self-approval hole, not the
  deliberate R4 change. To list all of them, CI should block each counterexample and re-query, or diff
  policy by policy.
- `risk: -1` shows that range assumptions (`0 ≤ risk ≤ 4`) belong in a shared assumption policy, the
  same lesson as the zone envelope.

### 7.2 Org floor ⊆ manifest ⊆ ceiling (`logs/band-*.log`)

This uses the same zone compiler, on reach and limits only (8 actions):
- **floor**: crates, plus the git fetch of the repository;
- **manifest**: `examples/self-hosting`;
- **ceiling**: crates and `*.crates.io`, git fetch of `/public/*`, `GET /repos/public/**`, a forbid on
  `mcp-proxy.anthropic.com`, and 4g / 4 cpus / 4h.

| check | expected | result | string ms | segment ms | counterexample |
|---|---|---|---|---|---|
| floor ⊆ self-hosting manifest | holds | holds | 52 | 96 | – |
| self-hosting manifest ⊆ ceiling | holds | holds | 129 | 242 | – |
| manifest + git-receive-pack ⊆ ceiling | fails | fails | 132 | 319 | `POST https://github.com/public/wicket.git/git-receive-pack: the child allowed by reach rule 4 …; the parent needs a grant: outside reach` |
| floor ⊆ manifest without static.crates.io | fails | fails | 82 | 241 | `GET https://static.crates.io/: …` |
| manifest keeps the ceiling's forbids | fails (no forbid list) | fails | 148 | 672 | `GET https://mcp-proxy.anthropic.com/ is not forbidden in the child …, but the parent forbidden by forbid rule 0` |

## 8. Cedar and SymCC limits hit

1. **`like` has no one-segment wildcard.** Cedar `*` crosses `/`. Exact only by counting slashes (no
   `**`) or by changing the data model to segment attributes. `*` next to `**` can't be written exactly
   on a string path, and the approximations make cvc5 return `unknown`.
2. **No single-character wildcard, character classes or string length.** wicket's `?` and `[...]` can
   only be approximated. None of the example manifests use them.
3. **`like` patterns must be literals** (already known from research 18). Everything here is generated
   policy text per zone: for a parent plus child of 10–300 rules, 21–169 KiB (string model) and
   63–254 KiB (segment model).
4. **No regex, case folding or normalisation.** Host lower-casing and path canonicalisation have to be
   *assumed*, through shared envelope forbids, or SymCC reasons about requests the proxy never
   evaluates.
5. **No range types in the schema.** Counterexamples use `-1` and `i64::MAX`, so assumptions have to be
   written as policies.
6. **Request environments are fixed by the schema.** Each HTTP method is a declared action, so a
   manifest method outside the list (e.g. `PROPFIND`) needs a schema change. Every check runs once per
   environment: 20 queries per containment check.
7. **Dynamic quantities have to be baked into policy text per spawn**: the remaining model budget, time
   left and child slots. That's fine for generated static policies, but every spawn is a new policy set.
8. **One counterexample per query.** Enumerating violations means more queries (per rule or per field),
   or blocking each found model and re-querying.
9. **First-match semantics.** `evaluate` stops at the first matching reach rule (which matters for
   `allow_dangerous`). Cedar is order-free, so the compiler has to add negated earlier matches.
10. **cvc5 `--tlimit` is per process**, as described in §2. Use `cvc5_with_args(["--tlimit-per=…"])`, or
    a fresh process per check.
11. **Templates.** Not used here; SymCC rejects template-linked policies (research 18). Nothing in this
    experiment needed them: per-zone static text was enough.

## 9. Conclusion for #58

**Is B viable?** Not as designed, and not worth it.
- **Speed is acceptable.** For realistic zones (≤ 20 rules), one containment proof plus counterexamples
  takes 0.1–0.5 s with the exact encoding and under 75 MiB, so the spawn path could afford it.
- **Robustness is not.**
  - With the natural encoding, ordinary globs from our own examples (`/v1/code/sessions/*/worker/**`)
    make cvc5 return `unknown` at 60 s, on 1.3.1 and on 1.4.2.
  - The exact segment encoding fixes that, but it is a bespoke data model (depth ≤ 8) that the proxy
    would also have to enforce.
  - Its cost grows faster than linearly: 2.6 s at 100 rules, 30 s at 300.
  - It still gives one counterexample per action.
- **The result:** B needs a structural fallback for `unknown` and for "name every violation", plus a
  wicket-written zone-to-Cedar compiler inside the TCB whose correctness this experiment had to establish
  by difference testing. That fallback *is* A's capability algebra, so B adds a solver to the spawn path
  without removing the hand-written check. **Recommendation: keep A (research 18 §6); close the B option.**

**How A should use SymCC.**
1. **Org-policy CI diff.** Per request environment, run `check_implies_with_counterexample_opt` in both
   directions, plus `check_equivalent` for pure refactors. Queries take milliseconds.
   - Replay each counterexample with `Authorizer::is_authorized` to print the deciding policy ids.
   - Add shared assumption policies for ranges and canonical values.
   - To list every change, re-query after blocking each counterexample.
2. **floor ⊆ manifest ⊆ ceiling in CI**, with this experiment's compiler, the **segment path model**
   (exact), and the shared envelope.
   - Include the not-forbidden check, so a manifest keeps the ceiling's forbids.
   - Run host-sliced per-rule queries when listing violations.
   - About 0.1–0.7 s per manifest.
3. **SymCC as a test oracle for `subset.rs`**: generate zone pairs, and require that whenever `subset.rs`
   says "within", SymCC proves it. It found the forbid gap and the one-segment-`*` incompleteness (§6) on
   the first run.
4. **Operational:** pin cvc5 1.3.1, which SymCC is tested against; 1.4.2 was no better. Use
   `--tlimit-per`, treat `unknown` as a failed check with a clear message, and keep SymCC and cvc5 out of
   the node and spawn path (CI and the control plane only), as §5.1 already says.

## 10. Reproducing

```
export PATH=$HOME/.cargo/bin:$PATH CARGO_BUILD_JOBS=1
timeout 3600 cargo build --release
./run-all.sh      # first pass: string model, hard queries on cvc5 1.3.1/1.4.2 (≈40 min)
./run-all2.sh     # second pass: segment model, band, org, scale (≈25 min)
# single pieces: CVC5=$PWD/tools/cvc5 [SEG=1] [TLIMIT_MS=…] [CASES=rc-,sh-push] target/release/symcc-zones zones 5
```

The cvc5 binary comes from `https://github.com/cvc5/cvc5/releases/download/cvc5-1.3.1/cvc5-Linux-x86_64-static.zip`,
unzipped into `tools/dl-cvc5-1.3.1/` and linked as `tools/cvc5`. `target/`, `tools/` and `logs/` are
gitignored (`.gitignore` in this directory).
