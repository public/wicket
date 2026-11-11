# Experiment: a vendored, patched biscuit-auth on the request path (follow-up to #59)

**Question.** Can a vendored, patched biscuit-auth decide a depth-5 request fast enough for wicket's
per-request path? Target: warm median ≤ 20 µs and p99 ≤ 50 µs at depth 5, every correctness property
kept, and limits that don't depend on load.

**Answer: go on speed, but the recommendation for wicket stays plain records** (§8).
- **Speed.** Step 3 (a compiled world shared between threads) decides depth-5 requests A–D in a
  **6.9–10.7 µs median, 18–28 µs p99** warm. Stock 6.0.0 takes 965–1,168 µs median and 1.7–2.1 ms p99,
  about 100× slower. Plain records take 0.4–0.7 µs.
- **Correctness.** All 45 checks of #59 pass on every step. A differential test against stock 6.0.0
  on 100,000 random requests over 2,000 random chains gave the same decision every time, for every
  fork path.
- **Limits.** Limits are deterministic: there is a step budget (fuel) and no wall clock. Every
  legitimate request uses at most 282 steps; the limit is 4,000. A request at the limit gets the same
  outcome on every run.
- **Hostile blocks.** The fact explosion and the 150-rule chain are refused once per token, when the
  token is prepared. The 200-regex block is denied after 0.4 ms in step 2. Step 3 compiles the
  patterns once, so the same block is allowed after 0.11 ms. The structural lint rejects all three
  before any evaluation.
- **The price.** About 1,900 added lines on top of an unreleased upstream main. 1,233 of them are a
  second, hand-written Datalog evaluator, and that evaluator is what meets the target. The per-token
  (cold) cost also rises, from 2.0 ms to 3.2 ms at depth 5.

Everything is in this directory: the fork in `vendor/`, the harness in `src/`, raw outputs in `logs/`.

---

## 1. What was built

**Base.** Upstream `eclipse-biscuit/biscuit-rust` main at `aa5a672` (2026-11-09), not 6.0.0. Main
already has three things this experiment needs:
- a step counter in `RunLimits` (#352), counting one step per candidate fact and per operator;
- an O(1) candidate lookup by (predicate, arity);
- a `Sync` `Authorizer` (#357).

It has no way to reuse a loaded token across requests, and it still enforces `max_time` on the wall
clock. Tokens minted by 6.0.0 load unchanged.

The vendored crates are `vendor/biscuit-auth` (version `6.0.0-fork.0`) and `vendor/biscuit-parser`.
Their licences are kept, and `vendor/NOTICE` records the provenance and every change. The harness
links the fork next to crates.io `biscuit-auth = "=6.0.0"`. Tokens are minted by stock 6.0.0 with
#59's code (`src/bisc.rs`, `model.rs`, `plain.rs` and `stats.rs` are copied unchanged), then
serialized and loaded into the fork.

**Steps, as fork APIs** (`src/fk.rs` maps each to an engine):

| step | API | what it does |
|---|---|---|
| 0 (reference) | `AuthorizerBuilder::build(&token)` per request | upstream main, unchanged API |
| 1 | `AuthorizerBuilder::prepare(&token)` → `PreparedAuthorizer` (`Send + Sync`, behind an `Arc`); `.session()` per thread → `authorize(&facts, &limits)` | the token is decoded, translated and saturated once. Request facts go into an overlay (`FactView` = shared base + per-request `FactSet`). Before each request the session truncates its symbol-table copy and clears the overlay. Upstream limits, wall clock included. |
| 2 | the same, with `PreparedLimits { max_time: None, .. }` | fuel only: facts, iterations, steps. `.matches()` costs 16 steps per pattern byte plus 1 per 16 input bytes, because upstream compiles the regex on every evaluation. Plus the structural lint (`src/lint.rs`, using the new `Biscuit::block_datalog`). |
| 3 | `PreparedAuthorizer::compile()` → `CompiledAuthorizer` (`Send + Sync`, no per-thread copy); `authorize`, or `allows` (stops at the first failed check) | compiled world, described below |

**How step 3 compiles a token:**
- **Values:** 16-byte copyable values. Strings stay symbol indices; sets and byte strings are interned.
- **Predicates and origins:** each predicate gets a dense slot. Origins are 64-bit masks, so a scope
  check is one AND.
- **Queries:** each query keeps, per body predicate, the token facts it can see (scope and constants
  pre-filtered). Variables are renumbered into a fixed array.
- **Expressions:** a postfix program on a fixed stack. `||`/`&&` closures become jumps, and regexes
  are compiled once.
- **Per request:** facts are interned into a reused thread-local scratch space, so a warm request
  allocates nothing (§3.3). Rules run semi-naively over the overlay only.
- **Fallback:** anything the compiler doesn't represent (arrays, maps, closures with parameters, FFI,
  string concatenation, more than 62 blocks) sends the whole token to the generic engine. So does
  `{}`, which parses as an empty map. Any expression error at run time (a type error, an overflow)
  re-decides that request on the generic engine, so errors come out exactly as there.

---

## 2. Method

Same as #59. Measurements use `std::time::Instant` around each call, with n/10 warm-up calls and then
n = 20,000 warm calls (3,000 for once-per-token costs), reported as median and p99 in µs.
- **WARM** means the verified token is cached. Per request: the revocation check against a
  10k-entry set, then the decision with request facts built beforehand. Stock clones its static
  `AuthorizerBuilder`, adds the facts, builds and authorizes, exactly as in #59.
- **Requests A–D** at the leaf, at depth d = 1–5 (the authority block, d spawn blocks, and one
  third-party grant):
  - A: an allowed GET;
  - B: a denied GET outside reach;
  - C: a risk-3 PUT allowed only through the grant;
  - D: a spawn.

  Each one's decision is asserted before it is timed.
- **Machine:** a shared 4 vCPU Vultr VPS (Broadwell). Each run had one job slot. Load average was
  1.0–1.3 during the final run (`logs/env-final.log`), and the same box ran other sessions'
  idle processes. Toolchain: rustc 1.99.1, release profile (opt-level 3, codegen-units 16, no LTO).
- **Per-step runs.** Each step was measured right after it was written: `logs/bench-step1.log`,
  `bench-step2.log` and `bench-step3a.log`. All variants were then re-measured together in one final
  run (`logs/bench.log`), which the tables use.
  - The step-1 run overlapped for a minute or two with a type-check build, and its code still cloned
    each request fact (that was fixed before step 2). Its numbers are within 7% of the final run's.

---

## 3. Results

### 3.1 Depth 5, WARM, median / p99 µs (`logs/bench.log`)

| variant | A allow | B deny | C via grant | D spawn |
|---|---|---|---|---|
| stock 6.0.0, build per request | 991 / 1,715 | 1,168 / 2,072 | 1,099 / 1,958 | 965 / 1,695 |
| upstream main, build per request | 949 / 1,625 | 1,149 / 1,977 | 1,054 / 1,792 | 932 / 1,591 |
| step 1: prepared, per-thread session, overlay | 101 / 202 | 134 / 266 | 179 / 308 | 87 / 178 |
| step 2: as step 1, fuel only | 98 / 195 | 128 / 264 | 163 / 330 | 84 / 178 |
| **step 3: compiled, shared** | **7.8 / 19.4** | **10.3 / 27.5** | **10.7 / 26.6** | **6.9 / 18.2** |
| step 3, decision only (`allows`, early exit) | 7.8 / 18.2 | 2.6 / 5.2 | 10.6 / 18.8 | 6.9 / 13.5 |
| plain records (#59) | 0.7 / 0.8 | 0.4 / 0.4 | 0.6 / 0.7 | 0.4 / 0.5 |

### 3.2 Every depth: median range over A–D (worst p99 in brackets), µs

| variant | d1 | d2 | d3 | d4 | d5 |
|---|---|---|---|---|---|
| stock 6.0.0 | 412–516 (912) | 565–685 (1,179) | 719–880 (1,523) | 854–1,029 (1,809) | 965–1,168 (2,072) |
| upstream main | 409–505 (878) | 543–692 (1,178) | 703–863 (1,461) | 817–989 (1,680) | 932–1,149 (1,977) |
| step 1 | 38–73 (153) | 50–99 (195) | 60–124 (225) | 75–144 (275) | 87–179 (308) |
| step 2 | 37–71 (121) | 48–97 (199) | 60–122 (248) | 71–142 (280) | 84–163 (330) |
| **step 3** | **3.0–4.9 (11.6)** | **4.0–6.4 (16.6)** | **5.0–8.0 (22.3)** | **6.0–9.4 (24.1)** | **6.9–10.7 (27.5)** |
| step 3, early exit | 2.4–4.9 (11.5) | 2.4–6.4 (14.6) | 2.4–8.0 (19.6) | 2.5–9.4 (19.8) | 2.6–10.6 (18.8) |
| plain records | 0.2–0.3 (0.6) | | 0.3–0.5 (1.1) | | 0.4–0.7 (0.8) |

**What each step bought:**
- **Upstream main alone** is 0–8% faster than 6.0.0, which is within noise. The per-request `build`
  still dominates.
- **Step 1** removes `build` from the request path: about 10× faster. What remains is the generic
  engine. A step-2 profile (`logs/callgrind-s2-0.log`) shows 544k instructions per decision:
  - 80% in `Rule::find_match` (boxed iterators, a `HashMap` per binding, `Term` and set clones);
  - about 22% in malloc and free.
- **Step 2** is the same speed as step 1. Dropping the wall clock saves only the `Instant::now()`
  calls.
- **Step 3** is another 10–15× faster. Request A takes about 45k instructions, with no allocation.
  Cost grows by about 1 µs per spawn level, against 140 µs for stock.
- **Early exit** only helps denials: B drops to 2.6 µs because the first failed check ends the
  evaluation.

Sharing works (`logs/threads.log`): 1, 2 and 3 threads sharing one `CompiledAuthorizer` made 103k,
202k and 266k decisions/s over a mix of A–D, with 0 wrong.

### 3.3 Where step 3's time goes (callgrind, depth 5; `logs/callgrind-s3-*.log`)

- **Request A** (45k instructions per decision):
  - expression evaluation: 33% self;
  - the join over candidate facts: about 25%;
  - the check loop: 9%;
  - loading and interning the 13 request facts: 10%;
  - memcmp/memcpy: about 2%;
  - malloc: none.
- **Request B with the full report:** about 5% goes on allocation, all of it cloning the check texts
  for the error list. `allows` skips that.

The target was met with the first compiled version, so I stopped there. Obvious next steps would be an
uninitialised stack, fewer bounds checks, and indexing request facts by first argument. Each is worth
maybe 10–30% and isn't needed.

### 3.4 Once per token (fork, depth 5; `logs/bench.log`)

| piece | median µs | p99 µs |
|---|---|---|
| parse + verify signatures (`Biscuit::from`) | 1,135 | 1,753 |
| structural lint | 354 | 627 |
| prepare: build, translate, saturate, format check texts | 1,260 | 2,184 |
| compile | 236 | 428 |
| **COLD A: parse + revocation + lint + prepare + compile + decide** | **3,156** | **5,061** |
| for comparison: stock 6.0.0 COLD A (#59 §3.3) | 1,992 | 3,306 |

**Cold is about 1.5× stock's.** Each node pays it once per token and then caches the result. It is
also unoptimised:
- prepare formats every check's text up front;
- the lint decodes every block again into builder types;
- parsing is slower than 6.0.0's 953 µs in #59. Upstream main moved to ed25519-dalek 3 and prost
  0.14; I didn't investigate the cause.

Building the 13 request facts in builder types costs 2.5 µs per request. That cost is outside the
WARM numbers, as it was for stock.

---

## 4. Deterministic limits

### 4.1 Fuel (`logs/limits.log`)

The chosen limits are `PreparedLimits { max_facts: 256, max_iterations: 8, max_steps: 4000,
max_time: None }`.

| depth 5 | A | B | C | D |
|---|---|---|---|---|
| steps, step 2 (generic engine) | 191 | 244 | 282 | 168 |
| steps, step 3 (compiled) | 185 | 238 | 276 | 162 |
| facts in the world | 23 | 23 | 23 | 18 |

- **How steps grow:** about 29 steps per level (depth 1: 58–109).
- **Headroom:** the most any legitimate request used is 282 steps, so 4,000 gives 14×.
- **Why the two counts differ:** step 3 pre-filters token facts by constant, which saves a few
  steps.
- **Boundary test:** request A on step 3 with `max_steps` = 184 was denied with
  `TooManySteps` on 5 runs out of 5. With 185 it was allowed on 5 out of 5. Load can make a request
  slower, but it can't change its decision.

Choices:
- **The fork's steps are its own measure.** They follow upstream's rule (one step per candidate fact
  visited, one per operator), with two changes:
  - the token's facts are saturated once, when the token is prepared, and step 3 runs rules
    semi-naively, so a request never pays for rules that only read token facts;
  - `.matches()` is weighted by length.
- **The regex weight is conservative.** Compiling the 37-byte hostile pattern takes 26 µs, about 53
  generic-engine steps at 494 ns each. The fork charges 16 steps per byte, which is 592.
- **Time per step depends on the engine.** For a whole request it is about 40 ns per step on step 3
  (about 150 ns for a regex match) and about 500 ns on step 2. So 4,000 steps cap the CPU per request
  at roughly 0.6 ms on step 3 and 2 ms on step 2. That holds while each step stays bounded, which the
  lint's size caps guarantee (sets of at most 64 elements, strings of at most 1 KiB).

### 4.2 Hostile holder blocks (#59 §4), appended to the depth-5 chain, request A

| appended block | stock 6.0.0, defaults (1 ms) | stock, max_time 50 ms | fork, prepare (once per token) | step 2, per request | step 3, per request | lint |
|---|---|---|---|---|---|---|
| fact explosion (40×40) | denied, 2.6 ms | denied, 2.5 ms | refused: TooManyFacts after 1,640 steps, 3.3 ms | denied, 0.1 µs (prepare error kept) | denied, 0.1 µs | rejected (rules in a first-party block), 0.37 ms |
| 150-rule chain | denied, 2.3 ms | denied, **21.7 ms** | refused: TooManyIterations after 36 steps, 2.1 ms | denied, 0.1 µs | denied, 0.1 µs | rejected, 0.56 ms |
| 200 regex checks | denied (Timeout), 2.6 ms | **allowed, 12.2 ms** | ok, 2.4 ms (+6.6 ms to compile the 200 patterns for step 3) | **denied: TooManySteps at 4,356 steps, 0.40 ms** | **allowed, 0.11 ms (785 steps)** | rejected (200 checks > 32 per block), 0.76 ms |

How to read the table:
- **Rule floods** are now stopped once per token, at prepare. Every later request is refused at no
  cost.
- **The 200 regex checks only narrow**, so allowing them isn't a safety problem, only a CPU one.
  - Stock lets them through at 12 ms per request once `max_time` is raised enough to avoid spurious
    denials.
  - Step 2 denies them deterministically after 0.4 ms.
  - Step 3 matches precompiled patterns cheaply enough to allow them at 0.11 ms, inside the fuel.
    Compiling them once costs 6.6 ms per token, which no step budget covers.
- **The lint is the real control; fuel is the backstop.** Order on a node: lint → prepare → compile,
  each cached by the token's bytes.

### 4.3 Structural lint (`src/lint.rs`)

**First-party blocks** may carry:
- facts `tenant`/`principal`/`zone` only, and no rules;
- checks (`check if` / `reject if`, not `check all`) over the fixed ambient vocabulary:
  `time box op host method path path_depth risk inject spawn llm_used msg_from`, plus `approved/4`.
  `approved/4` is allowed only under `trusting <key>`, and no other scopes are allowed.
- operators: comparisons, equality, `contains`/`starts_with`/`ends_with`, `!`, `&&`/`||`. No
  `.matches`.

**Third-party blocks** may carry:
- `approved/4` rules whose bodies read only `time box epoch uses_left`;
- `approval/3` facts;
- nothing else, and only if signed by a key that some first-party block trusts.

**Caps:** 32 KiB per token, 16 blocks, 32 checks per block, 32 alternatives per check, 8 predicates
per query, 64 operators per expression, sets of 64 elements, strings of 1 KiB.

**Results:**
- The legitimate chains at depth 0–5 pass, in 89–373 µs once per token.
- Rejected: the forged `approved` fact, the holder rule, `.matches`, a foreign predicate, an untrusted
  third-party signer, and all three hostile blocks.
- Accepted: `check if true` and plain narrowing checks, as they should be.
- Of the differential test's random chains, 603 of 2,000 would be rejected by the lint (forged facts,
  holder rules, `check all`, attacker-signed grants). They were decided anyway, to test the engine.

---

## 5. Correctness

**The 45 checks of #59 §5** (`logs/correct.log`) pass with every decision and every parse made by
each engine in turn: stock, upstream main, step 1, step 2 and step 3. The checks are:
- no widening, only narrowing;
- expiry and leases, agent grants;
- revocation ids (the fork's ids equal stock's);
- the 9,982 byte flips, block drop, block reorder and transplant;
- the plain-records checks.

The per-step logs `correct-step1.log` and `correct-step2-3.log` show the same.

**Differential test** (`src/diff.rs`, `logs/diff.log`):
- **Chains:** 2,000 random chains, built from #59's ceilings with random narrowing and random extra
  reach entries per level. 75% carry a grant whose host, method, path, expiry, box and epoch are
  random, signed by the approver, the parent's grantor, the leaf's own key or an attacker. 20% carry
  a random holder block, such as `check if true`, a forged `approved`, a holder rule, `check all` or
  narrowing checks.
- **Requests:** 50 per chain. Each is request A–D with 0–3 random mutations to time (including exact
  expiries), tenant, box, epoch, ledger, host, method, path, risk, inject, spawn, LLM or message
  fields. 2% carry an ill-typed fact, which makes expressions fail.
- **Result:** of 100,000 requests, stock allowed 17,948 and denied 82,052. **Upstream main, step 1,
  step 2 and step 3 made the same decision on all 100,000. No divergence, and no run-limit denials.**
- **Coverage of the compiled path:** 1,983 of the 2,000 chains compiled. The other 17 hold a `{}`
  literal, which is a map, and used the generic engine. 1,679 requests (the ill-typed ones whose bad
  fact got evaluated) fell back to the generic engine at run time.

**Upstream's own unit tests** pass on the fork, 97 of 98 (`logs/upstream-unit-tests.log`). The one
failure regenerates `schema.rs` and needs the `protoc` binary, which isn't installed here.

**Known semantic differences from stock.** None affects a decision unless an expression errors or a
limit is hit:
- **Fact order.** The fork visits token facts before request facts; stock orders them by origin.
  Under stock, a query where one candidate errors and another succeeds can succeed or fail depending
  on that order. Step 3 hands any expression error to the generic engine, which has the same
  sensitivity. The lint rules out the ill-typed checks that could cause it.
- **Limits.** Step counts and iteration counts differ from upstream's, because of pre-saturation,
  semi-naive rules and the regex weight. Limits are a fork-defined budget.

---

## 6. Fork size and what is upstreamable

`logs/fork.diff`. Upstream `biscuit-auth/src` is 19,595 lines.
- **Modified upstream files:** 7, with +199 / −11 lines:
  - `datalog/mod.rs`: +122 / −11;
  - `token/mod.rs`: +32;
  - `datalog/symbol.rs`: +19;
  - `datalog/expression.rs`: +16;
  - `datalog/origin.rs`: +5;
  - `lib.rs`: +4;
  - `token/authorizer.rs`: +1;
  - the two manifests.
- **New files:** `token/authorizer/prepared.rs` (439 lines; steps 1–2) and `datalog/compiled.rs`
  (1,233 lines, 1,076 without comments and blanks; step 3).

| change | lines | upstreamable? | already on upstream main? |
|---|---|---|---|
| step counter; O(1) candidates; `Sync` authorizer | — | — | **yes** (#352, #357), unreleased |
| `FactSource` / `FactView` overlay, `run_overlay`, `prepare` / `session` | ~560 | **yes**: a "load once, add request facts" API is the natural follow-up to the `Sync` authorizer, and it is general | no: main can't add facts after `build` and memoises `run()` |
| `max_time: Option` (deterministic mode) | small | **yes**: the step counter makes the wall clock optional | no: main still enforces `max_time` |
| `.matches()` weighted by length (or a compiled-regex cache) | 16 | yes, probably as a cache | no |
| `Biscuit::block_datalog` (block contents in builder types) | 32 | yes | no (only `print_block_source`) |
| compiled evaluator (`compiled.rs`) | 1,233 | unlikely as is: it is a second evaluator next to the generic one. Its ideas (interned values, origin bitmasks, pre-filtered candidates, no per-binding `HashMap`) could go into the generic engine over time. | no |

Steps 1 and 2 would be a reasonable upstream PR on their own, but they reach only about 100 µs. **Only
step 3 meets the target, and step 3 is the part upstream is least likely to take.**

---

## 7. Remaining costs

- **Per request at depth 5:** 7–11 µs warm, against 0.4–0.7 µs for plain records (10–25×). That is
  under wicket's own `wicket_core::evaluate` today (about 20 µs), but with its globs precompiled
  (#74) evaluate takes about 0.13 µs.
- **Per token:** 3.2 ms cold (parse, lint, prepare, compile), against 2.0 ms for stock and 0.64 ms
  for plain records. It is cached per token, and there is room to cut it (§3.4).
- **Size:** unchanged from #59. The token is 10 KB (13.4 KB base64) at depth 5.
- **Trusted computing base:** the authorization path would include:
  - all of biscuit-auth (about 19.6k lines) plus the fork (about 1.9k);
  - an unreleased upstream main, with new major versions of ed25519-dalek and prost;
  - a hand-written compiled evaluator whose only guarantee is the differential test against the
    generic engine.

  Plain records are about 250 lines.
- **Maintenance:** the fork has to be rebased onto upstream's changes, such as the step budget API,
  the snapshot format and the expression set. Every rebase has to re-run the differential test.

---

## 8. Recommendation for wicket

**Keep plain signed records on the request path, with Biscuit as the CI oracle (#59 §7).** Speed is no
longer the reason. The reasons now are these:
1. **The fast part is a hand-written evaluator.** Getting under 20 µs takes `compiled.rs`, a 1,233-line
   evaluator checked only by differential tests against Biscuit. Plain records are the same
   arrangement (a hand-written evaluator, differential-tested against Biscuit in CI) at a fifth of
   the size, 10–25× faster, and without vendoring 20k lines of an unreleased fork.
2. **Cold cost and size are worse.** They don't matter while tokens stay on the node, but they buy
   nothing wicket uses: the fixed vocabulary means nobody writes Datalog.
3. **The limits problem is solved either way.** Biscuit can be given deterministic fuel, but plain
   records have no evaluator to exhaust in the first place.

**What to keep from this experiment:**
- Upstream `prepare` / overlay and the optional `max_time` (§6) as small, general PRs to
  biscuit-rust. They make Biscuit usable on a per-request path for other users at about 100 µs.
- Reuse the fork's prepared/compiled path for the CI oracle: against a prepared or compiled token, the
  differential test in CI runs 10–100× faster.
- The lint's rules, as the validation plain records apply to every link: fixed vocabulary, grants
  only from trusted keys, size caps.

**When to revisit:**
- chains must be verified outside wicket;
- or nodes must attenuate without certified node signing keys.

Then the vendored step-3 fork meets the latency budget as measured here. Re-run the differential test
on every rebase, and keep the lint in front of it.

---

## 9. Reproducing

Run from `experiments/biscuit-fast/`. The fork is `vendor/biscuit-auth` (upstream
`eclipse-biscuit/biscuit-rust` `aa5a672` plus `logs/fork.diff`). Nothing else needs fetching
beyond crates.io.

```sh
CARGO_BUILD_JOBS=1 cargo build --release
target/release/biscuit-fast correct                  # 45 checks × 5 engines      > logs/correct.log
target/release/biscuit-fast correct stock,main,s1    # one subset of engines
target/release/biscuit-fast limits                   # fuel, boundary, regex weight, hostile blocks, lint > logs/limits.log
target/release/biscuit-fast threads                  # > logs/threads.log
target/release/biscuit-fast diff                     # DIFF_CHAINS=2000 DIFF_REQS=50 DIFF_SEED=59 > logs/diff.log
BENCH=stock,main,s1,s2,s3,s3x,plain,cold target/release/biscuit-fast bench   # > logs/bench.log
# per-step runs: BENCH=stock,main,s1,plain (step 1), BENCH=s2 (step 2), BENCH=s3,s3x (step 3)
# ITER_SCALE=0.3 shortens every loop

cargo build --profile profiling
PROFILE_VARIANT=s3 PROFILE_REQ=0 ITER_SCALE=0.5 valgrind --tool=callgrind target/profiling/biscuit-fast profile
PROFILE_VARIANT=s2 PROFILE_REQ=0 ITER_SCALE=0.1 valgrind --tool=callgrind target/profiling/biscuit-fast profile

(cd vendor/biscuit-auth && cargo test --release --lib)  # upstream unit tests; `proto` needs protoc
```

Engines: `stock` (6.0.0), `main` (the fork through the stock API), `s1`, `s2`, `s3`. Bench variants
also accept `s3x` (`allows`, early exit), `plain` and `cold` (once-per-token costs).
