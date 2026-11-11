# Experiment: data-only blocks or Datalog checks? (token layout for #76)

**Question.** Should wicket's spawn and grant blocks carry Datalog checks (today's draft, design A),
or one typed fact each, intersected by wicket's own code (design B)? Or both, cross-checked (design C)?
Research 23 §4 found that Agent Mesh and limes chose B. The cost is that "a child can't exceed its
parent" moves from Biscuit's semantics into wicket code.

**Answer: use B for #76.** Keep A's Datalog compiler as a CI oracle, not in tokens.
- **Correctness.** All 46 ported properties pass on A, B and C, plus 10 data-block checks on B
  (§3.1). Six deliberate intersection bugs in B's evaluator are all caught (§3.2).
- **Differential.** On 100,000 random requests over 2,000 random chains, B makes the same decision
  as A on every request where both use the same path matching. 8 requests differ, and all 8 are the
  glob `/tokio/*` against A's prefix-plus-depth encoding of it. B follows wicket's own matcher there,
  so B is the one that agrees with wicket (§3.3).
- **Speed.** At depth 5, warm, B takes **0.4–2.3 µs median (p99 ≤ 6 µs)** with wicket-core's
  `CompiledZone` for requests A, B and D. The grant request C takes 6.5 µs (p99 31 µs). A takes
  6.9–10.6 µs (p99 ≤ 36 µs), plus 2.4 µs per request to build its Datalog facts. With an allocation-free prefix matcher, B takes
  0.4–1.8 µs. B's once-per-token load is 1.8 ms against A's 2.9 ms. B's token is 26% smaller (§4).
- **Attack surface.** B never evaluates attacker-authored logic, so there is nothing to exhaust and no
  fuel to tune. Every hostile Datalog block is refused at load, by the extractor's shape check. The
  worst token B's caps allow costs 21 ms to load and 37 µs per request (§5).
- **Trusted code.** B is about 330 lines of wicket code plus wicket-core's `CompiledZone`. It needs
  one 25-line accessor in Biscuit (`block_datalog`). It needs none of biscuit-fast's 1,645-line
  prepared/compiled evaluator, and no Datalog engine on the request path. A needs 336 lines of wicket
  code plus that evaluator (§6).
- **A bug in today's draft.** A's generator writes an empty list as `{}`, which Biscuit parses as
  an empty map. The lint then refuses legitimate tokens: 31 of the 2,000 random chains (§3.3).
- **C buys nothing in production.** Its token is 65% larger than A's, it loads in 4.8 ms, and it
  decides at A's speed. Its cross-check is exactly the differential test, which runs as well in CI.

Everything is in this directory: code in `src/`, raw outputs in `logs/`.

---

## 1. What was built

### 1.1 The three designs

| | A: checks (today's draft) | B: data-only | C: hybrid |
|---|---|---|---|
| authority block | `tenant`, `principal`, `zone(name)`, 11 checks | `tenant`, `principal`, `zone("<json>")` | A's block plus `zone_spec("<json>")` |
| spawn block | 9 checks | exactly one `zone("<json>")` fact | A's block plus `zone_spec("<json>")` |
| grant block (third-party) | an `approved(…) <- …` rule and an `approval(…)` fact | exactly one `grant("<json>")` fact | both |
| gate at load | `lint.rs` (fixed vocabulary, caps) | `zf.rs` extractor (shape, canonical JSON, caps) | both |
| decision | the fork's compiled evaluator (biscuit-fast step 3, fuel 4,000 steps) | wicket code: every zone block must allow; grants counted per block | A decides; B runs next to it and every disagreement is counted |
| what Biscuit provides | signatures, the append-only chain, third-party binding, revocation ids, the Datalog engine | signatures, the chain, third-party binding, revocation ids | everything A uses |

The authority block is data-only in B as well. Research 23 suggested keeping Datalog there; I didn't,
because any check in the authority block puts an evaluator back on the request path. The authority
block is root-signed, so it can't be hostile. Data-only there is about cost and one code path, not
safety.

All three are generated from the same capability model as #59 and biscuit-fast (`src/model.rs`, a
cut-down `ZoneSpec` called `Ceiling`). Tokens are minted with stock biscuit-auth 6.0.0 and loaded into
biscuit-fast's fork, as there.

### 1.2 B's encoding: one canonical JSON string per block

The fact holds the `Ceiling` (or `Grant`) as serde_json's compact output, fields in declaration order.
The extractor parses it with `deny_unknown_fields`, re-serializes it, and refuses the token unless the
bytes are identical. So there is exactly one accepted encoding of each zone: no whitespace, key order,
escape or number-format variants, and no duplicate keys.

Why JSON in one fact, rather than a set of structured facts (`reach(host, methods, path)`, …):
- **It reuses the typed structs.** wicket already serializes `ZoneSpec` with serde. A set of facts
  needs a second schema, and code to rebuild the struct from it.
- **Facts are a set; zones are ordered.** wicket's `evaluate` takes the first matching reach rule, and
  `allow_dangerous` depends on which rule matched. A fact set loses the order unless every fact
  carries an index.
- **One shape check.** "Exactly one `zone/1` string fact" is the whole check. With structured facts,
  every predicate needs its own arity, type and count rules.
- **No Datalog injection.** Facts are built with the typed builder (`fact("zone", &[string(json)])`),
  never by formatting Datalog text. Research 23 §0 item 5 lists injection through `format!` as a
  recurring bug elsewhere.
- **Size.** The level-5 zone is 799 bytes of JSON against 1,387 bytes of Datalog source (`logs/sizes.log`).

The cost is that the zone is opaque to Biscuit. A stock Biscuit verifier would see only facts and no
checks, so it would treat the token as unrestricted (§7).

The extractor (`zf::extract`) fails closed. Any block that isn't exactly the expected shape refuses
the whole token. It never skips a block. The rules:
- block 0: one `tenant`, at most one `principal`, one `zone`; no external key;
- other first-party blocks: exactly one `zone` fact;
- third-party blocks: exactly one `grant` fact;
- nowhere: rules, checks or scopes;
- every fact: exactly one string term;
- caps: 32 KiB per token (checked before parsing), 16 blocks, 8 KiB per zone, 1 KiB per grant,
  64 reach entries, 32 forbids, 32 entries per other list, 256 bytes per string;
- fields: hosts lower-case, methods upper-case, path prefixes literal (no glob metacharacters),
  grant keys 64 lower-case hex digits.

Then each zone's reach and forbid entries are compiled into a wicket-core `CompiledZone`, and its
`dangerous_ok` list into a second one. This happens once per token.

### 1.3 B's decision

`zf::Chain::allows` allows a request only if the tenant matches block 0 and **every** zone block
allows it. A block allows a request if all of these hold:
- the request is before `not_after`;
- the box is the block's box or below it;
- the op kind is listed;
- for HTTP: `CompiledZone::evaluate` says `AllowByReach`, or a grant this block trusts matches. A
  `Forbidden` verdict always denies;
- for HTTP, if the risk is above `max_risk`: the request is in `dangerous_ok`, or a trusted grant
  matches;
- for HTTP, any injected credential is listed;
- spawn limits, LLM budget and `accept_from` hold.

These are exactly A's checks. A's Datalog in `bisc.rs` is the specification.

`Matcher::Model` is the same evaluator with the model's own prefix matching instead of `CompiledZone`.
It separates "is the intersection right" from "do globs and prefixes agree".

### 1.4 Grants and approvals in B

A grant is not another zone to intersect. It widens a block's reach for one exact request
(host, method, path). It must not widen anything the grantor couldn't do itself. B handles this the
way A does:
- **The grant block.** A grant is a third-party block holding `grant("<json>")`. The JSON has the
  grant id, box, epoch, host, method, path, expiry, approver and passkey digest. The node calls
  `third_party_request()`, the approver signs, and the node appends. Biscuit binds the block to the
  previous signature, so it can't be moved to another chain (tested). It gets its own revocation id
  (tested).
- **Trust is per block.** Each zone block lists the keys it trusts (`grant_keys`):
  - every block trusts the approval service, for human approvals;
  - a spawn block also trusts its parent box's grantor key, for agent grants (#50).

  A grant counts in a block only if that block lists the grant's signer. The extractor reads the
  signer from Biscuit's external key, not from the JSON.
- **So an agent grant stays within the parent's ceiling.** A grant from b4's key widens only the
  leaf's block. Blocks 0–4 still have to allow the request on their own terms. That is "within the
  grantor's authority", with no extra rule.
- **Human approvals.** A human approval is trusted by every block, so it passes every reach and risk
  check. Forbids, spawn limits, budgets and injection still apply: there is no grant escape for those.
- **The lease is live only while all of these hold:** the request is before the grant's expiry; the
  box is exactly the grant's box, so a child box inheriting the token doesn't get it; the epoch
  matches; and the node's ledger has uses left. When the lease lapses, the grant stops counting. The
  chain stays valid.

The agent-grant properties in §3.1 show each case:
- b4 grants within its reach: allowed;
- b4 grants outside its reach: denied by block 3;
- b4 grants a risk-3 PUT it couldn't do itself: denied;
- the approval service grants the same PUT: allowed;
- an approval for a path the authority forbids: denied;
- a box can't approve itself: no block trusts the leaf's own key.

---

## 2. Method

- **Same harness as biscuit-fast.** `std::time::Instant` around each call. Warm-up of n/10 calls, then
  n = 20,000 warm calls (3,000 for once-per-token costs). Median and p99 in µs.
- **Warm** means the token is loaded and cached. Each request pays the revocation check (every block
  id against a 10k-entry set) plus the decision. The request's input is built beforehand: A's 13
  Datalog facts (2.4 µs to build) or B's wicket-core `Op` (0.1 µs).
- **Requests A–D** at the leaf, depth 1–5: an allowed GET, a denied GET, a risk-3 PUT allowed only
  through the human approval, and a spawn. Each decision is asserted before timing.
- **A's node pipeline** is parse → lint → prepare → compile (biscuit-fast's step 3). In §3.1 the lint
  is now part of A's load, which biscuit-fast's correctness run didn't do. The differential decides A
  whether or not the lint accepts the token, as biscuit-fast did, and records the lint separately.
- **Machine.** A shared 4 vCPU Vultr VPS (Broadwell). One job slot, one thread. Load average 0.76
  before the bench and 1.09 after (`logs/env-bench.log`). rustc 1.99.1, release profile.
- **The fork.** It uses biscuit-fast's vendored fork (`../biscuit-fast/vendor/`): upstream biscuit-rust
  `aa5a672` plus biscuit-fast's patches. Design B only needs its 25-line `Biscuit::block_datalog` accessor.
- **Changes to copied files.** `bisc.rs`, `fk.rs`, `plain.rs` and `stats.rs` are copied from
  biscuit-fast unchanged. `model.rs` gains `deny_unknown_fields` on its serialized types. `lint.rs`
  gains `Policy::data_facts`, which admits C's `zone_spec` and `grant` facts.

---

## 3. Correctness

### 3.1 Property checks (`logs/correct.log`)

| design | checks | result |
|---|---|---|
| A: checks (step 3, with lint) | 46 | all pass |
| B: data-only, `CompiledZone` | 56 | all pass |
| B: data-only, model matcher | 56 | all pass |
| C: hybrid | 57 | all pass; B agreed with A on every decision |

**What the suite covers.** It ports biscuit-depth's 45 checks, minus the 5 plain-records checks, plus
6 new ones every design runs:
- an approval can't reach a path that only the authority block forbids;
- a well-formed zone block wider than the leaf doesn't admit request B;
- a holder block that trusts an attacker key, plus a grant signed by that key: denied by the other
  blocks;
- a block naming a wider box and a later expiry doesn't admit another subtree;
- the second line (`plain::narrows`) accepts every scenario level;
- the second line names the widening in the wider block.

B adds 10 data-block checks. Each of these is refused at load:
- non-canonical JSON;
- an unknown field;
- a duplicated key;
- a missing field;
- two zone facts in one block;
- an integer term;
- a narrowing Datalog check;
- a zone fact in a third-party block signed by a trusted key;
- an empty block;
- 65 reach entries.

C adds one more check: B agreed with A on every decision C made.

**Properties whose meaning changes under B:**

| property | A | B |
|---|---|---|
| a holder appends `check if true`, a forged `approved` fact or a rule | the lint refuses the last two; the engine ignores all three | the token is refused at load: any rule, check or misplaced fact fails the shape check |
| a node narrows | appends a check, e.g. `method("GET")` | appends a zone. To narrow one dimension, it appends a zone that allows everything else (the tests use `top()` with one field changed) and lists no grant keys, so grants don't pass it. A Datalog check is refused |
| a forged grant | an `approved` fact in a first-party block is out of scope for `trusting` | a `grant` fact in a first-party block is refused at load |
| an untrusted third-party grant | the lint refuses the token | the extractor accepts it, but no block counts it. Refusing it as well would be a one-line change |
| no widening | Datalog checks can only add conditions | intersection in wicket code: every block is evaluated, none skipped |

Everything at the Biscuit layer is unchanged, because B still uses it:
- 9,982 / 7,455 / 16,490 single-byte flips (A / B / C): none loads;
- dropping, removing or reordering blocks, the wrong root key, a transplanted third-party block, and
  appending to a sealed token: all rejected;
- revocation ids per block and per subtree.

### 3.2 Does the suite constrain B's evaluator? (`logs/mutants.log`)

B's intersection is hand-written, so the suite must fail if it is wrong. Six typical bugs were
simulated by transforming the loaded chain:

| mutant | caught |
|---|---|
| decide with the leaf's zone only | yes |
| skip the authority block | yes, after adding the "authority forbids" check (see below) |
| a grant counts in a block if any block trusts its signer | yes |
| ignore the box binding | yes |
| ignore expiry | yes |
| a grant counts in every block, whatever it trusts | yes |

"Skip the authority block" passed all 55 checks of the first version. Each spawn level narrows the
one before, so only the authority's forbid rules distinguish it, and no request hit them. Adding "an
approval can't reach a path only the authority forbids" caught it. #76's tests should include it,
and the mutants should run in CI. They should also run against the differential's random chains,
where a "skip block k" bug shows up without a hand-written probe.

### 3.3 Differential (`logs/diff.log`)

**Setup.**
- The generator is biscuit-fast's: 2,000 random chains with random narrowing and widening per level,
  75% with a random grant (approver, parent grantor, the leaf's own key or an attacker) and 20% with
  a holder block. Each chain gets 50 random requests, seed 76.
- Each holder block has a B equivalent: a narrower zone, or a malformed block where A's block is
  hostile Datalog.
- Four canonical edge paths were added to the request set: `/tokio/`, `/tokio/latest/`,
  `/repos/acme/` and `/simple/`.
- There are no ill-typed request facts. B's requests are typed, so there is nothing to mistype.

| design | same decision as A | different |
|---|---|---|
| B, `CompiledZone` | 95,942 | **8** |
| B, model matcher | 95,950 | 0 |
| C (decides with A) | 70,450 | 0 (its cross-check: 2 disagreements) |

A allowed 17,783 of the 100,000 requests and denied 82,217. 1,537 of the 2,000 chains have a link
wider than its parent. All of them were decided correctly by intersection.

**The 8 disagreements are a matcher difference, not an intersection bug.** With the model matcher, B
agrees with A on all 95,950 requests.
- 6 are `GET /tokio/latest/`: A allows, B denies.
- 2 are `GET /tokio/`: A denies, B allows.

`logs/globs.log` checks all four path forms against 18 canonical paths. Only these two differ.

**B agrees with wicket-core's own `evaluate` on these paths; A doesn't.** If the zone means what
`evaluate` says, which is how wicket decides today, B is right. A encodes the glob `/tokio/*` as
`starts_with("/tokio/")` plus `path_depth == 2`. That differs from globset in two places:
- `*` matches the empty segment, so the glob matches `/tokio/` (depth 1);
- `*` can't cross the trailing `/`, so the glob doesn't match `/tokio/latest/` (depth 2).

Under A, a node's per-zone decision (`CompiledZone::evaluate`) and the token's decision would
disagree on these paths. Under B there is one matcher. #76 should either make A's compiler exact, or
drop it.

**Tokens refused at load.** C runs the lint and the extractor:

| reason | chains | requests A allowed on them |
|---|---|---|
| B: rules, checks or scopes in a block (holder rule) | 43 | 359 |
| B: a grant fact in a first-party block (forged grant) | 38 | 345 |
| C: lint, signed by a key no block trusts | 440 | 3,709 |
| C: lint, `{}` term (an empty set compiled by A's generator) | 31 | 155 |
| C: lint, `check all`, forged `approved`, rules | 41 + 36 + 43 | 830 |

Refusing these tokens is intended in both gates. One A-side bug showed up: A's generator writes an
empty list (no images, no `accept_from`) as `{}`. Biscuit parses that as an empty *map*, the lint
rejects it, and the step-3 compiler falls back to the generic engine. 31 legitimate chains were hit.
B has no such encoding trap: an empty list is `[]`.

---

## 4. Speed and size (`logs/bench.log`, `logs/sizes.log`)

### 4.1 Warm, per request, depth 5, median / p99 µs

| variant | A allow | B deny | C via grant | D spawn |
|---|---|---|---|---|
| A: checks, compiled (step 3) | 8.0 / 27.4 | 10.5 / 36.1 | 10.6 / 32.8 | 6.9 / 20.2 |
| **B: data-only, `CompiledZone`** | **2.3 / 5.6** | **1.4 / 4.2** | **6.5 / 30.9** | **0.4 / 1.7** |
| B: data-only, model prefix matcher | 0.5 / 1.0 | 0.4 / 0.9 | 1.8 / 3.1 | 0.6 / 0.9 |
| C: decide with A (release) | 7.9 / 28.0 | 18.2 / 37.0 | 10.7 / 34.5 | 7.0 / 19.0 |
| C: decide with A, cross-check B (debug) | 10.3 / 22.5 | 11.7 / 26.3 | 17.8 / 42.1 | 7.1 / 16.0 |

Neither design's numbers include building the request's input. That costs A 2.4 µs per request
(13 Datalog facts) and B 0.1 µs (one wicket-core `Op`), so A's real per-request cost at depth 5 is
about 9–13 µs.

C's 18.2 µs for B deny is a load spike. It decides with the same code as A's 10.5 µs.

### 4.2 Every depth: median range over A–D (worst p99 in brackets), µs

| variant | d1 | d2 | d3 | d4 | d5 |
|---|---|---|---|---|---|
| A | 3.6–5.0 (14.2) | 3.9–6.5 (15.9) | 5.0–8.1 (18.7) | 6.1–9.7 (26.0) | 6.9–10.6 (36.1) |
| B, `CompiledZone` | 0.2–2.7 (6.2) | 0.2–3.8 (7.1) | 0.3–4.8 (11.6) | 0.4–5.8 (14.0) | 0.4–6.5 (30.9) |
| B, model matcher | 0.2–0.4 (0.9) | 0.2–0.6 (0.7) | 0.3–0.8 (1.4) | 0.4–1.0 (1.9) | 0.4–1.8 (3.1) |

**Where B's time goes.**
- `CompiledZone` is 4–5× slower than a prefix matcher on this workload, because it allocates on every
  call:
  - `host_matches` lower-cases the host and the pattern, and formats `".{suffix}"`, once per reach
    entry;
  - `NeedsGrant` and `Forbidden` verdicts format a message.
- That is why request C costs most (6.5 µs): every block below the leaf returns `NeedsGrant` before
  the grant is checked.
- An allocation-free matcher would bring B to about 0.4–1.8 µs, close to plain records (#59). wicket
  wants that anyway, because every proxy request calls `evaluate`.

### 4.3 Once per token, depth 5 (median / p99 µs)

| piece | A | B | C |
|---|---|---|---|
| parse + verify signatures | 1,074 / 1,717 | 860 / 1,290 | 1,141 / 1,784 |
| gate | lint 374 / 649 | `block_datalog` 18, JSON + canonical + validate 48 | lint + extract |
| compile | prepare + compile 1,473 / 2,553 | `CompiledZone` × 6 blocks: 708 / 1,397 | both |
| **COLD: parse + revocation + gate + compile + decide** | **2,937 / 5,164** | **1,798 / 2,311** | **4,762 / 8,080** |
| second line (`plain::narrows`, every link) | | 1.8 | |

About 80% of B's extract is glob compilation: globset builds a regex per glob, at 20–40 µs each. The
JSON part costs 48 µs. Two ways to make it cheaper:
- cache compiled zones by their JSON string (identical across a box's children);
- use the prefix matcher for the literal forms the extractor allows.

### 4.4 Token size (bytes; every row includes the leaf's grant block)

| depth | A | B | C |
|---|---|---|---|
| 0 | 2,875 | 2,021 | 4,473 |
| 1 | 4,456 | 3,282 | 7,203 |
| 3 | 7,432 | 5,586 | 12,259 |
| 5 | 10,018 (13,360 base64) | **7,455 (9,940 base64)** | 16,490 (21,988 base64) |

- **Per block at depth 5** (A / B / C): authority 2,356 / 1,533 / 3,686, spawn 1,269–1,578 /
  926–1,258 / 2,083–2,724, grant 534 / 503 / 817.
- **B is 26% smaller than A.** It is about the size of #59's plain JSON records (7,337 B). CBOR in the
  string would shrink it further.
- **Identical JSON is stored once.** Biscuit interns strings per token, so a block that repeats an
  earlier zone costs almost nothing. §5 uses this to fit 16 blocks under the cap.

---

## 5. Attack surface: a node that appends blocks (`logs/hostile.log`)

A compromised node can append any first-party block, and it can attach third-party blocks signed by
any key it holds. It can't forge a trusted approver's signature.

### 5.1 biscuit-fast's hostile Datalog blocks, appended to the depth-5 chain

| appended block | A (lint) | B (extractor) | C |
|---|---|---|---|
| fact explosion (40×40) | refused: rules in a first-party block, 1.4 ms | refused: rules not allowed, 1.9 ms | refused by the lint, 1.6 ms |
| 150-rule chain | refused, 1.9 ms | refused, 2.2 ms | refused, 1.8 ms |
| 200 regex checks | refused: 200 checks > 32, 2.3 ms | refused: checks not allowed, 2.9 ms | refused, 2.4 ms |

Load time is mostly parsing and signature checks, which come before either gate. In A, the lint is
the control and fuel is the backstop (biscuit-fast §4). B needs no backstop: it never evaluates what
an appended block says, it only reads data from it.

### 5.2 Hostile data blocks (B)

| appended block | result | load |
|---|---|---|
| a zone fact with a 1 MiB string | refused before parsing (token cap 32 KiB) | 0 µs |
| the same, with no token cap | refused by the 8 KiB zone cap | 9.3 ms (parsing the 1 MiB token) |
| JSON nested 3,000 deep | refused: typed parsing stops at the first wrong type | 1.8 ms |
| 4,000 extra `zone` facts in one block | refused by the token cap; without it, at the second fact | 0 µs / 5.8 ms |
| 17 blocks | refused (16-block cap) | 1.5 ms |
| a reach path with glob metacharacters | refused (literal prefixes only) | 1.9 ms |
| an upper-case host or lower-case method | refused | 1.9 ms |
| a grant fact in a first-party block; a zone fact in a third-party block; two zone facts; an integer term | refused (§3.1) | |
| a wider zone, or a zone trusting an attacker's grant key | loads; changes nothing, because of intersection and per-block trust (§3.1) | |
| **the costliest token the caps allow:** 9 extra blocks, each 64 wildcard reach entries and 32 `dangerous_ok` entries (7.4 KB of JSON, interned once) | **loads: 21 ms per token; request A then takes 37 µs median, 66 µs p99** | |

**What bounds the cost in each design.**
- **A:** the lint's caps, with fuel as a backstop. biscuit-fast measured about 0.6 ms of CPU per
  request at the 4,000-step limit. The same 9 zones as A blocks are 88 KB, which the lint refuses.
- **B:** the caps alone. The worst case is 16 blocks × 96 globs. That is deterministic and needs no
  budget at run time.
- **B's real exposure is glob compilation**, at about 21 ms per token. Caching compiled zones by
  string, or matching literal prefixes without globset, removes most of it.

### 5.3 If B's payload carried wicket-core globs verbatim

A full `ZoneSpec` carries real globs. A 344-byte brace glob and a 242-byte `*a*a…` glob each take
about 0.4 ms to compile, and they match in 0.5 µs (they compile to a regex, so there is no
backtracking). `/**/**/…` (181 bytes) matches in 2.3 µs. With a 256-byte cap per glob and the entry
caps, the worst case stays in milliseconds per token. Glob payloads are safe with caps, but slower
to load than literal prefixes.

### 5.4 Confusion between blocks

Each role has one predicate, and each predicate is accepted in one kind of block only:
- `zone` only in first-party blocks;
- `grant` only in third-party blocks, with the signer taken from Biscuit's external key;
- `tenant` only in block 0.

A misplaced fact refuses the token. In A, the equivalent protection is Biscuit's scoping. A forged
`approved` fact in a first-party block isn't visible under `trusting <key>`, and the lint also
refuses it. That scoping is the trap research 23 found other projects falling into. B has no scopes
to get wrong.

---

## 6. Trusted code (`logs/loc.log`, code lines only, no blanks or comments)

| piece | A | B |
|---|---|---|
| generator (ceiling → block) | 109 (`bisc.rs` compile, grant rule) | 59 (`zf.rs`: typed facts, canonical JSON) |
| gate at load | 227 (`lint.rs`) | 194 (`zf.rs` extractor: shape, caps, canonical check, validation, compile) |
| decision | Biscuit's Datalog engine; step 3 needs `compiled.rs` (1,076) + `prepared.rs` (370) + 199 lines of edits to upstream files | 76 (`zf.rs` evaluator: intersection, grant trust, lease liveness) + wicket-core `CompiledZone` (60) and `host_matches`/`compile_glob` (20), already on wicket's request path |
| Biscuit patches needed | all of biscuit-fast's: about 1,900 lines | `Biscuit::block_datalog` and `BlockDatalog`: 25 lines |
| optional second line | | `narrows`: 62 |
| **wicket-written total** | **336 + 1,645 fork lines** | **329 (+ 62)** |

**What each relies on Biscuit for.**
- **Both:** Ed25519 signatures over the append-only chain; the third-party request bound to the last
  signature; revocation ids per block; protobuf parsing.
- **A only:**
  - Datalog semantics: checks only add conditions, and `trusting` scopes;
  - the step-3 evaluator agreeing with the generic engine. The only evidence for that is
    biscuit-fast's differential test.
- **B only:** `block_datalog`, to read each block's facts after verification. That is a small, general
  accessor and a reasonable upstream PR. Nothing in B runs Datalog. On the token, B calls only
  `Biscuit::from`, `block_count`, `block_datalog`, `block_external_key` and
  `revocation_identifiers`; nothing in `prepared.rs` or `compiled.rs` (checked by grep, not built
  separately). So B should ship on upstream main plus that accessor. B needs no prepared authorizer, no compiled evaluator, no fuel
  and no wall-clock limits.

**What moves into wicket code under B.** "A child can't exceed its parent" sounds bigger than what
actually moves. Under intersection, a wider appended block is harmless in B, just as a wider check
block is harmless in A (both tested). Three things move:
1. evaluate every block and skip none;
2. count a grant only in blocks that list its signer;
3. the lease conditions (expiry, exact box, epoch, ledger).

All three are in the 76-line evaluator, and the mutants in §3.2 cover each one. The second line
(`narrows` at load) catches a *generator* bug, not a security hole. 1,537 of the 2,000 random chains
widen somewhere, and intersection still decided them correctly.

wicket_core's own `subset::check` couldn't serve as the second line directly. It takes a full
`ZoneSpec` with budgets, child slots and images, and it requires a child to repeat the parent's
forbids. Chain links don't need that under intersection. `plain::narrows` (the model's version) was
used instead.

---

## 7. Recommendation for #76, and open risks

**Use B.**
- **Blocks.** Spawn and grant blocks carry one canonical-JSON fact each. The authority block is data
  too.
- **Gate.** The extractor refuses anything else at load.
- **Decision.** wicket intersects every block, counting grants per block by signer.
- **The fork shrinks.** It becomes upstream main plus `block_datalog`, or a release once that
  accessor lands upstream. biscuit-fast's compiled evaluator and fuel aren't needed on the request
  path.
- **Datalog moves to CI.** Keep `bisc::compile` as the oracle: on random chains, B's decisions must
  equal the Datalog's (this experiment's `diff`), with the model matcher, or with an exact glob
  encoding. Run the mutants from §3.2 alongside.
- **Not C.** C costs 65% more token and 60% more cold load to run the same comparison in production.

**What #76 needs to decide along the way.**
1. **The payload type.** `Ceiling` here is a stand-in. Mapping it onto `ZoneSpec` showed gaps:
   - `ZoneSpec` has no box binding, expiry, op list or grant keys. These belong in a chain envelope
     around the zone;
   - `ZoneSpec` has no per-zone risk threshold. wicket uses a fixed R3 and a per-rule
     `allow_dangerous`, where the model uses `max_risk` plus a `dangerous_ok` list;
   - wicket decides by the first matching rule, the model by any matching rule. They differ when an
     earlier rule matches without `allow_dangerous` and a later one with it.

   This experiment sidesteps the question by deciding risk in wicket code (it passes R0 to
   `CompiledZone`). #76 can't: it has to pick one set of semantics for both the zone and the chain.
2. **Globs or literal prefixes in tokens.** Literal prefixes are cheap to compile and easy to cap.
   Real globs are what `ZoneSpec` has. The 8 differential disagreements are exactly this question.
3. **Untrusted third-party grants.** Ignore them, as here, or refuse the token, as A's lint does.

**Open risks.**
- **Foreign verifiers.** A stock Biscuit verifier sees B's data blocks as facts, with no checks, so it
  would accept the token as unrestricted. Add one authority-block check that fails unless the
  authorizer supplies a wicket-only ambient fact (for example `check if wicket_node($v), $v >= 1`).
  Then a non-wicket verifier denies everything. Exports to outside services stay a separate,
  node-minted token (research 23 §4).
- **Hand-written intersection.** It is small (76 lines) and mutation-tested, but its only independent
  check is the CI differential against the Datalog oracle. That is the same arrangement #59
  recommended for plain records.
- **`CompiledZone`'s costs.** It allocates per request and compiles globs slowly (§4.2, §4.3, §5.2).
  These are wicket-core issues that matter outside tokens too.
- **One run on a shared VPS.** Expect ±30% on timings. The ratios are what matter.

---

## 8. Reproducing

Run from `experiments/biscuit-datablocks/`. It uses biscuit-fast's fork (see §2) and wicket-core's
`CompiledZone`, which arrives with PR #80: build it after #80 merges, or from that branch. Nothing else
needs fetching beyond crates.io.

```sh
CARGO_BUILD_JOBS=1 cargo build --release
target/release/biscuit-datablocks correct            # §3.1, all designs   > logs/correct.log
target/release/biscuit-datablocks correct b,c        # some designs (a, b, bm, c)
target/release/biscuit-datablocks mutants            # §3.2                > logs/mutants.log
target/release/biscuit-datablocks diff               # §3.3, DIFF_CHAINS=2000 DIFF_REQS=50 DIFF_SEED=76 > logs/diff.log
target/release/biscuit-datablocks globs              # glob vs prefix      > logs/globs.log
target/release/biscuit-datablocks bench              # §4.1–4.3            > logs/bench.log
target/release/biscuit-datablocks sizes              # §4.4                > logs/sizes.log
target/release/biscuit-datablocks hostile            # §5                  > logs/hostile.log
./loc.sh                                             # §6                  > logs/loc.log
# ITER_SCALE=0.3 shortens every timing loop
```
