# Experiment #59: Biscuit verification at delegation depth

**Question.** Is Biscuit (`biscuit-auth`) fast and small enough to carry zone ceilings, grants and leases
when a node checks them on every request (architecture A, research 18 §5.1; design "Identity is JWT;
authority is Biscuit")? Or should wicket use the fallback, plain signed records?

**Answer: no-go for Biscuit on the per-request path. Go for plain signed records**, using the chain
semantics this experiment checked (details in §7). Biscuit gets every semantic right. The problem is
cost. At spawn depth 5 (56 checks, one third-party approval), a request against an already-verified
token takes **≈1.0–1.2 ms median and 1.7–2.1 ms p99** on this box. The same check over plain records
takes **0.4–0.7 µs**. The token is **10.0 KB** (13.4 KB in base64), against 7.3 KB for plain records.

Everything is in this directory: code in `src/`, raw outputs in `logs/`.

---

## 1. Encoding (draft format)

wicket generates every block from the capability algebra (`src/model.rs`, a cut-down `ZoneSpec`). Nobody
writes Datalog by hand. The compiler is `src/bisc.rs::compile`. The full generated depth-5 chain is in
`logs/show.log`.

### 1.1 Ambient facts: the node supplies them per request, never the box

| fact | meaning |
|---|---|
| `time($t)` | the node's clock (a Biscuit date) |
| `request_tenant($t)`, `node($n)`, `box($b)`, `epoch($e)` | who the request is for. Box ids are hierarchical paths: `b0/b1/b2` |
| `op($o)` | `http`, `spawn`, `llm` or `msg` |
| `host`, `method`, `path`, `path_depth`, `risk` | HTTP requests. `risk` comes from the dangerous-pattern list (0–4) |
| `inject($k)` | the `host\|header\|secret` the egress proxy would inject |
| `spawn($image, $iso, $mem, $cpu_milli, $pids, $secs)` | spawn requests |
| `llm_used($requests, $tokens)`, `msg_from($zone)` | budget use, message sender |
| `uses_left($grant, $n)` | the node's ledger. Biscuit is stateless, so use counts come from here |

The node authorizer is just `check if tenant($t), request_tenant($t); allow if true;`. All authority
lives in the token.

### 1.2 Authority block (signed by the control plane's root key)

The root principal's ceiling: here a trigger, `nightly-ci`. It has facts `tenant`, `principal` and `zone`,
then 11 checks:

```datalog
check if time($t), $t <= 2026-11-11T16:13:00Z;                                  // expiry
check if box($b), $b == "b0" || $b.starts_with("b0/");                         // subtree binding
check if op($o), {"http", "spawn", "llm", "msg"}.contains($o);                 // op kinds
check if op($o), $o != "http"                                                   // reach: one `or` branch per rule
  or host("api.github.com"), method($m), {"GET","HEAD","POST","PATCH"}.contains($m), path($p), $p.starts_with("/repos/acme/")
  or host($h), $h.ends_with(".githubusercontent.com"), method($m), {"GET","HEAD"}.contains($m)
  or host("docs.rs"), method("GET"), path($p), $p.starts_with("/tokio/"), path_depth(2)   // `/tokio/*` without a regex
  or …
  or host($h), method($m), path($p), approved($g, $h, $m, $p) trusting ed25519/<approval service>;  // grant escape
reject if host($h), $h.ends_with(".internal");                                   // forbid: no escape
reject if host("api.github.com"), path($p), $p.starts_with("/repos/acme/secrets-vault/");
check if op($o), $o != "http" or risk($r), $r <= 2
  or <dangerous_ok rules> or <grant escape>;                                    // risk
check if op($o), $o != "spawn" or spawn($i,$iso,$mem,$cpu,$pids,$secs), {…}.contains($i), $iso >= 2, $mem <= 8589934592, …;
check if op($o), $o != "llm" or llm_used($r, $k), $r < 3000, $k < 4000000;
check if op($o), $o != "msg" or msg_from($z), {"ops"}.contains($z);
reject if inject($k), !{"api.github.com|Authorization|gh-app-acme"}.contains($k);
```

Rules for the shape:
- **Every dimension is a check scoped by `op`** (`$o != "spawn" or …`), so one chain serves every kind of
  request.
- **Path globs compile to `starts_with` plus `path_depth`**, never `.matches()`. biscuit-auth compiles
  a regex on every evaluation (`Regex::new` in `datalog/expression.rs`). The regex variant was 21–26% slower
  in total (§3.4).
- **`check all` is not vacuous**: it fails when nothing matches. Spawn requests carry no `inject` fact,
  so the inject check is written as `reject if inject($k), !{…}.contains($k)`. The first version used
  `check all` and wrongly denied spawns.

### 1.3 Spawn block (appended by the node, no key needed)

The same 9 checks (no forbids; the parent's still apply), compiled from the child's ceiling:
- a shorter expiry;
- the child's box subtree (`b0/b1/…/bk`);
- narrower reach, risk, spawn limits, budgets and `accept_from`.

Its grant escape trusts **two keys**:
- the approval service (human approvals);
- the **parent box's grantor key**, for agent grants (#50).

The grantor key must be **per box, not per node**. If one node key signed for two boxes on the same
node, a box could approve its own escalation: its own block would trust the node key that signs its
grants. With per-box keys, only the child's block trusts the parent's key. The grant still has to pass
every ancestor block on its own terms, which is exactly "a grant must be within the grantor's own
authority". The tests in §5 show this.

A size variant keeps only the statements that differ from the parent's block (`compile_diff`). It
saves only 9% at depth 5, because the reach check dominates and changes at every level.

### 1.4 Grant / lease: a third-party block (signed by the approver)

```datalog
approved("g-7f3a", "api.github.com", "PUT", "/repos/acme/api/pulls/7/merge")
  <- time($t), $t <= 2026-11-11T08:38:00Z, box("b0/b1/b2/b3/b4/b5"), epoch(3),
     uses_left("g-7f3a", $n), $n > 0;
approval("g-7f3a", "human:alex@acme", hex:<passkey assertion digest>);
```

The flow:
1. The node calls `third_party_request()`, which is bound to the token's last signature.
2. The approver signs the block with its key.
3. The node appends it.

The lease is a **rule, not checks**. The block's own checks would apply to the whole token, so a
lease with checks would make the whole zone chain fail when the lease expires. As a rule, `approved`
simply stops being derived once the lease is expired, used up, or presented by another box or epoch.
The lease's own checks never run against the chain.

The block's revocation id is separate from the zone blocks' ids, so a single lease can be revoked on
its own.

### 1.5 Revocation

- **Per block:** `revocation_identifiers()` returns one 64-byte id per block (that block's signature).
- **Feed:** the feed carries a revocation set. The node checks every id of a cached token against it on
  each request; with 10k entries this costs 0.3–0.9 µs.
- **Subtrees:** sibling chains share the ids of their common prefix, so revoking block *k* revokes
  every chain derived from it.

---

## 2. Environment and method

- **Machine:** a Vultr VPS: 4 vCPU Intel Broadwell (no TSX, IBRS; AVX2), 7.9 GB RAM, shared
  with Chrome/VNC and other sessions.
- **Toolchain and crates:** rustc 1.99.1.
  - `biscuit-auth = "=6.0.0"`: the current crates.io release (2025-07-16), with ed25519-dalek 2.2.0
    and prost 0.10.4.
  - The fallback uses ed25519-dalek 2, serde_json and sha2.
- **Build:** release profile (opt-level 3, codegen-units 16, no LTO).
- **Runs:** each benchmark was a single thread in one job slot (about one core, 2 GB).
- **Load:**

  | when | load average | notes | log |
  |---|---|---|---|
  | before run 1 | 1.61 | another session's single-job `cargo build` held another slot | `logs/env-before-bench.log` |
  | after run 1 | 2.62 | | `logs/env-after-bench.log` |
  | run 2 | 1.55 at start, 2.53 at end (§3.5) | | `logs/env-bench-run2.log` |

  `vmstat` showed steal at 0. Other work shares the CPU, so treat absolute numbers as "this box, lightly
  loaded". The *ratios* are what matter.
- **Timing:** `std::time::Instant` around each call. There are n/10 warm-up calls, then:
  - n = 2000 for mint and attenuate;
  - n = 3000 for cold verification;
  - n = 20000 for warm verification.

  Medians and p99 are reported in µs. Run 2 repeats everything at 0.3× the iterations.
- **Chains:** depth *d* = the authority block, *d* spawn blocks, and one third-party grant block at the
  leaf. Each level narrows the one before (`model::level`).
- **Requests at the leaf:**
  - **A**: an allowed GET in reach.
  - **B**: a denied GET outside reach. Every branch is evaluated.
  - **C**: a risk-3 PUT allowed only through the third-party approval.
  - **D**: a spawn checked against limits.

  The assertions in the benchmark check that each one decides as expected at every depth.
- **Cold:** `Biscuit::from(bytes, root_pk)` (parse and verify every signature), the revocation check,
  then build the authorizer with the request facts and authorize.
- **Warm:** the parsed, verified `Biscuit` is cached. Per request: the revocation check, clone the static
  `AuthorizerBuilder`, add the request facts, `build(&token)`, `authorize()`.
- **Commands:** `target/release/biscuit-depth show|correct|bench|limits|profile`.
  - Outputs: `logs/show.log`, `correct.log`, `bench.log` (run 1), `bench-run2.log`, `limits.log`,
    `profile.log`.
  - Profiles: `logs/callgrind-*.log`. Callgrind was used because `perf` is blocked by
    `perf_event_paranoid=4`.

---

## 3. Results

### 3.1 Token size

| depth | blocks | checks | Biscuit bytes | Biscuit base64 | plain records bytes | plain base64 |
|---|---|---|---|---|---|---|
| 0 | 2 | 11 | 2,875 | 3,836 | 1,963 | 2,618 |
| 1 | 3 | 20 | 4,456 | 5,944 | 3,212 | 4,283 |
| 2 | 4 | 29 | 5,972 | 7,964 | 4,386 | 5,848 |
| 3 | 5 | 38 | 7,432 | 9,912 | 5,492 | 7,323 |
| 4 | 6 | 47 | 8,746 | 11,664 | 6,420 | 8,560 |
| **5** | 7 | **56** | **10,018** | **13,360** | **7,337** | **9,783** |

Every row includes the grant block, so depth 0 is the authority block plus a grant.

What makes up the size:
- **Per block:** the authority block is 2.36 KB, each spawn block 1.26–1.58 KB, the third-party grant
  534 B, and sealing adds 32 B.
- **Encoding density:** the binary encoding is about as large as the Datalog text. Protobuf spends a
  message on every term and every expression op.
- **Diff-only variant:** 9,135 B (42 checks) at depth 5.

For comparison, the plain records are JSON. They are 27% smaller, and CBOR would shrink them further.

**Is it small enough?** Yes for the node-held design: no token enters the box, and the token travels
only when a child is placed on another node. **No** if a token ever has to ride in a request header:
13 KB of base64 is over the common 8 KB header limits.

### 3.2 Mint and attenuate (Biscuit, depth 5; other depths are the same within noise)

| operation | median µs | p99 µs |
|---|---|---|
| mint authority block (parse Datalog + sign) | 465 | 832 |
| append spawn block (parse Datalog + sign) | 483 | 760 |
| append spawn block (builder parsed earlier) | 351 | 497 |
| third-party: node makes request | 0.2 | 1.0 |
| third-party: approver signs grant block | 80 | 154 |
| third-party: node appends grant block | 306 | 536 |
| serialize (to_vec) | 3.8 | 11.5 |

Spawns and grants are rare (many an hour, not per request), so this is fine. Fallback: appending a
spawn link costs 45 µs; the mint-time narrowing check costs 0.6 µs.

### 3.3 Per-request verification and authorization (Biscuit), median / p99 µs

| depth | checks | parse+verify only | **COLD** A / B / C / D | **WARM** A / B / C / D | of WARM: Datalog run (A / B / C / D) |
|---|---|---|---|---|---|
| 1 | 20 | 460 / 779 | 921/1528 · 1046/1731 · 1033/1675 · 1056/1624 | 425/748 · 519/900 · 474/825 · 423/733 | 68 · 148 · 115 · 64 |
| 2 | 29 | 589 / 990 | 1243/2045 · 1336/2224 · 1305/2221 · 1210/2017 | 579/1003 · 706/1230 · 649/1131 · 570/976 | 91 · 207 · 160 · 84 |
| 3 | 38 | 727 / 1189 | 1540/2506 · 1648/2759 · 1576/2661 · 1469/2486 | 733/1264 · 900/1506 · 818/1444 · 714/1228 | 113 · 244 · 200 · 103 |
| 4 | 47 | 861 / 1388 | 1772/2914 · 1899/3220 · 1897/3180 · 1792/2716 | 876/1496 · 1046/1801 · 970/1700 · 876/1466 | 139 · 331 · 235 · 125 |
| **5** | **56** | **953 / 1576** | **1992/3306 · 2209/3742 · 2109/3513 · 1944/3201** | **995/1725 · 1230/2116 · 1129/1954 · 985/1682** | **160 · 345 · 275 · 144** (p99 312 · 633 · 458 · 272) |

The revocation check (all ids against a 10k-entry set) costs 0.3–0.9 µs at every depth.

How cost grows with depth:
- **Cold:** about 270 µs per added block. Ed25519 verification is 59 µs per signature here, and there
  are 8 signatures at depth 5 (7 blocks plus the external signature). The rest is protobuf decoding.
- **Warm:** about 140 µs per added block.

### 3.4 Where the warm time goes (depth 5, request A; `logs/profile.log`, `logs/callgrind-*.log`)

| piece | median µs | p99 µs |
|---|---|---|
| clone static AuthorizerBuilder + add 13 request facts | 3.5 | 8.1 |
| **`build(&token)`**: decode and translate all 7 blocks into the authorizer's symbol table | **804** | 1400 |
| Datalog fixpoint + 56 checks (`authorize`) | 160 | 312 |
| *projected:* clone an Authorizer that already holds the token, then authorize | 262 | 475 |
| *same request with regex path patterns (depth 5, warm A / B)* | 1250 / 1491 | 2118 / 2559 |

**Callgrind breakdown.** Of all instructions:
- 74% are in `AuthorizerBuilder::build`:
  - re-decoding each block's protobuf takes 15%;
  - round-tripping every check and rule through the builder types into the authorizer's symbol table
    (`convert_from`/`convert`, `SymbolTable::insert`, string clones) takes about 56%.
- 17% are in `authorize`.
- malloc and free account for about 35% of the total.

**What can be cached safely:**
- **The parsed, verified `Biscuit`, keyed by the token bytes. Safe.** Signature verification depends
  only on the bytes and the root key. Flush the cache when the root key rotates. Check revocation ids on
  every request (it costs under 1 µs), or evict cache entries when the feed revokes them. This turns
  2.0 ms cold into 1.0 ms warm at depth 5.
- **A loaded `Authorizer` reused across requests: impossible in 6.0.0.** It has no way to add facts
  after `build`, and `run()` memoises its result. Cloning a built authorizer still costs 91 µs. A fork
  that adds facts to a pre-built authorizer would get to about 260 µs.
- **Decisions: only under the fixed vocabulary.** With it, `time` appears only in `<=` comparisons, so a
  decision is constant until the next expiry. A decision cache would have to:
  - key on every ambient fact (op, host, method, path, risk, inject, spawn tuple, epoch);
  - expire entries at the earliest block or lease expiry;
  - invalidate on ledger changes (`uses_left`) and on revocations.

  That is a correctness burden, and agent traffic rarely repeats exact paths. Not recommended.

### 3.5 Run-to-run variation

Run 2 (`logs/bench-run2.log`) repeated everything at 0.3× the iterations:

Run 2 started at 08:28 UTC (load 1.55) and ended at 08:31 UTC (load 2.53). At depth 5, medians agree with run 1 to within about 5%:

| depth 5, median µs | run 1 | run 2 |
|---|---|---|
| Biscuit::from (parse + verify) | 953 | 978 |
| COLD A / B / C / D | 1992 / 2209 / 2109 / 1944 | 2025 / 2201 / 2196 / 2008 |
| WARM A / B / C / D | 995 / 1230 / 1129 / 985 | 999 / 1198 / 1155 / 999 |
| Datalog run A / B (p99) | 160 (312) / 345 (633) | 167 (341) / 360 (656) |
| WARM A / B, regex path patterns | 1250 / 1491 | 1280 / 1484 |
| plain COLD A / WARM A | 639 / 0.7 | 627 / 0.7 |

---

## 4. RunLimits

`logs/limits.log`.

| depth | facts in the world | iterations | smallest `max_facts` that passes | smallest `max_iterations` | Datalog run µs (A / B / C / D) |
|---|---|---|---|---|---|
| 1 | 14–19 | 1 | 20 | 2 | 86 / 156 / 120 / 66 |
| 3 | 16–21 | 1 | 22 | 2 | 161 / 267 / 194 / 102 |
| 5 | 18–23 | 1 | 24 | 2 | 187 / 351 / 282 / 152 |

How the minimums came out:
- The only rule is the lease rule, so the fixpoint takes a single iteration.
- `max_facts` must be strictly greater than the fact count: the engine checks `facts >= max_facts`.
- `max_iterations` must be at least 2, because `authorize` subtracts the iterations already used.
- Request B denies anyway, so its "minimum" isn't meaningful and is left out of the table.

**The defaults (1000 facts, 100 iterations, 1 ms) pass, but `max_time` = 1 ms is too tight.**
- At depth 5, the Datalog run for B (deny) was 345 µs median, 633 µs p99 and 1,255 µs max on this
  lightly loaded box.
- An *allow* (A/C) reached 508/655 µs max.
- `max_time` counts the run plus the checks, not `build`. It is measured in wall-clock time, so CPU
  contention turns into spurious denials: the decision depends on load.

**At a limit:** all three limits return `Token::RunLimit(TooManyFacts | TooManyIterations | Timeout)`,
which displays as "Reached Datalog execution limits", and the request is denied (fail closed). That was
shown for max_facts = facts, max_iterations = 1 and max_time = 1 µs.

**Hostile blocks.** A holder, i.e. a compromised node whose chain another node verifies, appended
blocks designed to exhaust the verifier:

| appended block | default limits | with max_time = 50 ms |
|---|---|---|
| fact explosion: 40×40 cross product | denied after 2.8 ms (TooManyFacts) | same |
| a chain of 150 rules | denied after 2.4 ms | **denied after 22 ms** (100 iterations) |
| 200 regex checks | denied after 2.7 ms (Timeout) | **allowed after 13 ms**: the checks only narrow, but they burn CPU |

Two things weaken these limits:
- `max_time` doesn't cover `build`, and it's checked only *between* queries.
- So raising it to avoid spurious denials also raises the cost an attacker can impose.

**If Biscuit were used:**
- Set `max_facts` to 256, `max_iterations` to 8 and `max_time` to about 5 ms.
- Add a **structural lint before authorizing**:
  - first-party blocks: only checks from the fixed vocabulary, no rules, no `.matches`;
  - third-party blocks: only `approved(...) <- …` rules, and only from keys the zone blocks trust;
  - caps on checks per block and on token bytes (e.g. 32 KB).

---

## 5. Correctness checks

`logs/correct.log`. All 45 pass, 0 fail.

| property | test | result |
|---|---|---|
| baseline | A allowed, B denied, C allowed only through the approval, D allowed (depth 5) | pass |
| **no widening** | append `check if true`, then request B | denied by block 0's reach check |
| | append a forged `approved(...)` fact | ignored: first-party facts aren't in the `trusting` scope |
| | append a rule that derives `approved` | ignored |
| | a third-party approval signed by an attacker key | ignored |
| | the leaf "approves" itself with its own grantor key | denied: no block trusts the leaf's own key |
| | a block containing `allow if true` | parse error: blocks can't carry policies |
| | a new block with a later expiry | the leaf's earlier expiry still applies |
| | a request served for another tenant | denied by the authorizer's tenant check |
| **only narrowing** | append `method GET only`; append `no spawn` | A still allowed; C and D now denied |
| | drop the last block, remove a middle block, reorder blocks (protobuf edit) | rejected at parse |
| **expiry and leases** | A at the leaf's expiry: allowed; 1 s later: denied | pass |
| | C after the lease expires: denied, while A is still allowed (an expired lease doesn't kill the chain) | pass |
| | C with `uses_left = 0`, with no ledger entry, in a later epoch: denied | pass |
| | C from the leaf's child b6, which inherits the grant block: denied; A from b6: allowed | pass |
| | A presented for a box outside the chain's subtree: denied | pass |
| **agent grants** | parent b4's key grants POST within b4 but outside the leaf: allowed | pass |
| | b4 grants a path outside b4's own reach: denied by block 3 | pass |
| | b4 grants a risk-3 PUT that b4 couldn't do itself: denied; the human approval service grants the same PUT: allowed | pass |
| **revocation** | siblings c1 and c2 share the ids of blocks 0–3 and differ at block 4 | pass |
| | revoke c1's own block: c1 is revoked, c2 and the parent are not | pass |
| | revoke b2's spawn block: b3, c1 and c2 are all revoked | pass |
| | the grant block has its own id | pass |
| **tampering** | flip each of the 9,982 bytes in turn (XOR 1): 0 variants parse | pass |
| | the wrong root key; a third-party block made for c1 moved onto sibling c2; appending to a sealed token | all rejected |
| **fallback** | same decisions for A–D | pass |
| | a widening link signed by a valid node key doesn't admit B (intersection) | pass |
| | the narrowing check names the widening | pass |
| | 7,337 single-byte flips: 0 verify | pass |

---

## 6. Comparison with the fallback (plain signed records)

**What the fallback is** (`src/plain.rs`, about 250 lines including the narrowing check):
- **Links:** each link is a JSON record carrying `prev` = SHA-256 of the previous link (payload and
  signature) and a signer id, plus a body. The body is a zone ceiling (the same `Ceiling` struct) or a
  grant.
- **Framing and signatures:** each link is a u16 length, the payload, then a 64-byte Ed25519 signature.
  The root key signs link 0. Spawn links are signed by a node key the verifier knows from the feed.
  Grant links are signed by any key, but count only where a zone link lists that key in `grant_keys`.
- **Evaluation:** a hand-written evaluator checks the request against **every** zone link, so authority
  is the intersection of all links, just as in Biscuit.
- **Mint-time check:** a hand-written narrowing check (`narrows`) gives readable errors.

At depth 5:

| depth 5 | Biscuit 6.0.0 | plain records | ratio |
|---|---|---|---|
| token size | 10,018 B (13,360 base64) | 7,337 B (9,783 base64) | 1.37× |
| append a spawn link | 351–483 µs | 45 µs | ~10× |
| cold (parse + verify + revocation + decide), median / p99 | 1,944–2,209 / 3,201–3,742 µs | 639–649 / 939–1,022 µs | ~3.2× |
| warm (cached verified chain), median / p99 | **985–1,230 / 1,682–2,116 µs** | **0.4–0.7 / 0.8–1.3 µs** | **~2,000×** |
| DoS surface | Datalog with RunLimits that depend on wall-clock time | none beyond parsing | |

**Cold cost.** In both formats it is mostly Ed25519. The fallback's 661 µs is 7 × 59 µs of
verification plus JSON parsing. Batch verification would roughly halve that, and it's paid once per
token anyway.

**What Biscuit gains:**
- **Attenuation without a signing key.** Each block's ephemeral key chains to the next, so spawn links
  need no certified node keys. The fallback needs node signing keys, short-lived and certified through
  the feed. Design §3.2 already plans these.
- **A spec and several implementations,** so a verifier outside wicket can check a chain. That matters
  only if chains leave wicket.
- **Third-party blocks and revocation ids out of the box.** Both are about 20 lines in the fallback:
  - grant links bind `prev`, so they can't be transplanted (tested);
  - link hashes are revocation ids with the same subtree property, because shared prefixes hash
    identically. That follows from the construction; it wasn't separately tested.
- **One generic evaluator.** The fallback's evaluator is hand-written TCB. It reuses matchers wicket
  already has: `host_matches` and globs in manifest.rs, the ⊆ logic in subset.rs.

---

## 7. Go / no-go for #59

**No-go: don't put `biscuit-auth` 6.0.0 on the per-request path. Go: use plain signed records for zone
chains, grants and leases**, with the semantics validated here:
- intersection over every link at decision time;
- hierarchical box binding;
- per-box grantor keys;
- grant links bound to the previous link's hash;
- leases that lapse without invalidating the chain;
- link hashes as revocation ids;
- a fixed vocabulary.

Keep the format behind an interface, as the design already says.

Reasons:
1. **Per-request cost.** About 1 ms median and 2 ms p99 per request at depth 5, even with the verified
   token cached, against under 1 µs for the fallback.
   - The proxies are per node and shared by every box (design §7.1), so 1 ms of CPU per request caps a
     vCPU at roughly 1,000 decisions a second, on top of Cedar.
   - The cost grows by about 140 µs per spawn level.
   - The best case with a fork (reusing a loaded authorizer) is still about 260 µs. The Datalog
     evaluation alone is 145–345 µs for about 50 checks, about 3 µs per check, mostly allocation.
   - Research 18 §4 assumed "each check is microseconds". Per check that's true; per request it isn't.
2. **The limits make denials depend on load.** The 1 ms default `max_time` is within 2× of the measured
   p99, and is exceeded at the max. Raising it, as needed, also raises the CPU a hostile block can burn
   (13–22 ms observed). `max_facts` and `max_iterations` are not a concern: about 24 facts and 2
   iterations are needed.
3. **Size is acceptable, not good.** 10 KB at depth 5 is fine held on the node. It is 37% larger than
   JSON records, and too big for a header if a token ever travels per request.
4. **The model survives without Biscuit.** Every property this experiment needed was reproduced in the
   fallback and passes the same tests. The fixed vocabulary means nobody uses Datalog's expressiveness
   anyway.

**What to carry over:**
- **Biscuit as a test oracle.** Keep `compile` as a **differential oracle in CI**: property-test the
  hand-written evaluator against the Biscuit compilation on random ceilings and requests. That way the
  fallback's TCB is checked by an independent engine without paying for it at runtime.
- **The attenuation rule: only checks can be added.** The fallback gets this from intersection over
  every link; the design text should say so explicitly.

**When to revisit:**
- biscuit-auth gains a reusable authorizer that takes per-request facts, and evaluates about 50 checks
  in under 50 µs (track upstream; the step counter and the Sync authorizer landed on main on
  2026-11-09, unreleased);
- or chains must be verified by parties outside wicket, in other languages.

A hybrid was considered and rejected: Biscuit at rest, verified once per chain, then decompiled to the
algebra for per-request checks. It would need two pieces in the TCB (a compiler and a decompiler) and
would lose the one-evaluator benefit.

**Follow-ups for the design text and research 18 §5.1:**
- "authority is Biscuit" becomes "authority is a signed capability chain; Biscuit-compatible semantics,
  plain records".
- Experiments #58 and #60 should measure the fallback's chain.
