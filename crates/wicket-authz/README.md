# wicket-authz

A box's authority as a Biscuit token: design A of #76 ("Identity is JWT; authority is Biscuit" in
`docs/design.md`). It uses the patched fork in `third_party/` (load once, step budget, compiled
evaluator).

| block | signed by | holds |
|---|---|---|
| 0 | root key (control plane): `mint` | `tenant`, `principal`, `zone` facts; the root ceiling as checks; `check if request_tenant(...)` |
| spawn | the node, first-party: `Token::attenuate` | `zone` fact; the child's ceiling as checks |
| grant | approval service or parent's grantor key, third-party: `grant` | `approved(gid, host, method, path) <- time, box, epoch, uses_left` rule; `approval` fact |

A node calls `load(bytes, root_key, revoked)` once per token. It verifies the signatures, checks
every block's revocation id, runs the structural check, then prepares and compiles the token. After
that, `Loaded::decide(&Request)` returns `Allow`, `NeedsGrant` or `Forbidden` for each request.

## Choices

- **Payload:** wicket's own `Ceiling` (not `ZoneSpec`). `Ceiling::from_zone` covers the common case.
  The format sits behind `Token`, `Ceiling`, `Grant`, `Request` and `Decision`.
- **No values in Datalog text.** Every value is a `code_with_params` parameter, and lists are
  `Term::Set`s, so an empty list is an empty set and never `{}` (which parses as a map).
- **Paths are matched by globset's own regex** (wicket's options), so tokens match exactly what
  wicket-core matches:
  - the `(?-u)` flag is dropped, because Biscuit's regexes run on strings;
  - the `path` fact carries the path's bytes as Latin-1, which is identical for ASCII;
  - so `?` and `\xHH` mean one byte on both sides.
- **`.matches()` is allowed, in one form.** The design section says "no `.matches`"; this crate
  allows exactly `$p.matches("<literal>")` on a variable bound by `path`, because globs need it. The
  structural check limits it:
  - at most 256 bytes per pattern and 128 patterns per block;
  - the pattern must compile under a 64 KiB size limit. A pattern Biscuit can't compile never
    matches, which would silently drop a `reject if`.
- **Reach rules are a set.** wicket-core's `CompiledZone::evaluate` changed with this crate: a
  request is allowed by reach if *some* matching rule allows its risk. Datalog alternatives have no
  order.
- **Denials are classified from one evaluation.** The evaluator reports every failed check:
  - any failed hard check means `Forbidden`: time, box, op kinds, tenant, forbid, limits, injections;
  - if only reach or risk checks failed, the answer is `NeedsGrant`. These are the checks with an
    alternative that reads `host`, `risk` or `approved`.
  - Metadata and private hosts are `Forbidden` before evaluation, as in wicket-core.
- **The structural check is strict** (see `structure.rs`). Caps:
  - 16 blocks: depth 5 is the design target, plus grants and headroom;
  - 64 KiB per token;
  - per block: 64 checks, 64 alternatives per check, 8 predicates per query, 128 regexes.
- **`mint` and `attenuate` run the same structural check** on the token they produce, so a zone
  over a cap fails where it is made rather than at every node. Grants aren't checked there: a node's
  `load` refuses a grant from a key that no block trusts.
- **The step budget is 25,000 steps**, with no wall clock. A token at every cap is cut off at the
  budget, in about 0.1 ms, and decided `Forbidden`.
- **Legitimate tokens run compiled.** The tests assert that every request on every legitimate token
  they build is decided by the compiled evaluator, never its generic fallback. The largest took 308
  steps there.
- **Cost is estimated at mint** (`cost.rs`, #183). The generic engine, the compiled evaluator's
  fallback, compiles each `.matches()` pattern on every evaluation and charges 16 steps per pattern
  byte. So a request's cost there grows with the globs on its host. `mint` and `attenuate` estimate,
  per host, the pattern bytes a request to it can evaluate: reach, risk and forbid globs on that host
  and on any wildcard that matches it, summed over every block of the chain. They take
  `1,000 + 16 x bytes` as the steps, and refuse a token over the budget with `AuthzError::Cost`:

  ```
  cost: zone z: host big.example: its 30 path globs compile to 2420 pattern bytes, which could cost
  about 39720 steps per request in the generic engine (budget 25000, ...)
  ```

  A node's `load` doesn't estimate. The budget bounds what it didn't make, failing closed.
- **How the bounds are measured.**
  - Oracle 1 covers every zone in `examples/` and the subset tests. Oracle 3 covers the fixed
    depth-0..5 chains. Both run the generic engine and assert that each request stays within its
    token's estimate. Oracle 1 measured up to 5,242 generic steps, oracle 3 up to 6,605. The zone
    of #183 (`tests/fixtures/zone-183.yaml`) measured 9,497 steps against an estimate of 11,048.
  - `MEASURED_MAX_STEPS` (7,000) is asserted on oracle 3's fixed chains only, as a regression
    signal for the fork and the generator. It doesn't cover `examples/`, so adding an example
    can't trip it. A new example that is too costly is refused at mint instead.
- **Grant blocks travel in-process only.** `SignedGrant` has no `from_bytes`: Biscuit has no parser
  for a lone third-party block. The feed doesn't need one. The control host signs grants and appends
  them, then publishes the whole token (`wicket-feed`'s `token.rs`). An out-of-process approver will
  need the parser.

## Tests

| file | what it checks |
|---|---|
| `tests/oracles.rs` | Oracle 1: a single block decides as `CompiledZone`, compiled, on every example and subset-case zone, and on the zone of #183 |
| | An oversized zone is refused at mint, and an oversized chain at `attenuate` (#183) |
| | Oracle 2: a chain decides as the intersection of its zones |
| | Oracle 3: compiled and generic engines agree, failed checks included. 25k requests by default (the generic engine takes about 0.4 ms a request, recompiling regexes); `-- --ignored` runs all 100k through `AuthorizerBuilder` too (about 3.5 min) |
| `tests/properties.rs` | #59's checks, plus: block 0's forbids beat approvals, empty lists, Datalog traps, non-ASCII paths |
| `tests/hostile.rs` | hostile blocks are refused at load; the step budget bounds the rest |
