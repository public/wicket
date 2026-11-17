# Mutation testing of the decision code (#326)

[cargo-mutants](https://mutants.rs) changes the code one small way at a time: it swaps `>` for
`>=`, `&&` for `||` or `+` for `*`, makes a function return a constant, or deletes a match arm.
Then it runs the tests. A mutant the tests still pass on is a change nobody would notice: either a
test gap, or a change that makes no difference (an equivalent mutant).

`ci/mutants.sh` runs it on wicket's decision code. A surviving mutant fails the run unless
`ci/mutants.accepted` lists it with the reason it is equivalent. The `mutants` workflow
(`.github/workflows/mutants.yml`) runs it weekly and on demand: it takes about 40 minutes, too long
for every pull request.

## What is mutated

| set | code | tests run on each mutant |
| --- | --- | --- |
| core | `wicket-core`: `subset.rs` (spawned zones within their parent's), `op.rs` (risk, reach, public addresses), `canon.rs` (canonical paths), `budget.rs` (the model budget counter) | `cargo test -p wicket-core --lib` |
| matchers | `wicket-core/src/manifest.rs`: the host, glob and model matchers (`host_matches`, `compile_glob`, `fold_case_glob`, `wildcard_for`, `names_host`, `allows_model`, `model_covers`, `check_models`) | the same |
| authz | `wicket-authz`: `decide.rs` (loading a token and deciding), `token.rs` (minting and grants), `cost.rs` (the step estimate) | `cargo test -p wicket-authz` |
| grant | `wicket-control/src/grant.rs`: who may grant what (`within_authority`, `agent_terms`, `check_terms`, `bounds`, `outlasts`, `check_ttl`, `check_prefix`, `agent_renews`, `descendant_chain`) | `cargo test -p wicket-control --lib grant` |

Each crate's slowest test is skipped for each mutant:
- wicket-core's `segment_proofs_agree_with_the_matcher` takes 26 of its 28 seconds;
- wicket-authz's `oracle3` checks the vendored evaluator's compiled engine against its generic
  one, which isn't the code being mutated.

Both still run on every pull request. A survivor of the fast suite that either of them would have
caught still counts here as a gap in the fast suite.

## Results (2026-11-16, cargo-mutants 27.1.0)

Measured on `verify/cheap-checks` before and after its tests. "Missed" counts the mutants every
test passed on. Unviable mutants (they don't compile) and timeouts (a loop that never ends, so
caught) aren't counted as missed.

| file | mutants | missed before | missed after | the after survivors |
| --- | ---: | ---: | ---: | --- |
| `wicket-core/src/budget.rs` | 79 | 75 | 0 | |
| `wicket-core/src/subset.rs` | 194 | 54 | 0 | |
| `wicket-core/src/op.rs` | 168 | 53 | 3 | equivalent (accepted) |
| `wicket-core/src/canon.rs` | 83 | 3 | 0 | |
| `wicket-core/src/manifest.rs` (matchers) | 69 | 6 | 1 | a real gap: see below |
| `wicket-authz` (`decide.rs`, `token.rs`, `cost.rs`) | 114 | 15 | 6 | equivalent or diagnostics only (accepted) |
| `wicket-control/src/grant.rs` (grant rules) | 32 | 1 | 0 | |
| **all** | **739** | **207** | **10** | |

What the 207 were, and what killed them:
- **`budget.rs`, 75 of 79.** It had no unit tests. Kani proves its arithmetic and loom its
  concurrency, but `cargo test` runs neither, and wicket-proxy's model tests only sample it. New
  exact-value tests now cover every committed and remaining figure, slices and their renewal line,
  reservations, settling, carve-outs (including the exact fit) and giving them back.
- **`op.rs`, 46 of them in `is_public_ip`.** Only wicket-proxy's dial tests sampled it. A table now
  puts an address inside each non-public range next to a public neighbour just outside it. Also:
  risk ranks and names, a POST opening an issue or a pull request, and each cloud metadata host on
  its own.
- **`subset.rs`, 54.** Budget and limit bounds weren't tested as inclusive. Nothing checked the
  fields `unapprovable` compares, one at a time, or `path_covered`'s shortcuts for globs the
  splitter can't read. The splitter's brace and class tracking and `parse_bytes`'s suffixes were
  untested too.
- **The rest.**
  - `canon.rs`: the length cap is inclusive, and each control character is refused.
  - `manifest.rs`: `names_host` and `wildcard_for`, and folded classes.
  - `wicket-authz`: the token size cap is inclusive; a signing key's `Debug` shows only its public
    half; `has_org_layer` is true exactly with an org layer (it is what stops a node splicing a
    host); steps are counted.
  - `grant.rs`: an agent's grant without a number of uses is refused by `bounds` itself, not only
    later by `agent_terms`.
- **`SignedGrant::to_bytes`** had no caller (grant blocks never travel alone, `wicket-feed`), so it
  was removed rather than tested.

### Accepted (`ci/mutants.accepted`)

- `op.rs`: `>` to `>=` where `classify` raises a risk. Raising a risk to the value it already has
  changes nothing.
- `op.rs`: `||` to `&&` in two of `is_public_ip`'s clauses. Other clauses already refuse
  `0.0.0.0`, `255.255.255.255` and `::` (`o[0] == 0`, `o[0] >= 240`, `s[..6] == [0; 6]`). The
  redundant clauses are kept because they say what is meant.
- `cost.rs`, four mutants. The step estimate is an upper bound checked when a token is made. These
  move its ties, an empty pattern set, a host predicate's arity (always one term) and its exact
  boundary. None of them changes a decision.
- `decide.rs`: `is_compiled` and `last_fell_back` are diagnostics nothing outside tests reads, and
  every fixture token compiles.

### A gap the mutants found

`fold_case_glob` doesn't fold a class range with a non-letter end. In `[a-~]` the letters `a`–`z`
keep their case, so a forbid rule written that way would match `/b` but not `/B`. Forbid rules are
meant to ignore ASCII case: this under-forbids. Classes like `[a-z0-9]` fold correctly, and the gap
needs a range that crosses from letters to punctuation. It is filed as a test gap, not fixed in
this change, and its mutant (`&&` to `||` on that line) is left out of `ci/mutants.accepted`, so
the weekly run fails until it is fixed.

## Running it

```sh
ci/mutants.sh                 # everything (about 40 minutes on 4 cores)
ci/mutants.sh --only core     # one set: core, matchers, authz or grant
ci/mutants.sh --list          # what each set would mutate, testing nothing
```

A mutant that loops and allocates (`fold_case_glob`'s `+=` turned `*=`) is ended by the timeout. On
a small machine it can run out of memory first, so run it on a CI runner or a workstation, not a
4 GiB box.
