# Experiments

Throwaway prototypes that answer one design question each. Their code isn't part of the wicket build:
each directory is a standalone Cargo project with its own `[workspace]`. The findings go into the
design, research and tickets. Each `RESULTS.md` holds the method, the numbers and the verdict, and
`logs/` holds the raw output behind them. `target/` and downloaded tools are git-ignored.

All four ran on 2026-11-11 on a shared 4 vCPU Vultr VPS, so expect ±30% noise on timings.

| experiment | question | verdict |
|---|---|---|
| [`symcc-zones/`](symcc-zones/RESULTS.md) (#58) | Can Cedar's symbolic compiler prove "child zone ⊆ parent zone" fast enough to sit in the spawn path (architecture B)? | **No: keep A.** Fast enough (median 0.13 s), but cvc5 returns `unknown` for mid-path `*` globs. The exact segment encoding is 28 of 28 correct but scales superlinearly (30 s at 300 rules). Use SymCC in CI: org policy diffs (0–9 ms), floor ⊆ manifest ⊆ ceiling (0.05–0.7 s), and as a test oracle for `subset.rs`. |
| [`biscuit-depth/`](biscuit-depth/RESULTS.md) (#59) | Is Biscuit fast and small enough to carry zone chains, grants and leases, checked on every request? | **No on the request path: use plain Ed25519 signed records.** Biscuit gets every property right but costs about 1 ms per request at depth 5 (plain records: under 1 µs), and its 1 ms default time limit makes denials depend on load. Keep the Biscuit encoding as a differential oracle in CI. |
| [`biscuit-fast/`](biscuit-fast/RESULTS.md) (follow-up to #59) | Can a vendored, patched biscuit-auth be made fast enough for the request path? | **Yes on speed: 6.9–10.7 µs median, 18–28 µs p99 at depth 5** (stock: about 1 ms). It loads each token once, replaces the wall-clock limit with a step budget, and compiles the Datalog. It matches stock on 100k random requests. The price is about 1,900 lines on unreleased upstream main, 1,233 of them a second evaluator. The fork is in `vendor/` (Apache-2.0, see `vendor/NOTICE`). |
| [`freshness-feed/`](freshness-feed/RESULTS.md) (#60) | Does a node fail narrow when the control plane fails, catch up when it returns, refuse bad updates and keep revocation bounded? | **Yes.** Revocation is 0.74 ms p50 with push and at most the freshness TTL when partitioned. All 14 bad updates are refused, including a control plane restored from an old backup. About 1,050 lines. Two protocol fixes are in §7. |

## What changes as a result

- **Authority** stays in the Biscuit format (owner, after `biscuit-fast`). Stock biscuit-auth is too slow
  for the request path (#59), so wicket vendors upstream main with three patches from `biscuit-fast`:
  - load a token once, then add each request's facts on top;
  - a step budget instead of the wall-clock limit;
  - a compiled evaluator, with the stock engine as fallback.

  The patched version needs a structural check before loading and a differential test against the
  stock engine in CI. `biscuit-depth`'s plain records are the measured fallback.
- **SymCC in CI** (#51):
  - the segment model;
  - cvc5 1.3.1 pinned, run with `--tlimit-per` (`--tlimit` kills the process);
  - `unknown` counts as a failure.
- **Node defaults for 0.0.1** (#57):
  - freshness TTL 30 s, refresh 5 s, narrow window 120 s;
  - bounds: revocation ≤ 30 s (about 1 ms with push), and reads ≤ 150 s on a partitioned node.
- **Bugs found in wicket itself**:
  - `subset.rs` ignores forbid rules, and wrongly refuses a child glob under a one-segment `*`;
  - `canonical_path` accepts `//`;
  - `evaluate` compiles globs on every call (about 20 µs a decision instead of about 0.13 µs).

## Reproducing

Each `RESULTS.md` ends with the exact commands. Build with `cargo build --release` in the experiment's
directory. `symcc-zones` also needs cvc5 1.3.1 in `symcc-zones/tools/` (see its §10).
