# Experiments

Throwaway prototypes that answer one design question each. Their code isn't part of the wicket build:
each directory is a standalone Cargo project with its own `[workspace]`. The findings go into the
design, research and tickets. Each `RESULTS.md` holds the method, the numbers and the verdict, and
`logs/` holds the raw output behind them. `target/` and downloaded tools are git-ignored.

All three ran on 2026-11-11 on a shared 4 vCPU Vultr VPS, so expect ±30% noise on timings.

| experiment | question | verdict |
|---|---|---|
| [`symcc-zones/`](symcc-zones/RESULTS.md) (#58) | Can Cedar's symbolic compiler prove "child zone ⊆ parent zone" fast enough to sit in the spawn path (architecture B)? | **No: keep A.** Fast enough (median 0.13 s), but cvc5 returns `unknown` for mid-path `*` globs. The exact segment encoding is 28 of 28 correct but scales superlinearly (30 s at 300 rules). Use SymCC in CI: org policy diffs (0–9 ms), floor ⊆ manifest ⊆ ceiling (0.05–0.7 s), and as a test oracle for `subset.rs`. |
| [`biscuit-depth/`](biscuit-depth/RESULTS.md) (#59) | Is Biscuit fast and small enough to carry zone chains, grants and leases, checked on every request? | **No on the request path: use plain Ed25519 signed records.** Biscuit gets every property right but costs about 1 ms per request at depth 5 (plain records: under 1 µs), and its 1 ms default time limit makes denials depend on load. Keep the Biscuit encoding as a differential oracle in CI. |
| [`freshness-feed/`](freshness-feed/RESULTS.md) (#60) | Does a node fail narrow when the control plane fails, catch up when it returns, refuse bad updates and keep revocation bounded? | **Yes.** Revocation is 0.74 ms p50 with push and at most the freshness TTL when partitioned. All 14 bad updates are refused, including a control plane restored from an old backup. About 1,050 lines. Two protocol fixes are in §7. |

## What changes as a result

- **Authority** is a signed capability chain made of plain records, with Biscuit-compatible semantics:
  - intersection over every link;
  - per-box grantor keys;
  - each grant bound to the previous link's hash;
  - leases that lapse without invalidating the chain.

  It replaces "authority is Biscuit" in the design (#57).
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
