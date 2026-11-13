# Experiments

Throwaway prototypes that answer one design question each. Their code isn't part of the wicket build:
each directory is a standalone Cargo project with its own `[workspace]`. The findings go into the
design, research and tickets. Each `RESULTS.md` holds the method, the numbers and the verdict, and
`logs/` holds the raw output behind them. `target/` and downloaded tools are git-ignored.

All five ran on 2026-11-11 on a shared 4 vCPU Vultr VPS, so expect ±30% noise on timings.

| experiment | question | verdict |
|---|---|---|
| [`symcc-zones/`](symcc-zones/RESULTS.md) (#58) | Can Cedar's symbolic compiler prove "child zone ⊆ parent zone" fast enough to sit in the spawn path (architecture B)? | **No: keep A.** Fast enough (median 0.13 s), but cvc5 returns `unknown` for mid-path `*` globs. The exact segment encoding is 28 of 28 correct but scales superlinearly (30 s at 300 rules). Use SymCC in CI: org policy diffs (0–9 ms), floor ⊆ manifest ⊆ ceiling (0.05–0.7 s), and as a test oracle for `subset.rs`. |
| [`biscuit-depth/`](biscuit-depth/RESULTS.md) (#59) | Is Biscuit fast and small enough to carry zone chains, grants and leases, checked on every request? | **No on the request path: use plain Ed25519 signed records.** Biscuit gets every property right but costs about 1 ms per request at depth 5 (plain records: under 1 µs), and its 1 ms default time limit makes denials depend on load. Keep the Biscuit encoding as a differential oracle in CI. |
| [`biscuit-fast/`](biscuit-fast/RESULTS.md) (follow-up to #59) | Can a vendored, patched biscuit-auth be made fast enough for the request path? | **Yes on speed: 6.9–10.7 µs median, 18–28 µs p99 at depth 5** (stock: about 1 ms). It loads each token once, replaces the wall-clock limit with a step budget, and compiles the Datalog. It matches stock on 100k random requests. The price is about 1,900 lines on unreleased upstream main, 1,233 of them a second evaluator. The fork is in `vendor/` (Apache-2.0, see `vendor/NOTICE`). |
| [`biscuit-datablocks/`](biscuit-datablocks/RESULTS.md) (for #76) | Should spawn and grant blocks carry Datalog checks (A), one typed zone fact each intersected by wicket (B), or both (C)? | Recommended **B**. All properties pass on A, B and C, and B matches A on 100k random requests except 8 where B follows wicket's own glob matcher. B is 0.4–2.3 µs warm against A's 6.9–10.6 µs, loads in 1.8 ms against 2.9 ms, and its token is 26% smaller. It evaluates no attacker-written logic and needs only a 25-line Biscuit accessor, not the 1,645-line compiled evaluator. **Owner's decision: A**, Biscuit as intended, because wicket needs approval blocks, offline grants and narrowing by Biscuit's semantics. Constraints are recorded in #76; B stays the fallback and a CI oracle. |
| [`freshness-feed/`](freshness-feed/RESULTS.md) (#60) | Does a node fail narrow when the control plane fails, catch up when it returns, refuse bad updates and keep revocation bounded? | **Yes.** Revocation is 0.74 ms p50 with push and at most the freshness TTL when partitioned. All 14 bad updates are refused, including a control plane restored from an old backup. About 1,050 lines. Two protocol fixes are in §7. |
| [`network-overhead/`](network-overhead/RESULTS.md) (#62) | What does wicket's egress path cost per request and per GB, and where does the time go? | **The per-request audit write and the in-box socat dominate, not TLS interception.** Kept-alive 1 KB: 1.32 ms through the proxy vs 0.13 ms direct; 0.47 ms with the audit write off the path. socat stalls new connections ~40 ms (no TCP_NODELAY) and its 8 KiB buffer caps gVisor downloads at 14 MB/s (170 with 256 KiB). Interception costs 2.4 CPU-s/GB; a splice-through prototype 0.17. Fixes: batch audit writes, replace socat (#92), splice-through for wholesale-allowed hosts. |
| [`hibernate/`](hibernate/RESULTS.md) (#70) | What does it take for a Claude Code agent in a box to sleep and wake, by rebuild + `claude --resume` and by gVisor checkpoint/restore? | **Build rebuild + resume for 0.0.1, with `docker pause` for Idle.** A fresh box resumed all 46 prior messages from a 0.2 MB bundle (`projects/` + workspace + volumes, tar+zstd -3): hibernate 0.49 s, wake 5.2 s end to end. gVisor checkpoint works (0.2 s, 20 MB, restore 0.13 s) but drops `wicket.internal`'s address and needs direct runsc. Nothing stops a double wake: a generation-counted claim does (one winner in 500 races). wicket must own `cleanupPeriodDays`. |
| [`bundle-formats/`](bundle-formats/RESULTS.md) (E5, #195) | Should hibernation bundles keep wicket's tar+zstd+sealing, move to the restic format (`rustic_core`), or use tar+zstd with `age`? | **Recommended: the restic format, one repository per agent, under wicket's manifest.** After a session it stores 18 MB instead of 125 (Rust repo), 0.1 instead of 56 (Node) and 1.9 instead of 19 (small files); 5–18× less after 20 sessions. Costs: 140–300 MB of memory against 15–40, slower first saves on many small files, a 0.x library, and wicket's own restore checks in front of it (rustic_core's restore follows symlinked parents and makes device nodes, and panicked on a tampered pack). `age` equals today's sealing in size and speed but leaves hibernation non-incremental. |

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
