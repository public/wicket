# Build and test times (#219)

What a session waits for after a one-line change, on the shared development host (4 vCPU, 8 GB RAM,
other sessions building at the same time), and what makes it shorter. The loop (`loop.sh`): append a
comment to one file, then

- **build:** `cargo build -p wicket-cli` (the binary the end-to-end scripts run);
- **test build:** `cargo test --no-run` for the affected crates (the change's crate and its reverse
  dependencies, as `ci/affected.py` selects them);
- **test run:** running those tests.

Two cargo invocations with different package sets can resolve different features and rebuild the
dependency tree (wicket-autonomy's finding, #243). The loop's prime builds both invocations' sets, and
cargo keeps an artifact per feature set, so the timed phases don't pay that.

Each phase's wall time and peak memory (the largest process) is in `loop.jsonl`, from a warm target
dir with that variant's settings, all under `boxslot run --mem 4500M`. The host's load varied from 2 to
6 during the runs, so differences of 20–30% between single runs are within noise; the ones below are
far beyond it.

## Results

| variant | proxy: build | proxy: test build | proxy: test run | core: build | core: test build | core: test run | peak |
|---|---|---|---|---|---|---|---|
| **today**: `CARGO_INCREMENTAL=0`, sccache, `-j1` | 55 s | 97 s | 28 s | 88 s | 150 s | 389 s | 2.0 GiB |
| incremental, `-j3`, line tables only (workspace), no debug info (dependencies) | 13 s | 52 s | 24 s | 19 s | 24 s | 365 s | 1.6 GiB |
| the same, linked with mold | 16 s | 92 s | 35 s | 16 s | 41 s | 429 s | 1.5 GiB |
| **after**: the profile in `Cargo.toml`, incremental (cargo's default), no sccache, `-j3` | 16 s | 58 s | 23 s | 35 s | 39 s | 276 s | 1.6 GiB |

The whole loop after a change in **wicket-proxy**: 180 s → 97 s. After a change in **wicket-core**
(every crate's tests are affected): 627 s → 350 s. The core test run also includes #237 (the Cedar
crates optimized in test builds: `tests/cedar.rs` 230 s → 119 s).

## What helped, and what didn't

- **Incremental builds** (cargo's default for dev and test, turned off today by `CARGO_INCREMENTAL=0`).
  This is the main gain for one-line changes: rustc recompiles only what changed in the changed crate
  and its dependents. sccache refuses to run with `CARGO_INCREMENTAL` set.
- **sccache didn't help across worktrees.** Its cache keys include the target dir's absolute path
  (`--out-dir`, `-L dependency=…`): a second build of the same crates into another target dir got 0
  hits out of 69. It only helps a rebuild in the same target dir, which incremental builds do better.
  (Today's first warm build took 792 s, and 310 s the second time, in the same dir.)
- **`-j3`** inside `boxslot --mem 4500M`: peaks stayed at 1.6 GiB.
- **Less debug info** (the `[profile.dev]` in `Cargo.toml`): line tables for wicket's own crates keep
  file and line in panics and backtraces; dependencies have none. Smaller objects, faster links, less
  memory, and a 4.8 GB warm target dir.
- **mold: no gain.** Rust 1.99 already links with LLD by default on x86_64 Linux (`readelf -p
  .comment`: `Linker: LLD 23.1.1`), and mold wasn't faster than it here.
- **Test run time** is now dominated by a few slow tests (`tests/cedar.rs`, wicket-core's unit tests,
  `oracles`), not by building. That is #218's test selection, and the tests themselves.
- **A clean cold build at `-j1`** (no sccache) ran for more than 2 hours on the shared host without
  finishing: stopped. Warm builds are what the loop needs.
- **Not tried, per the coordinator's cut:** `-j2`, nextest, split debug info, fewer test binaries, and
  unifying the two RustCrypto generations (104 duplicate crates in `cargo tree -d`, from the vendored
  biscuit fork's newer crypto stack). The second round, below, did the last two.

## The environment for sessions

```sh
unset RUSTC_WRAPPER CARGO_INCREMENTAL   # incremental builds (cargo's default); sccache refuses them
export CARGO_BUILD_JOBS=3
boxslot run --mem 4500M --name <session> -- timeout 3600 <command>
```

CI keeps `CARGO_INCREMENTAL=0` (`.github/workflows/`): its builds start from a cache, not from a
previous build, so incremental state would only take space there.

## Scripts

- `loop.sh LABEL [proxy|cli|core…]`: the loop above, for the environment it runs in.
- `measure.sh LABEL [STEP…]`: clean, incremental, test and release builds, with `cargo --timings`.

## Second round: fewer test binaries, one crypto generation

Measured in a wicket box (2 vCPU, 3 GiB, nothing else building) at `-j1`, with no sccache and
incremental builds, by `measure.sh` (`results.jsonl`, labels `base-j1` and `after-j1`). **Not
comparable to the table above**, which ran on the shared 4-vCPU host at `-j3`: compare the two
rows of this table with each other only. One run each.

| | touch wicket-core | touch wicket-cli | `cargo test --workspace` (built) | peak |
|---|---|---|---|---|
| **before** (`base-j1`, 408e279) | 110 s | 47 s | 400 s | 1.9 GiB |
| **after** (`after-j1`, f7dc5f1: both changes) | 94 s | 44 s | 388 s | 2.0 GiB |

"touch" is `cargo build --workspace --all-targets` after a one-line change in that crate. Both
test runs are recorded as `test-run-failed`; they failed only on tests that cannot pass in a box
(below). The `test-build` step (3–4 s both times) ran after the touch steps had built everything,
so it measures nothing. The after numbers cover both changes at once; the box ran out of time
before measuring them separately, so the split below is by what each change removes, not by time.

- **One integration-test binary per crate** (`tests/integration/main.rs` with one module per old
  file, in wicket-authz, -core, -fwd, -placement and -proxy): 20 test targets → 9 (wicket-feed,
  -policy, -policy-diff and -sim have one file each). Executables in a full `--all-targets` debug
  build: 48 (1720 MiB, `base-j1` `sizes`) → 30 (862 MiB, counted from cargo's artifact list after
  the merge with main, which adds wicket-sim's two). Each binary removed is one link fewer
  whenever a crate below it changes: wicket-proxy alone went from 5 integration binaries to 1. In
  the merged branch, warm, `-j1`: rebuilding wicket-proxy's tests after a one-line change in
  `tests/integration/main.rs` takes 2.4 s, and after one in `src/lib.rs` (the library, its unit
  tests and the integration binary) 6.0 s.
- **Crypto crates aligned with the vendored biscuit fork** (ed25519-dalek 3, p256 0.14, sha2 0.11,
  getrandom 0.4): `cargo tree -d --workspace` 105 → 56 entries, 50 → 27 crate names. The
  RustCrypto stack is no longer compiled twice (curve25519-dalek, ed25519, ecdsa, elliptic-curve,
  p256, sha2, signature, pkcs8, spki, der and the rest are gone from the list). What remains is
  mostly not ours to align: `digest` 0.10 via lalrpop's sha3 (cedar-policy-core's build), `rand`
  0.9 via ulid and turmoil, `getrandom` 0.2 via ring, `rcgen` 0.13 (ours) beside 0.14
  (instant-acme), and two of syn, regex, nom, itertools and thiserror. Cargo.lock: 467 → 444
  packages before the merge with main, 449 after it (wicket-sim and turmoil). The merge also
  needed wicket-sim moved to ed25519-dalek 3.
- **The touch builds:** wicket-core 110 s → 94 s (−15%), wicket-cli 47 s → 44 s (within noise for
  one run). That fits fewer and smaller test binaries to relink after a change low in the tree.

### Tests that fail in a box

Rerun on the merged branch (`cargo test --workspace --no-fail-fast`), the failures are all known
and box-only:

- wicket-cli: `daemon::proto::tests::fds_and_credentials_cross_the_socket` and
  `daemon::tests::an_operator_reads_state_as_itself_through_the_daemon` (the box's uid has no
  passwd entry);
- wicket-fwd: `udp::relays_datagrams_both_ways_over_a_stream_socket_with_the_original_destination`;
- wicket-proxy: `h3::requests_are_decided_like_http1_over_a_stream_socket` and `…_over_seqpacket`
  (HTTP/3 over loopback).

The hibernate outbox directory-link test passed this time. One failure is new and is not from
this branch: wicket-sim's `deterministic` (seed 7 traced differently in two runs, in the model
budget's slices) fails in some runs, on origin/main as well (1 failure in 5
runs there; 2 in 4 on this branch, counting the full run).

### Still open for #219's done-when

- **A clean build**, before and after: not recorded in either round (`-j1` cold on the shared host
  ran more than 2 hours; the box rounds measured warm builds only).
- **`cargo test --workspace`**, before and after: recorded, but neither run was green (the box-only
  failures above). A run outside a box would give a clean pair.
- **One CI run**, before and after: not recorded.
- Tried in neither round: `split-debuginfo` and nextest locally (CI already runs nextest), and
  measuring the release build (`measure.sh release`). Not checked in this round: CI's agent-image
  reuse across steps and parallel e2e jobs (item 3).

## Third round: wicket-cli's clean build, duplicates and Cedar

Measured in a wicket box (5 CPUs, 8 GiB, nothing else building) by `measure.sh`'s `cli-*` steps
(`results.jsonl`, labels `base-j1c` on origin/main 8275c33 and `after-j1c` on `perf/builds`), with
incremental builds and no sccache, at `-j1`. The box warned about memory at `-j2` (a clean build's
link peaks at 2.4 GiB, and the box's own file cache adds to it), so these comparisons are at `-j1`.
The `base-j2` rows are three clean builds of the base at `-j2`, for scale: 194.8, 194.3 and
192.5 s. Incremental steps were run three times each (medians below); clean builds once each,
since one run takes six minutes and the box warned about memory every time. Clean builds at `-j1` are
nearly serial, so their wall time is close to the sum of the units in `cargo --timings`
(timings-*-j1c-cli-clean.html). That sum is the more reliable measure: 353.1 s vs. 327.6 s.

| step (wicket-cli, debug) | before | after |
|---|---|---|
| clean `cargo build -p wicket-cli` | 355.3 s (441 units) | **329.4 s** (425 units) |
| clean `cargo clippy -p wicket-cli --all-targets` | 190.6 s | 186.0 s |
| build after a one-line change in wicket-core | 10.30 s | 10.26 s |
| build after a one-line change in wicket-cli | 5.57 s | 5.56 s |
| clippy after a one-line change in wicket-cli | 7.33 s | 7.37 s |
| `cargo test -p wicket-cli --no-run`, first after the builds | 41.1 s | 40.0 s |
| the same after a one-line change in wicket-cli | 6.76 s | 6.62 s |
| peak memory (largest process: the link) | 2.4 GiB | 2.4 GiB |

**What the clean build spends** (base, `-j2`): cedar-policy-core 75 s and cedar-policy 26 s (both
at opt-level 2, on the critical path: cedar → wicket-policy → wicket-cli), the `wicket` binary
24 s, biscuit-auth 22 s, regex-automata 9 s twice (host and target, with different features),
zstd-sys and libsqlite3-sys's C builds 8 s and 5 s, lalrpop 5 s. Everything else is under 5 s.
Incremental builds after a one-line change are already short (5–10 s) and are dominated by the
`wicket` binary's own compile and link: nothing below changed them.

### What helped

- **Cedar at opt-level 1** (it was 2, from #237). Measured on the two crates alone, twice each
  (`cargo clean -p` and then a rebuild, `--timings`), with `tests/cedar.rs` run once at each level:

  | opt-level | cedar-policy-core | cedar-policy | `tests/cedar.rs` run |
  |---|---|---|---|
  | 0 | 14.4 s | 3.1 s | 100 s |
  | 1 | 44.6 s | 12.9 s | 64 s |
  | 2 | 56.7 s | 25.4 s | 55 s |

  Level 1 saves 25 s of every clean build (and every CI run that builds the dependencies) and costs
  9 s whenever the differential test runs. Level 0 would save 65 s of a clean build but cost 45 s on every run of
  the test: worse for CI, whose cache keeps the dependencies built. A `[profile.test]` override
  can't keep the tests optimized and the build not: in `cargo test`, dependencies build with the
  dev profile. This is most of the clean build's 26 s.
- **Duplicates.** `cargo tree -d --workspace` names: 27 → 21; wicket-cli's: 26 → 18; Cargo.lock
  460 → 448 packages.
  - rcgen 0.13 → 0.14 (instant-acme's version) and x509-parser 0.16 → 0.18: rcgen, pem,
    yasna and thiserror 1 (with thiserror-impl) are no longer compiled twice, and neither are the old
    asn1-rs, der-parser and oid-registry. `ca.rs` now signs through rcgen's `Issuer`. A
    re-loaded run CA now presents its certificate as issued in the chain, where it used to
    present a re-signed copy.
  - ulid without its `std` feature: ids come from `wicket_core::new_ulid` (the same layout, from
    getrandom 0.4), so rand 0.9, rand_core 0.9 and getrandom 0.3 are built only for wicket-sim
    (turmoil).
  - rusqlite 0.32 → 0.43, without default features but with `cache`: hashlink 0.12, one
    hashbrown. No source change; the bundled SQLite goes from 3.46.0 to 3.54.1.

### Tried, and left as it is

- **biscuit-auth at a lower opt-level:** 13.0 s at 2, 14.6 s at 1, 4.6 s at 0, but wicket-authz's
  tests take 4.8 s, 5.9 s and 16 s, and every crate's tests mint tokens with it. Kept at 2.
- **Cedar without its default features** (ip, decimal and datetime extensions): an org policy may
  use them, so it would be a behaviour change.
- **The remaining duplicates aren't ours to remove:** base64 0.22 (instant-acme's latest, reqwest
  0.12, the biscuit fork) beside 0.23 (hyper-util, pem 4), syn 2 and 3, nom 7 (x509-parser's asn1
  stack) and 8 (the biscuit fork), itertools and digest 0.10 (lalrpop, Cedar's build),
  getrandom 0.2 (ring), num-bigint 0.4 (der-parser), unicode-width (Cedar's miette), and
  regex-automata and the like built twice, for build scripts and for the target, with different features.
- **A faster linker:** the second round found mold no faster than the LLD that Rust 1.99 links with
  by default, and this round's incremental steps (5–10 s) leave little to a linker.
- **Splitting wicket-cli:** its own compile is 24 s of a clean build and 5.6 s after a one-line
  change. Splitting it into crates would let a clean build at `-j2` or more overlap some of that,
  and nothing at `-j1`. It's a large change for a few seconds, so not this round.
- **CI:** it already caches with Swatinem/rust-cache (pinned by commit) and runs nextest. Not
  measured this round: a CI run before and after, and `cargo test --workspace` (the box-only
  failures above still make it red here).
