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
