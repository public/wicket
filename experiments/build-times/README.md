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
  biscuit fork's newer crypto stack).

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
