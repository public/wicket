# Fuzzing wicket

A box is the untrusted side of wicket: everything it sends crosses a parser on the host or the node.
These [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets fuzz those parsers
([#323](https://github.com/public/wicket/issues/323)). `fuzz/` is its own Cargo workspace, so
`cargo build` and `cargo test` at the root don't build it.

| Target | What it fuzzes | The oracle, besides panics and hangs |
|---|---|---|
| `egress` | the egress proxy, end to end: a box's connection (CONNECT, plain HTTP, or the inside of a TLS tunnel) to local origins | what is decided is what goes upstream: no request reaches an origin without a decision of the same method, host and path |
| `gateway` | the control host's gateway tools as a box's node asks them (`Gateway::call_tool`, #257), and MCP's handshake | every call answers; only the control host's own tools are asked of it; `initialize` carries a version and the instructions |
| `chan` | the control/node channel's frames, both directions, and version negotiation | a frame that decodes re-encodes to one that decodes to itself |
| `feed` | the node's feed replica: raw frames, and payloads signed with the feed's keys | an unsigned frame never changes the replica's state |
| `token` | Biscuit box tokens, with blocks a holder appends (or raw bytes), loaded, verified and decided | a token decides every probe the same in the compiled evaluator and the generic engine (or the engine refuses) |
| `manifest` | manifests through `wicket_agent::load`, zone compilation, Cedar ceilings and subset admission | a manifest that parses compiles or is refused; an admitted child's zone reaches nothing its parent's doesn't |
| `store` | tree decoding and `Cas::checkout` | a tree that decodes re-encodes to its bytes; nothing is written outside the target, and no tampered object is checked out |
| `git` | how a git push's requests are decided (`wicket_core::git`) | a push is decided as the push of its repository |
| `canon` | canonicalize-or-reject: `canonical_host` and `canonical_path` (#361) | a host or path taken is taken again unchanged, and is what a URL parser makes of it (never an IP address; the path decided is the path sent) |
| `time` | durations and times as manifests, operator files and flags write them (`wicket_core::time`, #437) | a duration or time that parses prints as one that parses back to itself; whitespace around a duration's terms changes nothing |

Each target is a one-line binary in `fuzz_targets/` calling `wicket_fuzz::<target>::run`; the
harnesses live in `src/`, with their oracles documented at the top of each file. The seed corpora in
`corpus/<target>/` come from the tests (`cargo run --example seeds` writes them again), and
`regressions/<target>/` holds every input that once found something.

## Running

```sh
# Every seed and past finding, through the same harnesses, on stable (what CI runs first):
cd fuzz && cargo test

# A short run of some targets (the script installs cargo-fuzz if it is missing):
ci/fuzz.sh --secs 60 egress gateway
# The targets a change selects (ci/determinator/suites.toml):
ci/fuzz.sh --affected
```

cargo-fuzz needs a nightly compiler: `ci/fuzz.sh` uses the stable one with `RUSTC_BOOTSTRAP=1`. By
hand:

```sh
cd fuzz
RUSTC_BOOTSTRAP=1 cargo fuzz run -O -s none --codegen-units 16 egress /some/scratch corpus/egress
RUSTC_BOOTSTRAP=1 cargo fuzz run --dev egress /some/scratch corpus/egress   # debug, with ASan
```

Memory: in a 4 GiB box, build with `CARGO_BUILD_JOBS=1`. The debug build with ASan (`--dev`) fits.
An optimized build fits only as `-O -s none --codegen-units 16`, because with cargo-fuzz's default
of one codegen unit, cedar-policy-core alone needs more than 3 GiB to compile. Optimized runs are
100 to 1000 times faster than debug ones (`feed`, `token`, `manifest` especially), so they are what
CI runs. Set `WICKET_FUZZ_TMP` to a directory on a large volume: the harnesses' scratch files go
there instead of `/tmp`.

## In CI

- A pull request fuzzes the targets its change selects, 60 s each, in groups of up to three, one
  job per group (`ci.yml`'s `fuzz-target` matrix, after which `Fuzz (short)` passes when they all
  did). A group's targets run one after another and share its build. Fewer jobs keep a full run
  within the runners it gets at once (15), so the longer jobs don't wait behind fuzzing. The
  corpora are replayed once, in a job of their own. The crates a harness links are listed with it in `ci/determinator/suites.toml`.
- Every night, every target runs for 20 minutes on its own runner (`fuzz.yml`), and a finding is
  filed as an issue.
- A finding is minimized (`cargo fuzz tmin`) and uploaded. Keep it: add the minimized input to
  `regressions/<target>/` with the fix, and `cargo test` here runs it from then on.
