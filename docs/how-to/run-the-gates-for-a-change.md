# Run the gates for a change

## Before you push: `ci/preflight.sh`

`ci/preflight.sh` runs the cheap checks CI runs, so a pull request doesn't fail in CI on something
you could have caught before pushing. It takes about two minutes with a warm build directory, most of
it clippy.

```sh
ci/preflight.sh                 # the cheap checks and clippy over the affected crates
ci/preflight.sh --full          # and the affected crates' tests
ci/preflight.sh --base REF      # compare with REF instead of origin/main
ci/preflight.sh --all           # clippy (and tests) over the whole workspace, with no selection
```

It runs, in order:

- `cargo fmt --all -- --check`;
- `ci/check-public.py` (tokens, home-directory paths, public IP addresses) over tracked files and the
  untracked ones git doesn't ignore, so a new file is checked before its commit. Use documentation
  addresses (`203.0.113.0/24`) and `/home/you/` in examples and tests;
- `ci/check-terms.sh`, `ci/check-doc-links.sh` and `ci/check-plugin.py`;
- `ci/changelog.py check --base origin/main`: a change to more than docs and CI adds a fragment in
  `changes/`;
- both lockfiles, with `cargo metadata --locked`: the workspace's and the fuzz workspace's
  (`fuzz/Cargo.lock`, which a dependency change in a crate the fuzz targets link can leave stale);
- gitleaks over the commits since the merge base, when `gitleaks` is on `PATH`, with the repository's
  `.gitleaks.toml`. Without it the step is skipped with a note; CI runs it over every commit. A
  published test vector that looks like a key needs an allowlist entry in `.gitleaks.toml`;
- `cargo clippy --all-targets --locked -- -D warnings` over the crates the change affects (the
  selection below, uncommitted and untracked files included), or the workspace if the selection fails.

Every check runs. It ends with a summary of what passed, failed or was skipped, and exits 1 if
anything failed. It can't catch a test that passes here and fails on CI's runners, such as one that
reads the host's own disk: keep tests to the files they make.

## All the gates: `ci/gates.sh`

`ci/gates.sh` runs the checks a change must pass. With `--affected`, it runs only what the change can
affect, which is what CI runs for a pull request.

```sh
ci/gates.sh --affected            # what this change can affect, compared with origin/main
ci/gates.sh --affected --no-e2e   # without the end-to-end suites
ci/gates.sh                       # everything
ci/gates.sh --suites "smoke hibernate"   # these end-to-end suites
```

`GATES_SLOT` is a command to run each heavy step through: cargo builds and tests, and the end-to-end
suites. The light checks run directly. On a shared host, give it the slot command, so a docs-only
change never waits for a slot:

```sh
GATES_SLOT="boxslot run --name <session> --mem 4500M -- timeout 3600" ci/gates.sh --affected
```

`--affected` looks at the change since the merge base with `origin/main` (`--base REF` for another),
including uncommitted and untracked files, so you can run it before a commit. The script prints what
it selected and why, file by file. To see the selection without running anything:

```sh
cargo run -q --locked --manifest-path ci/determinator/Cargo.toml -- --worktree
```

## What it selects

The selection is `ci/determinator`, a small CI tool around [guppy's
determinator](https://docs.rs/determinator), with its rules in `ci/determinator/rules.toml` and the
suites in `ci/determinator/suites.toml`. Both are reviewed like code.

- **Crates.** Each changed file under a workspace crate marks that crate changed. A change to a
  crate's `Cargo.toml` or to `Cargo.lock` marks every crate whose build it changes: the determinator
  simulates cargo's builds before and after the change and compares them. The rules mark crates for
  files outside the crates that a crate reads (`examples/`, `web/`, `images/`, the Lean spec), and for
  code another crate's tests follow (the simulation follows the node's run loops). Every crate that
  depends on a changed one is affected (normal, dev and build dependencies). Clippy runs with `-p`
  for the affected crates, and nextest with `-p` for them and `-E 'rdeps(=<crate>) | …'` for the
  changed ones. A change to `wicket-core` affects 12 of the 16 crates. A change to `wicket-fwd`
  affects it, `wicket-proxy`, `wicket-chan`, `wicket-cli` and `wicket-sim`.
- **Suites.** A suite runs when a path it lists changes (its script, its scenarios), or when a crate
  it lists is affected. Each end-to-end suite lists what it exercises that the others don't:
  - `smoke`, `acceptance`, `daemon-uids` and `update` list `wicket-cli`, which nearly every crate
    change affects;
  - `node-e2e` and `acceptance-nodes` list `wicket-node` and `wicket-chan`, and the control host's
    side of the node channel (`noderun.rs`, `nodecall.rs`, `enrol.rs`, `nodeca.rs`);
  - `hibernate` and `restore` list `wicket-store` and the hibernation and state-store paths;
  - `install-test` lists `deploy/`, the packaging scripts and the CLI's install path (the daemon,
    units, root copies, `wicket self`);
  - `tla` lists only its models.

  The end-to-end suites run the built binary, so a change only to tests (`[tests]` in
  `ci/determinator/suites.toml`: `crates/*/tests/`, test modules and their data) selects none of
  them. Kani lists `wicket-core`, and Lean lists `wicket-authz`. Each fuzz target lists the crates its
  harness links.
- **Docs only.** A change to Markdown, `docs/`, `experiments/` or `refs/` selects no crate and no
  suite: only the doc checks run. A change to `docs/reference/cli.md` also runs `wicket-cli`'s tests,
  one of which checks that page against every command's `--help`.
- **Everything.** These select every crate and suite:
  - the toolchain (`rust-toolchain.toml`), cargo's configuration (`.cargo/`, `.config/`), the
    workspace's `Cargo.toml`, or `third_party/`;
  - `.github/`, or the selection itself (`ci/determinator/`, `ci/gates.sh`);
  - a file outside the crates that no rule claims;
  - an empty change, or an error in the selection.

`ci/preflight.sh` always runs, with the selection's crates for clippy.

## Tests with cargo-nextest

When `cargo-nextest` is installed, `ci/gates.sh` runs the tests with it (`--profile ci`, in
`.config/nextest.toml`, and the selection's filterset). Then it runs the doctests with `cargo test --doc`, since nextest doesn't run
them, over the same crates as the tests, so cargo reuses what the tests built. It runs them only when
a selected crate has a doc-comment code block rustdoc would run, and the workspace has none today.
A test that fails and then passes on a retry is reported as `FLAKY` in the summary, and never passes
silently. Without nextest, `cargo test` runs instead. CI installs the version pinned in
`.github/workflows/ci.yml`, checksum-verified. nextest is a development tool, not a dependency of
wicket.

## In CI

- **A pull request** runs what its change selects. The `select` job prints the selection in its
  summary.
- **The `full-ci` label** on a pull request runs everything. Adding the label starts a run. The
  `select` job reads the pull request's labels from the API when it runs, not from the event that
  started it, so a label added just after a push counts whichever of the two runs survives (#246). If
  the labels can't be read, it runs everything.
- **Every push to `main`, and a nightly run,** run the full set, as the signed build does
  (`build.yml`), which never uses a selection.
- **Node and update suites** (`node-e2e`, `acceptance --nodes local`, `update`) run nightly in
  `acceptance.yml`, and in local gates when a change selects them. They don't run on pull requests.
- **No AI attribution**: commit messages, and a pull request's title and body, carry no AI
  attribution: no Co-Authored-By trailer for an assistant, no "Generated with" footer, no session
  link (`ci/no-attribution.py`, in `attribution.yml`, which reruns when the body is edited, and in
  `ci/preflight.sh`). Naming a harness wicket runs is fine. Turn on the same check for your own
  commits once per clone: `git config core.hooksPath .githooks`.
- **Supply chain**: `cargo deny --locked check` (`deny.toml`: RustSec advisories, licences, banned
  crates and sources) runs on every pull request, every push and nightly, whatever the change selects
  (#326). Run it locally with `cargo install --locked cargo-deny@0.20.2`.
- **Mutation testing** of the decision code (`ci/mutants.sh`) runs weekly in `mutants.yml`, not on
  pull requests: a mutant the tests don't catch fails it unless `ci/mutants.accepted` says why it is
  equivalent. Results and how to run it: [verification/mutants](../../verification/mutants/README.md).
- **Acceptance** (`ci/acceptance.sh`, on pull requests in the smoke job and nightly) includes a box
  that tries every way out of its reach, and ends with `wicket doctor --invariants` over the ledger
  it made (#326). The node end-to-end run (`ci/node-e2e.sh`) ends with it too, its node's shipped
  records included, and the simulation's placement and messages seeds run its clock-free checks over
  the ledgers they write (#324's trace validation).

If the `select` job fails, every job runs in full.

## Keep the rules honest

CI runs the rules' own tests (`cargo test --manifest-path ci/determinator/Cargo.toml`). They check
the selection on synthetic changes, with nextest's own filterset code evaluating each filterset over
the workspace. They also check that every tracked file is in a crate or claimed by a rule, and that
every path the rules name exists. Last, they find every file a crate reads from outside its own
directory (`include_str!`, paths such as `../../examples`), and check that a change to it selects
that crate. When you add such a file, add a rule to `ci/determinator/rules.toml`.

## A change to the ledger's schema

Each migration is an expand step or a contract step ([Migrations](../explanation/updates.md#migrations)).
An older build can be reading the ledger your build writes: after a rollback, and for the seconds
of a handover, when a run's supervisor still runs the build it started on. So an expand step leaves
what an older build reads alone. A step that adds rows an older query would mishandle to a table it
reads is not one, whatever its DDL (#475).

Before such a change, copy the previous build's queries over the tables it touches into
`crates/wicket-store/src/previous_build.rs`, with the kinds of row each handles. Its test then reads
a ledger your build writes with them.
