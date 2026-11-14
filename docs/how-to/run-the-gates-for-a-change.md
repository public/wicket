# Run the gates for a change

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
ci/affected.py --worktree
```

## What it selects

- **Crates.** Each changed file under a workspace crate selects that crate. `ci/affected.py` then
  adds every crate that depends on it (normal, dev and build dependencies, from `cargo metadata`).
  Clippy and the tests run with `-p` for those crates only. A change to `wicket-core` selects 10
  of the 14 crates; a change to `wicket-fwd` selects it, `wicket-proxy` and `wicket-cli`.
- **End-to-end suites.** `ci/affected.map` maps paths to suites, and is reviewed like code. A
  change to `wicket-fwd` or the agent image runs the smoke test. Hibernation and state code runs
  `hibernate.sh` (both modes) and `restore.sh`. Node code runs `node-e2e.sh --local` and
  `acceptance.sh --nodes local`. Update code runs `update.sh`. A CLI command group under
  `crates/wicket-cli/src/cmd/` runs the suites that call its commands.
  The exceptions are `run`, `dev`, `secret`, `identity`, `audit` and `image`: nearly every suite calls
  them, so changing one of those groups runs every suite.
- **Docs only.** A change to Markdown, `docs/`, `experiments/` or `refs/` runs the doc checks only:
  `check-public.py` and the Markdown links. A change to `docs/reference/cli.md` also runs
  `wicket-cli`'s tests, one of which checks that page against every command's `--help`.
- **Everything.** These select every crate and suite:
  - the workspace's `Cargo.toml` or `Cargo.lock`, any crate's `Cargo.toml`, `third_party/`, or the
    toolchain;
  - `.github/`, or the selection itself (`ci/affected.py`, `ci/affected.map`, `ci/gates.sh`);
  - a file no rule maps (outside a crate);
  - an empty change, or an error in the selection.
- **Every suite.** Crate code the map doesn't list selects every suite. That includes the node
  protocol, the ledger's schema, token formats, `wicket-core` and `run.rs`.

rustfmt, `check-public.py` and the Markdown link check always run.

## Tests with cargo-nextest

When `cargo-nextest` is installed, `ci/gates.sh` runs the tests with it (`--profile ci`, in
`.config/nextest.toml`). Then it runs the doctests with `cargo test --doc`, since nextest doesn't run
them, over the same crates as the tests, so cargo reuses what the tests built. It runs them only when
a selected crate has a doc-comment code block rustdoc would run, and the workspace has none today.
A test that fails and then passes on a retry is reported as `FLAKY` in the summary, and never passes
silently. Without nextest, `cargo test` runs instead. CI installs the version pinned in
`.github/workflows/ci.yml`, checksum-verified. nextest is a development tool, not a dependency of
wicket.

## In CI

- **A pull request** runs what its change selects. The `select` job prints the selection in its
  summary.
- **The `full-ci` label** on a pull request runs everything. Adding the label starts a run.
- **Every push to `main`, and a nightly run,** run the full set, as the signed build does
  (`build.yml`), which never uses a selection.
- **Node and update suites** (`node-e2e`, `acceptance --nodes local`, `update`) run nightly in
  `acceptance.yml`, and in local gates when a change selects them. They don't run on pull requests.

If the `select` job fails, every job runs in full.

## Keep the map honest

`ci/affected.py --self-test` runs in CI. It checks the mapping on synthetic changes, and finds every
file a crate reads from outside its own directory (`include_str!`, paths such as `../../examples`).
For each such file, a change to it must select that crate. When you add one, add a rule to
`ci/affected.map`, or let the file stay unmapped, which selects everything.
