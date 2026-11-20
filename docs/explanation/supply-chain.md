# Supply chain: what wicket's build and CI download, and how each is checked

wicket treats a box as hostile, so a bad package that an agent installs *inside* a box is contained by
design. What matters is what ends up in the wicket binary, its build, its release signing, or the
hosts it installs onto: those control the control host. This page lists every outside thing the
build, CI and the installers fetch, and how each is checked ([#718](https://github.com/public/wicket/issues/718)).

The rule is that what a download is checked against lives in this repository, not on the server it
came from. A hash fetched next to the file (a `.sha512`, a `SHASUMS256.txt`) shows only that the
server agrees with itself. Where a project publishes such a file, whoever updates the pin compares it
then, by hand, and commits the value.

## How each is checked

| What | Fetched by | From | Checked against |
|---|---|---|---|
| Rust crates (459, plus the vendored `biscuit-auth`) | cargo, every build | crates.io | `Cargo.lock` checksums; `cargo deny` (advisories, yanked crates, crates.io only, licences) on every PR |
| Rust toolchain (`rust-toolchain.toml`) | rustup, on the runner | static.rust-lang.org | rustup's sha256 from the same server's channel manifest: **the same server** (rustup has no signature check) |
| GitHub Actions | the runner | github.com | full commit SHA in each `uses:`, the version in a comment |
| gVisor `runsc` (the gVisor CI jobs) | `.github/actions/gvisor-setup` | storage.googleapis.com | sha512 in the action ([#722](https://github.com/public/wicket/issues/722)); no fallback to the server's `.sha512`. Releases publish no signature |
| gVisor `runsc` (acceptance, installs, Vultr nodes) | apt, in `acceptance.yml`, `deploy/install.sh`, `deploy/vultr/node-setup.sh` | gVisor's apt repository | apt's signature check, with gVisor's signing key accepted only if it is exactly the one key with the fingerprint pinned in each file ([#722](https://github.com/public/wicket/issues/722)) |
| Docker | apt, in the installers | the distribution (`docker.io`) | the distribution's apt signatures |
| Other Debian/Ubuntu packages (musl-tools, tcpdump, the installers' prerequisites) | apt | the distribution | the distribution's apt signatures |
| Agent image base images (`rust`, `node`) | `docker build` | Docker Hub (through `mirror.gcr.io` in CI) | `@sha256:` digest in `images/claude-code/Dockerfile` ([#720](https://github.com/public/wicket/issues/720)) |
| Install-test images (`ubuntu:24.04`, `debian:12`), the runsc self-test's `busybox` | `docker run` | Docker Hub | digest in `ci/base-images.sh` and the gVisor action ([#720](https://github.com/public/wicket/issues/720)) |
| Litestream, versitygw | `docker pull` | Docker Hub | digest in `deploy/install.sh`, `ci/restore.sh`, `ci/update/snapshot-store.sh` |
| Claude Code (in the agent image) | `docker build` | registry.npmjs.org | sha512 of the wrapper and platform tarballs in the Dockerfile; no install scripts run ([#721](https://github.com/public/wicket/issues/721)) |
| Session view's npm packages (126, compiled into the binary) | `ci/session-view.sh` | registry.npmjs.org | `web/session/package-lock.json` integrity hashes, `npm ci --ignore-scripts`; the bundle must rebuild byte for byte |
| Node.js (for the session view) | `ci/install-node.sh` | nodejs.org | sha256 in each workflow; required, no fallback to the runner's Node ([#722](https://github.com/public/wicket/issues/722)) |
| gitleaks | `ci.yml` | GitHub releases | sha256 in `ci.yml` |
| cargo-nextest | `ci.yml` | GitHub releases | sha256 in `ci.yml` |
| cargo-deny, cargo-mutants, cargo-fuzz, kani-verifier | `cargo install --locked` | crates.io | the crate's own `Cargo.lock` checksums (versions pinned in the workflow or script) |
| Kani release bundle (CBMC, Kani's compiler) | `ci.yml`, then `cargo kani setup --use-local-bundle` | GitHub releases | sha256 in `ci.yml` ([#722](https://github.com/public/wicket/issues/722)); `cargo kani setup` alone downloads it unchecked |
| Kani's nightly Rust toolchain | `cargo kani setup` (rustup) | static.rust-lang.org | rustup's sha256 from the same server, as for the main toolchain |
| Lean toolchain | `ci/lean.sh` | GitHub releases | sha256 in `ci/lean.sh` (and its version in `verification/lean/lean-toolchain`). No Mathlib: the spec has no Lake dependencies |
| TLA+ tools (`tla2tools.jar`) and the JRE for TLC | `ci/tla.sh` | GitHub releases | sha256s in `ci/tla.sh` |
| cvc5 (the solver for SymCC's policy diff) | `ci/policy-diff.sh` | GitHub releases | sha256 in `ci/policy-diff.sh`; SymCC itself is a crate (`Cargo.lock`) |

## What's left

- **The Rust toolchains** are checked only against hashes from the server that serves them. Pinning
  each component's hash in the repository would close that. It isn't done.
- **Hashes recorded on first use.** Where a project publishes no signature (gVisor's archive, Kani's
  bundle, most GitHub release assets), the pinned hash is what the file was when someone first
  pinned it, compared with whatever the project publishes beside it. It stops a later swap, not
  one that was already in place.
- **Examples** outside CI aren't covered here: `examples/self-hosting` installs Rust with rustup's
  `curl | sh`, and an `npm install` inside a box (the npm cache's own test) is the box's business.

## Keeping pins fresh

Renovate proposes updates to action SHAs, image digests, the tool versions and hashes above, and the
lockfiles, as pull requests for review. None is merged automatically
([#726](https://github.com/public/wicket/issues/726)).
