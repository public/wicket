# Run wicket in wicket

Have an agent work on wicket's own source in a wicket box, and, if you choose, update the
installation to a build it made. `examples/self-hosting/` is the worked example; any project can
describe its own workload the same way ([write a zone for a project](write-a-zone-for-a-project.md)).

## 1. Set up once

From the repository root:

```sh
wicket image --tag wicket-self:dev --dir examples/self-hosting     # the agent image plus a Rust toolchain

# A separate clone for the agent to work in, with an HTTPS remote (the box can't use SSH).
git clone https://github.com/public/wicket.git ../wicket-self
git -C ../wicket-self config user.name "…"; git -C ../wicket-self config user.email "…"

# Optional, for pushes and pull requests: a fine-grained GitHub token limited to this repository
# (Contents: read and write; Pull requests: read and write), typed into the terminal, never a chat.
wicket secret set github-wicket --hosts github.com,api.github.com
```

What `examples/self-hosting/manifest.yaml` gives the agent:

- **The checkout, mounted in place** (`--workspace-dir`), so commits land in a real clone on the host.
  Mounting in place is root's only on an installed host: there, run it with `sudo`.
- **Two volumes** that persist between runs: cargo's registry cache and the build directory.
- **Reads** of crates.io, this repository over git, and its issues and pull requests on GitHub.
- **Writes that wait for you:** pushes and creating pull requests are outside the reach, so each one
  is a pending request. GitHub's branch protection keeps `main` closed regardless.
- **No credentials in the box.** If you stored the token, wicket injects it at the proxy; without
  it, reads are anonymous and writes fail at GitHub after you approve them.
- **No AI attribution trailers** on its commits (`adapter_settings`), and a session that stays open
  30 minutes after each turn.

## 2. Run a session

```sh
wicket run examples/self-hosting/manifest.yaml --image wicket-self:dev \
  --workspace-dir ../wicket-self --task "Fix …, run the tests, and commit on a new branch."
wicket session <run>               # its session, live: type prompts while it runs
```

## 3. Update the installation to the agent's build

1. Give the zone what a release build needs: reach `github.com` (the checkout), `index.crates.io`,
   `static.crates.io`, `crates.io` and `static.rust-lang.org` (GET only), memory for a release build
   (`limits: { memory: 6g, cpus: 2, timeout: 2h }`), and an image with a Rust toolchain (the
   example's, or another built with `wicket image --dir`).
2. Ask the agent to build, test and package:
   `cargo build --release --locked -p wicket-cli && ci/package.sh target/release/wicket /workspace/out`,
   with `cargo test --workspace --locked`, and then to call `request_update` with the archive's
   sha256 (and, if it likes, the commit it built). That files an R4 request,
   `UPDATE wicket.internal/self/<sha256>`, and nothing else.
3. Approve it in the console. Its confirmation shows what approving installs: the file in the run's
   `/workspace/out` with that sha256, its size, the commit the agent says it is (its word, not
   checked), and the nodes it reaches after the control host. Signing the approval with your
   passkey applies it: wicket copies that file from the run's outbox, hashes it again, and runs
   `wicket self update <it> --nodes all` as the `wicket` user, as wicketd would, with its health
   gate and rollback ([update and roll back](update-and-roll-back.md)). Its log is
   `<data dir>/runs/<run>/update-<request>.log`. The agent is told how it ended (done, rolled back,
   or failed and why) in a notice from wicket, and its run carries on through the update.

The approval is used up by the update that accepts it, whatever uses the grant had left; a second
update to the same artifact needs a second approval. Like every grant made for an agent's request, it
lapses if the agent's identity is revoked first, so update before ending the agent.

**From a terminal instead.** Only a box on the control host's own node has its outbox on the control
host; for a box on another node, the card says so and approving only accepts the sha256. Then, or
if you approve with `sudo wicket approve <request>`, copy the archive out of the run's workspace
(`<data dir>/runs/<run>/workspace/out/`, or the node's run directory), check its sha256 against the
request, and run `sudo wicket self update /tmp/wicket-…tar.gz --nodes all`; or
`sudo wicket self apply-update <request>`, which takes it from the outbox as the console does.

An update applied from the console moves the `wicket` user's versions (`/var/lib/wicket-versions`)
and the services that run from them; root's own copy and `/usr/local/bin/wicket` (#261) stay where
they were, as root never runs what the `wicket` user staged. `sudo wicket self admit <artifact>`
moves root's link.

What isn't covered: wicket's own end-to-end tests need Docker in the box, which a box doesn't have
([design](../explanation/design.md) §21).
