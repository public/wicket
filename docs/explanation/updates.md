# How updates work

`wicket self` (#162) updates an installation to another wicket build: the control host first, then its
nodes, a canary first, each switched blue/green, watched by a health gate, and switched back if the gate
fails. A build an agent made in a box can be installed too, once a human approves it. This page is the
design; [update and roll back](../how-to/update-and-roll-back.md) is the runbook, and `ci/update.sh` is
the test.

## Versions on disk

Each build is a directory named by its **build id**, the first 12 hex digits of the binary's sha256
([files](../reference/files.md#versions)):

```
/var/lib/wicket-versions/            (the versions root; the wicket user's, 0755)
  3f9c0a1b2c4d/wicket                one build
  3f9c0a1b2c4d/manifest.json         its version, protocol, schema, the artifact's sha256, what accepted it
  8e21d07f9a55/…                     another
  current  -> 8e21d07f9a55           what runs
  previous -> 3f9c0a1b2c4d           what `wicket self rollback` goes back to
/usr/local/bin/wicket -> /var/lib/wicket-versions/current/wicket
```

A switch replaces `previous` and then `current` (each an atomic rename of a new link). A rollback is a
switch to `previous`, so the two trade places and a second rollback goes forward again. Every wicket
process running from a staged version starts its children from `current` (the console's runs,
wicketd's commands, a run's children, this host's node's `serve`, the reconciler's adopting supervisors),
so after a switch everything new is the new build.

**Pruning** (#166). `wicket self prune [--nodes all|n1,n2] [--dry-run] [--keep-snapshots 5]` removes what
neither a running box nor a rollback needs: on the control host and each node named, every version that is
neither `current` nor `previous` and that no process runs (`/proc/*/exe`), and that version's agent image
unless a container, running or stopped, was made from it; and ledger snapshots beyond the newest five,
always keeping the newest of the current and previous versions' (the way back past a contract step). A
committed `wicket self update` prunes the same way where it updated (`--no-prune` to keep everything).
Each target pruned is a `self.pruned` audit record. An image that also carries another tag (`install.sh` makes `wicket/claude-code:poc` an alias of
the installed version's) keeps that tag.

A node keeps the same layout under `~/.local/share/wicket-node/versions/`, with `~/.local/bin/wicket` a link
to its `current`; `wicket node install` stages the control host's current build there.

In **development mode** (no install) the versions root is where the running binary is if it is a staged
version, else `$WICKET_VERSIONS`, else `<data dir>/versions`. The first `wicket self update` imports the
binary that runs it as the first version, so there is something to roll back to. From then on run
`<data dir>/versions/current/wicket` (put it on `PATH`): a binary outside the versions root, such as
`target/debug/wicket`, keeps starting its children from itself.

## What may be installed

An artifact is a wicket binary, or a release archive from `ci/package.sh` (only its `wicket-…/wicket` is
read from it; nothing else is unpacked). `wicket self update` copies it into a private staging directory
and works only on that copy: hashes it, verifies it, asks the binary what it is (`wicket self describe`),
and stages it. It is accepted only if

- it is **signed by a release key** this installation trusts: a detached `<artifact>.sig` (Ed25519 over a
  domain-separated sha256 of the artifact) by a key in `<data dir>/release-keys/` (`wicket self trust-key`,
  or `install.sh --release-key`); or
- a **human approved its sha256** for one update: an agent's `request_update` (below), approved with
  `wicket approve` or in the console like any R4 request. The approval is used up by the update that
  accepts it, whatever uses the grant had left.

Anything else is refused, and the refusal is an audit record (`self.update_refused`). There is no switch
that skips verification.

**Who may update.** Through wicketd, `self update`, `self rollback` and `self trust-key` are root's alone
(`sudo wicket self …`, the host break-glass); not an operator's, not a passkey's in the console, and not
the daemon's own uid either, which runs runs' supervisors, proxies and gateways. An agent can only ask:
`request_update` files an R4 request and returns; nothing an agent can call updates wicket.

## Protocol versions and skew

Nodes used to refuse any control host running another build, which made every update all-or-nothing.
Now the control channel is versioned: two ends talk if their protocol versions are at most one apart,
at the lower one. So the control host can go first, and its nodes follow one at a time; a node at N
also talks to a control host rolled back to N−1. `wicket self update` refuses a build more than one
protocol version from the running one. The rules for changing the protocol, and what each version
added, are in [protocol](../reference/protocol.md#versions-and-skew).

## The rollout

`wicket self update ARTIFACT [--nodes all|n1,n2] [--only-nodes] [--window 30s] [--interval 10s]
[--check CMD]... [--canary MANIFEST --image IMAGE]`:

1. **Accept and stage** the artifact (above). Record `self.staged`.
2. **The control host.** Check the target's schema against the ledger's floor; **snapshot** the ledger
   (`<data dir>/snapshots/<time>-<old version>.db`, `VACUUM INTO`, the last five kept); **switch**
   (`self.switched`); **hand over**:
   - runs' supervisors on this host are stopped with SIGKILL, which leaves their boxes running (a SIGTERM
     would stop them), and the new build's `wicket reconcile` adopts each run (#151's path: a new
     supervisor takes the box over, its model and gateway sockets included);
   - this host's own node's `serve` gets SIGHUP: it saves where each box's output got to, commits its
     audit, and re-executes itself from `current` with the same pid; the new build adopts the boxes;
   - the console (`wicket serve`) and the reconciler (`reconcile --every`) get SIGHUP and re-execute
     themselves from `current` (pid files in `<data dir>/pids/`).
3. **Gate** the control host (below). On failure: switch back, hand over again, and stop.
   On success: `self.committed`.
4. **The nodes**, one at a time, the first named the canary: push the binary over the node's pinned ssh
   (sha256-checked there), switch its `current`, and SIGHUP its `serve` (or restart its `wicket-node`
   service if no `serve` runs); the `serve` re-executes itself and adopts its boxes. Gate the node. On
   failure, switch that node back and stop the rollout: the nodes already done stay on the new build,
   which the skew allows.
5. **wicketd last.** It gets SIGHUP and re-executes itself once no command is running through it (the
   update itself is one).

Boxes never stop: neither a re-executed `serve` nor a killed supervisor stops a box (#151, #159).

## Health gates and automatic rollback

After each switch the gate runs once and then every `--interval` until `--window` has passed. Each round
is a `self.health` audit record. Any failure is a rollback.

- **The control host**: the new build's `wicket self health`, which opens the ledger (running its
  migrations) and verifies the audit chain, reaches Docker, completes a handshake with this host's own
  node and with each node being updated, and (first round only) runs `--canary`: a manifest it must run to
  success (`ci/update/canary.yaml`: a box that reaches example.com through the new build's egress).
- **A node**: it answers the control host as the new build, and every box it had before the switch is
  still there.
- **Both**: every `--check` command, run with `sh -c`, `$WICKET` the new build's binary and
  `$WICKET_UPDATE_TARGET` `control` or `node:<name>`. This is where a site's own smoke test goes (and how
  `ci/update.sh` injects a failure).

An automatic rollback is recorded as `self.rolled_back` with `"automatic": true` and the reason; a manual
one (`wicket self rollback`) with `false` and who ran it.

## Migrations

The ledger (and each node's `audit.db`, which is the same store) records its **schema version** (the
newest that has opened it) and its **floor** (the oldest that may open it) in `schema_meta`.

- **Expand** steps (a new table, a new column with a default, a new index) bump the version and leave the
  floor: older builds ignore what they don't know, so a rollback across them is safe. Every migration up to
  #162 is one of these (version 1).
- **Contract** steps (dropping or rewriting anything an older build reads) raise the floor to their
  version. A build below the floor refuses to open the ledger, and `wicket self rollback` refuses to
  switch to it. A contract step ships only in a release after the one whose expand step stopped anything
  from reading the old shape.
- **Never destructive on the way up**: the snapshot taken before every switch is the way back past a
  contract step. [Update and roll back](../how-to/update-and-roll-back.md#restore-a-ledger-snapshot)
  has the procedure.

The snapshots are local files (`<data dir>/snapshots/<unix time>-<old build id>.db`). The state store
(#154) streams the ledger itself off the host, but doesn't hold these snapshots yet.

## Not yet

- The control host's own wicketd re-executes only once no command runs through it, so a long `wicket
  attach` session delays it (it logs that it is waiting).
- `self update` doesn't install new systemd units or rebuild the agent image: an update that needs
  either says so in its release notes ([update and roll back](../how-to/update-and-roll-back.md)).
- Ledger snapshots aren't copied to the state store.
