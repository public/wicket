# Update wicket and roll back

Move an installation to another wicket build, blue/green, and back. [How updates
work](../explanation/updates.md) explains the rollout, the health gates and migrations;
`ci/update.sh` is the test.

To update to builds CI signed for `main`, by hand or on a timer, see [Update from CI-signed
builds](update-from-ci.md).

Updating is root's alone on an installed host: `self update`, `self rollback`, `self prune` and
`self trust-key` are refused for operators, passkeys and the daemon's own uid. An agent can only ask
(`request_update`).

Root runs only its own copies of wicket (`/usr/local/lib/wicket/<build id>/wicket`, which
`/usr/local/bin/wicket` links to), never a file in `/var/lib/wicket-versions`, which the `wicket` user
can write ([why](#on-an-installed-host-why-this-is-safe)).

## Once: on a host installed before #261

Before #261, `/usr/local/bin/wicket` linked into the `wicket` user's versions root, so `sudo wicket`
ran a binary that user could replace. Update such a host once with `deploy/install.sh` from the new
release's archive, as root, instead of `self update`:

```sh
tar -xzf wicket-0.0.2-x86_64-linux.tar.gz && sudo wicket-0.0.2/deploy/install.sh
```

It makes root's copy from the archive, points `/usr/local/bin/wicket` at it, installs the new units
(the `wicket` user's services now run `/var/lib/wicket-versions/current/wicket` directly) and
restarts the services. A `self update` from an older build to this one is refused over those units,
and the command its refusal prints (`sudo /var/lib/wicket-versions/<id>/wicket self apply-units`)
is the one not to run: the new build refuses to run as root from there anyway.

## Once: trust a release key

An update is accepted only if a release key this installation trusts signed it, or a human approved
its sha256 ([run wicket in wicket](run-wicket-in-wicket.md)). There is no switch that skips this.

```sh
wicket self keygen release.key          # release.key (private: keep it offline) and release.key.pub
sudo wicket self trust-key release.key.pub                             # or: sudo deploy/install.sh --release-key release.key.pub
```

Where the release is built, sign it and ship the `.sig` beside the archive:

```sh
wicket self sign --key release.key wicket-0.0.2-x86_64-linux.tar.gz    # writes ….tar.gz.sig
```

The key never needs to be on a control host. To rotate it: trust the new key, sign with it, and
delete the old `.pub` from `<data dir>/release-keys/`. The project's own releases don't ship
signatures yet: this is for your own builds.

## Update

```sh
sudo wicket self status                                                # versions, current and previous, schema
sudo wicket self update wicket-0.0.2-x86_64-linux.tar.gz --nodes all   # control host, then every node
```

- The artifact is a wicket binary, or a release archive from `ci/package.sh` (only its `wicket` is
  read). Its signature is `<artifact>.sig` unless `--sig` says otherwise. It must be readable by the
  `wicket` user (`/tmp` is).
- `--nodes all` (or `n1,n2`) updates nodes after the control host, one at a time, the first a canary.
- A build more than one protocol version ahead (a host that missed releases) is a **jump**: it needs
  every enrolled remote node in `--nodes` (`--nodes all`), and switches them with the control host
  instead of after it. If a node is left out, the update is refused and names it: add it, or revoke a
  node you no longer use (`sudo wicket node revoke NAME`). With no remote nodes, a jump just works.
  `--only-nodes` updates only them, when the control host already runs the build.
- Each new build is watched for `--window` (30 s) every `--interval` (10 s). Add your own smoke test
  with `--check 'CMD'` (repeatable; `$WICKET` is the new binary and `$WICKET_UPDATE_TARGET` is
  `control` or `node:<name>`), and a manifest the new build must run once with `--canary
  ci/update/canary.yaml`.
- Any failed check switches that host back on its own, and stops the rollout. Nodes already done
  stay on the new build, which the protocol skew allows.
- Boxes keep running throughout: supervisors, nodes' `serve`, the console and the reconciler hand
  over to the new build.
- Afterwards it prunes, as `wicket self prune` does, where it updated (`--no-prune` to keep
  everything).
- Root's own side: before the update is forwarded to wicketd, `sudo wicket` copies the artifact's
  `wicket` into `/usr/local/lib/wicket/<build id>/` (root's; copied, then hashed). It refuses an
  artifact the `wicket` user could have written (one in its directories, or its own file): pass the
  artifact as you got it. Once the update commits, `/usr/local/bin/wicket` links to root's copy of
  the new build.

### A build that came another way

`--from-ci` and `self follow` (below, and [from CI](update-from-ci.md)) download the build as the
`wicket` user, so root has no copy of it and `/usr/local/bin/wicket` stays on the build root last
copied (the update says so). wicket's services run the new build either way. To have root run it
too, give root the artifact yourself:

```sh
sudo wicket self admit wicket-0.0.2-x86_64-linux.tar.gz   # root's copy; /usr/local/bin/wicket moves to it if it is current
```

### When the new version's systemd units differ

Each build carries its own systemd units (`deploy/systemd/`). `self update` runs as the `wicket`
user, which can't write `/etc/systemd/system`, so it refuses to switch to a build whose units
differ from the installed ones, and says what to run as root: root's own copy of that build, which
`sudo wicket self update ARTIFACT` made before it was refused:

```sh
sudo /usr/local/lib/wicket/<build id>/wicket self apply-units      # that build's own units, then daemon-reload
sudo wicket self update wicket-0.0.2-x86_64-linux.tar.gz --nodes all   # again: it goes on
```

For a build root has no copy of (`--from-ci`, `self follow`), the refusal says to make one first
with `sudo wicket self admit ARTIFACT`, from the build's artifact (its release archive, downloaded
yourself).

`apply-units` installs only what differs and restarts nothing (restarting wicketd stops the runs
started through it): each changed unit takes effect when its service next restarts, which it names.
Until then the old unit runs the new build, so a release changes its units only in ways the
previous release also runs under. A new unit is installed but not enabled. A rollback is never
refused over units; it warns, and `sudo /usr/local/lib/wicket/<previous id>/wicket self apply-units`
puts that build's back. `self follow` skips a build whose units aren't applied yet, and takes it once they
are. Running `deploy/install.sh` from the new archive does the same, and also restarts the services.

## Roll back

```sh
sudo wicket self rollback --nodes all       # the control host and every node back to previous
sudo wicket self rollback --nodes n1 --only-nodes
```

A rollback is a switch to `previous`, so a second rollback goes forward again. It refuses a build
below the ledger's schema floor: after a contract step, restore the snapshot instead (below). Root's
`/usr/local/bin/wicket` moves to root's copy of the build rolled back to, if it has one.

## Prune

```sh
sudo wicket self prune --dry-run            # what would go
sudo wicket self prune --nodes all --keep-snapshots 5
```

It removes versions that are neither `current` nor `previous` and that no process runs, their agent
images unless a container uses them, and ledger snapshots beyond the newest few (always keeping the
newest of the current and previous versions').

## Restore a ledger snapshot

The way back past a contract step, or from a bad migration. Each switch first snapshots the ledger to
`<data dir>/snapshots/<time>-<old build id>.db`, and, with a state store, pushes it there sealed (an
update doesn't switch until it is). If the control host itself is lost, restore a standby first
([state off the host](state-off-host-and-restore.md#restoring-onto-a-standby)), then fetch the
snapshot from the store:

```sh
sudo wicket state snapshots                                          # <time>-<build id>.db, oldest first
sudo wicket state snapshot 1763150400-0a1b2c3d4e5f.db --out /tmp/ledger-before.db
```

`--out` must not exist; the file is the wicket user's, 0600. The snapshots are sealed under
`state.key`, which is made on first use: take the recovery kit (`wicket state kit`) after the first
update with a state store, or after the first hibernation, so it holds that key. Then, with that file
as the snapshot:

1. Stop wicket's services: `sudo systemctl stop wicketd wicket-console wicket-reconcile wicket-state`.
2. As the `wicket` user, copy the snapshot over `/var/lib/wicket/ledger.db`, and remove
   `ledger.db-wal` and `ledger.db-shm`.
3. Switch `current` back by hand, in `/var/lib/wicket-versions`:
   `ln -sfn <build id> current.new && mv -T current.new current`; and root's link, if root has a
   copy of it: `sudo ln -sfn /usr/local/lib/wicket/<build id>/wicket /usr/local/bin/wicket`.
4. Start the services again.

Runs started after the snapshot aren't in it, and the reconciler leaves alone boxes of runs its
ledger doesn't know: stop those by hand (their containers carry a `wicket.run` label).

## In development mode

The same commands, as the data directory's owner, without `sudo`. The first `wicket self update`
imports the binary that runs it as the first version, so there is something to roll back to. From
then on run `<data dir>/versions/current/wicket` (put it on `PATH`): a binary outside the versions
root, such as `target/debug/wicket`, keeps starting its children from itself. There is no service
manager: this host's node's `serve` and any console or `reconcile --every` started from a staged
version re-execute on SIGHUP; anything started from elsewhere keeps running its own build until
restarted.

## On an installed host, why this is safe

`sudo wicket self update …` is forwarded to wicketd and runs as the `wicket` user, which owns the
versions root, so no step needs root inside wicketd. The `wicket` user's services (wicketd, the
console, the reconciler, the ledger's stream) run `/var/lib/wicket-versions/current/wicket`.

Root never runs a file there (#261): anything that took over wicketd could replace it first, and
would then run as root the next time root typed `sudo wicket`. So root runs only its own copies,
in `/usr/local/lib/wicket/` (root's, 0755): `/usr/local/bin/wicket` (what `sudo wicket …`, the
root `wicket-follow` service and operators run) links to one. Root makes each from an artifact it
names itself, copying it before hashing or running anything, and refuses an artifact the `wicket`
user could have written; the build id root reads from the versions root only chooses among root's
own copies. As root, wicket also refuses to run from a path the `wicket` user can write.

This doesn't make the `wicket` user harmless to root: it is in the `docker` group, and Docker is
root on the host. It closes the path through root running that user's binaries, so that taking over
the `wicket` user doesn't also hand over every later `sudo wicket` without going through Docker.
