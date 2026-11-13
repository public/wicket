# Update wicket and roll back

Move an installation to another wicket build, blue/green, and back. [How updates
work](../explanation/updates.md) explains the rollout, the health gates and migrations;
`ci/update.sh` is the test.

Updating is root's alone on an installed host: `self update`, `self rollback`, `self prune` and
`self trust-key` are refused for operators, passkeys and the daemon's own uid. An agent can only ask
(`request_update`).

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

An update that needs new systemd units or a new agent image says so in its release notes. Then run
`deploy/install.sh` from the new archive, or `sudo wicket image`: `self update` changes neither (the
units run `/usr/local/bin/wicket`, which follows `current`).

## Roll back

```sh
sudo wicket self rollback --nodes all       # the control host and every node back to previous
sudo wicket self rollback --nodes n1 --only-nodes
```

A rollback is a switch to `previous`, so a second rollback goes forward again. It refuses a build
below the ledger's schema floor: after a contract step, restore the snapshot instead (below).

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
`<data dir>/snapshots/<time>-<old build id>.db`.

1. Stop wicket's services: `sudo systemctl stop wicketd wicket-console wicket-reconcile`.
2. As the `wicket` user, copy the snapshot over `/var/lib/wicket/ledger.db`, and remove
   `ledger.db-wal` and `ledger.db-shm`.
3. Switch `current` back by hand, in `/var/lib/wicket-versions`:
   `ln -sfn <build id> current.new && mv -T current.new current`.
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
versions root, so no step needs root inside wicketd. Root then runs a binary the `wicket` user could
replace; that gives the `wicket` user nothing new, since it is in the `docker` group, which is root
on the host.
