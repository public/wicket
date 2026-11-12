# Control-plane state off the host, and a restore onto a standby

A control host holds the ledger, the keys, hibernated agents' bundles and the audit chain. With the
state store set up, losing the control host costs a restore of minutes and, for the ledger, at most
its stream's sync interval (one second by default). This is phase 4 of the control-plane plan
(docs/research/24-control-plane-ha.md §6.2, #154).

## Where each thing goes

| What | Where | How |
|---|---|---|
| The ledger: runs, agents, grants, nodes, passkeys, the audit chain | The state store, streamed | `wicket state replicate` (the `wicket-state` service) runs [Litestream](https://litestream.io) |
| Hibernated agents' bundles | The state store | `bundles: s3`, sealed under `state.key` as before |
| Audit records and signed checkpoints | The state store | an audit sink of `type: store` |
| Keys and files that rarely change: the identity issuer, the installation CA, the approver key, `state.key`, each node's feed key and pinned host key, the config files, the vault | The recovery kit | `wicket state kit`, kept offline by you |
| The feed root and the authority root | Offline | `wicket keys roots-offline` |
| Run directories (transcripts, workspaces), this host's own node, feed delta logs | Not kept | Runs that were running end as `lost`; the node is made again; each feed starts a new generation |

## Setting it up

1. **An S3-compatible bucket** (S3, R2, GCS's XML API, MinIO, versitygw), and a key that can read,
   write, list and delete in it. Store the secret key in the vault, bound to the endpoint's host:

   ```
   wicket secret set s3-wicket --hosts s3.eu-west-2.amazonaws.com
   ```

2. **`<data dir>/state-store.yaml`** (`/var/lib/wicket/state-store.yaml` installed):

   ```yaml
   s3:
     endpoint: https://s3.eu-west-2.amazonaws.com
     bucket: example-wicket
     prefix: prod/                # optional; every key starts with it
     region: eu-west-2
     path_style: true             # default; false for https://<bucket>.<endpoint>/
     access_key_id: AKIA…
     secret: s3-wicket            # the vault secret above
     conditional_put: true        # default: If-None-Match: *; false: a HEAD before each PUT
   bundles: s3                    # default local
   ledger:
     sync_interval: 1s            # the most a lost control host loses
     retention: 72h               # how far back --at can go
     # litestream: omitted, Litestream v0.5.18's image, pinned by digest, run with Docker (host
     # networking, the data directory mounted, as the wicket user). Or name another:
     #   litestream: { image: litestream/litestream@sha256:… }
     #   litestream: { binary: /usr/local/bin/litestream }   (a release you have checked)
   ```

   `deploy/install.sh` pulls that pinned image (the digest is `LITESTREAM_IMAGE` in
   `crates/wicket-cli/src/statestore.rs`; a test keeps the two equal), so the `wicket-state` unit needs
   nothing more. With `--skip-image`, or if the pull fails, the unit pulls it when it first starts.

3. **The audit sink**, in `audit-sinks.yaml`:

   ```yaml
   sinks:
     - { name: store, type: store }
   ```

   Its objects are `audit/<sink>/…` in the store, one per delivered batch and one per checkpoint,
   never overwritten.

4. **Check it**: `wicket state check --probe` writes, reads back and deletes a probe object, and says
   where each kind of state goes (without `--probe`, only the latter). The `wicket-state` service
   starts once `state-store.yaml` exists (`systemctl restart wicket-state`).
   - Each control host streams to a path of its own, `ledger/<lineage>/`, listed in
     `ledger/lineages.json` with when each started. A restore takes the lineage that was current (at
     `--at`, if given) and starts a new one. A host whose lineage was taken over refuses to stream, as
     does a new host pointed at a store that already holds a ledger.

5. **The recovery kit**: `wicket state kit --out /media/usb/wicket-kit.tar` (`--without-secrets` to
   leave the vault out and set the secrets again on the standby). **It holds every key that stays on
   the host, `state.key` and the vault, unencrypted, and the roots if they are still here: whoever has
   it owns the installation.** Encrypt it and keep it offline, as you would the roots. Make a new one after enrolling a node or changing a config file or secret.
   A secret linked to a file (`wicket secret link`, and `claude-oauth`, which points at the host's
   Claude login) comes back as the link: sign in again on the standby.

6. **The roots, offline**: `wicket keys roots-offline --to /media/usb/roots --days 30`.
   - It makes an online *issuing* key for boxes' tokens, with a certificate from the authority root.
   - It certifies every node feed's key for `--days`, copies both roots to the directory, checks the
     copies, and removes them from the host.
   - Nodes pin the same keys as before; tokens then carry the issuing key's certificate, which nodes
     check, by their own clock: past its end a box is refused everything, and a token that would
     outlive it isn't minted. (Nodes run the control host's own build: they refuse one running
     another, so every node reads these tokens.)
   - Before `--days` run out, renew with `wicket keys certify --roots /media/usb/roots` (or
     `WICKET_ROOTS=…`). Runs warn in the last week. Installed, run it as the wicket user, which must
     be able to read the directory: `sudo -u wicket WICKET_HOME=/var/lib/wicket HOME=/var/lib/wicket
     wicket keys certify --roots DIR`.
   - Enrolling a node, a new node's first run, and a feed's new generation need the roots: run those
     with `WICKET_ROOTS` set too. While the roots are offline, a feed's log isn't compacted (that
     starts a new generation).
   - `wicket keys roots-online --from DIR` puts them back.

## Restoring onto a standby

On a fresh host with wicket installed (and nothing started), as the wicket user:

```
wicket state restore --kit /media/usb/wicket-kit.tar             # or --at 2026-11-12T19:05:05Z
wicket keys certify --roots /media/usb/roots                      # with the roots offline
systemctl start wicketd wicket-console wicket-reconcile wicket-state
wicket reconcile
```

`state restore`:
- unpacks the kit;
- restores the ledger with Litestream, as the store last had it or as it was at `--at`, and verifies
  its audit chain;
- **puts back audit records the store's sink has beyond it** (the ledger's stream stopped before the
  export did): exported records that continue the restored chain exactly are appended, as they were,
  up to the newest checkpoint signed by the installation's issuer (whoever can write the bucket could
  forge records that chain, not a signed checkpoint), and the chain is verified again;
- **fences every agent**: its generation moves by 1000, past any the lost host could have handed out
  after the restore point, so a box still running at one of those is refused;
- sets every node feed to start a new generation (its delta log stayed behind): the next run that
  reaches a node publishes a fresh snapshot, under a certificate version above any the lost host
  issued (the kit's may be older); with the roots offline that needs `keys certify --roots` first,
  and until then a run on a node is refused, saying so;
- records `state.restored` in the audit chain.

Then:
- `wicket audit --verify --against store:<sink>` compares the restored chain with what was exported.
- What a restore discarded (everything after `--at`, or exported records past the last signed
  checkpoint) is reported as discarded, not as a mismatch; a copy that disagrees with a record the
  restore kept is still a mismatch.
- `wicket wake <agent>` brings a hibernated agent back from its bundle in the store.
- Runs that were running when the host was lost have no run directory here: the reconciler ends them
  as `lost`, and stops their boxes on nodes that can be reached.

`ci/restore.sh` runs all of this against a local S3 gateway (versitygw) and Litestream's image.

## What it doesn't do yet

- **Failover is manual.** A standby is restored by you, not promoted on its own (phase 5, #155).
- **Per-agent data keys** (the issue's other half): bundles are still sealed under one `state.key`,
  which is in the kit.
- **The kit isn't encrypted by wicket.** It's a tar of 0600 files holding every key that stays on the
  host, `state.key` and the vault (and the roots, if they are still on the host): whoever has it owns
  the installation. Keep it offline and encrypted (docs/limits.md).
- **Runs in flight are lost** with their run directories, as above.
