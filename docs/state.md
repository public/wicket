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
     litestream: { binary: /usr/local/bin/litestream }
     # or: litestream: { image: litestream/litestream@sha256:… }  (run with Docker, host networking)
   ```

   Litestream isn't installed by `deploy/install.sh`: install a release you have checked (wicket is
   tested with v0.5.18), or name its image.

3. **The audit sink**, in `audit-sinks.yaml`:

   ```yaml
   sinks:
     - { name: store, type: store }
   ```

   Its objects are `audit/<sink>/…` in the store, one per delivered batch and one per checkpoint,
   never overwritten.

4. **Check it**: `wicket state check` writes, reads back and deletes a probe object, and says where
   each kind of state goes. The `wicket-state` service starts once `state-store.yaml` exists
   (`systemctl restart wicket-state`).

5. **The recovery kit**: `wicket state kit --out /media/usb/wicket-kit.tar` (`--without-secrets` to
   leave the vault out and set the secrets again on the standby). It holds keys: keep it offline, as
   you would the roots. Make a new one after enrolling a node or changing a config file or secret.

6. **The roots, offline**: `wicket keys roots-offline --to /media/usb/roots --days 30`.
   - It makes an online *issuing* key for boxes' tokens, with a certificate from the authority root.
   - It certifies every node feed's key for `--days`, copies both roots to the directory, checks the
     copies, and removes them from the host.
   - Nodes pin the same keys as before; tokens then carry the issuing key's certificate, which nodes
     check (a node needs a build with #154 to load them).
   - Before `--days` run out, renew with `WICKET_ROOTS=/media/usb/roots wicket keys certify`. Runs warn
     in the last week.
   - Enrolling a node, a new node's first run, and a feed's new generation need the roots: run those
     with `WICKET_ROOTS` set too. While the roots are offline, a feed's log isn't compacted (that
     starts a new generation).
   - `wicket keys roots-online --from DIR` puts them back.

## Restoring onto a standby

On a fresh host with wicket installed (and nothing started), as the wicket user:

```
wicket state restore --kit /media/usb/wicket-kit.tar             # or --at 2026-11-12T19:05:05Z
WICKET_ROOTS=/media/usb/roots wicket keys certify                 # with the roots offline
systemctl start wicketd wicket-console wicket-reconcile wicket-state
wicket reconcile
```

`state restore`:
- unpacks the kit;
- restores the ledger with Litestream, as the store last had it or as it was at `--at`, and verifies
  its audit chain;
- **puts back audit records the store's sink has beyond it** (the ledger's stream stopped before the
  export did): exported records that continue the restored chain exactly are appended, as they were;
- **fences every agent**: its generation moves by 1000, past any the lost host could have handed out
  after the restore point, so a box still running at one of those is refused;
- sets every node feed to start a new generation (its delta log stayed behind): the next run that
  reaches a node publishes a fresh snapshot;
- records `state.restored` in the audit chain.

Then:
- `wicket audit --verify --against store:<sink>` compares the restored chain with what was exported.
- A restore to an earlier point (`--at`) discards what came after it; records exported after that
  point are reported as discarded, not as a mismatch.
- `wicket wake <agent>` brings a hibernated agent back from its bundle in the store.
- Runs that were running when the host was lost have no run directory here: the reconciler ends them
  as `lost`, and stops their boxes on nodes that can be reached.

`ci/restore.sh` runs all of this against a local S3 gateway (versitygw) and Litestream's image.

## What it doesn't do yet

- **Failover is manual.** A standby is restored by you, not promoted on its own (phase 5, #155).
- **Per-agent data keys** (the issue's other half): bundles are still sealed under one `state.key`,
  which is in the kit.
- **The kit isn't encrypted by wicket.** It's a tar of 0600 files: keep it where the roots are.
- **Runs in flight are lost** with their run directories, as above.
