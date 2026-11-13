# Files and directories

Where wicket keeps what. On an installed control host the data directory is `/var/lib/wicket`
(mode 0700, the `wicket` user's) and `HOME` is the same directory; in development mode it is
`~/.local/share/wicket`, or `$WICKET_HOME`.

## The control host

| path | what |
|---|---|
| `/usr/local/bin/wicket` | A link to `/var/lib/wicket-versions/current/wicket` (installed). |
| `/var/lib/wicket-versions/` | The [versions root](#versions). |
| `/etc/wicket/wicketd.yaml`, `/etc/wicket/console.env` | The daemon's policy and the console's options ([daemon](daemon.md)). |
| `/usr/local/share/wicket/` | The agent image's build directory. |
| `/run/wicket/wicketd.sock` | The daemon's socket. |

### The data directory

| path | what |
|---|---|
| `ledger.db` (`-wal`, `-shm`) | The ledger (SQLite, WAL): runs, agents, requests, grants, leases, links, nodes, passkeys, identities and the hash-chained audit log. |
| `identity/` | The keys (below). In development mode without `WICKET_HOME`, `~/.config/wicket/identity/`. |
| `$HOME/.config/wicket/secrets/` | The vault: one file per secret (mode 0600), or a `.ref` file for a linked one. Installed, `/var/lib/wicket/.config/wicket/secrets/`. |
| `state.key` | The key every hibernated agent's bundle is sealed under. Back it up with the data directory; without it no hibernated agent can be woken. |
| `runs/<run>/` | A [run's directory](#a-runs-directory). |
| `agents/<agent>/` | A long-lived agent's own files (`wake.log`, its durable volumes while it runs). |
| `objects/` | The object store for hibernated agents' bundles (sealed), unless `state-store.yaml` sends bundles to S3. `objects-scratch/` is its staging area. |
| `volumes/` | Zone volumes of the `node` class for this host's own node. |
| `nodes/<name>/` | Each enrolled node: `known_hosts` (its pinned host key), its feed's publisher state and delta log (`feed/`, `feed.lock`). |
| `local-node/` | This host's own node, `local`: its node key, identity certificate and node CA, laid out as a node's directory (below). |
| `manifests/` | Manifests the console may start. |
| `acme/` | The console's ACME account and certificate (0700/0600). |
| `snapshots/<time>-<version>.db` | Ledger snapshots taken before each `wicket self update` switch; the newest five are kept. |
| `pids/` | Pid files of the console and the reconciler, which `wicket self update` signals. |
| `release-keys/*.pub` | Release keys updates are accepted from. |
| `images.yaml` | The installation's image policy (#192): `require_digests: true` refuses a run unless its image and its zone's `images` are pinned by digest (the installation's own agent image excepted). |
| `ci-builds.yaml` | The repository whose CI-signed builds of main this installation takes, its token's vault secret, and `self follow`'s policy (#190). |
| `follow.json` | What `self follow` remembers: builds whose update failed here, and why it last didn't update. |
| `self-update.lock` | Held by the update or rollback running on this host. |
| `versions/` | The versions root in development mode (below). |
| `audit-sinks.yaml`, `state-store.yaml`, `placement.yaml` | [Configuration](configuration.md). |

### The identity directory

| file | what |
|---|---|
| `issuer.key` | The identity issuer: signs agent and node identities, the control host's half of the node handshake, and audit checkpoints. |
| `ca.key`, `ca.pem` | The installation CA: signs node CAs. |
| `approver.key` | Signs grant blocks in boxes' tokens. |
| `feed-root.key` (`.pub`) | The feed root: certifies each node feed's key. Can be moved offline. |
| `authz-root.key` (`.pub`) | The authority root: signs boxes' tokens, or certifies the issuing key. Can be moved offline. |
| `authz-issuing.key`, `authz-issuing.cert` | The issuing key and its certificate, while the roots are offline. |
| `roots-offline` | Present while the roots are offline; records when and for how many days. |

All private keys are 0600 files. `wicket state kit` writes the ones that stay on the host, with
`state.key` and the vault, into a recovery kit ([state off the host](../how-to/state-off-host-and-restore.md)).

### A run's directory

`runs/<run>/` on the control host:

| path | what |
|---|---|
| `workspace/` | The box's `/workspace` (copied in, or the `--workdir`); `workspace/out/result.json` is the result wicket reads after the run. |
| `transcript.jsonl`, `transcript.1.jsonl` | The agent's stream (or a program's output), the newest `limits.output` kept. |
| `agent.stderr.log` | The agent's stderr, the newest `limits.output` kept. |
| `console.log` | The output of a run the console started. |
| `ctl/run.json` | The run's record: what another supervisor needs to take it over. |
| `ctl/run-ca.key`, `ctl/run-ca.pem` | The run's CA, which the run's egress proxy terminates TLS with. |
| `ctl/progress.json` | Model spend and output offsets, saved as the run goes (every 3 s). |
| `ctl/authority.json` | When the box's authority ends, and whether its node confirmed the box stopped. |
| `ctl/holdings.json` | The secrets released to the run's node and its budget slice. |
| `ctl/attach.log` | The log of a supervisor that adopted the run (`wicket attach`). |
| `ctl/egress.sock`, `ctl/llm.sock`, `ctl/gateway.sock` | The run's own proxies and gateway, which its node reaches for what it doesn't decide itself. |
| `sock/` | The box's sockets: egress, model, gateway, QUIC, links, `stdin.sock`. |
| `tmp/`, `state/` | A long-lived agent's `/tmp` and `/wicket/state` (`$HOME` and Claude Code's config). |
| `children/` | Logs of the children it started. |

## A node

`~/.local/share/wicket-node/` (or `$WICKET_NODE_HOME`, or `wicket node serve --dir`), mode 0700, for
the user `serve` runs as:

| path | what |
|---|---|
| `node.key`, `node.pub` | The node's Ed25519 key, made on the node. |
| `node-cert.jwt` | Its identity certificate, `spiffe://<trust domain>/node/<name>`, 24 h. |
| `ca.key`, `ca.pem` | Its node CA (P-256, made on the node), signed by the installation CA, name-constrained to `--hosts`, 24 h. |
| `root.pem`, `feed-root.pub`, `authz-root.pub`, `issuer.pub.json` | What it verifies the control host with. |
| `node.json` | Its name and installation. |
| `feed/` | Its verified replica of the signed policy feed. |
| `audit.db` | Its own hash-chained audit log, shipped to the control host on every connect. |
| `asks.json` | Requests raised while the control host was unreachable, queued. |
| `slices/` | Budget slices, so a restart doesn't hand an offline node a fresh one. |
| `runs/<run>/` | Each box's directory: `node-box.json` (its record, for adoption), `node-spend.json` (its model spend), its sockets and workspace. |
| `volumes/` | Zone volumes of the `node` class. |
| `ctl/ctl.sock` | `serve`'s control socket (directory 0700), which `wicket node attach` joins an ssh session to. |
| `serve.pid`, `serve.lock` | The running `serve`. This host's own node also keeps `serve.log`. |
| `versions/` | Its versions root; `~/.local/bin/wicket` links to its `current`. |

Secrets a node fetched are never on its disk: they are in `serve`'s memory only.

## Versions

```
/var/lib/wicket-versions/            (the versions root; the wicket user's, 0755)
  3f9c0a1b2c4d/wicket                one build: its directory is named by its build id
  3f9c0a1b2c4d/manifest.json         its version, protocol, schema, the artifact's sha256, what accepted it
  8e21d07f9a55/…                     another
  current  -> 8e21d07f9a55           what runs
  previous -> 3f9c0a1b2c4d           what `wicket self rollback` goes back to
/usr/local/bin/wicket -> /var/lib/wicket-versions/current/wicket
```

A build id is the first 12 hex digits of the binary's sha256. In development mode the versions root
is where the running binary is if it is a staged version, else `$WICKET_VERSIONS`, else `<data
dir>/versions`. A node keeps the same layout under `~/.local/share/wicket-node/versions/`.
[Updates](../explanation/updates.md) explains how they are used.

## The box

| path in the box | what |
|---|---|
| `/workspace` | The workspace, read-write; `/workspace/out/` is where the result goes. |
| `/wicket/state` | `$HOME` and the harness's config. |
| `/tmp` | 512 MiB at most, checked every 5 s. |
| `/volumes/<name>` | Zone volumes. |
| `/etc/hosts` | wicket's, read-only: `wicket.internal` and link names. |

The root filesystem is read-only. [The box](box.md) has its addresses and ports.
