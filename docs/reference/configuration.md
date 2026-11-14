# Configuration files and environment variables

## Configuration files

Paths are given for an installed control host (`/var/lib/wicket` is the data directory, `<data
dir>`) and, in brackets, for development mode (`~/.local/share/wicket`, or `$WICKET_HOME`).

| file | read by | what | page |
|---|---|---|---|
| `/etc/wicket/wicketd.yaml` | `wicket daemon` | Who may read, run and revoke through the daemon. | [daemon](daemon.md#the-policy-file) |
| `/etc/wicket/wicket.yaml` (or `$WICKET_CONFIG`) | `wicket run` (each new run and wake) | Installation settings: decisions that belong to the owner, not to a manifest. A missing file means every default; an unreadable or invalid one stops the run. | [below](#wicketyaml) |
| `/etc/wicket/console.env` | the `wicket-console` unit | `WICKET_CONSOLE_ARGS`: the `wicket serve` options. | [daemon](daemon.md#the-systemd-units) |
| `/etc/docker/daemon.json` | Docker | gVisor registered as `runsc` with `--host-uds=open`. | [install](../how-to/install-on-a-host.md) |
| `<data dir>/audit-sinks.yaml` (or `$WICKET_AUDIT_SINKS`) | `wicket run`, `wicket serve`, `wicket audit export` | Where audit records are exported, and how often checkpoints are signed. | [audit](audit.md#the-sinks-file) |
| `<data dir>/state-store.yaml` | `wicket state …`, hibernation, `type: store` sinks | The S3-compatible state store, where bundles go, the ledger's stream. | [state off the host](../how-to/state-off-host-and-restore.md) |
| `<data dir>/placement.yaml` (or `$WICKET_PLACEMENT`) | the gateway (`request_capacity`), `wicket reconcile` | The placement backend (static hosts or Vultr) and the money envelope for leases. Without it `request_capacity` is off. | [place nodes on Vultr](../how-to/place-nodes-on-vultr.md#3-leases-for-agents) |
| `<data dir>/manifests/*.yaml` | `wicket serve` | Manifests the console may start, besides `examples/` of the directory `wicket serve` started in. | [console](console.md#actions) |
| `<data dir>/release-keys/*.pub` | `wicket self update` | Release keys whose signatures an update accepts. | [update and roll back](../how-to/update-and-roll-back.md) |

### `wicket.yaml`

| field | type | default | meaning |
|---|---|---|---|
| `acp.allow_subscription_backed_claude_adapter` | boolean | `false` | Whether Claude Code may run through its ACP adapter (`agent.acp.profile: claude-agent-acp`) on the zone's Claude subscription. The adapter runs the `claude` binary through the Claude Agent SDK, and whether a subscription may back that is the owner's reading of the subscription's terms ([research 21 §2.6](../explanation/research/21-agent-client-protocol.md#26-claude-code-over-acp-stays-the-fallback-not-the-default)). While it is `false`, such a run is refused when it starts, and so is a wake. |

Unknown keys are errors, so a misspelt setting can't silently stay at its default.

### `placement.yaml`

`examples/placement/placement.yaml` is a commented example.

| field | type | default | meaning |
|---|---|---|---|
| `owner` | string | the trust domain | The installation's name in the owner tag, `wicket-owner-<owner>`. Keep it stable: only instances with this tag are listed or destroyed. |
| `backend` | `static` or `vultr` | required | The operator's own enrolled machines, or fresh Vultr nodes. |
| `max_hourly_usd` | decimal string | required | Every lease together, worst case, per hour. |
| `max_total_usd` | decimal string | required | Every lease together, worst case, in total. |
| `static_hosts` | list | `[]` | For `static`: `name` (the enrolled node's name), `ssh_target`, `capacity: {vcpus, memory_mib}`, `isolation`, `region`. |
| `install_static` | boolean | `false` | Run `wicket node install` on a static host when a lease binds it. |
| `vultr` | object | none | For `vultr`: `region`, `ssh_key_ids` (keys in the Vultr account), `ssh_key` (the private half's path on this host), `give_up_silent` (default `4m`: a new node that gives no answer of any kind on port 22 for this long fails its lease and is destroyed; once the port answers, setup is waited for up to 15 minutes). The API key is the vault secret `vultr-api-key`. |
| `node_hosts` | list of strings | | Hosts the CA of a node enrolled for a lease may issue for (`node enrol --hosts`). |
| `warm_pool` | boolean | `false` | Keep a node whose lease ended until minute 50 of its paid hour instead of destroying it at once. |

## Environment variables

### For operators

| variable | default | meaning |
|---|---|---|
| `WICKET_HOME` | `~/.local/share/wicket` | The data directory. Set (without `WICKET_DAEMON_SOCKET`), it also means development mode: commands run in the caller's own process, not through the daemon. The identity directory moves to `$WICKET_HOME/identity`. |
| `WICKET_DAEMON_SOCKET` | `/run/wicket/wicketd.sock` | The daemon's socket. If set and missing, commands fail rather than fall back to development mode. |
| `WICKET_LOG` | `warn` | Log filter for stderr (`tracing` syntax: `info`, `wicket_proxy=debug`). Passed on to the daemon for the commands it runs. |
| `WICKET_ROOTS` | the identity directory | Where the feed root and authority root are read from while they are offline (`wicket keys certify`, enrolling a node, a feed's new generation). |
| `WICKET_AUDIT_SINKS` | `<data dir>/audit-sinks.yaml` | The audit sinks file. |
| `WICKET_PLACEMENT` | `<data dir>/placement.yaml` | The placement file. |
| `WICKET_CONFIG` | `/etc/wicket/wicket.yaml` | The installation settings file. |
| `WICKET_VERSIONS` | see [files](files.md#versions) | The versions root in development mode. |
| `WICKET_TRUST_DOMAIN` | | The trust domain, used only if no issuer key exists yet; must match it after. `wicket identity init` is the usual way. |
| `WICKET_IDENTITY_TTL` | `600` | Seconds an agent identity is valid (at least 20); it is re-issued at half that. |
| `WICKET_NODE_BUDGET_SLICE` | `0.25` | On the control host: the fraction of a run's model budget leased to its node at a time (0 < f ≤ 1). |
| `WICKET_LOCAL_NODE_IDLE_SECS` | `600` | Seconds this host's own node's `serve` waits with no boxes and no connections before it exits. |
| `WICKET_NODE_HOME` | `~/.local/share/wicket-node` | On a node: its directory. |
| `WICKET_H3_BOX_MTU` | `1452` | The packet size on the box's leg of HTTP/3 (at least 1200). `16000` is much faster under gVisor, for clients that accept large packets. |
| `WICKET_H3_HTTPS_RECORDS` | | `0` stops wicket's DNS answering HTTPS (`alpn=h3`) records. |
| `WICKET_DOCKER` | `docker` | The Docker command, split on spaces. |
| `WICKET_NODE_SSH` | | An ssh command to use instead of wicket's own for nodes, split on spaces, `%t` replaced by the target (tests use it to stand in for several nodes). |
| `WICKET_BOX_PREFIX` | | A prefix for box (container) names, `[A-Za-z0-9-]+` (`ci/acceptance.sh` uses `acc-`). |

### Set by wicket

These are set by wicket for processes it starts; setting them by hand gives no extra assurance.

| variable | set by | meaning |
|---|---|---|
| `WICKET_OPERATOR` | wicketd | Who is deciding, from the caller's `SO_PEERCRED`. Without it, `$USER@cli (host break-glass)`. |
| `WICKET_PRINCIPAL` | the console | The principal a run acts for (a JSON object with string `type`, `id` and `via`): the passkey-signed-in operator. Without it, the unix user. Anyone who can run `wicket` as this user could set it, which is why development mode is insecure. |
| `WICKET_CONSOLE_ARGS` | `/etc/wicket/console.env` | The `wicket-console` unit's `wicket serve` options. |
| `WICKET`, `WICKET_UPDATE_TARGET` | `wicket self update` | For `--check` commands: the new build's binary, and `control` or `node:<name>`. |
| `WICKET_AS_USER` | wicket, in the box | `uid:gid` the box's entry script drops to after setting up its addresses. |

### For tests

`WICKET_FEED_TTL_MS`, `WICKET_FEED_REFRESH_MS` and `WICKET_FEED_COMPACT_BYTES` override the feed's
timings and compaction threshold (`ci/node-e2e.sh` shortens them). `WICKET_SIGTERM_LEDGER`,
`WICKET_WRITER_CRASH_LEDGER`, `WICKET_FUZZ_SEED` and `WICKET_AUTHZ_DIFF_REQUESTS` are test hooks.
None of these is for production.

### In the box

The agent's environment points every client at wicket: `HTTPS_PROXY` and `HTTP_PROXY` at
`http://wicket.internal:3128`, `ANTHROPIC_BASE_URL` at `http://wicket.internal:8080`, a placeholder
`CLAUDE_CODE_OAUTH_TOKEN`, and the run CA in `SSL_CERT_FILE` and its relatives. A manifest can't set
any of these: see [`agent.env`](manifest.md#agent). The box is described in [the box](box.md).
