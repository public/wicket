# What wicket doesn't protect (0.0.1)

wicket 0.0.1 keeps credentials out of the box, gives the box no network of its own, and decides every
request the box makes against its zone. This page lists what that does not cover. Each item gives the
design section or pull request that has the detail. Unless an item says otherwise, it is a gap in 0.0.1,
not a permanent decision.

## Data inside a zone's reach

- **Anything the zone can reach is a way out.** wicket checks where a request goes (host, method,
  path). It does not check what the request carries. So an agent that has read something sensitive
  can send it to any host and path the zone allows: in a request body, a query string, or a commit.
  The defences the design plans for this are labels, handles, typed gates and sink provenance
  (design §4.2–§4.3, M5). None of them is built, so 0.0.1 has no taint tracking and no "no writing
  down" rule. Keep reach narrow, and keep write access in zones that read nothing untrusted.
- **Labels don't cross links.** No labels exist yet, so a box connected to another through a link
  ([#103](https://github.com/public/wicket/pull/103)) can pass it anything, whatever either box has
  read. Each `link.open` audit record says so.
- **Requests are judged by host, method and path, not by meaning.** There are no provider adapters yet
  (design §10, M2). Risk comes from a short, hand-maintained dangerous-pattern list that covers only
  GitHub, matched on lowercased path segments: pushes (and ref discovery other than a plain fetch),
  ref updates through the git data API, writes under `.github/`, merges and branch updates,
  workflow runs, repository settings, access and credential changes, and any GraphQL `POST` (R4,
  since wicket can't read the operation); posting comments, reviews, releases, issues and pull
  requests (R3). A POST that an allowed path accepts is otherwise allowed, whatever it does at the
  provider.
- **Reach rules and grants carry no scheme or port.** HTTPS (port 443) and plain HTTP (port 80) to a
  host are decided alike, except that a credential is never sent over plain HTTP: a plain-HTTP request
  to a host the zone injects a credential into (or swaps one for) is refused.
- **Response bodies are not scrubbed.** If an upstream echoes an injected credential back in a
  response body, the box sees it. Headers are scrubbed.
- **A host allowed wholesale is spliced through, not inspected.** If a reach rule allows a host for
  every method and path, the proxy decides on the hostname and relays the TLS unmodified. This needs
  nothing injected, nothing forbidden, and not the model host. Such a host gets one audit row per
  connection, no per-request decisions, no header filtering and no Host pinning, so behind a shared
  CDN it can reach other sites on the same CDN. `wicket zone MANIFEST` lists spliced hosts. A forbid
  rule on the host keeps it inspected (`docs/performance.md`).
- **Request bodies over 4 GiB fail.** Uploads stream upstream as they arrive, and a declared
  `content-length` goes upstream as declared. Bodies are read whole in three cases: GET and HEAD,
  which must have none; requests that arrive over HTTP/3, up to 64 MiB; and model calls through the
  model proxy, up to its own limit ([#142](https://github.com/public/wicket/issues/142)).
- **MCP is wicket's own gateway only.** Adapter-generated tools and isolated third-party MCP servers
  (design §8.2, M4/M4b) aren't built, so an agent has no third-party MCP servers.
- **Agents inside one box are one principal.** With `in_box_subagents: true` (the default), Claude
  Code's own subagents share the box, its identity and its reach. Only wicket children (`spawn`) get
  their own box and identity.

## The control host

- **Docker is root on the host.** Whoever can talk to Docker can escape any box. Under
  `deploy/install.sh` only the `wicket` user is in the `docker` group.
- **Development mode trusts the operator's whole user account.** Without `wicketd`, `wicket` runs as
  your user. Anything else running as that user, including an agent session outside wicket, can reach
  run sockets, read the ledger and vault, approve requests, and set `WICKET_PRINCIPAL` to claim another
  principal ([#87](https://github.com/public/wicket/pull/87)). `wicket doctor` reports this mode as
  insecure. The daemon install ([#109](https://github.com/public/wicket/pull/109)) closes this; see the README's
  Install section.
- **Under the daemon:**
  - Mounting a directory in place (`--workspace-dir`, and `wicket wrap`, which mounts its launcher's
    directory) is root's only. So wrapping a Remote Control session needs root. Docker mounts by path,
    and the directory's owner could swap the path for a link into wicket's data after any check.
  - The console runs as `wicket` with direct access to the ledger. It is not yet the untrusted front end
    the design describes (design §14.1.3), so a bug in the console is a bug in the control plane.
- **Keys are files.** The identity issuer key, the installation CA, and the feed, authorization and
  approver keys are 0600 files in the data directory. There is no split between an offline root and
  short-lived issuing keys, and no TPM or KMS (design §3.2). Root on the control host can mint any
  identity, grant or node certificate.
- **The audit log is only as safe as the host.** The hash chain shows tampering after the fact, but
  someone with write access to the ledger can rewrite the whole chain. Export with signed checkpoints
  (`docs/audit-export.md`) to a system they can't reach, and verify against it with
  `wicket audit --verify --against`. A SIGKILL or power cut can lose the last batch of records that
  nothing waited on, a few milliseconds' worth ([#107](https://github.com/public/wicket/pull/107)).

## The box

- **gVisor is the strongest isolation available.** It is a user-space kernel, not a VM. MicroVMs
  (Firecracker, Kata) need KVM and aren't supported yet (design §7.2). `isolation: runc` is weaker
  still.
- **Each box can use UDP port 443 only through wicket.** The in-box forwarder holds UDP 443 on every
  address, so a server in the box can't bind it, even on 127.0.0.1.
- **The `/tmp` cap is a poll, not a quota.** wicket stops a box whose `/tmp` goes over 512 MiB, checking
  every 5 s, so a fast writer can exceed the cap briefly ([#106](https://github.com/public/wicket/pull/106)).

## Authority and the Biscuit fork

- **The Biscuit fork has had no external audit.** Nodes decide every request with a vendored
  `biscuit-auth` (upstream main `aa5a672` plus three performance patches, `third_party/NOTICE`). It is
  tested against wicket's own matcher and the fork's general engine (about 74,000 differential decisions;
  [#83](https://github.com/public/wicket/pull/83), [#102](https://github.com/public/wicket/pull/102)). No
  one outside the project has reviewed the patches or the structural check.
- **The Cedar compiler is in the trusted computing base** (#51). Org and zone policies compile to
  token checks only within a fragment of Cedar (docs/policy.md); the compiler is differentially
  tested against Cedar's own evaluation (about 12,500 decisions over generated policies and requests in
  CI), not proven. A policy change reaches running boxes only when `wicket policy apply` revokes them
  (or at their token's end, with `--keep-runs`). SymCC treats path globs as opaque, so a changed glob
  reads as "may widen".
- **Spawn chains aren't used on nodes yet.** A child run on a node gets its own block 0 from its zone
  (checked as a subset by `spawn`), not a spawn block appended to its parent's token. So revoking a
  parent's block on a node doesn't by itself revoke a child there; the run revocation does
  ([#102](https://github.com/public/wicket/pull/102)).
- **At most 10 live grants per box on a node,** and a used-up grant holds its slot until it expires.
  A path-prefix grant is honoured on a node for the asked path only
  ([#88](https://github.com/public/wicket/pull/88), [#102](https://github.com/public/wicket/pull/102)).
- **Spawn refuses what it can't prove.** Path globs that `subset::check` can't prove contained are
  refused, even when they are narrower ([#30](https://github.com/public/wicket/pull/30),
  [#79](https://github.com/public/wicket/pull/79)).
- **A child's reservation counts as spent.** Model budget handed to a child isn't credited back when the
  child spends less ([#106](https://github.com/public/wicket/pull/106)).

## Remote nodes

- **A node is trusted with the boxes it serves.** It runs their Docker, terminates their TLS with its
  node CA, and makes their upstream requests. So root on a node can read those boxes' workspaces and
  their decrypted traffic, and can send any request to hosts within its CA's name constraints,
  ignoring the zone's reach, until the CA expires (24 h by default). What it never gets: injected
  credentials, the model token, and the hosts that use them. Those are tunnelled to the control host and
  decided there ([#88](https://github.com/public/wicket/pull/88)). Enrol nodes with `--hosts` as narrow as
  their boxes need.
- **Name constraints are subtrees.** A node CA for `api.example.com` can also mint `x.api.example.com`.
  The reach rules stay the exact gate; the constraint only bounds a stolen CA.
- **Revoked node CA serials are recorded but not distributed.** Revoking a node removes its pinned key
  and revokes its identity certificates. Its CA stays valid until it expires (24 h by default)
  ([#85](https://github.com/public/wicket/pull/85)).
- **The feed's root key can't be rotated,** and the publisher checks its own log's hash chain on open,
  not its signatures ([#84](https://github.com/public/wicket/pull/84)).
- **A node's clock is read once.** Feed freshness uses the wall clock at start plus a monotonic clock.
  After a deliberate clock step, restart `wicket-node`.
- **Runs survive a control-host restart, within limits** (#151). A run's new supervisor resumes from
  what the last one saved: its model counts from its last 3-second save (a long-lived agent's lifetime
  spend from its agent row), a parent's spawn slots are rebuilt from the children it started but its
  list of children to stop when it ends isn't (each child is adopted as its own run), and the grants re-minted into its box's token get the use
  counts the ledger had at handover. A wrapped session can't be taken over (its launcher was the dead
  process): it ends as `lost` and its box is stopped. A node that can't be reached leaves its runs
  running until it can, it is revoked, or they pass their timeout. By default a node keeps running a
  box whose run lease lapses (`WICKET_NODE_LEASE_EXPIRY=stop` stops it).
- **A box's output on its node's host is capped, and a burst can outrun it** (#151). The node's host
  keeps at most the zone's `limits.output` of a box's output (Docker's log, rotated). The node reads it
  from Docker as it comes, but a box writing faster than that (megabytes a second) loses what Docker
  rotates away before it is read, as it does while its node's `serve` is down: that output never reaches
  the control host, and isn't counted. `box.output` in the node's audit has the bytes read and a lower
  bound on what the host dropped; offsets count bytes read. Output that repeats itself exactly can be
  lined up on the wrong copy when an adopted box's replay is resumed (`box.output.gap` notes one that
  can't be lined up at all). The control host keeps the same amount (#160): the run's transcript
  (`transcript.jsonl`, then `transcript.1.jsonl` before it) and `agent.stderr.log` keep the newest
  `limits.output` of each stream, a program's output shown by its run stops there, and `run.output` in
  the audit records how many bytes of each were dropped. A single line longer than half the cap is kept
  whole, and a re-attached run's `agent.stderr.log` and stderr count are its own supervisor's only.
- **The join token is visible in `ps`** and shell history when passed as `--token`. It is single-use
  and short-lived ([#85](https://github.com/public/wicket/pull/85)).
- **What doesn't work on remote nodes yet:** wrapped sessions (`wicket wrap` runs on the control host's
  own node), plain `http://` to a host the
  node forwards, and tool decisions on the node: the gateway and the model proxy run on the node (#151)
  but relay every call to the control host, which decides the tools, holds the model credential and
  re-checks and counts each model call (its count is the authoritative one); while it is away only MCP's
  own handshake answers, and model calls stop (#152 moves credentials). Egress events from a disconnected period reach the audit log, not the live console
  ([#88](https://github.com/public/wicket/pull/88), [#102](https://github.com/public/wicket/pull/102),
  [#103](https://github.com/public/wicket/pull/103)). A link to a box on a remote node passes through the
  control host, and each connection into the target box costs a `docker exec` there.

## Hibernated agents

- **Bundles are sealed, not signed.** Each object is encrypted and authenticated under the
  installation's state key, and each tree is content-addressed and checked on restore. Anyone with the
  data directory (the key and the ledger) can still read or change an agent's state, and object keys and
  sizes aren't hidden. Bundles written before sealing are read as they are until the agent hibernates
  again. Sealing is done on the control host: on its way from a remote node the state is protected by
  the node's channel (ssh), and on the node it is plain files in the run's directory while the box
  runs, as any box's workspace is, removed once fetched. The store is a directory in the data directory; S3 and other remote stores
  aren't supported ([#106](https://github.com/public/wicket/pull/106)).
- **A rebuild restores files, not processes.** A box running anything besides the agent stays paused
  instead of hibernating.
- **Wrapped agents (`wicket wrap`) and boxes on nodes don't hibernate.**
- **There's no garbage collection** of agents or their bundles yet (design §13.6).

## The console

- **No external review yet.** The console is built to face the internet
  ([#99](https://github.com/public/wicket/pull/99)), but the dedicated security review (#44) and a TLS
  and headers scan on a real hostname are still to do.
- **`wicket approve` on the host is break-glass.** It is audited as such, but it bypasses the passkey.

## Money

- **Charges aren't reconciled against the provider.** Leases record what they billed by wicket's own
  arithmetic. Nothing compares that with Vultr's invoices yet (design §8.5,
  [#98](https://github.com/public/wicket/pull/98)).
- **Vultr has no idempotency token.** Two processes racing on one key can both create an instance; the
  next reconcile pass destroys the duplicate ([#89](https://github.com/public/wicket/pull/89)).

## Performance

Measured numbers for the network path, and how they were measured, are in
[docs/performance.md](performance.md).

- **HTTP/3 under gVisor is slow.** gVisor spends about 110 µs of CPU per UDP datagram, so downloads run at
  40–100 Mbit/s with standard 1452-byte packets. `WICKET_H3_BOX_MTU=16000` reaches 430–460 Mbit/s, but only
  for clients that accept large packets. HTTP/3 hasn't been checked with `curl --http3` or a browser yet
  ([#104](https://github.com/public/wicket/pull/104), [#108](https://github.com/public/wicket/pull/108)).
- **A new connection over a link takes 140–200 ms,** because each one runs `docker exec`
  ([#103](https://github.com/public/wicket/pull/103)).
- **Waking takes seconds.** A wake rebuilds the box and resumes the session; the gVisor checkpoint fast
  path isn't built ([#90](https://github.com/public/wicket/pull/90)).

## Built, not yet run live

These are covered by tests against fakes and mocks, but haven't run end to end against the real thing:

- **Vultr provisioning:** the live Vultr API (`wicket place create`), the enrol and `node install` step
  after it, a child actually running on a leased node, and the `wicket reconcile --every` loop
  ([#89](https://github.com/public/wicket/pull/89), [#98](https://github.com/public/wicket/pull/98)).
  Enrolment and `node serve` themselves have run against a real Vultr node
  ([#95](https://github.com/public/wicket/pull/95)).
- **ACME** has only been tested against a mock CA, not Let's Encrypt
  ([#99](https://github.com/public/wicket/pull/99)).
- **Links:** at most 32 link names per box, and the target image must contain `wicket-fwd`;
  `examples/links/chrome.yaml` hasn't been run ([#103](https://github.com/public/wicket/pull/103)).

## Not known yet

- **How agents behave at the edge** (design §21, E1). Agents get clear refusals and `await_grant`, but
  nobody has measured whether agents wait, route around a denial, or give up.
