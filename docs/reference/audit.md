# Audit: the log, its export and its verification

wicket's audit log is a hash-chained table in the control host's ledger (`ledger.db`). This page
covers how records get written (#62), how they are copied to systems outside the control host (#91),
what is sent, and how `wicket audit --verify --against` checks the ledger against it. [Export
audit](../how-to/export-audit.md) sets up a sink, including an OpenTelemetry Collector in front of
cloud logging.

## Writing: the batched audit writer

Each wicket process that writes a lot of audit records (`wicket run`, and `wicket node serve` on a
node) runs one background audit writer. The writer appends records in group commits: one SQLite
transaction and one fsync per batch, with the ledger in WAL mode and `synchronous = FULL`.

- **Records nothing waits on** are queued, and the request carries on. This covers the egress
  proxy's per-request `op` rows for requests the zone's reach allows, and refusals. They reach the
  disk with their batch, a few milliseconds later. Queuing one costs about 0.6 µs. Writing it inline
  cost 0.65–0.71 ms, under the ledger lock.
- **Records that must be on disk before they take effect** wait for their batch's commit. This
  covers every `Ledger::audit` call (decisions, approvals, revocations, leases, links, messages) and
  egress requests allowed by an operator's grant. Waiting is a shared flush: when 16 threads append
  durably at once, each record costs about 80 µs instead of an fsync each.
- **Order and the chain.** Each batch reads the chain head and appends its records under one
  `BEGIN IMMEDIATE` write lock. Processes that share the ledger interleave whole batches, so the
  hash chain stays a single chain.
- **Fail closed.** If a record that must wait cannot be committed, the action it records does not
  happen. A grant-allowed request gets a 503 (`audit-unavailable`) instead of being forwarded. An
  approval's grant is revoked. A link is closed before it carries traffic, and an expose or a message
  is withdrawn. Records nothing waits on keep their old behaviour: a failure is reported on stderr.
- **Durability.** A record is on disk once its durable append returns, or once a flush returns
  after it was queued. A crash after that loses nothing. `wicket run` and `wicket node serve` commit
  whatever is still queued when they exit normally, on SIGTERM and on ^C. Only a SIGKILL (or a power
  cut) can lose anything: at most the last batch of records nothing waited on, a few milliseconds'
  worth.

## Exporting

### The sinks file

The ledger remains the source of truth, and it is what `wicket audit --verify` checks. Audit records
are also streamed to the sinks set in the installation's sinks file:
`$WICKET_HOME/audit-sinks.yaml` by default (`~/.local/share/wicket/audit-sinks.yaml`), or the path
in `$WICKET_AUDIT_SINKS`.

```yaml
# How often each sink gets a signed checkpoint of the chain head.
checkpoint_every: 5m
# The most records per delivery.
batch: 500
# How big the audit table on this host may grow, in GB, before its oldest records are pruned
# (only with a durable sink and the state store streaming: see Retention below). Default 2.
host_gb: 2
sinks:
  # JSON lines, for journald, Vector or Fluent Bit. The path must be absolute (a sink with a
  # relative one is left out, with a warning); "-" means stdout, which only `wicket audit export`
  # writes to.
  - name: local-file
    type: jsonl
    path: /var/log/wicket/audit.jsonl
    # durable: true    # this file is kept off the host (retention may count on it)
  # OTLP/HTTP logs (JSON encoding) to an OpenTelemetry Collector. Records are POSTed to
  # <endpoint>/v1/logs.
  - name: collector
    type: otlp
    endpoint: http://127.0.0.1:4318
    headers: {}          # extra request headers, e.g. a tenant header the Collector routes on
    resource:            # extra resource attributes (service.name is always "wicket")
      deployment.environment: prod
  # Objects in the installation's state store (state-store.yaml, see "state off the host"): one per delivered
  # batch or checkpoint, audit/<name>/…, never overwritten. `wicket audit --verify --against
  # store:<name>` compares the local chain with them; a restore puts back records they have
  # beyond a restored ledger.
  - name: store
    type: store
```

### Who sends

`wicket serve` and every `wicket run` start an exporter thread when the sinks file
exists. `wicket audit export` runs one in the foreground (`--once` for a single pass, `--checkpoint`
to send a checkpoint now, `--status` for each sink's position and last error). Each sink is fed by
one process at a time, which holds a lease on it in the ledger. A run that ends makes a last pass and
hands its sinks over; if a process dies instead, another takes over within 30 s. Exporters use their own ledger connection and never touch a request's path.

### Delivery

Delivery is at least once, by sequence number:
- Each sink's cursor in the ledger is the last `seq` it acknowledged. The ledger is the buffer: a sink
  that is down keeps its cursor and catches up from it when it is back (backing off up to a minute
  between tries). Nothing is held in memory, and nothing is dropped.
- A record can arrive twice, for example if the process dies between a sink's acknowledgement and
  the cursor update. Deduplicate on `seq` where that matters.
- For OTLP, only a 2xx with no rejected records (OTLP partial success) counts as acknowledged. A 4xx
  is not skipped: the sink stops at that record and shows the error in `wicket audit export
  --status`. A record that is never accepted needs a person, not silence.
- Renaming a sink gives it a new cursor, so it starts again from `seq` 1.

### What is sent

One JSON object per record:

```json
{"type":"wicket.audit.record","seq":42,"ts":1762900000,"tenant":"default","run":"run_…","kind":"op",
 "body":{…},"prev":"<hash of seq 41>","hash":"<this record's hash>"}
```

In OTLP, each object becomes one log record. Its body is the object's JSON line, and its attributes
are `wicket.audit.type`, `wicket.audit.seq` (int), `wicket.audit.kind`, `wicket.audit.hash`,
`wicket.run` and `wicket.tenant`. Its time is the record's.

Each log record also has an event name (`eventName`) and the standard OpenTelemetry attributes its
record carries, so a collector can read decisions without knowing wicket's bodies (#368). The body
stays the chained record, which is what `--verify --against` checks.

| Record | `eventName` | Attributes besides wicket's own |
|---|---|---|
| An egress decision (`op`, body kind `egress`) | `wicket.egress.decision` | `http.request.method`, `server.address`, `url.path`, `wicket.decision.outcome`, `wicket.decision.risk`, `wicket.decision.reason` |
| A model call (`op`, body kind `llm`) | `gen_ai.client.inference.operation.details` | `gen_ai.operation.name` (`chat`), `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.usage.input_tokens` (cached tokens included), `gen_ai.usage.output_tokens`, `wicket.llm.cached_tokens`, `http.response.status_code`, `wicket.decision.outcome` |
| A tool call (`op`, body kind `tool`) | `wicket.tool.call` | `gen_ai.operation.name` (`execute_tool`), `gen_ai.tool.name` |
| A decision on a request (`decision`) | `wicket.approval.decision` | `wicket.decision`, `wicket.request.id`, `wicket.grant.id`, `wicket.decision.by`, and the request's `http.request.method`, `server.address`, `url.path` |
| A checkpoint | `wicket.audit.checkpoint` | |
| Anything else | `wicket.audit.<kind>` (`wicket.audit.op.<body kind>` for other `op` records) | |

A refused egress request (any outcome but `allow` or `spliced`) and a model call that failed (HTTP
status 400 or more) are `WARN` (severity 13), with `error.type` set to the outcome or the status.
Everything else is `INFO`.

## Checkpoints and `--verify --against`

Each record's hash covers every field it stores: `seq`, `ts`, `tenant`, `run`, `kind`, `body` and the
previous record's hash. These are v2 hashes and start with `v2:`; a record with any other hash
fails verification (development builds before #120 wrote v1 hashes, which covered only `prev`,
`kind` and `body`: such ledgers no longer verify).

The hash chain proves that the ledger is internally consistent, not that it is complete: whoever
controls the control host can rewrite a record and recompute every hash after it. Checkpoints close
that gap. Every `checkpoint_every`, each sink also receives:

```json
{"type":"wicket.audit.checkpoint","seq":42,"head":"<hash of seq 42>","ts":1762900300,
 "iss":"spiffe://wicket.example.com","kid":"…","jws":"<EdDSA JWS over {seq, head, ts, iss}>"}
```

The checkpoint is signed with the installation's issuer key (`wicket identity init`). It covers the
last record that sink has received, so the checkpoint always matches what the sink holds. Keep one
copy where the control host can't change it, for example a bucket with S3 Object Lock or GCS
retention behind the Collector. Then:

```console
$ wicket audit --verify --against exported.jsonl [--against more.jsonl] [--issuer-jwk issuer.pub.json]
```

This runs the normal verification first, then checks the local ledger against the exported copies:
- the signature on every checkpoint;
- that the local record at each checkpoint's `seq` has the checkpoint's head hash;
- that the local chain reaches the newest checkpoint;
- that every field of each exported record (`ts`, `tenant`, `run`, `kind`, `body`, `prev`, `hash`)
  equals the local record's.

A rewritten chain fails this check even if it was consistently re-chained, and so does a truncated
one. The files can be wicket's JSON lines, or a Collector `file` exporter's output (OTLP JSON, one
batch per line), from which the log bodies are read. `--issuer-jwk` checks signatures against a
public key you keep elsewhere (as `wicket identity issuer` prints it) rather than the local key file.

## Retention on the host

The audit table only grows. On a small installation it grew by about 30 MB a day, mostly
`node.audit` records copied up from the nodes (#582), so without retention a busy installation's
ledger grows by gigabytes. wicket prunes the oldest records on the host once the table is over a
size limit (`host_gb` in the sinks file, default 2).

How long a sink keeps what it was sent is a separate setting: a sink's `retention` is `forever`,
the default and so far the only value. Expire old records in the sink itself, with a bucket
lifecycle rule or a Collector's own retention.

**When it prunes.** Every reconcile pass (`wicket reconcile --every 1m`) checks the table, and
prunes only when all of these hold:

- at least one **durable** sink is configured: a `store` sink, or a file or Collector sink marked
  `durable: true`, where you know its copy outlives the host. Standard output is never durable,
  and a sink that isn't durable neither allows nor holds back a prune;
- the state store is streaming the ledger off the host now (`wicket state replicate`, as
  `wicket state status` shows it), so no history is lost with the host;
- the table's estimated size is over `host_gb`.

It cuts the table back towards 90% of the limit, so it isn't pruning on every pass. It cuts only
to a **checkpoint**, and only one that all of these hold for:

- a durable sink acknowledged it, and every durable sink has exported past it;
- the state store had synced it;
- no trigger still has to read past it (#578).

Checkpoints are otherwise made at a sink's cursor, near the head. So the first time a cut is
due, retention asks the exporter to sign one at the cut, and prunes on a later pass, once every
durable sink has it. It never cuts deeper than asked. Without a durable sink or a streaming state
store it never prunes, however big the table.

**What it keeps.** Records the host reads for itself stay: a run's Remote Control session
(`run.remote_session`) and restores (`state.restored`). Below the anchor they aren't part of the
verified chain; the sinks have them whole. The prune's `audit.pruned` record, which is chained,
lists each restore it kept below the cut by seq and hash. `--verify --against` excuses a mismatch
by a restore only if the restore is chained or listed there (with its fields still hashing to the
listed hash), so a restore inserted below the anchor excuses nothing.

**The anchor.** The checkpoint a prune cuts back to becomes the chain's anchor. The prune runs in
steps:

1. One transaction sets the anchor (seq, hash and the signed checkpoint), appends an
   `audit.pruned` record (the range, the checkpoint and the sink), and raises the ledger's schema
   floor to 32. A build that would walk the chain from seq 1 then refuses the ledger, rather than
   reporting it broken. So after the first prune, `wicket self rollback` to a build before
   schema 32 is refused: restore the snapshot taken before the update instead.
2. The records before the anchor are deleted 10,000 per transaction, so the write lock is never
   held long, and at most 500,000 per pass: a longer backlog goes over several passes.

An anchor counts only if an `audit.pruned` record after it names it, which only a prune writes.
So an anchor copied in from a saved checkpoint, with the records before it deleted, fails
verification even on an installation that never pruned.

`wicket audit --verify`, `wicket doctor`, `wicket self health` and a restore start from the
anchor:

- the first record kept must be the anchor's, with the hash its checkpoint signed;
- the anchor's signature is checked against the issuer key (or `--issuer-jwk`);
- the chain is walked from there, even half-way through a prune, and so are the nodes' chains;
- an anchor over no records fails.

`--verify --against` counts exported records and checkpoints from before the anchor as pruned,
not as mismatches.

**A sink's target.** Each sink's cursor is kept with what it was made against: a file's path, a
Collector's endpoint (and a hash of its headers), the state store's endpoint, bucket and prefix.
If that changes under the same name, the sink starts again from the first record (the export
status says why), rather than claiming records the new target never got. A cursor kept before
targets were recorded starts again the same way. Each checkpoint is kept with the target it was
delivered through. A prune counts a sink only while both still match where the sink points now,
checked in the prune's own transaction. If the state store's file doesn't read, a store sink's
target can't be told: its cursor is kept, the sink isn't fed, and nothing is pruned.

Every wicket process that exports reads `audit-sinks.yaml` when it starts. When a newer process
points a sink elsewhere, the sink's lease is freed for it. A process still running with the old
configuration then stops feeding the sink: it can't take the lease, move the cursor or record a
checkpoint for a target the sink has left, and its export status says to restart it.

**Space.** Ledgers made by this build use SQLite's `auto_vacuum = incremental`. After each prune
they give the freed pages back in steps of 2,000 pages (8 MB) a transaction, so the file shrinks.
A ledger made by an earlier build keeps the freed pages for new records (the file stops growing,
but doesn't shrink) until you run `wicket audit compact` once, with wicket's services stopped.
That is one full `VACUUM`, which rewrites the file under an exclusive lock and needs about as
much free space again. It took 69 seconds for a 2.5 GB ledger, with 1.27 GB of WAL. wicket never
does it on its own, because no service could write meanwhile. Run it as the wicket user, with the
services stopped (it refuses otherwise, and wicketd refuses to run it):

```sh
sudo systemctl stop wicketd wicket-console wicket-reconcile
sudo -u wicket WICKET_HOME=/var/lib/wicket wicket audit compact
sudo systemctl start wicketd wicket-console wicket-reconcile
```

It keeps SQLite's temporary copy beside the ledger (not in `/tmp`), checks that twice the file's
size is free there, and fails at once if a reconcile pass is running or anything else has the
ledger open for writing (opening the ledger waits at most 5 seconds for a writer first).

After a prune, `wicket doctor --invariants` checks only what the chain still holds: it says where
the chain starts, and the sinks hold what came before.

**Why 2 GB by default.** That is about two months of the small installation above. It's well
within what SQLite handles quickly, and under 5% of a typical 40 to 80 GB control host disk. The
limit is on the host only: sinks keep everything. At larger scale, keeping node detail on the
nodes (#582 step 7) is what keeps the table small, and `host_gb` is the backstop.

**Where to see it.** `wicket top` shows the table against its limit, the ledger file and the
anchor on its last line ("audit 0.18 GB of 2.00 GB (ledger file 0.25 GB), pruned to seq …"), and
so does the console, above Activity, with what retention waits for. Reconcile reports
`audit_pruned`, or `audit_retention` while it waits.

## Record kinds

Each record's `kind` says what it records. The kinds wicket 0.0.1 writes, by area (`grep` the code
for a kind to see its body):

| area | kinds |
|---|---|
| requests | `op` (an egress or model decision), `decision` (an approve, deny or renewal), `decision.refused` (a decision outside the decider's authority: an operator's `operators.yaml`, or an agent's own reach, or one on another effect than the one shown, #369), `effect.refused` (a spawn, link or capacity lease whose arguments changed after its approval, or a lease whose approval ended first: the grant or lease, both hashes and why), `grant.revoked`, `daemon.refused`, `digest.granted` (an operator's grant on a digest, #258: a pinned program's source when its manifest is run), `digest.accepted` (a digest accepted by the one check, naming the grant) |
| runs | `run.start`, `run.image`, `run.end`, `run.lost`, `run.child_stuck`, `run.attach`, `run.attach_failed` (a takeover failed while the run's box may still run: once per reason, with the count, #676), `run.attach_recovered`, `run.fence_released` (a fence released without its node, #690: `by`, `granter` `root` with `wicket node release-fence` or `human` in the console with a passkey, `granter_identity`, `why`, `via`, and the fence as released: `node`, `node_status`, `node_seen_ms`, `fenced_until_ms`, `source`, `effect_sha256`; written before the fence is lifted), `run.fence_release_failed` (the fence could not be lifted after its release was recorded, or its authority record changed since it was shown: it still holds; a crash between the two leaves a `run.fence_released` with no lift and no failure record, the run still fenced), `run.console_start`, `run.output`, `run.remote_session`, `run.remote_session_failed`, `run.exit_cause`, `run.agent_prompt`, `run.agent_call_refused`, `box.output`, `box.output.gap`, `box.exit_cause`, `box.memory_pressure` |
| agents | `identity.issued`, `identity.rotated`, `identity.revoked`, `message`, `message.refused`, `spawn.beyond_parent`, `delegation.started`, `delegation.reported`, `delegation.report_failed`, `delegation.continued`, `delegation.refused`, `delegation.ended`, `agent.hibernate`, `agent.wake`, `agent.wake_refused` |
| triggers | `trigger.created` (with the agent it reaches), `trigger.approved`, `trigger.paused` (by an operator, or `by: wicket` with why: its owner may no longer have it fire, or its firings kept failing), `trigger.resumed`, `trigger.renewed`, `trigger.done` (a timer that fired, or whose time passed: it fires nothing again), `trigger.deleted`, `trigger.fired` (a firing woke or messaged its agent, naming the agent and the message's id, length and sha256, or queued its run), `trigger.skipped` (with why: the hour's first over its limit, or a timer whose time passed), `trigger.failed` (with why, and a firing dead-lettered from a full queue) ([wake an agent on a schedule](../how-to/wake-an-agent-on-a-schedule.md)) |
| sessions | `session.opened`, `session.attached`, `session.prompt`, `session.cancel`, `session.escalation_answered`, `session.closed` (the console's session view, [console](console.md#sessions)) |
| links | `link.expose`, `link.open`, `link.close`, `link.cut` |
| operators | `operator.signed_in`, `operator.lockout`, `operator.passkey_added`, `operator.enrol_link_issued`, `operator.enrol_link_used`, `operator.reset`, `operator.sessions_revoked`, `operator.message` |
| secrets | `secret.set`, `secret.hosts`, `secret.removed`, `secret.refused` (the console's [secrets](console.md#secrets): by name, never a value) |
| nodes | `node.token`, `node.enrolled`, `node.ca_renewed`, `node.revoked`, `node.audit`, `node.audit.restart`, `node.ask_queued`, `node.authority_expired`, `node.secret_fetch`, `node.secret_fetched`, `node.secret_unavailable`, `feed.refused`, `image.received`, `image.refused` |
| placement | `lease.requested`, `lease.released`, `placement.node_created`, `placement.node_released`, `reconcile.<what>` (one per change a pass makes, such as `reconcile.destroyed` and `reconcile.run_adopted`) |
| updates | `self.staged`, `self.snapshot`, `self.switched`, `self.health`, `self.committed`, `self.rolled_back`, `self.update_refused`, `self.pruned`, `self.key_trusted`, `self.follow_update`, `self.follow_skipped`, `self.follow_failed` |
| state and keys | `state.kit`, `state.restored`, `keys.roots_offline`, `keys.roots_online`, `keys.certified` |
| org policy | `policy.applied` (`version`, `previous`, `by`, `effect_sha256`, `cedar_sha256`, `entities_sha256`, `widens`, and `decision`: the console's decision it applied, or null), `policy.apply_decided` (a console decision to apply one, #712: `version`, `cedar_sha256`, `entities_sha256`, `previous`, `widens`, `changes`, `unchecked`, `why`, `keep_runs`, `revokes`, `effect_sha256`, `by`, `granter`, `granter_identity`, `via` and the `signed` assertion; written before anything is applied), `policy.apply_failed` (a decided apply that installed nothing: `version`, `decision`, `error`), `policy.apply_incomplete` (an apply that installed its policy and then failed: `installed`, `error`), `policy.apply_finished` (the end of an apply: `revoked`, `revoked_beyond_preview` (runs started while the nodes were asked), `kept`, `already`). The runs an apply revokes are `identity.revoked` with its `decision` |

A node's own records arrive as `node.audit`, each carrying the node's record in its body.
