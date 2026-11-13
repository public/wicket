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
  egress requests allowed by a human's grant. Waiting is a shared flush: when 16 threads append
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
sinks:
  # JSON lines, for journald, Vector or Fluent Bit. path "-" means stdout; only
  # `wicket audit export` writes to stdout.
  - name: local-file
    type: jsonl
    path: /var/log/wicket/audit.jsonl
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

## Checkpoints and `--verify --against`

Each record's hash covers every field it stores: `seq`, `ts`, `tenant`, `run`, `kind`, `body` and the
previous record's hash. These are v2 hashes and start with `v2:`. Ledgers written by older versions
hold v1 hashes (64 hex digits), which cover only `prev`, `kind` and `body`. They still verify, and
new records continue the chain as v2. A v1 record after a v2 one fails, so a record can't be
downgraded to hide an edit. `wicket audit --verify` reports how many v1 records a ledger holds.

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
  equals the local record's. This catches a v1 record that was moved to another run or tenant, or
  given another time, which its hash doesn't cover.

A rewritten chain fails this check even if it was consistently re-chained, and so does a truncated
one. The files can be wicket's JSON lines, or a Collector `file` exporter's output (OTLP JSON, one
batch per line), from which the log bodies are read. `--issuer-jwk` checks signatures against a
public key you keep elsewhere (as `wicket identity issuer` prints it) rather than the local key file.

## Record kinds

Each record's `kind` says what it records. The kinds wicket 0.0.1 writes, by area (`grep` the code
for a kind to see its body):

| area | kinds |
|---|---|
| requests | `op` (an egress or model decision), `decision` (an approve or deny), `grant.revoked`, `daemon.refused` |
| runs | `run.start`, `run.end`, `run.lost`, `run.attach`, `run.console_start`, `run.output`, `run.remote_session`, `run.exit_cause`, `box.output`, `box.output.gap`, `box.reaped`, `box.exit_cause`, `box.memory_pressure` |
| agents | `identity.issued`, `identity.rotated`, `identity.revoked`, `message`, `spawn.beyond_parent`, `agent.hibernate`, `agent.wake`, `agent.wake_refused` |
| links | `link.expose`, `link.open`, `link.close`, `link.cut` |
| operators | `operator.signed_in`, `operator.lockout`, `operator.passkey_added`, `operator.enrol_link_issued`, `operator.enrol_link_used`, `operator.reset`, `operator.sessions_revoked`, `operator.message` |
| nodes | `node.token`, `node.enrolled`, `node.ca_renewed`, `node.revoked`, `node.audit`, `node.audit.restart`, `node.ask_queued`, `node.authority_expired`, `node.secret_fetch`, `node.secret_fetched`, `node.secret_unavailable`, `feed.refused` |
| placement | `lease.requested`, `lease.released`, `placement.node_created`, `placement.node_released`, `reconcile.<what>` (one per change a pass makes, such as `reconcile.destroyed` and `reconcile.run_adopted`) |
| updates | `self.staged`, `self.snapshot`, `self.switched`, `self.health`, `self.committed`, `self.rolled_back`, `self.update_refused`, `self.pruned`, `self.key_trusted` |
| state and keys | `state.kit`, `state.restored`, `keys.roots_offline`, `keys.roots_online`, `keys.certified` |

A node's own records arrive as `node.audit`, each carrying the node's record in its body.
