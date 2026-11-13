# Export audit

Stream the audit log off the control host, with signed checkpoints, and check the ledger against
what was exported. [Audit](../reference/audit.md) has the record and checkpoint formats, delivery
rules and every sinks-file field. Do this: the hash chain shows tampering only to someone who
trusts the host, and an exported copy with signed checkpoints, somewhere the host can't change it,
catches a rewritten or truncated chain.

## 1. Write the sinks file

`<data dir>/audit-sinks.yaml` (`/var/lib/wicket/audit-sinks.yaml` installed,
`~/.local/share/wicket/audit-sinks.yaml` in development mode), or the path in `$WICKET_AUDIT_SINKS`:

```yaml
checkpoint_every: 5m
sinks:
  - { name: local-file, type: jsonl, path: /var/log/wicket/audit.jsonl }
  - { name: collector, type: otlp, endpoint: http://127.0.0.1:4318 }
```

A `jsonl` sink suits journald, Vector or Fluent Bit; an `otlp` sink POSTs to an OpenTelemetry
Collector's `<endpoint>/v1/logs`; a `store` sink writes objects to the state store
([state off the host](state-off-host-and-restore.md)). The file must be readable, and a `jsonl`
path writable, by whoever runs wicket: the `wicket` user on an installed host.

## 2. Start exporting

Nothing to start: `wicket serve` and every `wicket run` export when the sinks file exists, each sink
fed by one process at a time. To export without either, or to catch up now:

```sh
wicket audit export            # in the foreground until stopped (the only writer of a path "-" sink)
wicket audit export --once     # one pass; non-zero if a sink failed
wicket audit export --checkpoint
```

## 3. Watch it

```sh
wicket audit export --status   # each sink's position, last checkpoint, who feeds it, last error
```

An OTLP sink that gets a 4xx stops at that record and shows the error here: a record that is never
accepted needs a person, not silence. Records can arrive twice; deduplicate on `seq` where that
matters.

## 4. Put a Collector in front of cloud logging

wicket ships no cloud SDKs: the OpenTelemetry Collector (contrib distribution) does the last hop.
Run it on the control host, listening on localhost only. Configure a **persistent sending queue**:
a Collector acknowledges a request once the record is queued, before it is delivered. Without
persistent storage, a Collector restart loses whatever is still queued, and wicket has already moved
its cursor past it.

Google Cloud Logging:

```yaml
extensions:
  file_storage/queue:
    directory: /var/lib/otelcol/file_storage
    create_directory: true
receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:4318
exporters:
  googlecloud:
    project: my-project
    log:
      default_log_name: wicket-audit
    sending_queue:
      storage: file_storage/queue
  # A local copy of everything, records and checkpoints, for `--verify --against`.
  file/audit:
    path: /var/log/otelcol/wicket-audit.jsonl
    append: true             # the default (false) truncates the file when the Collector starts
service:
  extensions: [file_storage/queue]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [googlecloud, file/audit]
```

`googlecloud` has no `retry_on_failure` key (the Collector refuses to start with one); it retries
through its own client.

CloudWatch Logs: the same receiver and extension, with this exporter.

```yaml
exporters:
  awscloudwatchlogs:
    region: eu-west-2
    log_group_name: wicket-audit
    log_stream_name: control-host
    sending_queue:
      queue_size: 10000
      storage: file_storage/queue
    retry_on_failure:
      max_elapsed_time: 0      # never give up
```

The `awscloudwatchlogs` exporter is alpha, and its README documents only an in-memory queue.
Collector 0.165.0 accepts `storage` on it, but check that on the version you run. Where it isn't
honoured, keep the `file/audit` copy above, or add a second wicket sink that writes JSON lines
your log agent ships.

Both examples pass `otelcol-contrib validate` (0.165.0). An `otlp` receiver with the `file/audit`
exporter was tested end to end:
- every record arrived, along with the checkpoints;
- a stopped Collector lost nothing once it was started again;
- `wicket audit --verify --against` on the file's output caught a consistently re-chained forgery.

The same pattern works for any other Collector logs exporter: Azure Monitor, Splunk HEC, Datadog.

## 5. Verify against the copy

Keep one copy where the control host can't change it (a bucket with S3 Object Lock, or GCS
retention, behind the Collector). Then, from any machine with the ledger:

```sh
wicket audit --verify --against /var/log/otelcol/wicket-audit.jsonl \
    --issuer-jwk issuer.pub.json        # the key as `wicket identity issuer` printed it, kept elsewhere
wicket audit --verify --against store:store       # what a `store` sink wrote to the state store
```

It runs the normal verification, then checks every checkpoint's signature, that the local chain
reaches the newest checkpoint with the same head hashes, and that every exported record equals the
local one. The files can be wicket's JSON lines or a Collector `file` exporter's OTLP JSON output.
