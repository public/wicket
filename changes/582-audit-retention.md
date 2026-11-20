---
area: Operations and audit
type: Added
---
- Audit retention on the host ([#582](https://github.com/public/wicket/issues/582)): once the
  audit table passes `host_gb` in the sinks file (2 GB by default), reconcile prunes its oldest
  records.
  - **When:** only with a durable sink (a `store` sink, or one marked `durable: true`) and the
    state store streaming the ledger.
  - **How far:** only back to a checkpoint a durable sink acknowledged, which every durable sink
    has exported past and the stream has synced. Retention asks the exporter for one at the cut,
    and deletes in short chunks.
  - **What stays:** the host keeps the records it reads itself (Remote Control sessions,
    restores).
  - **Verifying:** the checkpoint becomes the chain's anchor. `wicket audit --verify`, `doctor`,
    `self health` and restores check the chain from it, and its signature. A prune is audited
    (`audit.pruned`) and raises the ledger's schema floor to 32.
  - **Space:** new ledgers give the space back. For an existing ledger, run
    `wicket audit compact` once, with the services stopped.
  - **Sinks:** a sink's cursor starts again if its target changes, and sinks keep everything
    (`retention: forever`).
  - **Shown:** `wicket top` and the console show the table against its limit, and the anchor.
  - **Schema:** ledger schema 32.
  [Retention on the host](../docs/reference/audit.md#retention-on-the-host).
