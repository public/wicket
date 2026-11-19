---
area: Operations and audit
type: Added
---
- Audit retention on the host ([#582](https://github.com/public/wicket/issues/582)): once the
  audit table passes `host_gb` in the sinks file (2 GB by default), reconcile prunes its oldest
  records, but only with a sink and the state store configured. It never prunes past a checkpoint
  a sink acknowledged that every sink has exported past.
  - The checkpoint becomes the chain's anchor. `wicket audit --verify` checks the chain from it,
    and its signature, and `--verify --against` counts older exported records as pruned.
  - New ledgers use `auto_vacuum=incremental`, and a prune gives the space back. An existing
    ledger is switched with one `VACUUM` the first time a prune is due.
  - Sinks keep everything: a sink's `retention` is `forever`.
  - `wicket top` and the console show the table against its limit, and the anchor.
  - Ledger schema 32 adds `audit_checkpoints` and `audit_anchor`.
  [Retention on the host](../docs/reference/audit.md#retention-on-the-host).
