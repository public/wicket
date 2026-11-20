---
area: Operations and audit
type: Fixed
---
- Audit retention follow-ups ([#582](https://github.com/public/wicket/issues/582), after #677):
  - **Restores across prunes:** a prune lists only the restores the chain already vouched for, so a
    `state.restored` record forged below an earlier anchor can't become trusted at the next prune.
    A restore above the anchor counts only if it is in the chain.
  - **Settling a resumed prune:** a pass that resumed an earlier prune but can't tell where a sink
    points now gives the freed space back and reads the figures again.
  - **Relative paths refused:** a `jsonl` sink's path must be absolute (or `-`). Processes in
    different directories would otherwise write two files under one cursor.
  - **A busy ledger at start:** a process's audit exporter that finds the ledger busy when it starts
    tries again (1 s, doubling to a minute) instead of leaving export off until the process exits.
