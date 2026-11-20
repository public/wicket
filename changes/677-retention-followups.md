---
area: Operations and audit
type: Changed
---
- **Breaking (audit sinks): a `jsonl` sink with a relative path is no longer fed**
  ([#582](https://github.com/public/wicket/issues/582), after #677). Processes started in different
  directories would write two files under one cursor.
  - The sink is left out with a warning, from each process and `wicket self health`; `wicket self
    update` says it before it switches, and `wicket doctor` counts it as a problem. The file's other
    sinks are fed as before.
  - **Upgrading:** make every `jsonl` sink's `path` in `audit-sinks.yaml` absolute (or `-`), and do
    the same in any recovery kit or copy of the file you keep. A kit from before this change still
    restores, and its relative sinks are left out.
- Audit retention follow-ups (#582, after #677):
  - **A prune vouches only on a chain that holds.** Before it lists the restores it keeps, a prune
    verifies the audit chain from the anchor up to its cut (and past the last prune's record, when
    that is above the cut), and refuses (deleting nothing) if it doesn't hold. A restore forged
    below an earlier anchor, a list edited into a prune's record, or a record rewritten into a
    restore with the next one re-pointed, can't become trusted.
    `--verify --against` believes a prune's list only from a record still in the chain.
  - **Restore reads everything first.** `wicket state restore` loads the sinks file, the issuer key
    and the store's exported records before it replaces the ledger. One that fails to read fails the
    restore with nothing replaced, instead of half-way through.
  - **Settling a resumed prune.** A pass that resumed an earlier prune, but can't tell where a sink
    points now, gives the freed space back and reads the figures again.
  - **A busy ledger at start.** A process's audit exporter that finds the ledger busy when it starts
    tries again, from 1 s doubling to a minute, up to 30 times, each said. Before, it left export off
    until the process exited. An issuer key that fails to read on a later try is said too.
