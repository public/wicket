---
area: Operations and audit
type: Changed
---
- A run's supervisor reads the ledger only when what it depends on changed
  ([#582](https://github.com/public/wicket/issues/582), step 2). Its grant sync (every 250 ms), its
  revocation and node CA checks (every second), and its turn cancel and mode change checks (every
  second) each look at the ledger's change counters first. Each does its work when its topic moved,
  and at least every 10 s regardless. An idle run asks SQLite one cheap question per tick instead of
  running its queries.
