---
area: Updates
type: Removed
---
- A build upgrades a ledger from schema 17 on. A ledger older than that is refused with a message
  naming a build that still upgrades it (main at `a3135ea`): update through that build first. The
  upgrade steps for older ledgers are gone (#253).
