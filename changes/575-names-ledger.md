---
area: Identity, spawn and links
type: Added
---
- The ledger keeps names for boxes ([#575](https://github.com/public/wicket/issues/575), schema
  28):
  - the internal and public names boxes hold, each with its owner, port and lifetime;
  - the host ports public names are published on, one per node and port, quarantined after release;
  - the DNS records this installation created, which is the ledger's half of owning a record.

  Internal names are unique per zone and limited per workload. A public name waits for a human's
  approval, bound to what was shown. A standing name passes from one run of its workload to the
  next. Nothing asks for names yet: the gateway tool and the resolver come next.
