---
area: Remote nodes and capacity
type: Changed
---
- One spend check, a grant (#256). The installation's limits (`placement.yaml`'s
  `max_hourly_usd` and `max_total_usd`) are one tenant money quota grant, and every capacity lease,
  every node `wicket node create` makes and every warm node claimed from the pool reserves its money
  as money quota grants against it, in one transaction. Leases and created nodes now share that one
  budget. The placer's separate money envelope is gone, and so are `wicket node create`'s
  `--max-hourly` and `--max-total` flags: it reads the limits from `placement.yaml`, which it now
  needs. The limits themselves are unchanged ([#256](https://github.com/public/wicket/issues/256)).
