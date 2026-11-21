---
area: Operations and audit
type: Added
---
- `supervise.hosts: N` in `wicket.yaml` makes wicketd run N supervisor hosts: it starts them,
  hears their heartbeats, and fences one that dies or wedges (a higher epoch in the ledger first,
  then a kill and a fresh host), never for a ledger stall alone. Off by default; the hosts supervise
  no runs yet ([#582](https://github.com/public/wicket/issues/582)).
