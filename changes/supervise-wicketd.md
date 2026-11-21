---
area: Operations and audit
type: Added
---
- Experimental, and off by default (`supervise.hosts: 0`): `supervise.hosts: N` in `wicket.yaml`
  makes wicketd run N supervisor hosts. It starts them, hears their heartbeats, and fences one that
  dies or wedges (recorded, a higher epoch in the ledger, then a kill, and a fresh host once the old
  one is gone), never for a ledger stall alone. Hosts survive `systemctl stop wicketd` and are
  adopted by the next one. They supervise no runs yet
  ([#582](https://github.com/public/wicket/issues/582)).
