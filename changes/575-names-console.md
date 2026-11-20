---
area: Identity, spawn and links
type: Added
---
- The console's server side for the Names card ([#575](https://github.com/public/wicket/issues/575),
  step 4d): `GET /api/names`, `GET /api/names/<id>` and the dashboard's `names` list each name of the
  tenant with its state and why (pending, live, waiting, taken in the zone, out of sync, lapsed),
  full name, owner, target (node, its public addresses, host port, box port) and lifetime, with the
  agent's words in fields of their own; one name adds its records, the last plan's entries for it and
  its last connections. Passkey-signed actions approve (bound to the full name, the node and the
  effect, recomputed when applied), deny, renew and revoke names, and set a node's public addresses
  (operator kind `node`, at R4). `wicket names list --json`, `wicket names show --json` and `wicket
  names renew` are new. An approval, a denial, a renewal, a revocation and an address change are now
  recorded first, in the same write: one that can't be recorded isn't made (an approval used to be
  made, then undone). `wicket node set --public-ipv4/--public-ipv6` needs kind `node` too, and a
  refused address change no longer names the node (perhaps another tenant's) that has the address.
