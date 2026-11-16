---
area: Boxes and the egress path
type: Added
---
- Windowed egress caps ([#368](https://github.com/public/wicket/issues/368)):
  `zone.limits.egress: { window, requests, bytes }` caps the requests and bytes a zone's box sends
  through the egress proxy over a sliding window of up to 24 h. The count is per agent across all
  its activations, so a new session or a wake resets nothing. The control host keeps each window in
  the ledger and leases the node slices of it, and the node holds the box to its slice even offline
  (fail closed) and journals its count. A request that doesn't fit gets 429 `egress-cap`. A capped
  zone splices nothing, and a spawned zone's caps are never looser than its parent's. The node
  protocol is now 12 (`EgressSlice`): a box with caps starts only on nodes at 12 or later, and a
  control host at 12 no longer talks to nodes at 10.
