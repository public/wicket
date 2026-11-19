---
area: Remote nodes and capacity
type: Changed
---
- Placement reserves the room it chooses
  ([#579](https://github.com/public/wicket/issues/579), step 2). Choosing a node for a box and
  recording what the box asks for there are one ledger transaction, so two starts reading the same
  node reports can't both take its last room. A reservation counts until the node reports the box,
  or until its start fails or its run ends (2 minutes at most unconfirmed). `wicket run --node` and
  a lease's node pass the same filters (labels, taints, room, CA) when the node's last report says
  its room, and the start is refused with the reasons if a label, taint or CA keeps it off (for room,
  the node's own admission decides). Ledger
  schema 24 (`placements`; an expand step, after #576's 23).
