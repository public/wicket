---
area: Identity, spawn and links
type: Added
---
- A box can give one of its ports a stable internal name with the new `request_name` tool
  ([#575](https://github.com/public/wicket/issues/575)): `<name>.<zone>.wicket.internal`. Other
  boxes of its tenant reach it with `connect(name: "<name>.<zone>")`, decided as `connect` decides
  (its parent, boxes its zone's `accept_from` lists, or an operator's approval of exactly that link),
  and then resolve the name in their own box.
  - The name grants nothing, so it needs no approval. It must be one DNS label not held by another
    agent in the zone, an agent holds at most 3 names, and a name ends with its run.
  - Public names aren't available yet.
  - Audited as `name.registered`.
- **Protocol 19:** the control channel goes from 17 to 19, so wicket talks to peers at 17, 18 and 19
  (it talked to 15, 16 and 17). A node at 15 or 16 must be updated with its control host. A node at
  19 sends `request_name` only to a control host at 19, and otherwise tells the box its control host
  must be updated.
