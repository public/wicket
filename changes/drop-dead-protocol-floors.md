---
area: Nodes
type: Changed
---
- The code for control hosts and nodes older than protocol 11 is gone: with protocol 12 and a skew
  of one, no such peer can connect, so its checks (edge decisions, image pins, delivery and pulls,
  budget slices, credential swaps, forwarded egress) could never run. Nothing changes for any peer
  that can connect. What each protocol version added is now listed in full in
  [the protocol reference](../docs/reference/protocol.md#versions-and-skew) (#253).
