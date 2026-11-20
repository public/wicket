---
area: Boxes and the egress path
type: Fixed
---
- A node that goes back to a protocol below 19 can no longer be sent a zone that uses
  `decode_slash` ([#691](https://github.com/public/wicket/issues/691)). The control host now
  judges a node by the protocol its live connections talk, from any process on the host, and
  forgets a node's noted protocol when a connection to it drops or is refused. It checks again
  just before the record goes in the node's feed. The local node's protocol is noted whenever its
  running `serve` is this build, not only when this process started it. When it isn't, the refusal
  no longer tells you to update the node.
