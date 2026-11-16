---
area: Identity, spawn and links
type: Changed
---
- The box's node answers MCP's handshake itself
  ([#257](https://github.com/public/wicket/issues/257) slice 4a). `initialize` (with wicket's
  instructions, now also while the control host is unreachable), `ping`, `tools/list` and
  notifications are no longer relayed to the control host. The control host's duplicate `whoami`
  and `request_access` are gone (the node always answered them), along with the code for peers
  before protocol 5. No protocol change.
