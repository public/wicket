---
area: Identity, spawn and links
type: Added
---
- Public names are published on their node's host ports
  ([#575](https://github.com/public/wicket/issues/575), step 4c):
  - The run's supervisor gives each live public name its box holds, on a node that may publish it,
    a host port from `names.public.ports`. A box that moves keeps its port where it is free. The
    ports go in the box's record in the node's feed, so the names reconciler's SRV records name
    them.
  - The node listens on each port while the box holds authority there and the name lasts, from its
    own copy of the feed: it closes a port at once when the name is revoked or the box's authority
    ends, also while the control host is out of reach. It copies each connection's bytes into the
    box's port, at most 64 at once per name: layer 4 only, no TLS, no HTTP, no routing by name.
    Audited on the node as `name.port.opened`, `name.port.closed`, `name.port.failed`,
    `name.conn` and `name.conn.refused`.
  - A node publishes only the ports in its `publish.json`, which `wicket node install` writes for
    a node with the `names.public.nodes` labels. `deploy/vultr/node-setup.sh` admits the range in
    the firewall when given `WICKET_PUBLISH_PORTS`.
  - Protocol 21. **Nodes below 19 must be updated before the control host**: `wicket self update`
    refuses to switch the control host while a node it knows of is below the window, and a node
    it can't talk to is told to update first.
  - A public name without a host port on its node now waits, instead of getting A and AAAA records
    only (a change from #742).
  - A control host can't go back to a build before protocol 21 while a node's feed holds a box
    record with host ports (that build couldn't open the feed): `wicket self rollback` refuses,
    saying how to clear it, and a failed update's automatic rollback refuses too, keeping the new
    build and saying so loudly (`self.rollback_refused`).
