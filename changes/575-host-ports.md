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
    own copy of the feed: it closes a port within 2 s of its feed saying the name is revoked, and
    when the box's authority or the name's end passes, the last also while the control host is
    out of reach (a node that can't hear of a revoke keeps the port until one of those ends). It copies each connection's bytes into the
    box's port once its first byte has come (layer 4 only: no TLS, no HTTP, no routing by name).
    Per name: at most 32 at once, 8 per peer (an IPv6 /64 counts as one), 16 still silent (6 per
    peer); per node, 256 at once. A relay ends after 5 minutes idle, 30 s after the peer closes its
    side, or after an hour, and the box's `wicket-fwd` ends by itself the same way. Each connection
    is recorded when it starts and when it ends (`name.conn`), aggregated under load.
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
    The same holds for a node going back to such a build, by hand or after a failed health gate.
    `wicket node feed-checkpoint <node>` writes a checkpoint now, so a feed whose records no longer
    hold ports can be opened by such a build at once.
  - While an update from a build before protocol 21 runs its health gate, the control host's or
    a node's, no box's record (on that node) gets ports, so a failed gate can still roll back.
  - `names.public.ports` can't hold a port wicket itself listens on (the console's `--listen`, and
    webhook intake's, read from their settings; 8787 and 8443 by default), and a
    public name gets records only on a node at protocol 21 whose `publish.json` holds its port.
