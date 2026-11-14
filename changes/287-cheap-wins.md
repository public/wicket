---
area: Nodes
type: Changed
---
- Box starts are faster, in three places #287's breakdown measured
  ([#287](https://github.com/public/wicket/issues/287)):
  - Opening a node's feed before each box's token is minted (`token.keys`, ~92 ms) no longer
    verifies and compiles every box record its delta log ever held: only the records still held at
    its end are, as the rest are replaced or dropped later in the log. The state reached is the
    same. In a release build, a 1 MiB log of 250 runs opens in ~37 ms instead of ~330 ms.
  - A node reuses what an image reference is between box starts (`docker.image_inspect`, ~74 ms per
    start) while it follows Docker's image events, and forgets it all at any image event (a pull,
    tag, untag, load or delete) or when it stops following them. The pin check (#192) still runs
    against each identity, cached or not, and the box still starts by the image's id. The span is
    `docker.image_cached` when the cache answers.
  - The run's proxies and the node's per-box proxies bind their sockets before they are served,
    instead of being polled for every 20 ms (`proxies.sockets`, ~21 ms on each side). A socket
    that can't be bound now fails the start and names the socket. Before, the start waited up to a
    second for it and then went on without it.
