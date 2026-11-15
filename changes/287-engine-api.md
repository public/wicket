---
area: Nodes
type: Changed
---
- A node starts, watches and removes its boxes through Docker's Engine API, over the daemon's unix
  socket, instead of a `docker` CLI process for every call: create and start, inspect, wait, logs,
  kill, pause, rm, image inspect, and the image events that keep its image cache current
  ([#287](https://github.com/public/wicket/issues/287)). It does so when `WICKET_DOCKER` is plain
  `docker` (or `docker -H unix:///path`) and the socket can be opened: `-H`, else `DOCKER_HOST`,
  else `/var/run/docker.sock`. Anything else (`sudo -n docker`, a TCP or ssh host, a Docker context,
  a socket this user may not open) still runs the command for each call. `wicket node serve` says
  which it uses. The spans keep their names (`docker.run`, `docker.inspect`, …).
- A run's timings now also cover the box's own start and its end. The start is timed from when its
  runtime started it to when its program was started (`box.entry.init`, `.addrs`, `.setup`, `.fwd`,
  `.exec`). The image's `wicket-entry` writes these, so rebuild the image with `wicket image`. The
  end is timed from the program's exit (`box.finished`) through the node's teardown
  (`node.teardown.wait`, `.output`, `.inspect`, `.rm`, `.release`) to the control host's
  (`teardown.output`, `teardown.fetch`, `teardown`). The box's spans are placed by its node's clock.
