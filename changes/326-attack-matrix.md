---
area: Development
type: Added
---
- An attack matrix in the gVisor smoke job (`ci/attack-matrix.sh`): a program box told to get out
  of its reach, with fresh canaries planted where it must not get to (a secret injected only on an
  allowed echo host, a file outside its volumes and in wicket's data directory, another box's
  exposed port and pending request, the host's unix and abstract sockets and an HTTP listener on
  all its addresses, a per-node service whose reach is wider than the box's). About 190 attempts:
  other hosts, methods and request shapes; IP literals, loopback spellings, cloud metadata and
  names that resolve to internal addresses; path tricks against reach, forbid and prefix grants
  (an echo host shows what the upstream saw); reflected-credential echoes; raw TCP, UDP, ICMP and
  packet sockets; DNS over UDP, TCP, DoH and frames written straight to the forwarder's relay; the
  forwarder's ports and sockets; the gateway's tools (self-decisions, renewals, spawns, links,
  connects, standing and prefix asks, messages asking for grants); a service's link it may not open
  and a run claiming the service's zone; files outside its volumes and symlinks left where the host
  reads. Each outcome is compared with `ci/attack/expected.tsv`; from outside, no canary is in
  anything the box got back or left behind, the listeners saw nothing, the audit allowed nothing
  its zone doesn't, nothing else was granted or approved, and `wicket doctor --invariants` holds.
  Any attempt that gets through fails the job, named
  ([#215](https://github.com/public/wicket/issues/215), [#326](https://github.com/public/wicket/issues/326)).
