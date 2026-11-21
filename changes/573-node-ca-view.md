---
area: Remote nodes and capacity
type: Added
---
- A node's CA can be seen without reading the ledger (#573): `wicket node ca <node>` (`--json`) and the
  console's `GET /api/nodes/<node>/ca` show the hosts its active CA is constrained to and those it was
  enrolled with, how it may be widened at runtime, what live runs want of it and whether its CA covers
  each, what the next renewal signs, and its last widenings. `wicket node list` shows the active CA's
  hosts rather than only the enrolled ones, with the node's CA policy and the wants its CA doesn't cover
  yet; `--json` adds `ca.hosts`, `ca_policy` and `ca_wants`
  ([#573](https://github.com/public/wicket/issues/573)).
