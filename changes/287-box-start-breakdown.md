---
area: Boxes and the egress path
type: Changed
---
- Box starts, measured and cut ([#287](https://github.com/public/wicket/issues/287)). The node's
  feed no longer rewrites `statements.json` with the same bytes on every delta. That cost two
  fsyncs per delta and was most of a start's wait for the node, so `node.ready` drops from 32 to
  22 ms and a start from 105 to 94 ms in a gVisor box. A node lists wicket's boxes through Docker's
  Engine API instead of `docker ps`, so a node with the socket and no CLI adopts its boxes after a
  restart. New spans `quotas` and `authority.record` time what were gaps. `experiments/box-start`
  has a stand-in Docker Engine API (`fake-engine.py`) to time wicket's own part without Docker, and
  `measure.sh` runs with jq 1.7. The breakdown, and the step-3 choice (keep Docker for cold starts;
  restores are the step worth taking), are in docs/explanation/performance.md.
