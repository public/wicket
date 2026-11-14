---
area: Nodes
type: Added
---
- A box start records where its time goes: the manifest and its checks, the run CA, the identity,
  the policy and zone compile, the run's proxies and their sockets, the box's token, the feed, the
  node's connection and budget slice, the node round trip (`BoxStart` to `Started`), and on the node
  each Docker call, its own proxies and layout, and (with `WICKET_TIMINGS=1`) runsc's part of
  `docker run`, then the box's first output and first model request. The spans are kept in the
  run's record (`ctl/run.json`) and printed with `WICKET_TIMINGS=1`;
  `experiments/box-start/measure.sh` takes medians over N starts
  ([#287](https://github.com/public/wicket/issues/287)).
