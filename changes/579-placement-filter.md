---
area: Remote nodes and capacity
type: Added
---
- Node labels and taints, and a manifest's `placement:` (`node_selector`, `tolerations`)
  ([#579](https://github.com/public/wicket/issues/579)). `wicket node set <node> --label gpu=a100
  --taint dedicated=ci` records them (audited `node.labels`; `key-` removes one). A woken agent now
  goes only on a node that has its selector's labels, carries no taint it doesn't tolerate, has
  room for its limits, and whose CA covers its inspected hosts or may be widened to them (#573),
  bin-packed as before. The filter and score are one pure function, `wicket-placement::schedule`,
  whose refusals say every reason a node was out. Ledger schema 23 (`node_labels`, `node_taints`;
  an expand step, after 22).
