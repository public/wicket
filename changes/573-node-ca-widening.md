---
area: Remote nodes and capacity
type: Added
---
- A node's CA can be widened at runtime to the hosts its boxes need
  ([#573](https://github.com/public/wicket/issues/573)). With `wicket node set <node> --ca-hosts auto`
  (or a list of hosts it may grow to), a box whose reach, injections, credential swaps, model host
  or grants need an inspected host outside the node CA's name constraints gets it. Before the box
  starts, the control host renews the CA over the run's channel for the operator's hosts plus what
  its live boxes want, and audits `node.ca_widened`. Every renewal signs that, so hosts no box wants
  any more go at the next one. Only names a node CA may be constrained to are ever wanted (never
  `*`, an IP or a single label). The operator's hosts always stay, and wants share the room to 64
  entries a run at a time (what doesn't fit is audited). A CA that can't be widened is renewed for
  the operator's hosts instead of lapsing. Revoking or re-enrolling a node clears its policy. The
  default is `fixed`, as before: then a box start says which hosts the CA would need. Ledger schema
  20 (an expand step).
- A box's `request_access` for an https host its node's CA doesn't cover is asked for when the
  node's policy lets the CA be widened to it (`auto`, or a list that includes it): the approval's
  grant widens the CA. Under `fixed`, or a list that leaves the host out, the node still answers
  "not requested" (#571), and now names `wicket node set <node> --ca-hosts` as the fix. The node
  has the policy as it was when the box started.
