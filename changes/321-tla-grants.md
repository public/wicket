---
area: Development
type: Added
---
- A TLA+ model of grants and budget slices on nodes, checked with TLC
  ([#321](https://github.com/public/wicket/issues/321), model 1). It is in
  `verification/tla/GrantsOnNodes.tla`, and its README maps each action to the code.
  - Its actors are the control host, a node that may be cut off or crash, the box, and peers.
  - It checks that no request is allowed without a live grant, that model spend stays within the
    run's budget, and that a peer message never grants. It also checks that a reconnecting node
    converges and that an unused slice returns.
  - A switch selects today's two stacks, the state after slice 3 of
    [#257](https://github.com/public/wicket/issues/257), or its end state.
  - It decides the grant-expiry boundary: a grant is live while `now < expires_at`, in
    milliseconds. Today a node honours a grant up to 999 ms longer.
  - Variants that must fail keep today's spend and boundary bugs visible: spend not journalled
    before a call goes upstream (#324), the control host's own calls merged into the node's
    count, slices not held against the budget, an edge child's carve-out overwritten by the next
    slice, and no slice before the first `BudgetSlice`.
- `ci/tla.sh` runs every configuration in about 5 minutes. It uses a Temurin 21 JRE and
  `tla2tools.jar`, both pinned by sha256. CI runs it as the `tla` suite when the models or the
  node code they model change.
