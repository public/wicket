---
area: Development
type: Added
---
- What a widened node CA is signed for (#573) is in the Lean spec (`Wicket/NodeCa.lean`): every
  name the operator's hosts permit stays permitted, whatever runs want and whatever the cap; the
  CA is signed only for the operator's hosts and the wants, so a remote node's CA never permits
  every name; and merging entries drops no name. Widening moved into wicket-core
  (`splice::widen`, unchanged), and the oracle checks it, `subtree_permits` and coverage against
  the spec on generated cases ([#322](https://github.com/public/wicket/issues/322)).
