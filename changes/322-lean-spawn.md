---
area: Development
type: Added
---
- The Lean spec (`verification/lean`) covers three more parts of narrowing:
  - per-zone model allowlists: a spawned zone calls no model its parent may not;
  - `accept_from`'s principal entries: a spawned zone hears from no one its parent doesn't;
  - the spawn a node decides: an appended spawn block never widens its parent's token.

  The oracle now also checks wicket-core's model and `accept_from` decisions, and wicket-authz's
  token decisions on minted chains of blocks, against the spec
  ([#322](https://github.com/public/wicket/issues/322)).
