---
area: Operations and audit
type: Added
---
- wicket's core claim, that authority only narrows, is proved in Lean 4 (`verification/lean`, no
  `sorry`, no Mathlib): an agent's grant (`grant::within_authority`) permits only what the agent's
  own zone allows by reach, for a strict descendant, before the agent's authority ends; a zone
  `subset::check` admits for a spawn reaches nothing its parent can't, forbids all the parent
  forbids, and has no right, limit or credential its parent lacks; narrowing composes to
  grandchildren; forbid rules always win; the glob matcher agrees with the spec's language of paths
  (`*` within a segment, `**` across); and a canonical path can't escape a rule by an escape or a
  dot segment. The spec also runs as an oracle: `ci/lean.sh` (the `lean` CI suite) installs the
  pinned toolchain by checksum and checks wicket-core's decisions, `subset::check`,
  `reach_within`, `host_matches` and `canonical_path` against it on the authz fixtures and about
  33,000 generated cases ([#322](https://github.com/public/wicket/issues/322)).
