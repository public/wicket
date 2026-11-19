---
area: Development
type: Added
---
- The weekly mutation run (`ci/mutants.sh`) now covers the decisions moved into pure wicket-core
  functions: `quota.rs` (the money check, counted uses, a token's grant end, spawn limits) and
  `escalation.rs`, as a new `decisions` set. The moved functions in `op.rs` and `authority.rs` are
  in the existing sets. The first run found four test gaps, each now killed by a unit test: any one
  of reach or risk makes a check escalatable, the spawn ceiling's process and time caps hold at
  their values, and a wicket host or a reserved method alone is refused to agents
  ([#326](https://github.com/public/wicket/issues/326)).
