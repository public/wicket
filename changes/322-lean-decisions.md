---
area: Development
type: Added
---
- The Lean spec now covers wicket-core's pure decisions
  ([#322](https://github.com/public/wicket/issues/322)). A new file, `Wicket/Decisions.lean`,
  covers:
  - the SSRF guard (`is_public_ip`);
  - a grant's end in a node's token (#342);
  - agents' grant terms;
  - when a refusal is a grant request;
  - counted uses;
  - the money check;
  - the spawn ceiling.

  Each comes with its theorems, and the oracle checks wicket-core against these definitions on
  generated cases. Each Kani harness names its Lean theorem. In CI, `ci/lean.sh` shows Lean's
  errors and the oracle's divergences as annotations on the run.
