---
area: Operations and audit
type: Changed
---
- What a box is told uses the glossary's nouns too: a refusal's status line starts
  `Blocked by wicket box:` (`needs approval`, `needs approval (queued offline)`, `denied`,
  `control host unreachable`, `never allowed`, …), the box notice says "wicket box", and wicket's
  tool answers say an operator decides (`needs approval: request r-…` from `spawn` and `link`,
  `needs an operator` from `request_update`) ([#349](https://github.com/public/wicket/issues/349)).
- `spawn`'s `ask_human` is `escalate`, and `principals` lists operators as `kind: operator`, with no
  aliases. A long-lived agent's holder has a claim on it, not a lease: the ledger's schema 7 (an
  expand step) adds `agents.claim_until`, copied from `lease_until`, which is still written for
  older builds until a contract step drops it ([#349](https://github.com/public/wicket/issues/349)).
- The glossary ([concepts](../docs/explanation/concepts.md#the-nouns)) defines delegation, brief,
  report, handle, receipt, quota grant, budget slice, session page and device; design.md's
  "7. Boxes", prior-art and why-gvisor say box, and `ci/check-terms.sh` checks them for "sandbox"
  ([#349](https://github.com/public/wicket/issues/349)).
