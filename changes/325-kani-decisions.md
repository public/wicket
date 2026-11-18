---
area: Operations and audit
type: Added
---
- Three more Kani harness groups check the new decision arithmetic. Each decision now goes
  through a pure function in `wicket-core`, which the ledger and the control host call
  ([#325](https://github.com/public/wicket/issues/325)):
  - **The money check** (`quota::money_fits`): a reservation is accepted exactly when the hourly
    and total sums stay within their limits, for every `i64`. The sums are exact, so one that
    would overflow is refused, not wrapped.
  - **Agents' grant rules** (`authority::agent_term_refusal`): the default `agents:` rules refuse
    every grant `agent_terms` refused before the rules existed, and each rule lifts exactly its
    own refusal. Agents' renewals use the same function.
  - **A counted grant's uses** (`quota::take_use`, in `may_use`): a use takes exactly one, never
    takes a count below zero, and is never accepted at zero.
