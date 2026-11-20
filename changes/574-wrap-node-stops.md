---
area: Operations and audit
type: Fixed
---
- `wicket wrap` exits 1, not the box's 137, when the box's node stopped it (its authority expired,
  the timeout backstop, its control host stopped it) or the kernel killed it for memory: the code
  is the stop's, not the wrapped program's
  ([#574](https://github.com/public/wicket/issues/574)). A program that crashes or that a signal
  from elsewhere ends still passes its own code on.
