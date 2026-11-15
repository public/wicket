---
area: Model budgets
type: Fixed
---
- A node whose `wicket node serve` crashed or restarted mid-call could spend past a run's model
  budget. Its spend file was written once a second, and a call in flight wasn't counted, though the
  provider had billed it. The restarted node counted from less than was billed, and its budget slice
  then allowed the difference again. A node now writes the spend before each model call goes
  upstream, with calls in flight charged their whole reservation, and writes the file whole or not
  at all. Found by the new deterministic simulation
  ([#324](https://github.com/public/wicket/issues/324)).
