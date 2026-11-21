---
area: Approvals and the console
type: Added
---
- Two more console views on the host ([#713](https://github.com/public/wicket/issues/713)):
  `wicket node fences` lists the runs held on lost servers, as the console's card does, with the
  command that releases each. `wicket policy show --json` prints the console's policy view,
  including every kept version's Cedar and when and by whom it was applied.
