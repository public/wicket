---
area: Boxes and the egress path
type: Fixed
---
- A node now records `box.output.ended_early` when Docker ends a box's output stream while the box
  still runs, since what the box writes after that isn't read
  ([#824](https://github.com/public/wicket/issues/824)). The acceptance job's flood checks read
  the host's log while the box is alive, print their runs' ids, and on failure show those runs'
  node log lines and audit records.
