---
area: Remote nodes and capacity
type: Fixed
---
- A box started on a node right after a box of the same size exits there is admitted. The exited
  box's memory limit stopped counting as committed only once its output had been read and its exit
  recorded, seconds after its container ended, so admission control
  ([#377](https://github.com/public/wicket/issues/377)) refused the new box for lack of room. It now
  stops counting the moment Docker says the container ended.
