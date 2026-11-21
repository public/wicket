---
area: Updates
type: Fixed
---
- During a self update, only a supervisor whose binary is read and differs from the new build's is
  stopped ([#844](https://github.com/public/wicket/issues/844)). Before, one whose `/proc/<pid>/exe`
  couldn't be read was taken for another build and stopped. That could stop a supervisor of this
  very build: one that had just exited (a zombie), or one whose binary a failed read hid. Such a
  supervisor is now left running and said so in the update's output, for the health gate to judge.
  A zombie is skipped.
