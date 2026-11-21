---
area: Updates
type: Fixed
---
- During a self update, only a supervisor whose binary is read and differs from the new build's is
  stopped ([#844](https://github.com/public/wicket/issues/844)). Before, one whose `/proc/<pid>/exe`
  couldn't be read was taken for another build and stopped. That could stop a supervisor of this
  very build: one that had just exited (a zombie), or one whose binary a failed read hid. Such a
  supervisor is now left running, said so in the update's output and recorded as
  `self.supervisor_unknown`, for the health gate to judge. A zombie is skipped. If the new build's
  own binary can't be read, the handover fails, as `self.handover_failed`, instead of telling nothing
  apart.
