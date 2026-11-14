---
area: Updates
type: Added
---
- Each build carries its own systemd units: `wicket self update` refuses to switch an installed host
  to a build whose units differ from the installed ones until root runs that build's `wicket self
  apply-units` (installs them, reloads systemd, restarts nothing); `self follow` waits for it, and a
  rollback only warns ([#165](https://github.com/public/wicket/issues/165)).
