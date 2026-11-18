---
area: Updates
type: Fixed
---
- wicketd no longer hangs when `wicket self update` moves it to the new build while it has
  commands running. It had been refusing every command ("wicketd is moving to a new build") until
  it was restarted by hand. An update's "runs: N handed over, M adopted" now counts the runs that
  really have a new supervisor, including ones the reconciler service adopted first, and it no
  longer says wicketd waits for running commands to end
  ([#487](https://github.com/public/wicket/issues/487)).
