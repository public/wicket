---
area: Updates
type: Fixed
---
- Runs outlive `wicketd`. `wicket self update` moves the daemon to the new build at once instead of
  waiting for every command running through it to end, which a long-lived run never did. It hands
  its running commands to the new build, and their callers stay connected. Restarting `wicketd`
  (`deploy/install.sh`, `systemctl restart wicketd`) no longer ends the runs started through it:
  their boxes and supervisors go on, and only their callers' connections end (`wicket session
  <run>` opens one again)
  ([#455](https://github.com/public/wicket/issues/455)).
