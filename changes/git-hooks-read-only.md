---
area: Boxes and the egress path
type: Changed
---
- An in-place workspace's `.git/hooks` and `.git/config` are mounted read-only in the box, and a
  workspace fetched back from another node keeps the host's copies of them, so a box can't leave a
  hook or a `core.fsmonitor` that the operator's git then runs on the host. In the box, git commands
  that write `.git/config` (`git push -u`, `git remote add`, `git config`) now fail; a box that
  replaces the repository's `.git` directory isn't synced back
  ([#366](https://github.com/public/wicket/issues/366)).
