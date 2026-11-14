---
area: Placement
type: Fixed
---
- `wicket place create` on an installed host asks for the spend on the caller's terminal (through wicketd it
  used to refuse every time: "no terminal to ask on"), and refuses an ssh key the `wicket` user can't read
  before it creates anything. The how-to keeps the placement key under `/var/lib/wicket/ssh/`.
- `wicket image` on an installed version (a control host, or a node after `wicket node install`) builds
  `wicket/claude-code:<build id>` by default, the image runs placed there ask for; it used to build
  `:poc`, so the first run on a new node failed with "image … not found on node".
