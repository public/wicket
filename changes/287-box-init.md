---
area: Images
type: Changed
---
- A box's start skips node's `docker-entrypoint.sh` (#287). The agent image inherited it from its
  `node` base, so every box ran a shell, and a fork, before `wicket-entry`. The image now has no
  entrypoint, and `node` as its command, so a box started without a command still runs node.
  `wicket-entry` also writes when the sandbox's kernel came up, and the node splits
  `box.entry.init` into `box.entry.runtime` (from Docker's start to the sandbox up) and
  `box.entry.boot` (from the sandbox up to `wicket-entry`). Images built by an older `wicket image`
  keep the old start until they're rebuilt.
