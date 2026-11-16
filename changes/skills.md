---
area: Skills
type: Added
---
- wicket's own Claude Code skills, shipped in the repository as a plugin with a marketplace entry:
  `/plugin marketplace add public/wicket`, then `/plugin install wicket@wicket` (how-to: "Use
  wicket's skills"). `wicket-box` is for an agent inside a box (reach and requests, what 403 and
  503 answers mean, memory warnings, `finish` versus `hibernate`, messages and delegation, results,
  and habits that keep work), `wicket-operator` for running and looking after wicket,
  `wicket-manifest` for writing manifests and zones, and `wicket-coordinator` for an agent that
  runs other boxes.
- Every Claude Code agent in a box has `wicket-box` without installing anything: the Claude adapter
  writes it into Claude Code's config directory at each activation, from the copy built into wicket.
  An ACP agent other than Claude Code gets the same guide as `/wicket/state/wicket/AGENTS.md`,
  named in its notice.
- CI checks the plugin: the marketplace and plugin manifests, every skill's frontmatter, and that
  every link in the skills resolves, `#anchors` of links to these docs included
  (`ci/check-plugin.py`).
