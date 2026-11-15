# Use wicket's skills

wicket ships its own [Claude Code skills](https://code.claude.com/docs/en/skills) in this repository,
as a plugin with a marketplace entry: short, practical instructions that Claude Code loads when the
work calls for them, linking to these docs rather than copying them.

| skill | for |
|---|---|
| `wicket-box` | an agent working inside a box: asking for reach, what 403 and 503 answers mean, memory warnings, `finish` versus `hibernate`, messages and delegation, results, habits that keep work |
| `wicket-operator` | an operator: installing, running manifests, approvals, secrets, nodes and leases, `wicket session`, `wicket doctor`, troubleshooting |
| `wicket-manifest` | writing a manifest or a zone: reach, forbid, inject, limits, escalation, the model route, volumes, agents and programs, checking with `wicket zone` |
| `wicket-coordinator` | an agent that runs other boxes: warm workers or fresh boxes, briefs, collecting and merging work, cleaning up |

They live in [`plugins/wicket/skills/`](../../plugins/wicket/skills/), the plugin's manifest in
[`plugins/wicket/.claude-plugin/plugin.json`](../../plugins/wicket/.claude-plugin/plugin.json), and
the marketplace in [`.claude-plugin/marketplace.json`](../../.claude-plugin/marketplace.json).

## Install them in Claude Code

In a Claude Code session on your own machine (the control host, say):

```text
/plugin marketplace add public/wicket
/plugin install wicket@wicket
```

In a session, `/plugin install` opens the plugin's details, where you choose a scope and install
it. From a shell, `claude plugin marketplace add public/wicket` and `claude plugin install
wicket@wicket` do it at once. Claude Code then uses a skill when a task matches its description,
and you can call one yourself: `/wicket:wicket-operator`, say. `/plugin marketplace update wicket`
takes the newest skills from the repository.

To try a change to the skills before it is merged, add your checkout instead:
`/plugin marketplace add ./path/to/wicket`.

## In a box, without installing anything

Every Claude Code agent wicket runs has `wicket-box` already. The Claude adapter writes it into the
box at each activation as one of Claude Code's own skills, in its config directory
(`/wicket/state/claude/skills/wicket-box/SKILL.md`), from the copy built into wicket, so it always
matches the wicket that runs the box and needs no network. That holds for Claude Code driven by
wicket, through its ACP adapter, in Remote Control sessions and in wrapped ones. The other three
skills are for the operator's own Claude Code and for coordinators, and aren't put into boxes.

An ACP agent other than Claude Code has no skills to load, so it gets the same guide as a plain
Markdown file, `/wicket/state/wicket/AGENTS.md` (the skill without its frontmatter), and a line
in the notice wicket appends to its system prompt naming that file. wicket writes it outside
`/workspace`, so it never shows up in the project the agent works on.

## Check them

`ci/check-plugin.py` checks the marketplace and the plugin's manifest (required fields, names,
that the entry's source is the plugin and its name the plugin's), every skill's frontmatter (on the
first line; only the [Agent Skills](https://agentskills.io) fields, so a skill also loads outside
Claude Code; a name that is its directory's; a description), and every link in the plugin. A link
to a doc must be an absolute GitHub URL of this repository, whose path and `#anchor` it checks
here: an installed plugin is a copy of its own directory, so a relative link into `docs/` would
lead nowhere. CI runs it with the other documentation checks, and so does `ci/gates.sh`. With
Claude Code installed, `claude plugin validate .` checks the same files Claude Code's own way.

Keep the skills general: they are about using wicket, not about developing it, and their examples
use `example.com`.
