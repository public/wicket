# wicket's documentation

The documentation has four kinds of page, each with one job ([Diátaxis](https://diataxis.fr)):

- **Tutorials** teach by doing: one guided path from nothing to a working result, every step shown
  with what you should see. Start here if wicket is new to you.
- **How-to guides** are recipes for a goal, for someone who knows the basics.
- **Reference** is exact and complete: every command, field, tool, file and variable, taken from
  the code. Look things up here.
- **Explanation** is for understanding: the concepts, the security model and its limits, and why
  wicket is built the way it is.

## Tutorials

- [Your first box](tutorials/first-box.md): install in development mode, link the model credential,
  run an agent, approve its request in the console.
- [Approvals, children and links](tutorials/approvals-children-and-links.md): an agent starts a
  narrower child, you approve a wider one, and two boxes are linked.

## How-to guides

- [Install wicket on a host](how-to/install-on-a-host.md)
- [Put the console on the internet](how-to/put-the-console-on-the-internet.md)
- [Write a zone for a project](how-to/write-a-zone-for-a-project.md)
- [Store and link secrets](how-to/store-and-link-secrets.md)
- [Add a remote node](how-to/add-a-remote-node.md)
- [Place nodes on Vultr](how-to/place-nodes-on-vultr.md), and leases for agents
- [Hibernate and wake an agent](how-to/hibernate-and-wake-an-agent.md)
- [Drive a box from the Claude apps](how-to/drive-a-box-from-the-claude-apps.md)
- [Run a program instead of an agent](how-to/run-a-program.md)
- [Run an ACP agent](how-to/run-an-acp-agent.md)
- [Use HTTP/3](how-to/use-http3.md)
- [Export audit](how-to/export-audit.md)
- [Inspect a run's authority in the console](how-to/inspect-authority-in-the-console.md), and explain a decision
- [Edit a manifest in the console](how-to/edit-a-manifest-in-the-console.md), with its authority diff
- [Keep state off the host, and restore](how-to/state-off-host-and-restore.md)
- [Update wicket and roll back](how-to/update-and-roll-back.md)
- [Update from CI-signed builds](how-to/update-from-ci.md), and follow main
- [Run wicket in wicket](how-to/run-wicket-in-wicket.md)
- [Run the gates for a change](how-to/run-the-gates-for-a-change.md)
- [Run the acceptance tests](how-to/run-the-acceptance-tests.md)

## Reference

- [Command line](reference/cli.md): every command and flag (generated from `--help`)
- [Manifest](reference/manifest.md): every field, its type, default and meaning
- [MCP tools](reference/mcp-tools.md): the gateway's tools for agents
- [Policy in Cedar](reference/policy.md): org and zone policy, compiling to tokens, `wicket policy`
- [Risk classes](reference/risk-classes.md) and the dangerous-pattern list
- [Configuration files and environment variables](reference/configuration.md)
- [Files and directories](reference/files.md)
- [The daemon, and who may do what](reference/daemon.md)
- [Protocol and version skew](reference/protocol.md): responses to the box, the node channel,
  schema versions
- [The box](reference/box.md): what a workload sees from inside
- [Agents](reference/agents.md): identity, children, messages, sessions, hibernation
- [Nodes](reference/nodes.md): enrolment, `node serve`, placement, leases, the reconciler
- [Console](reference/console.md): passkeys, signed actions, authority views, manifests, what it enforces on the internet
- [Audit](reference/audit.md): the writer, export, checkpoints, record kinds

## Explanation

- [Concepts](explanation/concepts.md): zones, boxes, nodes, grants, identities, authority as tokens,
  deciding at the edge, the signed feed, links, leases, hibernation, audit
- [Security model](explanation/security-model.md) and [what wicket doesn't protect](explanation/limits.md)
- [Why gVisor](explanation/why-gvisor.md)
- [Performance of the network path](explanation/performance.md)
- [How updates work](explanation/updates.md)
- The design and the research behind it:
  - [Design](explanation/design.md) (v0.2; much of it not built yet)
  - [Research notes](explanation/research/) and the [prior art catalogue](explanation/prior-art.md)
  - [The origin conversation](explanation/00-origin-conversation.md)
- Records: the [proof-of-concept test record](explanation/poc-results.md) and the
  [security review before 0.0.1](explanation/security-review-0.0.1.md)

Changes are in [CHANGELOG.md](../CHANGELOG.md), assembled at release time from the fragments pull requests add under [changes/](../changes/README.md). `ci/check-doc-links.sh` checks every relative link
in these pages; `ci/gen-cli-reference.sh` writes the command-line reference.
