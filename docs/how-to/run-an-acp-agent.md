# Run an ACP agent

wicket can drive any agent that speaks the [Agent Client Protocol](https://agentclientprotocol.com)
(ACP) in a box, as its client. It offers the agent no file or terminal access outside the box, makes its
gateway the agent's only MCP server, and answers the agent's permission prompts once at a time. The
[reference](../reference/agents.md#acp-agents) has every rule.

## 1. Put the agent in an image

Build an image from wicket's agent image with the agent installed at a pinned version. Pin the version
and its registry integrity together, and never install `latest`. [`examples/acp-claude`](../../examples/acp-claude/)
has a Dockerfile that does this for Claude Code's ACP adapter.

```sh
docker build -t my-agent-acp:1 path/to/dockerfile-dir
```

## 2. Write the manifest

```yaml
task: Tidy the README and say what you changed in /workspace/out/result.json.
agent:
  name: tidy
  kind: acp
  acp:
    command: [my-agent, --acp]   # the agent's ACP mode, as the image has it
  image: my-agent-acp:1
zone:
  name: tidy
  images: [my-agent-acp:1]
  limits: { memory: 2g, cpus: 2, timeout: 30m }
```

A generic ACP agent gets no model route yet. The zone's `llm` is a Claude subscription, which only
Claude Code may use, so wicket refuses `llm` here. Routes for other providers come with #174. Until
then, the agent can use only what its zone's `reach` and `inject` give it.

## 3. Run it

```sh
wicket run tidy.yaml --workdir path/to/repo
```

The terminal shows the session as wicket sees it: the agent's messages, its tool calls and diffs, its
plan, and each of wicket's answers to it:

```
[agent] my-agent 1.4.2: ACP session 3f2… new
[tool]  Edit README.md (edit): /workspace/README.md
[wicket] agent prompt for Edit README.md (edit): allow_once (inside the box; what leaves it is decided at wicket's gates)
[wicket] the agent called terminal/create, which wicket doesn't offer: refused
[agent] finished: end_turn
```

Follow-ups (`wicket say`), hibernation (`hibernate_after`) and `wicket wake` work as for any agent. A
woken agent continues its own ACP session.

## Claude Code through its ACP adapter

`acp.profile: claude-agent-acp` runs Claude Code through its ACP adapter, with Claude Code's routes and
wicket's lockdown options. It is not the default and has not been run against a real subscription:
whether a subscription may back the adapter is an open question for the owner. See
[`examples/acp-claude`](../../examples/acp-claude/). Run Claude Code as `kind: claude-code` meanwhile.
