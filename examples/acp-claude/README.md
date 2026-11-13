# Claude Code through its ACP adapter

This example runs Claude Code in a wicket box through
[`claude-agent-acp`](https://github.com/agentclientprotocol/claude-agent-acp), with wicket as its ACP
client ([ACP agents](../../docs/reference/agents.md#acp-agents)). It is here so the adapter is pinned
and ready. **It is not the default, and it hasn't been run against a real subscription.**

The adapter runs the unmodified `claude` binary through the Claude Agent SDK. wicket's rule is that a
Claude subscription backs Claude Code itself, never an API key, and Anthropic asks Agent SDK products
to use API keys. Whether the owner's own subscription may back the adapter in a single-owner setup is
an open question for the owner. Research [21 §2.6](../../docs/explanation/research/21-agent-client-protocol.md#26-claude-code-over-acp-stays-the-fallback-not-the-default)
has the details. Until it is decided, run Claude Code as `kind: claude-code`, which drives the
`claude` CLI directly.

What the profile sets, beyond the generic ACP posture:

- Claude Code's environment: routes to wicket's LLM proxy and a placeholder token only.
- Its `settings.json`, as for `kind: claude-code` (`adapter_settings`, `cleanupPeriodDays`).
- `_meta.claudeCode.options`:
  - `strictMcpConfig: true`, so wicket's gateway is the only MCP server;
  - `settingSources: [user, project]`, without `local`, where the adapter keeps "always" decisions;
  - `disallowedTools`: `WebSearch`, plus `Agent` and `Task` when `in_box_subagents: false`;
  - the manifest's `model`.

Build the image (the adapter's version and registry integrity are pinned in the Dockerfile), then run:

```sh
docker build -t wicket/claude-code-acp:poc examples/acp-claude
wicket run examples/acp-claude/manifest.yaml --workdir path/to/repo
```

Not done:

- `acp-tck` against this pinned adapter (conformance 17 in design §6.1).
- A check that the adapter's `/remote-control` fails closed outside `vendor_rc` (conformance 18).
