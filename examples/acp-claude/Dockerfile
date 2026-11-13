# wicket's agent image plus Claude Code's ACP adapter, pinned (#66). Not the default: see README.md.
#
#   docker build -t wicket/claude-code-acp:poc --build-arg BASE=wicket/claude-code:poc examples/acp-claude
#
# The adapter's version and its registry integrity are pinned together; the build fails if the
# registry serves anything else. Never `latest`.
ARG BASE=wicket/claude-code:poc
FROM ${BASE}
ARG CLAUDE_AGENT_ACP_VERSION=0.104.1
ARG CLAUDE_AGENT_ACP_INTEGRITY=sha512-wokBSGBEpYWgewoK1xeg/hiNg6KDFw9yY5QD+jYjDu3oVfALJGVCsc+sIHAA2hVcflJsqxRrYv+6AnCRAwRyFQ==
RUN test "$(npm view "@agentclientprotocol/claude-agent-acp@${CLAUDE_AGENT_ACP_VERSION}" dist.integrity)" = "${CLAUDE_AGENT_ACP_INTEGRITY}" \
 && npm install -g --ignore-scripts "@agentclientprotocol/claude-agent-acp@${CLAUDE_AGENT_ACP_VERSION}" \
 && npm cache clean --force \
 && command -v claude-agent-acp
