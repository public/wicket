# wicket's agent image plus Claude Code's ACP adapter, pinned (#66). Not the default: see README.md.
#
#   docker build -t wicket/claude-code-acp:poc --build-arg BASE=wicket/claude-code:poc examples/acp-claude
#
# The adapter and every package it needs come from ./package-lock.json, each checked against the
# integrity recorded there, with no package's install script run (#721). Never `latest`: a new
# version is a new lockfile: `npm install --package-lock-only` after changing package.json, with npm
# 11.10+ so that ./.npmrc's min-release-age keeps out versions younger than 7 days (design §2,
# principle 21; CI's ci/dep-age.py checks it either way).
ARG BASE=wicket/claude-code:poc
FROM ${BASE}
COPY package.json package-lock.json /opt/claude-agent-acp/
RUN cd /opt/claude-agent-acp \
 && npm ci --ignore-scripts --omit=dev --no-audit --no-fund \
 && npm cache clean --force \
 && ln -s /opt/claude-agent-acp/node_modules/@agentclientprotocol/claude-agent-acp/dist/index.js /usr/local/bin/claude-agent-acp \
 && command -v claude-agent-acp
