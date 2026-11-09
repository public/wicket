# wicket agent image: Claude Code plus the tools a coding agent expects, and the in-box forwarder.
# Nothing secret is ever baked in or mounted: the box gets placeholders and routes only.
FROM node:22-bookworm-slim

ARG CLAUDE_CODE_VERSION=2.1.319

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates git socat curl jq ripgrep less procps python3 iproute2 \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
 && npm cache clean --force \
 && claude --version

COPY wicket-entry /usr/local/bin/wicket-entry
RUN chmod 0755 /usr/local/bin/wicket-entry

# Git inside the box never runs repository hooks.
RUN git config --system core.hooksPath /dev/null \
 && git config --system advice.detachedHead false

WORKDIR /workspace
