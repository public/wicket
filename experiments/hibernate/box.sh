#!/usr/bin/env bash
# Starts a wicket-shaped Claude Code box without wicket: the same `docker run` arguments as
# wicket-sandbox's build_args (gVisor, --network none, read-only root, the same capabilities and
# wicket-entry), the same environment as wicket-agent's claude_code_plan, and the same mounts
# (sock/, ca/, state/, /workspace, volumes). Used to wake an agent by rebuild, which `wicket run`
# can't do yet (it has no --resume).
#
#   box.sh NAME ROOT -- CLAUDE_ARGS...
#
# ROOT holds sock/ ca/ state/ workspace/ vol-cache/. stdin and stdout are the box's (stream-json).
# The host side of ROOT/sock/llm.sock must already be listening.
set -euo pipefail
name=$1 root=$2; shift 2; [ "${1:-}" = -- ] && shift
DOCKER=${DOCKER:-"sudo -n docker"}
uid=$(id -u):$(id -g)
exec $DOCKER run --rm --init --name "$name" --runtime runsc --network none \
  --memory 2g --cpus 1 --pids-limit 512 --cap-drop ALL --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:rw,nosuid,size=512m \
  --user 0:0 --env "WICKET_AS_USER=$uid" \
  --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --add-host wicket.internal:198.18.0.1 --workdir "${WORKDIR:-/workspace}" \
  --label wicket=1 --label hib=1 --interactive \
  --mount "type=bind,source=$root/sock,target=/wicket/sock" \
  --mount "type=bind,source=$root/ca,target=/wicket/ca,readonly" \
  --mount "type=bind,source=$root/state,target=/wicket/state" \
  --mount "type=bind,source=$root/workspace,target=${WORKDIR:-/workspace}" \
  --mount "type=bind,source=$root/vol-cache,target=/volumes/cache" \
  --env ANTHROPIC_BASE_URL=http://wicket.internal:8080 \
  --env CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-wicket-placeholder-hib \
  --env HTTPS_PROXY=http://wicket.internal:3128 --env HTTP_PROXY=http://wicket.internal:3128 \
  --env https_proxy=http://wicket.internal:3128 --env http_proxy=http://wicket.internal:3128 \
  --env NO_PROXY=localhost,127.0.0.1,::1,wicket.internal --env no_proxy=localhost,127.0.0.1,::1,wicket.internal \
  --env CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 --env DISABLE_AUTOUPDATER=1 \
  --env DISABLE_TELEMETRY=1 --env DISABLE_ERROR_REPORTING=1 \
  --env CLAUDE_CONFIG_DIR=/wicket/state/claude --env HOME=/wicket/state/home \
  --env WICKET_RUN=run_hib --env MCP_TOOL_TIMEOUT=660000 --env WICKET_TENANT=default \
  --env WICKET_CA_BUNDLE=/tmp/ca-bundle.pem \
  wicket/claude-code:poc \
  wicket-entry claude -p --input-format stream-json --output-format stream-json --verbose \
  --permission-mode bypassPermissions --disallowedTools WebSearch \
  --mcp-config '{"mcpServers":{}}' --strict-mcp-config "$@"
