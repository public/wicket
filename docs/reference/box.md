# The box

What a workload sees from inside its box. [Concepts](../explanation/concepts.md#the-box-and-the-control-host)
explains why it is built this way.

## Runtime

- gVisor (`runsc`) with `--network none`, a read-only root filesystem and no capabilities, unless the
  zone says `isolation: runc` (development only).
- The entry script (`images/claude-code/wicket-entry`) starts as root with only the network-admin
  capability, adds wicket's addresses to the loopback, and then runs everything as the agent's user
  (`WICKET_AS_USER`) with no capabilities.
- Memory, CPUs and PIDs from the zone's `limits`. `/tmp` is capped at 512 MiB, checked every 5 s.
- The agent image (`wicket image`, tag `wicket/claude-code:poc`) holds Claude Code, bash, curl, jq,
  git, python3 and `wicket-fwd`, the in-box forwarder.

## Addresses and names

wicket's proxy, model route and MCP gateway are at `wicket.internal` (198.18.0.1), so the agent has
all of localhost for its own servers.

| address | what |
|---|---|
| `wicket.internal:3128` | The egress proxy (`HTTPS_PROXY`, `HTTP_PROXY`). |
| `wicket.internal:8080` | The model proxy (`ANTHROPIC_BASE_URL`). |
| `wicket.internal:8081/mcp` | The MCP gateway ([tools](mcp-tools.md)). |
| `wicket.internal:53` | The box's resolver. |
| 198.19.0.0/16 | Synthetic addresses, one per host the zone can reach, on the box's loopback. |
| 198.18.1.1–198.18.1.32 | Link addresses: each linked name gets one, and a line in `/etc/hosts`, which wicket owns and the box can only read. At most 32 per box. |

wicket answers every DNS query itself, so a lookup can't carry data out. A host the zone can reach
resolves to its synthetic address; hidden and forbidden hosts get NXDOMAIN. wicket also answers
HTTPS records with `alpn=h3` (unless `WICKET_H3_HTTPS_RECORDS=0`).

The box's connections go through `wicket-fwd` over bind-mounted unix sockets to the proxies on its
node. QUIC sent to a synthetic address is relayed to wicket over a unix socket and served as that
host: see [use HTTP/3](../how-to/use-http3.md). The forwarder holds UDP port 443 on every address
in the box, so a server in the box can't take UDP 443, even on 127.0.0.1; TCP 443 and every other
port stay the agent's.

## What the box holds

- No secrets: placeholders only. The model credential is a placeholder `CLAUDE_CODE_OAUTH_TOKEN` (or,
  for a remote session, a placeholder login file); the proxies swap in the real value on the hosts
  the secret is bound to.
- The run's CA (or, on a node, the installation root for the node CA's leaves and the run's CA), in
  the trust store and `SSL_CERT_FILE`.
- Claude Code's settings, written by wicket: its MCP config names wicket's gateway as the only
  server, `cleanupPeriodDays` is wicket's, and only the [allowed adapter
  settings](manifest.md#agent) come from the manifest.

## Paths

See [files](files.md#the-box).

## What a refused request looks like

See [protocol](protocol.md#responses-to-the-box).
