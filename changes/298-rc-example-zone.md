---
area: Examples
type: Fixed
---
- `examples/remote-control-box.yaml` no longer leaves six background calls of a Remote Control session
  waiting for a human at every start. It forbids the bare `/v1/mcp_servers` (which
  `/v1/mcp_servers/**` didn't match) and a session's remote MCP (`/v2/ccr-sessions/*/mcp`). It
  reaches the session's own metadata (`GET /v1/code/sessions/*`). It refuses quietly the
  consumer-terms notice, the organization's fast mode and guest-pass referral eligibility, which a
  box has no use for. A test checks the example's verdicts
  ([#298](https://github.com/public/wicket/issues/298)).
