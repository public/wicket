---
area: Console
type: Added
---
- The console has a session page for each running ACP agent, opened from the run's **session**
  link: its messages and thoughts as they stream, tool calls with their arguments and results
  (diffs included), plans, other principals' prompts, and wicket's escalations inline, approved
  once or denied there with your passkey through the same signed decide action as the front page.
  Prompts typed there reach the agent as its next turn, and **Stop** cancels its running turn. It
  works on a phone, as the console does
  ([#327](https://github.com/public/wicket/issues/327); how-to: "Work with a running agent in the
  console").
  - The view is `web/session/`, a fork of acp-ui (Vue, MIT, about 33 KB gzipped). CI builds it from
    its committed lockfile, checks its licences and that two fresh builds give the same bytes, and
    the binary embeds it (`WICKET_SESSION_VIEW` at build time), served with Subresource Integrity
    under the console's CSP. A build without it serves a page saying so.
  - `session/cancel` on the session endpoint now cancels the agent's running turn: the endpoint
    queues it in the ledger and the run's supervisor sends the agent ACP's own cancel within a
    second or so. Audited as `session.cancel` and `run.turn_cancel`.
  - Session WebSockets are capped at 4 per console session and 32 in all. Over a cap, the open is
    refused before the passkey is asked for, and an upgrade gets 429 without spending its ticket.
