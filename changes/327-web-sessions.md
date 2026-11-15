---
area: Console
type: Added
---
- The console serves a boxed ACP agent's session over ACP on a WebSocket, `/api/runs/<run>/acp`, so
  a web view can show the session live: messages and thoughts as they stream, tool calls with their
  input, output and diffs, plans, how wicket answered each of the agent's permission requests, and
  other principals' prompts. Prompts sent on it reach the agent as its next turn
  ([#327](https://github.com/public/wicket/issues/327)).
  - Opening the socket needs the console's own origin and a fresh passkey assertion over a new
    `open_session` action. The assertion gives a single-use ticket for that run and console
    session, so a session cookie alone opens nothing. The socket acts as the operator's principal
    and closes when the console session or the run ends.
  - The run's pending escalations show up in the session as permission prompts. Answering one there
    decides nothing: a decision is still the console's signed decide action, with a passkey.
    Nothing the agent sends can raise such a prompt.
  - Opens, prompts (by principal, with the text's digest), answers to escalation prompts and closes
    are audited (`session.opened`, `session.attached`, `session.prompt`,
    `session.escalation_answered`, `session.closed`).
  - ACP runs now keep what wicket said to the agent next to the transcript, in `acp-client.jsonl`
    in the run directory, kept up to the zone's `limits.output`.
  - Two candidate views are in `experiments/web-sessions/`, with a comparison and a
    recommendation. The console doesn't serve either yet.
