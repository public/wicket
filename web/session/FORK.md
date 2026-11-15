# acp-ui, forked for wicket's session view

This is the console's session view (#327; [the console reference](../../docs/reference/console.md#sessions)),
moved here from `experiments/web-sessions/acp-ui` when the spike chose it.

Upstream is [formulahendry/acp-ui](https://github.com/formulahendry/acp-ui) at `cd9c3cb` (v0.1.16),
under the MIT licence ([LICENSE](LICENSE), copyright Jun Han). The fork leaves out:

- the Tauri desktop and mobile shell;
- agent configuration, saved sessions and settings;
- the traffic monitor and telemetry (Application Insights);
- the mode and model pickers;
- markdown rendering.

What came from upstream, and what changed:

| File | From upstream | wicket's changes |
| --- | --- | --- |
| `src/lib/transport/types.ts` | unchanged | none |
| `src/lib/transport/websocket.ts` | unchanged | a `protocols` option, for wicket's `wicket.ticket.<hex>` subprotocol |
| `src/lib/acp-bridge.ts` | its JSON-RPC client | no fs, host or traffic store; no 60 s timeout on `session/prompt`; permission requests are queued; `cancel` |
| `src/lib/types.ts` | unchanged | tool calls keep their input, output, diffs, and wicket's permission answer and escalation; messages keep plans and senders |
| `src/session.ts` | the update handler in `stores/session.ts` | no pinia; a tool call that starts a turn is shown; plans are shown; `_meta.wicket` is read; wicket's notices are their own messages |
| `src/components/ToolCallCard.vue` | unchanged | shows arguments, results, diffs and the permission answer; the console's colours |
| `src/components/PermissionDialog.vue` | unchanged | inline instead of a modal; once options only; wicket escalations decided with a passkey through the signing sheet |
| `src/App.vue` | the layout of `ChatView.vue` | text interpolation instead of `marked` + `v-html`; opening with a passkey, reopening, Stop (`session/cancel`), following the stream, a phone layout |
| `src/lib/wicket.ts`, `src/lib/sign.ts`, `src/components/SignSheet.vue`, `src/style.css` | none: wicket's | the console's API and signed actions (the decide path is `/api/decide/*`), the signing sheet pinned to the top (#124), the console's colours |
| `check/check.ts`, `check/ui.ts` | none: wicket's | the client against the real endpoint; the App under jsdom |

Bugs and gaps found in upstream along the way (worth reporting there):

- Agent markdown goes through `marked` into `v-html` without sanitizing, so an agent can put its
  own HTML on the page.
- Every request rejects after 60 s, `session/prompt` included, so a long turn shows as failed while
  the agent carries on.
- A `tool_call` that starts a turn (before any assistant message) is kept in a map but never shown.
- `plan` updates aren't rendered, and tool calls show no input, output or diffs.
- A second permission request replaces the first one's dialog.
