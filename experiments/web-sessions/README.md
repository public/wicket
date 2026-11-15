# Web session views (#327, first slice)

> **Outcome.** The acp-ui fork was chosen, and it is now the console's session view: its source is
> [`web/session/`](../../web/session/) (with [FORK.md](../../web/session/FORK.md)), the console
> serves it at `/session?run=<run>`, and [the console reference](../../docs/reference/console.md#sessions)
> describes it. The assistant-ui view and the dev proxy were removed when it moved; they are in
> this directory's history (#335). This write-up stays as the record of the comparison.

This is the spike for [#327](https://github.com/public/wicket/issues/327): one boxed agent's session
in the browser, over ACP, with wicket's escalations decided inline. It has three parts:

- **The endpoint**, in the crate: `crates/wicket-cli/src/serve/session.rs`, with its tests in
  `serve/tests/session.rs`. It stays when the views are chosen.
- **Two minimal views** on that endpoint, which stay here until one is picked:
  - `assistant-ui/`: the ACP TypeScript SDK with assistant-ui (React).
  - `acp-ui/`: a fork of formulahendry/acp-ui (Vue). See [FORK.md](../../web/session/FORK.md).
- **A comparison and a recommendation** (below).

**Recommendation: build on the acp-ui fork's approach** (Vue, a thin client of our own over the
fork's transport), **not on assistant-ui**. Use the ACP SDK's types in it, and decide later whether to
take its client too (see [Recommendation](#recommendation)).

## The endpoint

`GET /api/runs/<run>/acp` upgrades to a WebSocket that speaks ACP v1. wicket is the agent and the
browser is the client. There is one session per run, and its session id is the run id. The module
doc in `session.rs` is the reference. In short:

- **Who.** The socket acts as the operator's principal (#11), `spiffe://…/op/passkey/<name>`.
  Opening it needs all of these:
  - the console session cookie;
  - the console's own `Origin` (a cross-site page can't use the operator's cookie);
  - a ticket from a fresh passkey assertion over `{"action":"open_session","run":…}`. The ticket is
    single use, lasts 60 s, is bound to the console session and the run, and is sent as the
    `wicket.ticket.<hex>` subprotocol next to `acp.v1`, never in the URL. acp-ui already passes
    bearer tokens this way.

  The cookie alone opens nothing. The socket closes when the console session ends (sign-out, idle,
  expiry, revoked passkey) or when the run ends.
- **Bridge.** The supervisor (`wicket run`) stays the box's only ACP client (#66). It drives the
  agent over the box's stdio, through the node channel, and answers the agent's permission
  requests by wicket's policy. The endpoint reads both sides of that conversation:
  - the agent's side from the run's transcript;
  - wicket's side from `acp-client.jsonl`, which the supervisor now writes for ACP runs. Each entry
    carries the transcript offset it was written at, so the two sides merge in order.

  A prompt from the browser becomes an operator message from the principal, as `wicket say` does.
  The supervisor hands it to the agent as the next turn, and the browser's `session/prompt` is
  answered with the agent's stop reason when that turn ends. Other principals' prompts (the task,
  other operators, wicket's own notices) are shown as `user_message_chunk` with `_meta.wicket.by`.
- **Filtering.**
  - The agent's `_meta` is dropped everywhere, and only ACP v1's `session/update` kinds pass.
  - The agent's own requests are never forwarded. wicket's answers to its permission requests are
    shown as `tool_call_update` with `_meta.wicket.permission`.
  - The client's `cwd`, MCP servers and capabilities are ignored.
- **Escalations** are the run's pending requests in the ledger. Each is shown as a tool call
  `wicket:escalation:<id>` followed by a `session/request_permission` with once options only and
  `_meta.wicket.escalation`. **The ACP answer decides nothing.** The view decides through the
  console's signed decide action: the server's description, then a passkey assertion, through
  `/api/decide/*` (the same decide path as everywhere, #256). Only after that does it answer the
  ACP request. The endpoint reads the request's status from the ledger and audits what the client
  said next to what the ledger says.

  Peer messages never grant. Nothing the agent or a peer writes can raise one of these prompts:
  they come only from the ledger, the agent's `_meta` never passes, and agent tool calls using the
  `wicket:` id prefix are dropped.
- **Audit.**
  - `session.opened`, with the signed assertion;
  - `session.attached` and `session.closed`;
  - every prompt as `session.prompt`, with its principal, the operator message it queued, and the
    text's length and sha256;
  - every escalation answer as `session.escalation_answered`;
  - decisions themselves as `decision.*`, by the decide path;
  - wicket's answers to the agent's permission requests as `run.agent_prompt`, by the supervisor.

**Not in this slice:**

- `session/cancel`: the supervisor has no cancel channel yet, so the notification is ignored.
- The human answering the agent's own permission requests (#67's `answer_agent_prompts`): wicket's
  policy still answers them, and the view shows the answer.
- Images and resources in prompts.
- WebSocket connections aren't counted against the console's connection cap once upgraded. Each one
  needs a passkey-signed ticket, but a cap of their own is a follow-up.
- `wicket acp` for Zed (#67) can be a stdio↔WebSocket relay to this same endpoint; that's for later.

## The views

Both views do the same things:

- open the session (the signed `open_session` action, two steps as in #124: the server's description,
  then its own sign button);
- stream messages and thoughts;
- show tool calls with their input, output and diffs, with wicket's answer to the agent's permission
  request on the call;
- show plans and other principals' prompts;
- show a wicket escalation inline and decide it with a passkey;
- send prompts.

They share `common/wicket.ts`: the signed actions, the socket URL and subprotocols, and reading
`_meta.wicket`. Every string from the session is set as text. Neither view uses `innerHTML`, `v-html`
or markdown rendering.

### Build

Each view builds the same way (Node 22 and npm, versions pinned exactly, `package-lock.json`
committed):

```sh
cd assistant-ui    # or acp-ui
npm ci
npm run build          # type-check, then vite build -> dist/
npm run check:build    # the node check script -> check-dist/check.js
```

To try a view in a browser against a real console, on the console's origin (its cookie, Origin
check and passkeys need that):

```sh
wicket serve --listen 127.0.0.1:8788 --origin http://localhost:8787
node devproxy/serve.mjs assistant-ui/dist 8787 8788
# http://localhost:8787/session/?run=<run id>
```

The endpoint's ignored test drives both views' own client code (the code the views run, minus the
DOM) against a real listener, with a simulated supervisor:

```sh
(cd assistant-ui && npm ci && npm run check:build); (cd acp-ui && npm ci && npm run check:build)
WICKET_WEB_SESSIONS=$PWD cargo test -p wicket-cli --bin wicket -- the_views_clients --include-ignored
```

Both pass. Each check asserts that its view's store holds:

- the task's prompt, the thought, the plan, and the agent's message;
- the tool call's input and diff, and wicket's permission answer;
- the escalation card and its prompt, with once options only;
- the reply to its own prompt and the stop reason.

The Rust side asserts that the client's "approve" was audited and decided nothing.

**Not verified here:** rendering in a real browser. The box has no browser, and the Playwright
download is blocked. Both bundles are built to run under the console's CSP: no inline script or
style, no eval (checked: neither bundle contains `new Function` or `eval(`), and CSS in files.
React and Vue set styles through CSSOM, which `style-src 'self'` allows. Someone should still open
each view once on a desktop and a phone before choosing.

### Size and build cost

Sizes are vite 8 production builds; gzip is `gzip -9`.

| | assistant-ui + ACP SDK (React) | acp-ui fork (Vue) |
| --- | --- | --- |
| JS, minified | 737 KB | 83 KB |
| JS, gzip | 214 KB | 31 KB |
| CSS | 2 KB (ours) | 5 KB (upstream's components and ours) |
| npm packages in the lockfile (runtime) | 167 (99) | 82 (24) |
| `node_modules` | 116 MB | 77 MB |
| `npm ci` + build, this box | 21 s | 9 s |
| Same bytes on rebuild (same lockfile) | yes | yes, also after a fresh `npm ci` |

Of the 214 KB gzip on the left, measured separately: the ACP SDK's client and WebSocket stream are
about 41 KB, react and react-dom about 75 KB, and assistant-ui with what it pulls in (Radix, zod,
zustand, assistant-stream) about 100 KB. The SDK is large because it validates every message with
zod schemas. acp-ui avoids it at runtime: it uses the SDK for types only and has its own 150-line
JSON-RPC client.

For comparison, the console today is 600 lines of plain JavaScript, about 40 KB unminified.

### How well each renders ACP

| | assistant-ui + SDK | acp-ui (as upstream) | acp-ui fork |
| --- | --- | --- | --- |
| Streaming messages, thoughts | yes (text and reasoning parts) | yes | yes |
| Tool calls | yes: tool-call parts with args and result, our card | title, kind, status, paths only | + input, output, diffs |
| Diffs | our renderer, in the result | no | our renderer |
| Plans | a `data-plan` part, our renderer | no (logged as unhandled) | yes |
| Permission prompts | none built in: our card holds the SDK's handler's promise | modal dialog, every option including "always" | inline, once options only |
| Other principals' prompts | user messages with `metadata.custom.by` | user messages | + who sent it |
| A tool call before any assistant text | fine | **dropped** (kept in a map, never shown) | fixed |
| Long turns | fine | **fail after 60 s** (every request times out) | prompts don't time out |
| Agent text | text parts (markdown would need a renderer of our choosing) | **`marked` into `v-html`, unsanitized** | text interpolation |
| Protocol coverage | the SDK: every v1 type, validated | hand-rolled; misses new types until written | the same |

assistant-ui renders a chat well: streaming, auto-scroll, a composer, message parts by type, and
tool UIs by tool name. But ACP's model isn't its model. A session isn't a request–response chat:
other principals' turns arrive in the stream, tool calls update after the fact, and permission
requests are server-to-client calls. Each of these needs an adapter in our store (`session.ts`
folds ACP events into assistant-ui messages, about 200 lines) and a custom component. Its
runtime's notions of branching, editing, reloading and running state have to be kept out of the
way. The parts we'd use, the message-parts renderer and the composer, are the small half of what
we ship.

acp-ui upstream renders less than ACP sends, and its gaps are real bugs (above; worth reporting
upstream). Once fixed, its components are plain, small and easy to change. The fork kept its
transport and its component structure and replaced its store. Most of its app (settings, agents, Tauri, telemetry) didn't survive the
fork. What's left is about 1,300 lines with styles, of which wicket wrote or rewrote about 450.

### How wicket's own views fit

- **Escalations.** Both fit. In both, an escalation is an ACP tool call plus a permission request
  carrying `_meta.wicket.escalation`, decided by the console's passkey action before the ACP answer
  goes back.
  - In assistant-ui it is a tool UI registered by tool name (`wicket_escalation`), and the pending
    SDK handler's promise lives in our store.
  - In the fork it is the permission dialog component, extended. That was simpler: the dialog
    already exists, and it is only a component.
- **Box tree, budgets, grants, leases, hibernate/wake/finish** (#252, #316, #249). Neither library
  helps: these are wicket's views around the session, not parts of it. They are panels next to the
  session view, fed by the console's existing JSON API. They are easier to write in the stack the
  console is already closest to. Vue SFCs compile to plain DOM code with no virtual-DOM runtime
  surprise, and the console's own plain JS can sit next to them. In assistant-ui, anything outside
  the thread is plain React of our own anyway.
- **Messages between principals** (#252) fit the session stream as `user_message_chunk`s with
  `_meta.wicket.by` (done here), or later as their own `_meta` updates. Both views can show them.

### CI and embedding (reproducible, #190)

Either view is built the same way, and the binary changes the same way:

1. **CI builds the bundle** before `cargo build`. A job with a pinned Node runs `npm ci` from the
   committed lockfile (exact versions with integrity hashes), then `npm run build`, and writes
   `dist/` with no source maps and content-hashed file names. vite and rolldown give the same bytes
   for the same lockfile (checked above, including after a fresh `npm ci`). The bundle's sha256 goes
   into the release manifest.
2. **The binary embeds it** as the console embeds `console.js` today. `web.rs` adds the bundle's
   files under `/static/session/…` with their content hashes and SRI, under the same CSP. A small
   `build.rs`, or an `include_bytes!` of a generated file list, reads `dist/` from a path the CI job
   provides. Without it, a dev build serves a placeholder page.
3. **Committing `dist/` instead** (a vendored build) keeps `cargo build` free of Node, at the cost of
   reviewing a generated diff. The fork's 83 KB is reviewable as a generated artifact; assistant-ui's
   737 KB isn't, really.
4. **Supply chain**:
   - Pin, and never follow `latest` (as #66 asks of ACP agents).
   - `npm ci --ignore-scripts`: neither view needs install scripts.
   - Licence-check the lockfile.

   The fork's runtime is Vue (24 packages). The assistant-ui view ships 99 packages' worth of
   runtime.

## Recommendation

**Go with the acp-ui fork's approach**: a small Vue session view of our own, taking acp-ui's
WebSocket transport and component structure (MIT, attributed in FORK.md), with wicket's escalation
and principal views as components next to it.

- **Size and supply chain.** 31 KB against 214 KB gzipped, and 24 runtime packages against 99. The
  console is a phone app too, and every embedded byte ships in the binary.
- **Fit.** ACP's shape is a stream of updates plus server-to-client requests. A plain store and
  plain components map it one to one. assistant-ui's runtime has to be adapted around it, and most
  of what it brings (branching, editing, thread lists, cloud) we'd keep out of the way.
- **wicket's own views** (escalations, box tree, budgets) are ours to build either way. They are
  simpler as plain components than as tool UIs inside a chat runtime.
- **Risk.** acp-ui upstream is small and has one maintainer, and its rendering had real bugs. So
  fork it rather than depend on it: we keep the transport and the components we changed, and send
  the fixes upstream.

Open choices for the next slice:

- **Use the ACP SDK's types in the fork.** The fork already speaks the same wire format the SDK's
  client passed in the check. Taking the SDK's runtime client too (about 41 KB gzip, zod-validated)
  would buy protocol coverage, so weigh that cost against a hand-rolled client that has to follow
  ACP's changes.
- **Markdown for agent text.** Through a sanitizer, or a renderer that builds DOM nodes rather than
  HTML, in either view.

Next, in order:

1. Embed the chosen view and give it a CI build job.
2. `session/cancel` through the supervisor.
3. Let the human answer the agent's own permission prompts (#67).
4. Add the box tree and budgets panels.
5. Remove `wicket say` (#198).
