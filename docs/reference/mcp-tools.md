# The gateway's MCP tools

wicket's MCP gateway is the agent's only MCP server. Claude Code reaches it at
`http://wicket.internal:8081/mcp` and sees its tools as `mcp__wicket__<tool>`. The tools are defined in
`crates/wicket-proxy/src/gateway.rs` (`tools()`); every call is an event in the run's output
(`[wicket-tool] <name>: …`) and the tools that decide something are audited.

Every tool answers with one text block; a refusal or failure sets `isError`.

**On a node** (protocol 5, #164), the box's node decides from its token, connected or not:
`whoami`, `request_access` (which spends no grant), `await_grant` and `pending_requests`, `spawn` and
`spawn_agent` within the box's zone (the child starts on the node, its token attenuated there, and
the control host takes it over when it can be reached), and `send_message`, `await_message` and
`link` between boxes on that node, and push delivery of messages (see [Push delivery](#push-delivery)). While the control host is unreachable, what needs an operator
(`request_access` beyond the token, `request_capacity`, `request_update`, a spawn beyond the zone) is
queued on the node under a node-local id `q-…`; `await_grant` with that id follows it once it is
raised. Every other call is relayed to the control host, and fails clearly while it is away. What a
node still asks the control host, and why: [design §9.2.1](../explanation/design.md).

| tool | what it does | needs |
|---|---|---|
| [`await_grant`](#await_grant) | Wait for an operator's decision on a pending request | |
| [`pending_requests`](#pending_requests) | List this run's requests still waiting, and descendants' it may decide | |
| [`decide`](#decide) | Approve, deny or renew a descendant's request, grant or box authority within the caller's own reach | `escalation.grant` |
| [`request_access`](#request_access) | Ask an operator for reach ahead of time | |
| [`whoami`](#whoami) | This box's verified identity | |
| [`send_message`](#send_message) | Message the parent, a child or a permitted peer, by principal | |
| [`await_message`](#await_message) | Wait for the next message | |
| [`principals`](#principals) | Who this box may talk to, with each one's kind and state | |
| [`receipts`](#receipts) | What became of the messages this box sent | |
| [`spawn_agent`](#spawn_agent) | Start a child agent in a narrowed copy of this zone | `max_children` |
| [`spawn`](#spawn) | Start an agent or program in a zone the caller writes | `max_children` |
| [`continue_child`](#continue_child) | Give a child agent the caller delegated to another brief, its context intact | |
| [`delegations`](#delegations) | The caller's delegations: each child's state and its latest report's receipt | |
| [`request_capacity`](#request_capacity) | Ask for a machine of its own (a lease) | `placement.yaml` |
| [`request_update`](#request_update) | Ask the operator to update wicket to a build | |
| [`expose`](#expose) | Offer a TCP port to other boxes | |
| [`connect`](#connect) | Reach another box's port | |
| [`link`](#link) | Wire two boxes the caller controls | |
| [`unlink`](#unlink) | Close a link | |
| [`links`](#links) | The caller's links | |
| [`finish`](#finish) | End the session when the work is done | |
| [`hibernate`](#hibernate) | Sleep until a message arrives | a long-lived agent |

## `await_grant`

Waits for an operator to decide a pending request (the `request_id` from a 403 `pending-approval`
response, or from `request_access`, `spawn`, `connect` or `link`). Returns `granted`, `denied`,
`withdrawn`, or still pending after the timeout. After `granted`, the agent retries the original
request once. A run can only wait on its own requests.

| argument | type | default | |
|---|---|---|---|
| `request_id` | string | required | e.g. `r-1a2b3c4d` |
| `timeout_seconds` | integer, 5–600 | 300 | |

## `pending_requests`

Lists this run's requests that are still waiting for a decision. For an agent whose zone may grant
(`escalation.grant`, the default), it also lists its descendants' pending requests that it could
decide with [`decide`](#decide). No arguments.

## `decide`

Approves or denies a pending request from one of the caller's descendants (a box it started, or
one they started; [#50](https://github.com/public/wicket/issues/50)). The decision is signed with
the caller's wicket identity and recorded, with the chain from the asking run to the caller, as an
operator's is; the first decision on a request wins. Only the caller's own call decides: nothing sent
with `send_message` can make one. A request the caller may not decide is refused, saying why, and
stays pending for an operator. It may decide a request only when:

- the caller's zone has `escalation.grant` ([manifest](manifest.md#zone));
- it is an HTTP request for one path (SPAWN, LINK, CAPACITY, UPDATE, prefix requests and git
  pushes stay with operators);
- the caller's own zone allows it by reach at the request's risk, and the org policy doesn't
  refuse it: what the caller could do itself, never by one of its own grants.

An approval grants exactly the asked path, to the asking run only, for `uses` uses, and ends no
later than the caller's own authority. It signs the request's effect descriptor as it is then
(`pending_requests` lists each request's `effect` hash): if the request changed before the decision
is recorded, the decision is refused ([#369](../explanation/approvals-bound-to-effects.md)).

`decision: renew` ([#56](https://github.com/public/wicket/issues/56)) gives a live grant, or a
descendant box's authority, a new end `ttl_seconds` from now. It is signed, checked and recorded
as an approval is:

- a grant (`grant_id`, or `request_id` for the grant made for it) only if the caller could make it
  now: a descendant's request it may decide, for exactly that path, to that run only, with a
  number of uses (kept as they are). A push's window, a prefix or zone-wide grant, and an unlimited
  grant are renewed by an operator (`wicket grant renew`);
- a descendant box's authority (`run`), with `escalation.grant`. The box's token is minted again
  with the new end, so its node keeps it past its old one. It never goes past the box's run
  timeout. A box nobody renews stops when its authority ends, as before.

Either way it ends no later than the caller's own authority. A renewal only extends; to end
something sooner, revoke it.

| argument | type | default | |
|---|---|---|---|
| `request_id` | string | required, except for `renew` | from `pending_requests`; for `renew`, the request whose grant to renew |
| `decision` | `approve`, `deny` or `renew` | required | |
| `grant_id` | string | | `renew`: the grant to renew |
| `run` | string | | `renew`: the descendant box whose authority to renew |
| `uses` | integer, 1–100 | 1 | `approve` only |
| `ttl_seconds` | integer | 600 | at most 24h, and not past the caller's authority |

## `request_access`

Asks an operator for reach the agent needs but doesn't have, before trying or after a "needs human
approval" block. Returns a `request_id` for `await_grant`. Asking again for what an operator just denied
is refused, saying so.

| argument | type | default | |
|---|---|---|---|
| `url` | string | required | e.g. `https://api.example.org/v2/items` |
| `method` | string | `GET` | |
| `scope` | `exact` or `prefix` | `exact` | `prefix`: every path under the URL's path, in whole segments (`/repos/acme/app` covers `/repos/acme/app/…`, not `/repos/acme/app-secrets`). |
| `reason` | string | required | One sentence: what it is for. |

A grant never covers anything riskier than the request the operator was shown: approving an R2 prefix
doesn't allow the R4 operations under it. On a node, a prefix grant is honoured for the asked path
only.

## `whoami`

The box's wicket-issued identity: its principal (`id`, `spiffe://<domain>/t/<tenant>/z/<zone>/a/<agent>`),
agent name, zone, run, parent, children (each with its principal), what its `accept_from` lists
(`accepts_messages_from`), and the principal it acts for (a run an operator started names the
operator's identity in `principal.sub`). No arguments.

## `send_message`

Sends a message through wicket, which signs it with the sender's identity; the recipient sees who
sent it, verified. A message names a **principal**, not a run (#250): an agent is the same principal
across its restarts and wakes, so a message reaches it by the same name each time. Parent and child
may always message each other; anyone else only if the recipient's `accept_from` lists the sender's
principal or its zone. Run ids are not addresses.

| argument | type | |
|---|---|---|
| `to` | string, required | `"parent"`, or a principal: `spiffe://<domain>/t/<tenant>/z/<zone>/a/<agent>`, as `whoami` and `spawn` show it |
| `body` | any JSON value, required | at most 16 KB |
| `priority` | `now`, `next` (default) or `later` | how soon the sender wants it read: interrupt the recipient's turn, join it, or wait for it to end. The recipient's inbox hands out `now` first and `later` last; a harness that takes pushed messages gets it in `meta` (#252) |
| `in_reply_to` | string | the `message_id` being answered. A reply to a message the recipient sent this principal needs no `accept_from`: the sender gave its reply address when it wrote |

The answer's first line says where it went; its second, `receipt: {…}`, is the message's first
receipt (see [`receipts`](#receipts)): `delivered` (with the run), or `held` (with `why`, who can
`release` it, and when it `expires_at`). Every message carries its sender's principal as its
**reply address** (`reply_to`, signed in the envelope).

A message the recipient's `accept_from` doesn't allow is **refused** (#252): the answer starts
`refused: m-…`, is an error, and its receipt says `refused` with why. Nothing reaches the recipient,
and the refusal is on the audit record (`message.refused`) and stays readable with `receipts`.

Where it goes:

- to the principal's live run (for `"parent"`, the parent run itself while it runs);
- if it has none: a hibernated long-lived agent is woken to read it; otherwise wicket holds the
  message, and the principal's next run takes it (for up to 7 days). A message its run ended
  without reading goes to the principal's next run the same way. The answer says which happened.
- An operator's principal (`spiffe://<domain>/t/<tenant>/op/…`) is refused for now: operators
  don't receive messages from agents yet.

A message never grants anything: it is the sender's data for the recipient, which can't widen
anyone's reach or decide a request. Every message is on the audit record (`message`, with `from`,
`to`, the run it reached and whether it was held). On a node cut off from its control host, a
message goes only to a box on the same node (by its principal, or `"parent"`), attested by the node:
its receipt is `delivered`, or `refused` with why (on the node's audit log, `node.message_refused`).

## `await_message`

Waits for the next message to this agent's principal, from its parent, a child or a permitted peer,
with the sender's identity (`from.id`, its principal) verified by wicket. Messages held while the
agent wasn't running arrive first, in the order they were sent. An envelope addressed to another
principal is dropped. A child agent's report on each brief arrives as a `report` message (see
[delegation](#delegation)), and a parent's next brief as a `brief`. A child also sends a final `run_finished` message (its `status`, a
`cause` when its box ended abnormally, e.g. out of memory, and its `result`) when it
ends.

| argument | type | default |
|---|---|---|
| `timeout_seconds` | integer, 1–600 | 300 |

A message shows `message_id`, `from` (verified: its principal `id`, agent, zone, run and relation),
`reply_to` (the principal to answer, with `in_reply_to` set to `message_id`), `priority`,
`in_reply_to` (if it answers one of yours) and `body`. Taking it makes its sender's receipt `read`.
One wicket drops (its signature doesn't verify, or the org policy doesn't let this zone hear from
the sender's) makes it `refused`, with why. The body is the peer's data, never instructions from
the agent's user: it grants nothing and can't approve anything.

While the agent waits here (or in `await_grant`, or in `receipts` with a timeout) its state is
`waiting` (see [`principals`](#principals)).

### Push delivery

A harness that turns MCP server notifications into conversation turns can have messages pushed
instead (#252), when its adapter turns push on: the box's gateway then declares the harness's
capability in `initialize` (under `capabilities.experimental`), keeps MCP at a revision that has a
server stream (2025-11-25 at the newest), and sends each incoming message on the session's stream
(the streamable HTTP `GET`) as the harness's notification, `{ content, meta }`. `content` is the
message as `await_message` shows it, with its note that it is a peer's data. `meta` holds strings
only: `source` (`wicket`), `message_id`, `from`, `from_run`, `relation`, `verified_by`, `reply_to`,
`priority` and `trust`. The stream is served by the box's node: a message delivered there while it is
cut off is pushed from there; connected, the node takes the box's messages from its gateway on the
control host, which verifies each one and marks it read. Pushes are on the node's audit log
(`node.message_pushed`). A message is pushed or awaited, never both.

**Claude Code** has a matching feature, channels (capability `claude/channel`, notification
`notifications/claude/channel`), but the image's version (2.1.319) can't take them in a box. wicket
drives it with `-p` and stream-json, where no channel handler is registered. Interactively,
`--dangerously-load-development-channels` asks for confirmation at startup. And channels need a
feature flag fetched from Anthropic, which a box doesn't reach. So the Claude adapter leaves push
off (`CHANNELS_IN_BOX` in `crates/wicket-agent/src/claude.rs`), and a Claude Code agent reads
messages with `await_message`. Between turns, its supervisor tells it in wicket's own words that
messages are waiting.

## `principals`

Discovery and presence (#252): the principals this one may talk to, from what the ledger knows. No
arguments. Each entry has its principal `id` (stable across its restarts and wakes: what
`send_message` takes), `kind` (`agent`, `human`; `program` once programs have identities, #255),
agent name and zone, `relation` (`parent`, `child`, `peer`, `operator`), and two flags:
`may_send_to` (its `accept_from` lists this principal or its zone, or it is the parent or a child)
and `may_hear_from` (this zone's `accept_from` lists it, and the org policy agrees). Its `state` is
one of:

| state | meaning |
|---|---|
| `running` | it has a live run that hasn't reported what it is doing |
| `busy` | in a turn |
| `idle` | between turns |
| `waiting` | in `await_message`, `await_grant` or a `receipts` wait |
| `hibernated` | a long-lived agent asleep: a message wakes it |
| `offline` | no live run: a message is held for its next one |

Operators that `accept_from` names are listed as `kind: operator`, `state: offline`: they don't receive
agents' messages yet (they will through the CLI and the console). Principals of other tenants are
never listed.

## `receipts`

What became of the messages this principal sent (#252), in any of its runs. Each receipt has the
`message_id`, the recipient (`to`), its `priority`, `sent_at`, and a `state`:

| state | meaning |
|---|---|
| `delivered` | in the inbox of the recipient's live run (`run`), not read yet |
| `read` | the recipient took it (`read_at`): `await_message`, or pushed into its conversation |
| `held` | the recipient has no live run (`why`), or is hibernated and being woken. `release` says who can release it (its next run, started by whoever may start it, or wicket waking it), and `expires_at` when it stops waiting |
| `refused` | not delivered, and `why`: not in the recipient's `accept_from`, or dropped at delivery |
| `expired` | held for 7 days and never read |

| argument | type | default |
|---|---|---|
| `message_id` | string | none: the latest 20 receipts |
| `timeout_seconds` | integer, 0–600 | 0: with `message_id`, wait until it is read, refused or expired |

A receipt is readable only by its sender.

## `spawn_agent`

Starts a child agent in its own box with its own identity, in the caller's own zone, optionally
narrowed to some of its hosts. Returns the child's run id and its principal, which `send_message`
addresses it by, and a [handle](#delegation): its task is a delegation, whose report comes back as a
message. Refused when `max_children` is 0 or spent.

| argument | type | |
|---|---|---|
| `name` | string, `^[a-z][a-z0-9-]{0,31}$`, required | the child's agent name |
| `task` | string, required | |
| `reach_hosts` | list of strings | only these hosts from the caller's own reach |

## `spawn`

Starts a new box, an agent (with a task) or a program (a command, such as a long-running service),
in a zone the caller describes. The zone must be within the caller's: reach, credentials, model
budget (carved out of the caller's), memory, CPUs, PIDs, time, isolation, images and
`max_children` can only narrow. If it isn't, the answer lists every violation; with `escalate` it
becomes a pending R4 request, `SPAWN wicket.internal/zones/<zone>/<name>`, for exactly that zone
and those arguments (their sha256 is in the request's [effect](../explanation/approvals-bound-to-effects.md)):
the caller waits with `await_grant` and calls `spawn` again with the same arguments. While it is
pending, a call for the same child with other arguments waits on it ("waiting: request …"); once
it is granted, other arguments are refused and audited (`effect.refused`), and a second call with
the approved ones, after the child started, is refused too: an approval starts one child. A different
model route or a credential the caller doesn't have is refused outright, with no approval path.
Returns the new run id, and for an agent a [handle](#delegation).

| argument | type | default | |
|---|---|---|---|
| `name` | string, `^[a-z][a-z0-9-]{0,31}$` | required | |
| `kind` | `agent` or `program` | `agent` | |
| `task` | string | | for agents |
| `command` | list of strings | | for programs |
| `image` | string | the caller's | from the caller's image or its zone's `images` |
| `zone` | object | see below | a [manifest zone](manifest.md#zone): `reach`, `forbid`, `unlisted_hosts`, `wildcards`, `inject`, `volumes`, `llm` (`max_requests`, `max_output_tokens`), `limits`, `isolation`, `images`, `accept_from` |
| `max_children` | integer ≥ 0 | 0 | at most 64; counts against the caller's |
| `escalate` | boolean | false | put a zone beyond the caller's to an operator |
| `placement` | `{"lease": "l-…"}` or `{"node": "<name>"}` | where the caller runs | an active lease from `request_capacity`, or the node the caller runs on |

What `zone` leaves out: no reach and no credentials; the caller's limits, isolation,
`unlisted_hosts` and `wildcards`; for an agent, half the model budget the caller has left, and the
caller's `escalation`. A program may not ask for more (`escalation.request: false`) unless `zone`
says `escalation: { request: true }`, which the caller's zone must allow too. The spawned zone is named
`<caller's zone>.<name>.<caller's run>`.

## Delegation

An agent `spawn` (or `spawn_agent`) starts is a delegation (#252): its task is its first brief.
`spawn` ends its answer with the child's handle, one line of JSON:

```text
handle: {"principal":"spiffe://<domain>/t/<tenant>/z/<zone>.<name>.<run>/a/<name>","delegation":"d-…","run":"run_…","name":"<name>"}
```

- **Reports are messages.** When a top-level turn of the child's on its brief ends, wicket sends the
  turn's result to the parent's principal as a message of kind `report`, signed with the child's
  identity: `body` is `{ delegation, turn, status, report }` (`status` is `turn_ended` or
  `turn_failed`; `report` is the turn's result, its last 12 KiB). The parent reads it with
  `await_message`, and it has a receipt like any message (the child reads it with `receipts`; the
  parent sees it in `delegations`). The child's session stays open after it: wicket never ends it.
  When the child's run ends, its `run_finished` names the delegation too.
- **Continuing a child.** `continue_child` gives the same child another brief, in the same run, so
  its context is intact: a `brief` message the child's session wakes with (its next turn), and its
  report on it comes back as the next `report`. A child is continued only once it has reported on
  its last brief; one still working is refused (add to its brief with `send_message`), and one
  whose run ended is refused (spawn a new one).
- **What holds.** A brief or a report is a message: data, which grants nothing. The child keeps the
  zone it was spawned with, within its parent's (#256): continuing it changes no authority. Only the
  agent that delegated (its principal) may continue a child: anyone else, by name, principal or
  delegation id, is refused, and isn't told whose child it is. Every step is audited:
  `delegation.started`, `delegation.reported`, `delegation.continued`, `delegation.refused` and
  `delegation.ended`.

## `continue_child`

Another brief for a child agent the caller delegated to, once it has reported on its last one.
Returns the brief's message id, the handle and the brief's first receipt.

| argument | type | default | |
|---|---|---|---|
| `child` | string, required | | the child's name, principal or delegation id (`d-…`); the newest of the caller's by that name |
| `brief` | string or object, required | | what to do next, at most 16 KB |
| `priority` | `now`, `next` or `later` | `next` | as for `send_message` |

Refused, with why: no child by that name (`no child`), another agent's child (`is not your
child`), a child still working on its brief, or one whose run has ended.

## `delegations`

The caller's delegations, newest first (at most 50): each one's `delegation` id, `name`,
`principal`, `run`, `run_status`, `presence` (as [`principals`](#principals) says it), `state`, `turn`
(1 for the task, one more per continuation), and the receipts of its latest `report` and `brief`.

| state | meaning |
|---|---|
| `working` | on its brief: its first turn, or a continuation |
| `reported` | its turn ended and its report was sent to the parent: `continue_child` may give it another brief |
| `ended` | its run is over |

## `request_capacity`

Asks an operator for a machine of the agent's own for a while: more CPU or memory, another isolation
tier, a region. It costs money, so an operator always decides, within the budget in `placement.yaml`;
an ask over budget is refused before an operator sees it. Without `placement.yaml` the tool is off.
Returns a lease id; calling again with `{lease}` waits until its node is ready. Then `spawn` with
`placement: {"lease": …}` places boxes there. The node is destroyed when the lease ends, and what
runs on it stops.

| argument | type | default | |
|---|---|---|---|
| `vcpus` | integer ≥ 1 | 1 | |
| `memory_mib` | integer ≥ 128 | 1024 | |
| `isolation` | `process`, `gvisor` or `vm` | `gvisor` | |
| `region` | string | | a preference, e.g. `lhr` |
| `duration_minutes` | integer, 1–1440 | | |
| `max_hourly_usd` | number or string | | the most the node may cost per hour |
| `reason` | string | | |
| `lease` | string | | instead of asking: wait for this lease |
| `timeout_seconds` | integer, 1–900 | 300 | with `lease` |

## `request_update`

Asks the operator to update the installation to a build the agent made. It files an R4 request,
`UPDATE wicket.internal/self/<sha256>`, and nothing else: once an operator approves it, the operator's
`wicket self update` accepts that artifact once. See
[run wicket in wicket](../how-to/run-wicket-in-wicket.md).

| argument | type | |
|---|---|---|
| `sha256` | string, required | the artifact's sha256, 64 hex digits |
| `reason` | string, required, at most 1000 characters | what the build changes, and where the artifact is |

## `expose`

Offers a TCP port of this box (a server on 127.0.0.1 or 0.0.0.0) to other boxes. The parent may
connect without it; other boxes may if this zone's `accept_from` lists theirs, or an operator approves.

| argument | type | default |
|---|---|---|
| `port` | integer, 1–65535, required | |
| `name` | string | the agent's name: connectors see `<name>.wicket.internal` |

## `connect`

Reaches a TCP port of another box: one of the caller's children (by name or run id; no `expose`
needed), its parent, or a box that exposed the port. Returns the address to use in the caller's box,
`<name>.wicket.internal:<port>`, relayed by wicket. Connecting lends the caller the target's
authority, so a target whose reach isn't within the caller's needs an operator: the answer is then a
request id for `await_grant`, after which the caller calls `connect` again.

| argument | type | |
|---|---|---|
| `box` | string, required | a child's name, a run id, or `"parent"` |
| `port` | integer, 1–65535, required | |

## `link`

Wires two boxes the caller controls (itself, `"self"`, or its own children): box `from` gets
`<name>.wicket.internal:<port>`, reaching `port` of box `to`. The policy is `connect`'s: `to`'s
reach must be within `from`'s, or an operator approves.

| argument | type |
|---|---|
| `from` | string, required |
| `to` | string, required |
| `port` | integer, 1–65535, required |

## `unlink`

Closes a link the caller opened or is an end of. Live connections over it are dropped.

| argument | type |
|---|---|
| `link` | string, required: its id, `l-…` |

## `finish`

Ends the agent's session (#249): at the end of the current turn wicket closes the harness's input,
the harness exits and the run ends. A harness that hasn't exited by the zone's `limits.exit_grace`
(30 s by default) after its session closed (a background process of its keeps it waiting, say) has
its box stopped: the workspace is synced back, and the run is recorded as succeeded, with a note
naming the processes wicket stopped (#293). wicket never ends a session by itself: until the agent calls `finish`
or exits, its session stays open for prompts (`wicket session`, the console's session page) and messages, up to the zone's
`limits.timeout` or the end of its authority. No arguments. Relayed to the control host on a node.

## `hibernate`

Asks to be hibernated at the end of the current turn, once nothing but the agent runs in its box:
the box stops and its state is kept (workspace, `$HOME`, `/tmp`, durable volumes), and a message to
the agent or its operator's prompt (`wicket session`) wakes it, with that as its next turn. If something else
still runs, it gets the zone's `limits.exit_grace` (30 s by default) to end; then wicket stops it and
hibernates the agent, naming what it stopped in `wicket agents` (a wake restores files, not
processes). Only for a long-lived agent
wicket started itself: a wrapped or Remote Control session is refused. No arguments. See
[hibernate and wake](agents.md#hibernate-and-wake).

## `links`

The links the caller opened or is an end of, open and closed. No arguments.
