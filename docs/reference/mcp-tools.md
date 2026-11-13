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
`link` between boxes on that node. While the control host is unreachable, what needs a human
(`request_access` beyond the token, `request_capacity`, `request_update`, a spawn beyond the zone) is
queued on the node under a node-local id `q-…`; `await_grant` with that id follows it once it is
raised. Every other call is relayed to the control host, and fails clearly while it is away. What a
node still asks the control host, and why: [design §9.2.1](../explanation/design.md).

| tool | what it does | needs |
|---|---|---|
| [`await_grant`](#await_grant) | Wait for a human's decision on a pending request | |
| [`pending_requests`](#pending_requests) | List this run's requests still waiting | |
| [`request_access`](#request_access) | Ask a human for reach ahead of time | |
| [`whoami`](#whoami) | This box's verified identity | |
| [`send_message`](#send_message) | Message the parent, a child or a permitted peer | |
| [`await_message`](#await_message) | Wait for the next message | |
| [`spawn_agent`](#spawn_agent) | Start a child agent in a narrowed copy of this zone | `max_children` |
| [`spawn`](#spawn) | Start an agent or program in a zone the caller writes | `max_children` |
| [`request_capacity`](#request_capacity) | Ask for a machine of its own (a lease) | `placement.yaml` |
| [`request_update`](#request_update) | Ask the operator to update wicket to a build | |
| [`expose`](#expose) | Offer a TCP port to other boxes | |
| [`connect`](#connect) | Reach another box's port | |
| [`link`](#link) | Wire two boxes the caller controls | |
| [`unlink`](#unlink) | Close a link | |
| [`links`](#links) | The caller's links | |

## `await_grant`

Waits for a human to decide a pending request (the `request_id` from a 403 `pending-approval`
response, or from `request_access`, `spawn`, `connect` or `link`). Returns `granted`, `denied`,
`withdrawn`, or still pending after the timeout. After `granted`, the agent retries the original
request once. A run can only wait on its own requests.

| argument | type | default | |
|---|---|---|---|
| `request_id` | string | required | e.g. `r-1a2b3c4d` |
| `timeout_seconds` | integer, 5–600 | 300 | |

## `pending_requests`

Lists this run's requests that are still waiting for a human. No arguments.

## `request_access`

Asks a human for reach the agent needs but doesn't have, before trying or after a "needs human
approval" block. Returns a `request_id` for `await_grant`. Asking again for what a human just denied
is refused, saying so.

| argument | type | default | |
|---|---|---|---|
| `url` | string | required | e.g. `https://api.example.org/v2/items` |
| `method` | string | `GET` | |
| `scope` | `exact` or `prefix` | `exact` | `prefix`: every path under the URL's path, in whole segments (`/repos/acme/app` covers `/repos/acme/app/…`, not `/repos/acme/app-secrets`). |
| `reason` | string | required | One sentence: what it is for. |

A grant never covers anything riskier than the request the human was shown: approving an R2 prefix
doesn't allow the R4 operations under it. On a node, a prefix grant is honoured for the asked path
only.

## `whoami`

The box's wicket-issued identity: agent name, zone, run, parent and children. No arguments.

## `send_message`

Sends a message through wicket, which signs it with the sender's identity; the recipient sees who
sent it, verified. Parent and child may always message each other; anyone else only if the
recipient's zone lists the sender's in `accept_from`.

| argument | type | |
|---|---|---|
| `to` | string, required | `"parent"`, or a run id |
| `body` | any JSON value, required | at most 16 KB |

## `await_message`

Waits for the next message to this agent, from its parent, a child or a permitted peer, with the
sender's identity verified by wicket. A child also sends a final `run_finished` message (its `status`, a
`cause` when its box ended abnormally, e.g. out of memory, and its `result`) when it
ends.

| argument | type | default |
|---|---|---|
| `timeout_seconds` | integer, 1–600 | 300 |

## `spawn_agent`

Starts a child agent in its own box with its own identity, in the caller's own zone, optionally
narrowed to some of its hosts. Returns the child's run id; its messages and result come through
`await_message`. Refused when `max_children` is 0 or spent.

| argument | type | |
|---|---|---|
| `name` | string, `^[a-z][a-z0-9-]{0,31}$`, required | the child's agent name |
| `task` | string, required | |
| `reach_hosts` | list of strings | only these hosts from the caller's own reach |

## `spawn`

Starts a new box, an agent (with a task) or a program (a command, such as a long-running service),
in a zone the caller describes. The zone must be within the caller's: reach, credentials, model
budget (carved out of the caller's), memory, CPUs, PIDs, time, isolation, images and
`max_children` can only narrow. If it isn't, the answer lists every violation; with `ask_human` it
becomes a pending R4 request, `SPAWN wicket.internal/zones/<zone>/<digest>`, for exactly that zone:
the caller waits with `await_grant` and calls `spawn` again with the same arguments. A different
model route or a credential the caller doesn't have is refused outright, with no approval path.
Returns the new run id.

| argument | type | default | |
|---|---|---|---|
| `name` | string, `^[a-z][a-z0-9-]{0,31}$` | required | |
| `kind` | `agent` or `program` | `agent` | |
| `task` | string | | for agents |
| `command` | list of strings | | for programs |
| `image` | string | the caller's | from the caller's image or its zone's `images` |
| `zone` | object | see below | a [manifest zone](manifest.md#zone): `reach`, `forbid`, `unlisted_hosts`, `wildcards`, `inject`, `volumes`, `llm` (`max_requests`, `max_output_tokens`), `limits`, `isolation`, `images`, `accept_from` |
| `max_children` | integer ≥ 0 | 0 | at most 64; counts against the caller's |
| `ask_human` | boolean | false | put a zone beyond the caller's to a human |
| `placement` | `{"lease": "l-…"}` or `{"node": "<name>"}` | where the caller runs | an active lease from `request_capacity`, or the node the caller runs on |

What `zone` leaves out: no reach and no credentials; the caller's limits, isolation,
`unlisted_hosts` and `wildcards`; for an agent, half the model budget the caller has left. The spawned zone is named
`<caller's zone>.<name>.<caller's run>`.

## `request_capacity`

Asks a human for a machine of the agent's own for a while: more CPU or memory, another isolation
tier, a region. It costs money, so a human always decides, within the budget in `placement.yaml`;
an ask over budget is refused before a human sees it. Without `placement.yaml` the tool is off.
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
`UPDATE wicket.internal/self/<sha256>`, and nothing else: once a human approves it, the operator's
`wicket self update` accepts that artifact once. See
[run wicket in wicket](../how-to/run-wicket-in-wicket.md).

| argument | type | |
|---|---|---|
| `sha256` | string, required | the artifact's sha256, 64 hex digits |
| `reason` | string, required, at most 1000 characters | what the build changes, and where the artifact is |

## `expose`

Offers a TCP port of this box (a server on 127.0.0.1 or 0.0.0.0) to other boxes. The parent may
connect without it; other boxes may if this zone's `accept_from` lists theirs, or a human approves.

| argument | type | default |
|---|---|---|
| `port` | integer, 1–65535, required | |
| `name` | string | the agent's name: connectors see `<name>.wicket.internal` |

## `connect`

Reaches a TCP port of another box: one of the caller's children (by name or run id; no `expose`
needed), its parent, or a box that exposed the port. Returns the address to use in the caller's box,
`<name>.wicket.internal:<port>`, relayed by wicket. Connecting lends the caller the target's
authority, so a target whose reach isn't within the caller's needs a human: the answer is then a
request id for `await_grant`, after which the caller calls `connect` again.

| argument | type | |
|---|---|---|
| `box` | string, required | a child's name, a run id, or `"parent"` |
| `port` | integer, 1–65535, required | |

## `link`

Wires two boxes the caller controls (itself, `"self"`, or its own children): box `from` gets
`<name>.wicket.internal:<port>`, reaching `port` of box `to`. The policy is `connect`'s: `to`'s
reach must be within `from`'s, or a human approves.

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

## `links`

The links the caller opened or is an end of, open and closed. No arguments.
