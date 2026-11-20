# Manifest

A manifest is the YAML file `wicket run` takes: the task, one workload (an agent or a program) and
the zone it runs in. This page lists every field. The source of truth is
`crates/wicket-core/src/manifest.rs`; spawned zones (the `spawn` tool's `zone`) use the same `zone`
schema ([MCP tools](mcp-tools.md#spawn)).

Every object refuses fields it doesn't know (`deny_unknown_fields`), so a misspelt key is an error,
not a silent default. Durations are numbers with units, one or more terms (`90s`, `15m`,
`2h`, `1h 30m`, `1.5h`): `ns`, `us`, `ms`, `s` (`sec`, `seconds`), `m` (`min`, `minutes`), `h`
(`hr`, `hours`), `d` (`days`), `w` (`weeks`), `M` (`months`, 30.44 days) and `y` (`years`,
365.25 days), or `0`. Sizes are numbers with an optional `b`, `k`, `m` or `g` suffix, in binary units
(`2g` is 2 GiB, `1500m` is 1500 MiB).

```yaml
tenant: t0                  # optional
task: |                     # the trusted task text
  Read octocat/Hello-World and summarise it in /workspace/out/result.json.
agent:                      # exactly one of agent or program
  name: summariser
zone:
  name: research
  reach:
    - { host: api.github.com, paths: ["/repos/octocat/Hello-World/**"] }
  llm: { max_requests: 60, max_output_tokens: 60000 }
  limits: { memory: 2g, cpus: 1, timeout: 15m }
```

## Top level

| field | type | default | meaning |
|---|---|---|---|
| `tenant` | string | `t0` | The tenant. 0.0.1 is single-tenant: leave it out. |
| `task` | string | `""` | The trusted task text, given to the agent as its first turn (or to a program, which may ignore it). It is the only input policy derivation ever sees. Required for agents, except a Remote Control session (`agent.remote`) that wicket doesn't drive, whose messages come from the vendor's app. `wicket run --task` replaces it. |
| `agent` | [agent](#agent) | none | An agent, run by its [harness](#harness-modes). |
| `program` | [program](#program) | none | A deterministic workload with no model. |
| `zone` | [zone](#zone) | required | Where the workload runs, and what it may reach. |
| `placement` | [placement](#placement) | none | What the box asks of the node it goes on. |
| `service` | [service](#service) | none | For a program: what makes it a per-node service other boxes use. |

Exactly one of `agent` and `program` must be given.

## `service`

What makes a program a per-node service ([#579](https://github.com/public/wicket/issues/579)): one instance on every node that matches, which other boxes on that node use through a link (`zone.uses`). An operator installs it; no agent can start one. A service is a program, and its own zone's reach is what it fetches under.

| field | type | default | meaning |
|---|---|---|---|
| `per_node` | bool | `true` | One instance per matching node (the only kind so far). |
| `node_selector` | map of string to string | none | Labels a node must have to run it. |
| `tenancy` | `per_tenant` or `shared` | `per_tenant` | One instance per tenant using it on a node, or one for all of them. `shared` needs `public_only: true`. |
| `public_only` | bool | `false` | The operator's statement that it serves only public content, so a shared instance carries nothing from one tenant to another. |
| `port` | integer | required | The port its users connect to. |
| `env` | map of string to string | none | Environment its users get, `{host}` and `{port}` filled in: what points their tools at it (`npm_config_registry: http://{host}:{port}/`). Never a variable wicket controls (proxies, CA bundles, `WICKET_*`, `PATH`, `HOME`). |
| `drain` | `drop` | `drop` | What happens to its volumes when its node is released: its instances are stopped first, and their volumes go with the node. `keep` is refused until wicket can keep them. |

`wicket service add <manifest>` installs one from a snapshot: its manifest and its program's source are copied into `services/<name>/<sha256>/` under wicket's data directory, the source's digest pinned in the copy, and that is what runs (audited `service.added`, with its sha256, reach, tenancy and `public_only`). Changing what you installed changes nothing until you add it again. A service's zone may not ask for more (`escalation.request: true` is refused). `wicket service list` shows them; `wicket service remove` stops their instances and audits it. Each `wicket reconcile` pass keeps one instance on every active node its `node_selector` matches where a live box's zone `uses` it, per tenant unless `tenancy: shared` (only the service's own tenant's boxes, while wicket is single-tenant). It never starts one on a capacity lease's node past its lease, and an instance never holds such a node by itself. An instance no box has used for 10 minutes is stopped. One that ends is started again after a minute, then after twice as long each time one doesn't last (an hour at most). An instance is an ordinary run of the program on that node (`services/<name>/logs/<run>.log` in the data directory has its output).

An instance wicket started offers its `port` under the service's name once its box starts (a run that merely says `service:` offers nothing, and a spawned box is never a service). A service's zone is its instances' alone: any other run that names it is refused, since it would share the service's kept volumes. A box whose zone `uses` the service gets the service's `env` at its start, and its program starts once the link is up (up to 150 s, `WICKET_WAIT_LINKS` in its environment), so its first request finds the service. Once the instance on its node runs (up to 2 minutes), it gets a link to it: `<name>.wicket.internal:<port>`. The link's target is the instance wicket recorded starting for that service on the box's node and tenant (the shared one only for a shared service), and whose identity is the service's own zone and program: never a box that merely exposed a port under that name. It opens without a human only if the box's zone reaches everything the service's does. Otherwise a request is filed for exactly that link, and the link opens once it's granted. The box's output says what became of each.

## `placement`

What a box asks of its node ([#579](https://github.com/public/wicket/issues/579)), beside its [`limits`](#limits), which placement reserves as its requests. Today it decides where a woken agent goes ([nodes](nodes.md#placement)); `wicket run --node` and a spawn's placement hint name the node themselves.

| field | type | default | meaning |
|---|---|---|---|
| `node_selector` | map of string to string | none | Labels the node must have, each with this value (`gpu: a100`). |
| `tolerations` | list of strings | none | Node taints the box may go on despite: `key` (any value) or `key=value`. A node's taint keeps off every box that doesn't tolerate it. |
| `priority` | integer, -1000 to 1000 | `0` | Where the box waits for a node among its own tenant's boxes, and which boxes it may displace: higher first. It never moves another tenant's boxes. A spawned box's is at most its parent's, approved or not. |
| `preemptible` | boolean | `false` | A long-lived agent's box may be asked to hibernate to make room for a box of its tenant of higher priority. A spawned box of a preemptible parent is preemptible too. |
| `affinity` | list | none | What the box wants on its node: `{ service: <name> }` (a service its `zone.uses` names, whose instance runs there) or `{ volume: <name> }` (a volume its `zone.volumes` declares with `keep: true`, which the node holds). Preferred, unless `required: true`. |
| `anti_affinity` | list | none | What the box wants off its node: `{ zone: <name> }` (any box of that zone) or `{ principal: spiffe://… }` (that agent's boxes). Preferred, unless `required: true`. |

A node that lacks a required affinity, or runs a box a required anti-affinity names, is out; of the nodes left, the one meeting the most preferences goes first, then bin-packing decides. Placement decides where a box goes and nothing more: its authority is issued as for any run, and the node's own admission still decides. A node is seen with the boxes of the box's own tenant running there, the service instances it may use there, and, for a kept volume, whether a box of the box's zone runs there or ran there within the volume's retention; never another tenant's boxes. Waiting wakes are served first come, first served across tenants, and by `priority` within one ([nodes](nodes.md#placement)). A waiting wake with no node for it may ask its own tenant's long-lived agents marked `preemptible`, of a lower priority, to hibernate to make room, each audited as `placement.preempted`; nothing is revoked, an agent with a live child is never chosen (hibernating would stop the child), and one that doesn't hibernate within 5 minutes is left alone ([nodes](nodes.md#placement)). Programs are never preempted, by design: a program has no stop that keeps its work.

Keys are lowercase letters and digits with `.`, `_`, `-` or `/` inside, at most 63; values are letters, digits, `.`, `_` and `-`, at most 63. A manifest without `placement` reads the same to a node that doesn't know it; one with it needs its node on this release or later when it spawns there.

## `agent`

The agent's harness decides how long it runs (#249): its session stays open after each turn, and the
run ends when the agent calls wicket's [`finish`](mcp-tools.md#finish) tool or exits, at
`zone.limits.timeout`, or when its authority ends. wicket has no turn or idle timers.

| field | type | default | meaning |
|---|---|---|---|
| `name` | string | required | The agent's name, the last part of its SPIFFE ID (`…/a/<name>`). |
| `harness` | string | `claude-code` | What runs the agent in its box. `claude-code`: Claude Code, driven by wicket over its stream-json. `acp`: any agent that speaks the Agent Client Protocol, started from [`agent.acp`](#agentacp). See [harness modes](#harness-modes). |
| `model` | string | the harness's default | The model id passed to the agent. For `acp`, only with a known `acp.profile`. |
| `max_turns` | integer | none | The most agentic turns per task, passed to Claude Code. Not for `acp`. |
| `max_children` | integer | `0` | How many boxes this agent may start with `spawn`. `0`: it doesn't work. A child's own `max_children` counts against its parent's. |
| `in_box_subagents` | boolean | `true` | Whether Claude Code may run its own subagents (its Agent tool) inside the box. They share the box, its identity and its reach; their requests are attributed but not provably identified. `false` makes wicket children the only kind of subagent. |
| `image` | string | the agent image | The image the agent's box starts from: the installation's agent image, or one `zone.images` allows. A tag of a repository `zone.images` pins starts as that pin. `wicket run --image` overrides it. See [pins](#image-pins). |
| `env` | map of string to string | `{}` | Non-secret environment variables for the agent. Names are `[A-Z0-9_]+`. Refused: `HOME`, `PATH`, `USER`, and names starting `ANTHROPIC_`, `CLAUDE_`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `ALL_PROXY`, `SSL_`, `CURL_`, `NODE_`, `MCP_`, `GIT_SSL` or `WICKET_`. |
| `adapter_settings` | map | `{}` | Settings for the harness (for Claude Code, its `settings.json`). Only `includeCoAuthoredBy`, `attribution`, `outputStyle`, `alwaysThinkingEnabled` and `language` are allowed. `cleanupPeriodDays` is wicket's own and refused. |
| `remote` | object | none | The harness's remote modes: a session in the vendor's apps (for Claude Code, Remote Control), which the owner drives, or which wicket drives and the owner watches and steers (`drive`). See [`agent.remote`](#agentremote). |

### Harness modes

An agent is one kind of workload; its harness runs in one of four modes, and the harness's adapter
says which it has (a mode it hasn't is refused, saying so):

| mode | how | `claude-code` | `acp` |
|---|---|---|---|
| driven | the default: wicket starts the harness and gives it the task, prompts and messages as turns. The only mode that hibernates and wakes. | yes | yes |
| remote | `agent.remote`: the harness registers its own session with its vendor's apps, and the owner drives it from there. It starts when the owner sends its first message. | Remote Control (`claude remote-control`) | no |
| driven remote | `agent.remote` with `drive: true`: driven, as above (the task is its first turn; it hibernates and wakes), with its session also in the vendor's apps, where the owner watches it and can send it messages. | Remote Control turned on in `claude -p` | no |
| wrapped | `wicket wrap`: a command line another program launched runs in a box, keeping its launcher's stdio. | Remote Control's session processes | no |

(`spawn`'s `kind`, `agent` or `program`, is the workload type, not the harness.)

### `agent.remote`

| field | type | default | meaning |
|---|---|---|---|
| `name` | string | required | The session's name in the vendor's apps: 1–64 letters, digits, spaces, `-`, `_` or `.`. |
| `permission_mode` | string | `default`; `bypassPermissions` with `drive` | How far the harness acts without asking: `acceptEdits`, `auto`, `bypassPermissions`, `default`, `dontAsk` or `plan`, as `claude remote-control --permission-mode` takes them. `default` asks in the app before each action, as a session on the owner's machine would, so an unattended box waits on prompts nobody answers; `bypassPermissions` lets it work unattended. Any other value is refused. A harness adapter that has no permission modes refuses any but `default`. With `drive`, a driven Claude Code asks wicket, not the app: what wicket's rule allows is raised as a `TOOL` request for a human to decide (#363). |
| `drive` | boolean | `false` | wicket drives the session (#285): it starts the harness as in the driven mode and gives it the task, prompts and messages as turns, and the session is also registered in the vendor's apps. Needs a `task`. Claude Code's `claude -p` takes no Remote Control flag; wicket turns Remote Control on over its stdin (a `remote_control` control request) before the first turn. |

Whatever the permission mode, wicket's proxies decide what the box can reach: the mode only says
whether the harness asks the owner in the app first, as `bypassPermissions` does for the driven mode.

The zone's `llm.secret` is then the account login, which the box only ever holds as a placeholder.
See [drive a box from the Claude apps](../how-to/drive-a-box-from-the-claude-apps.md).

### `agent.acp`

For `harness: acp` (and only then). See [ACP agents](agents.md#acp-agents) for what wicket offers the agent
and how it answers it.

| field | type | default | meaning |
|---|---|---|---|
| `command` | list of strings | required | The agent's command inside the box, such as `[gemini, --experimental-acp]`. The image must already have it, at a pinned version: nothing is installed when the box starts. |
| `profile` | string | none | A wicket profile for a known adapter: what wicket itself sets for it. `claude-agent-acp`: Claude Code through its ACP adapter, with Claude Code's placeholders and routes, its `settings.json`, and wicket's `_meta.claudeCode.options`. None: a generic ACP agent, which gets wicket's shared routes and the manifest's `env` only; `model` and `adapter_settings` are refused. |

A manifest can't set `_meta`, MCP servers or a system prompt for an ACP agent: wicket sets those.
`remote` and `max_turns` are refused.

## `program`

| field | type | default | meaning |
|---|---|---|---|
| `name` | string | required | The program's name, the last part of its SPIFFE ID. |
| `command` | list of strings | required, not empty | The command run in the box, in `/workspace`. |
| `source` | string | none | A directory, relative to the manifest, copied into `/workspace`. |
| `digest` | string | none | The approved source digest (`wicket program digest DIR`: the source's plain tree, [store.md](../explanation/store.md)). When set, a run refuses any other source. Without it, the run prints the digest and is a development run. An earlier build's `wicket-program-v1` digest is accepted with a warning until `wicket zone pin` rewrites it. |
| `image` | string | the agent image | The image the program runs in, by tag or [pinned](#image-pins). The agent image has bash, curl, jq, git and python3. |

A program is an agent without a model: a program's zone has no model (a `zone.llm` section is an
error), and it may not ask for more by default. Its zone's [`escalation.request`](#zone) defaults to
`false`, so a request outside its reach is refused and nothing is queued. With `escalation: {
request: true }` it becomes a pending request, as an agent's would, and the program may wait with
`await_grant`.

## `zone`

| field | type | default | meaning |
|---|---|---|---|
| `name` | string | required | The zone's name, part of every SPIFFE ID in it (`…/z/<name>/…`). A spawned zone is named `<parent zone>.<name>.<parent run>`. |
| `isolation` | `gvisor` or `runc` | `gvisor` | The runtime. `runc` is plain containers, for development only. |
| `reach` | list of [reach rules](#reach) | `[]` | What the box may reach without asking. |
| `unlisted_hosts` | `escalate` or `hide` | `escalate` | What a host name no reach rule names is. `escalate`: a request to it becomes a pending request, unless its registered domain doesn't exist (only that is looked up, never the full name), when it is an unknown host. `hide`: it doesn't exist for the box (NXDOMAIN, and the proxy refuses the connection before TLS with a not-found status). |
| `wildcards` | `{ forbid, max_names }` | `{ forbid: false, max_names: 32 }` | Wildcard reach rules (`*.cdn.example`). wicket resolves every name under one on the host, so the names are a narrow channel out of the box. It resolves a name only after a request to it is allowed, and reaches at most `max_names` (at least 1) distinct names under each rule per run. With `forbid: true`, no reach rule may be a wildcard. `wicket zone` warns about each one. |
| `forbid` | list of [forbid rules](#forbid) | `[]` | Hosts or paths refused outright, whatever the method: no pending request, no grant. Checked before `reach`. |
| `inject` | list of [inject rules](#inject) | `[]` | Credentials the egress proxy adds to requests. |
| `llm` | [llm](#llm) | none | The model route. Required for an agent whose harness takes one (`llm: {}` takes the harness's route), refused for programs and for a generic `acp` agent. |
| `volumes` | list of [volumes](#volumes) | `[]` | Named directories that persist between runs of the zone. |
| `images` | list of strings | `[]` | Images boxes in this zone may start children from with `spawn`, besides their own: by tag, or [pinned by digest](#image-pins). |
| `accept_from` | list of principals or zone names | `[]` | Who may message agents in this zone besides parent and children: a principal (`spiffe://<domain>/t/<tenant>/z/<zone>/a/<agent>`), or a zone name for every agent in it. Those listed (a principal, or every agent in a listed zone) may also connect to its exposed ports. Senders are identified by wicket, never by their own claim. |
| `escalation` | `{ request, grant }` | `{ request: true, grant: true }`; for a program, `request: false` | Who in this zone may escalate ([#50](https://github.com/public/wicket/issues/50)). `request: false`: anything outside the zone's reach is "never allowed" instead of a pending request (`request_access`, `spawn` with `escalate`, `request_capacity` and `request_update` ask nobody). `grant: false`: the zone's agents can't [`decide`](mcp-tools.md#decide) their descendants' requests. A spawned zone keeps its parent's unless it narrows them, and can't be given one the parent lacks. |
| `uses` | list of service names | `[]` | Per-node services the zone's boxes use ([#579](https://github.com/public/wicket/issues/579)): each reached at `<name>.wicket.internal`, the instance on the box's own node. **Using a service is having its reach**: a box that uses an npm cache can make it fetch whatever the box names, so its link to the service opens without a human only if this zone's reach covers the service's. A spawned zone may use only the services its parent uses. See [`service`](#service). |
| `limits` | [limits](#limits) | see below | Resources, time and output. |

### `reach`

A request is allowed by reach if some rule matches its host name, method and path, and its
[risk](risk-classes.md) is R2 or lower or the rule has `allow_dangerous`. Rules are a set, not an
ordered list.

| field | type | default | meaning |
|---|---|---|---|
| `host` | string | required | A host name, exact (`api.github.com`) or `*.example.com` for one or more labels under `example.com` (not `example.com` itself). Matched ignoring case and a trailing dot. No `/`. |
| `methods` | list of strings | `[GET, HEAD]` | The methods allowed. The proxy forwards only GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS. |
| `paths` | list of globs | `["/**"]` | Path globs, each starting with `/` (a request's path always does; a manifest with one that doesn't is refused): `*` matches within one segment, `**` across segments. Case-sensitive. The query string isn't matched. |
| `allow_dangerous` | boolean | `false` | Allow requests the dangerous-pattern list rates R3 or R4 without a grant. |
| `decode_slash` | list of segment numbers | `[]` | Path segments in which one encoded slash, `%2F` or `%2f`, between two non-empty parts, is decided as `/` for this rule's host ([#664](https://github.com/public/wicket/issues/664)). Segments are numbered as the client wrote the path, 1 for the first. For an API that names one resource with an encoded slash: npm asks for a scoped package as `/@scope%2fname`, so `decode_slash: [1]` has every rule and forbid of the zone on the host read it as `/@scope/name`. The decoded path must still be canonical. The request goes upstream as written, so the option assumes the upstream reads `%2F` there as `/` (as npm's registry does); use it only for such an API. Only for a host named exactly (not `*.`). The box's token carries it, and a node decodes only what the token allows. A zone using it runs only on nodes at protocol 19 or later. Otherwise an encoded slash is refused. A spawned or linked zone may use it only where its parent's rule for the host does, and standing reach never carries it. |

A host allowed wholesale (every forwarded method, `/**`, `allow_dangerous` where the host can be
rated R3+, nothing forbidden or injected, not the model host) is spliced through rather than
inspected: see [performance](../explanation/performance.md#splice-through-for-hosts-allowed-wholesale).
`wicket zone MANIFEST` shows which hosts are.

### `forbid`

| field | type | default | meaning |
|---|---|---|---|
| `host` | string | required | As in `reach`. |
| `paths` | list of globs | `["/**"]` | As in `reach` (each starting with `/`), but matched ignoring ASCII case, since many upstreams fold case. `/**` forbids the whole host, which then can't be connected to at all. A glob that doesn't compile forbids everything on the host. |

#### Git pushes

A git push over smart HTTP is decided as one request, the push of its repository
(`POST {repo}/git-receive-pack`): its ref discovery (`GET {repo}/info/refs?service=git-receive-pack`)
and its upload share one pending request, and one approval covers both, with git's retries, for
5 minutes (whatever uses the approver picked). An agent asking ahead with `request_access` for
either URL asks for that same request. Fetches are reads, as before.

wicket decides which repositories a box may push to, not which refs: it doesn't read the push's
body. Limit what a push can change where the forge enforces it, by injecting a token scoped to the
repositories the task needs and protecting branches and tags with the forge's own rules (on GitHub,
rulesets or branch protection).

### `inject`

| field | type | default | meaning |
|---|---|---|---|
| `host` | string | required | The host name the credential goes to. |
| `header` | string | required | The one header it goes in (`Authorization`). |
| `format` | string | `{secret}` | The header's value. `{secret}` is the secret; `{basic:USER}` is `base64(USER:secret)`, so `Basic {basic:x-access-token}` is HTTP Basic with a token as password. Must contain one of the two. |
| `secret` | string | required | The vault secret's name. Its host binding must cover `host`, or the run is refused. |
| `optional` | boolean | `false` | If the secret isn't in the vault, send requests to the host without it instead of refusing to start. The secret is read at each request, so one set later is used from the next (#415). |

A credential is only ever sent over HTTPS: plain HTTP to a host with an inject rule is refused.

### `llm`

| field | type | default | meaning |
|---|---|---|---|
| `provider` | string | the harness's | The model proxy's profile for the provider's API. `anthropic` is the only one. |
| `secret` | string | the harness's | The vault secret holding the model credential. Never an API key. For `agent.remote`, the account login. |
| `upstream` | URL | the harness's | The model's base URL. Its host must be in the secret's host binding. Changed for a mock model in tests. |

The route's defaults belong to the agent's harness, and its adapter fills them in when the
manifest is loaded, so core and the proxies take them as data (#255). For `claude-code`, and for
`acp` with `profile: claude-agent-acp`, the route is provider `anthropic`, secret `claude-oauth` (the
Claude subscription token from `claude setup-token`, or linked to the host's Claude login) and
upstream `https://api.anthropic.com`. A generic `acp` agent has no route. The vault has no default
host bindings: `wicket secret set` and `wicket secret link` bind a harness's default secret to its
upstream's host when it is stored with no binding of its own.
| `max_requests` | integer | `300` | The most model requests over the agent's life. |
| `max_output_tokens` | integer | `400000` | The most output tokens over the agent's life. Each call reserves its `max_tokens` up front. |
| `max_input_tokens` | integer | none | The most input tokens, cache reads and writes included. None: no input cap. |
| `allow_server_tools` | boolean | `false` | Forward server-side tools (web search and fetch), URL sources, the MCP connector and containers. They make the provider reach hosts the zone never allowed, so they are refused by default. |
| `models` | list of strings | none (any model) | The models a box may call: exact names (`claude-opus-4-5`) or prefixes ending in `*` (`claude-sonnet-*`). The model proxy refuses, with a 403, a call naming another model or none. `agent.model` must be in the list. A zone a box starts may only narrow it: with a list here, a child must have one, each entry within one of these (a prefix only within a prefix). |

With `models`, list every model the harness calls on its own too. Claude Code, for one, uses a small
model (Haiku) for background work such as titles and summaries, and those calls are refused if it
isn't listed (#366).

### `volumes`

| field | type | default | meaning |
|---|---|---|---|
| `name` | string | required | `[a-z0-9-]+`, unique within the zone. |
| `path` | string | required | Where it is mounted, read-write: an absolute path under `/volumes/`, with no `..`. |
| `persist` | `durable`, `node` or `cache` | `node` | What happens when an agent hibernates. `durable`: the agent's own, bundled with its state and restored on wake. `node`: shared by the zone on the node that runs it, kept there, not bundled. `cache`: never bundled, and may be empty after a wake on another node. |
| `keep` | boolean | `false` | Kept on the node across runs ([#377](https://github.com/public/wicket/issues/377)). Not kept, the volume is the run's own cache: empty when the run starts, deleted once the run's work is collected, or `retention` after the run ends if it never is. Not for a `durable` volume (that one is the agent's, and goes with its state). |
| `retention` | duration | kept: none; a cache: `7d` | A kept volume: how long it may go unused before its node deletes it (none: never). A run's cache: how long after the run ends it is kept if the run's work isn't collected. |

A kept volume is per tenant and zone, and shared by the zone's runs: what one run leaves there the
next one reads. Any other volume is its run's alone. A control host from before #377 marks no
volume either way, and its nodes keep every volume, as before.

### `limits`

| field | type | default | meaning |
|---|---|---|---|
| `memory` | size | `2g` | Memory, swap included (a box never swaps past it). At least 1 byte. The agent is warned at 90% of it; a box over it is killed by the kernel, and its run says so ([the box](box.md#runtime)). |
| `cpus` | number | `1` | CPUs. At least 0.01. |
| `pids` | integer | `512` | Processes. At least 1. |
| `timeout` | duration | `30m` | Total time in a box over the agent's life, time waiting between turns included. Not zero. The box is stopped when it is reached. |
| `authority` | duration | the `timeout` | How long the box's authority lasts from the run's start: its token's block 0, and so how long its node keeps working for it without the control host. Never longer than `timeout`, never zero. The node stops the box when it ends, unless a principal who may grant it renews it first (`wicket grant renew <run> --ttl`, or a parent agent's `decide`; [#56](https://github.com/public/wicket/issues/56)), never past the `timeout`. |
| `output` | size | `64m` | How much of the box's output (stdout and stderr) its node's host and the control host's transcript keep, each. At least `64k`. |
| `on_output_full` | `keep_newest` or `stop` | `keep_newest` | When output passes `output`: keep the newest (the oldest goes, and the bytes dropped are recorded), or stop the box. |
| `memory_advice` | string | none | Advice for this zone's work, appended to the warning its agent gets at 90% of `memory` ([the box](box.md#runtime)), for example ``CARGO_BUILD_JOBS=1, `make -j1`, one test run at a time``. One line of at most 300 characters. The warning itself says only what holds for any box: use less memory now and save work in progress. A spawned zone inherits it, and may replace it (an empty string: none). |
| `exit_grace` | duration | `30s` | How long the harness has to exit by itself once its session is over: after the agent called [`finish`](mcp-tools.md#finish) and its session closed (then the box is stopped, the run recorded as succeeded with the processes left named), or when it asked to [`hibernate`](mcp-tools.md#hibernate) while other processes ran in the box (then they are stopped and it hibernates). |

Docker reads a zero limit as "no limit", so every limit must be a positive bound.

## Spawned zones

The `spawn` tool takes a `zone` object with these fields. What it leaves out: no reach and no
credentials; the parent's limits (and its `memory_advice` even when it gives its own limits), isolation, `unlisted_hosts` and `wildcards`; for an agent, half the parent's
remaining model budget. The zone must be a subset of the parent's, as
[concepts](../explanation/concepts.md#zones-and-the-subset-rule) explains, or it is refused with
every violation listed.

## Image pins

An image is named by a tag (`wicket-self:dev`) or pinned by digest (#192): `name@sha256:<64 lowercase
hex>`, or `sha256:<64 hex>` alone. Anything with `@` must be a valid pin, or the manifest is refused.

- **A pin is what a box starts.** Its node finds the image by the pinned reference, or by the digest
  alone, and starts it by its id, the digest Docker reports for it (`docker image inspect`'s `Id`, or one
  of its `RepoDigests`). Moving a tag to another image changes nothing.
- **Delivered if missing.** A remote node that hasn't the image gets it from the control host, over the
  node channel, and verifies it against the pin before importing it ([nodes](nodes.md#images-on-nodes)).
  If neither has it, the node refuses the box.
- **What a pinned entry allows.** In `zone.images`, a pinned entry allows that digest, by the pin
  itself, by the digest alone, or by any tag of the same repository: a child asking for
  `wicket-self:dev` when the zone pins `wicket-self@sha256:…` starts as the pin. Another digest of the
  repository is refused.
- **A tag entry** allows that tag, resolved when the box starts.
- **A child's default image** (one that names none) is its parent's image, pinned to the digest the
  parent's box started as.
- **Recorded:** every box's digest, in its run's record (`ctl/run.json`'s `image_digest`) and the
  audit (`run.image`).
- **Accepted by a grant (#258):** a run an operator starts with a pinned image is accepted by a
  grant on that digest (`run`, in the run's zone), the one "may this digest run" check. Running
  the manifest records the operator's grant for a day if none is live (`digest.granted`), and each
  run is accepted by one (`digest.accepted`, naming it). A child's image, pinned to its parent's,
  is decided where it is spawned and isn't granted again.
- **Requiring pins:** an installation can require every image to be pinned (`images.yaml`,
  [files](files.md)). `wicket zone pin MANIFEST` rewrites a manifest's tags to their current digests, and
  `wicket image digest REF…` prints them.
