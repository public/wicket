# Manifest

A manifest is the YAML file `wicket run` takes: the task, one workload (an agent or a program) and
the zone it runs in. This page lists every field. The source of truth is
`crates/wicket-core/src/manifest.rs`; spawned zones (the `spawn` tool's `zone`) use the same `zone`
schema ([MCP tools](mcp-tools.md#spawn)).

Every object refuses fields it doesn't know (`deny_unknown_fields`), so a misspelt key is an error,
not a silent default. Durations are [humantime](https://docs.rs/humantime) strings (`90s`, `15m`,
`2h`, `1h 30m`). Sizes are numbers with an optional `b`, `k`, `m` or `g` suffix, in binary units
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
| `task` | string | `""` | The trusted task text, given to the agent as its first turn (or to a program, which may ignore it). It is the only input policy derivation ever sees. Required for agents, except a remote session (`agent.remote`), whose messages come from the vendor's app. `wicket run --task` replaces it. |
| `agent` | [agent](#agent) | none | A Claude Code agent. |
| `program` | [program](#program) | none | A deterministic workload with no model. |
| `zone` | [zone](#zone) | required | Where the workload runs, and what it may reach. |

Exactly one of `agent` and `program` must be given.

## `agent`

The agent's harness decides how long it runs (#249): its session stays open after each turn, and the
run ends when the agent calls wicket's [`finish`](mcp-tools.md#finish) tool or exits, at
`zone.limits.timeout`, or when its authority ends. wicket has no turn or idle timers.

| field | type | default | meaning |
|---|---|---|---|
| `name` | string | required | The agent's name, the last part of its SPIFFE ID (`…/a/<name>`). |
| `kind` | string | `claude-code` | The harness. `claude-code`: Claude Code, driven by wicket over its stream-json. `acp`: any agent that speaks the Agent Client Protocol, started from [`agent.acp`](#agentacp). |
| `model` | string | the harness's default | The model id passed to the agent. For `acp`, only with a known `acp.profile`. |
| `max_turns` | integer | none | The most agentic turns per task, passed to Claude Code. Not for `acp`. |
| `max_children` | integer | `0` | How many boxes this agent may start with `spawn` or `spawn_agent`. `0`: neither tool works. A child's own `max_children` counts against its parent's. |
| `in_box_subagents` | boolean | `true` | Whether Claude Code may run its own subagents (its Agent tool) inside the box. They share the box, its identity and its reach; their requests are attributed but not provably identified. `false` makes wicket children the only kind of subagent. |
| `image` | string | the agent image | The image the agent's box starts from: the installation's agent image, or one `zone.images` allows. A tag of a repository `zone.images` pins starts as that pin. `wicket run --image` overrides it. See [pins](#image-pins). |
| `env` | map of string to string | `{}` | Non-secret environment variables for the agent. Names are `[A-Z0-9_]+`. Refused: `HOME`, `PATH`, `USER`, and names starting `ANTHROPIC_`, `CLAUDE_`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `ALL_PROXY`, `SSL_`, `CURL_`, `NODE_`, `MCP_`, `GIT_SSL` or `WICKET_`. |
| `adapter_settings` | map | `{}` | Settings for the harness (for Claude Code, its `settings.json`). Only `includeCoAuthoredBy`, `attribution`, `outputStyle`, `alwaysThinkingEnabled` and `language` are allowed. `cleanupPeriodDays` is wicket's own and refused. |
| `remote` | object | none | A remote session the owner drives from the vendor's apps (for Claude Code, Remote Control). See [`agent.remote`](#agentremote). |

### `agent.remote`

| field | type | default | meaning |
|---|---|---|---|
| `name` | string | required | The session's name in the vendor's apps: 1–64 letters, digits, spaces, `-`, `_` or `.`. |

The zone's `llm.secret` is then the account login, which the box only ever holds as a placeholder.
See [drive a box from the Claude apps](../how-to/drive-a-box-from-the-claude-apps.md).

### `agent.acp`

For `kind: acp` (and only then). See [ACP agents](agents.md#acp-agents) for what wicket offers the agent
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
| `digest` | string | none | The approved source digest (`wicket program digest DIR`). When set, a run refuses any other source. Without it, the run prints the digest and is a development run. |
| `on_pending` | `fail` or `wait` | `fail` | What happens to a request outside the zone's reach. `fail`: refused, nothing queued. `wait`: it becomes a pending request, as an agent's would, and the program may wait with `await_grant`. |
| `image` | string | the agent image | The image the program runs in, by tag or [pinned](#image-pins). The agent image has bash, curl, jq, git and python3. |

A program's zone has no model: a `zone.llm` section is an error.

## `zone`

| field | type | default | meaning |
|---|---|---|---|
| `name` | string | required | The zone's name, part of every SPIFFE ID in it (`…/z/<name>/…`). A spawned zone is named `<parent zone>.<name>.<parent run>`. |
| `isolation` | `gvisor` or `runc` | `gvisor` | The runtime. `runc` is plain containers, for development only. |
| `reach` | list of [reach rules](#reach) | `[]` | What the box may reach without asking. |
| `unlisted_hosts` | `escalate` or `hide` | `escalate` | What a host no reach rule names is. `escalate`: a request to it becomes a pending request, unless its registered domain doesn't exist (only that is looked up, never the full name), when it is an unknown host. `hide`: it doesn't exist for the box (NXDOMAIN, and the proxy refuses the connection before TLS with a not-found status). |
| `wildcards` | `{ forbid, max_names }` | `{ forbid: false, max_names: 32 }` | Wildcard reach rules (`*.cdn.example`). wicket resolves every name under one on the host, so the names are a narrow channel out of the box. It resolves a name only after a request to it is allowed, and reaches at most `max_names` (at least 1) distinct names under each rule per run. With `forbid: true`, no reach rule may be a wildcard. `wicket zone` warns about each one. |
| `forbid` | list of [forbid rules](#forbid) | `[]` | Hosts or paths refused outright, whatever the method: no pending request, no grant. Checked before `reach`. |
| `inject` | list of [inject rules](#inject) | `[]` | Credentials the egress proxy adds to requests. |
| `llm` | [llm](#llm) | none | The model route. Required for agents (`llm: {}` takes every default), refused for programs. |
| `volumes` | list of [volumes](#volumes) | `[]` | Named directories that persist between runs of the zone. |
| `images` | list of strings | `[]` | Images boxes in this zone may start children from with `spawn`, besides their own: by tag, or [pinned by digest](#image-pins). |
| `accept_from` | list of zone names | `[]` | Zones whose agents may message agents in this zone, and connect to its exposed ports, besides parent and children. Senders are identified by wicket, never by their own claim. |
| `escalation` | `{ request, grant }` | `{ request: true, grant: true }` | Who in this zone may escalate ([#50](https://github.com/public/wicket/issues/50)). `request: false`: anything outside the zone's reach is "never allowed" instead of a pending request (`request_access`, `spawn` with `ask_human`, `request_capacity` and `request_update` ask nobody). `grant: false`: the zone's agents can't [`decide`](mcp-tools.md#decide) their descendants' requests. A spawned zone keeps its parent's unless it narrows them, and can't be given one the parent lacks. |
| `limits` | [limits](#limits) | see below | Resources, time and output. |

### `reach`

A request is allowed by reach if some rule matches its host, method and path, and its
[risk](risk-classes.md) is R2 or lower or the rule has `allow_dangerous`. Rules are a set, not an
ordered list.

| field | type | default | meaning |
|---|---|---|---|
| `host` | string | required | An exact host (`api.github.com`), or `*.example.com` for one or more labels under `example.com` (not `example.com` itself). Matched ignoring case and a trailing dot. No `/`. |
| `methods` | list of strings | `[GET, HEAD]` | The methods allowed. The proxy forwards only GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS. |
| `paths` | list of globs | `["/**"]` | Path globs: `*` matches within one segment, `**` across segments. Case-sensitive. The query string isn't matched. |
| `allow_dangerous` | boolean | `false` | Allow requests the dangerous-pattern list rates R3 or R4 without a grant. |

A host allowed wholesale (every forwarded method, `/**`, `allow_dangerous` where the host can be
rated R3+, nothing forbidden or injected, not the model host) is spliced through rather than
inspected: see [performance](../explanation/performance.md#splice-through-for-hosts-allowed-wholesale).
`wicket zone MANIFEST` shows which hosts are.

### `forbid`

| field | type | default | meaning |
|---|---|---|---|
| `host` | string | required | As in `reach`. |
| `paths` | list of globs | `["/**"]` | As in `reach`, but matched ignoring ASCII case, since many upstreams fold case. `/**` forbids the whole host, which then can't be connected to at all. A glob that doesn't compile forbids everything on the host. |

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
| `host` | string | required | The host the credential goes to. |
| `header` | string | required | The one header it goes in (`Authorization`). |
| `format` | string | `{secret}` | The header's value. `{secret}` is the secret; `{basic:USER}` is `base64(USER:secret)`, so `Basic {basic:x-access-token}` is HTTP Basic with a token as password. Must contain one of the two. |
| `secret` | string | required | The vault secret's name. Its host binding must cover `host`, or the run is refused. |
| `optional` | boolean | `false` | If the secret isn't in the vault, send requests to the host without it instead of refusing to start. |

A credential is only ever sent over HTTPS: plain HTTP to a host with an inject rule is refused.

### `llm`

| field | type | default | meaning |
|---|---|---|---|
| `provider` | string | `anthropic` | The only provider supported. |
| `secret` | string | `claude-oauth` | The vault secret holding the Claude subscription token (from `claude setup-token`, or linked to the host's Claude login). Never an API key. For `agent.remote`, the account login. |
| `upstream` | URL | `https://api.anthropic.com` | The model's base URL. Its host must be in the secret's host binding. Changed for a mock model in tests. |
| `max_requests` | integer | `300` | The most model requests over the agent's life. |
| `max_output_tokens` | integer | `400000` | The most output tokens over the agent's life. Each call reserves its `max_tokens` up front. |
| `max_input_tokens` | integer | none | The most input tokens, cache reads and writes included. None: no input cap. |
| `allow_server_tools` | boolean | `false` | Forward server-side tools (web search and fetch), URL sources, the MCP connector and containers. They make the provider reach hosts the zone never allowed, so they are refused by default. |

### `volumes`

| field | type | default | meaning |
|---|---|---|---|
| `name` | string | required | `[a-z0-9-]+`, unique within the zone. |
| `path` | string | required | Where it is mounted, read-write: an absolute path under `/volumes/`, with no `..`. |
| `persist` | `durable`, `node` or `cache` | `node` | What happens when an agent hibernates. `durable`: the agent's own, bundled with its state and restored on wake. `node`: shared by the zone on the node that runs it, kept there, not bundled. `cache`: never bundled, and may be empty after a wake on another node. |

Volumes are per tenant and zone, and shared by the zone's runs: what one run leaves there the next
one reads.

### `limits`

| field | type | default | meaning |
|---|---|---|---|
| `memory` | size | `2g` | Memory, swap included (a box never swaps past it). At least 1 byte. The agent is warned at 90% of it; a box over it is killed by the kernel, and its run says so ([the box](box.md#runtime)). |
| `cpus` | number | `1` | CPUs. At least 0.01. |
| `pids` | integer | `512` | Processes. At least 1. |
| `timeout` | duration | `30m` | Total time in a box over the agent's life, time waiting between turns included. Not zero. The box is stopped when it is reached. |
| `authority` | duration | the `timeout` | How long the box's authority lasts from the run's start: its token's block 0, and so how long its node keeps working for it without the control host. Never longer than `timeout`, never zero. The node stops the box when it ends. |
| `output` | size | `64m` | How much of the box's output (stdout and stderr) its node's host and the control host's transcript keep, each. At least `64k`. |
| `on_output_full` | `keep_newest` or `stop` | `keep_newest` | When output passes `output`: keep the newest (the oldest goes, and the bytes dropped are recorded), or stop the box. |

Docker reads a zero limit as "no limit", so every limit must be a positive bound.

## Spawned zones

The `spawn` tool takes a `zone` object with these fields. What it leaves out: no reach and no
credentials; the parent's limits, isolation, `unlisted_hosts` and `wildcards`; for an agent, half the parent's
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
- **Requiring pins:** an installation can require every image to be pinned (`images.yaml`,
  [files](files.md)). `wicket zone pin MANIFEST` rewrites a manifest's tags to their current digests, and
  `wicket image digest REF…` prints them.
