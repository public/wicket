---
name: wicket-manifest
description: Use when writing or changing a wicket manifest (the YAML that wicket run takes) or a zone for spawn - choosing reach, forbid and inject rules, limits and memory_advice, escalation, the llm route and budget, volumes, an agent or a program - and when checking one with wicket zone before running it.
---

# Writing a wicket manifest

A manifest is one task, one workload (an `agent` or a `program`) and the **zone** it runs in: what
its box may reach without asking, what it may never reach, the credentials added on the way out,
and its limits. Every field, with its default, is in the
[manifest reference](https://github.com/public/wicket/blob/main/docs/reference/manifest.md); the
recipe is [write a zone for a project](https://github.com/public/wicket/blob/main/docs/how-to/write-a-zone-for-a-project.md).
Unknown fields are errors, so a misspelt key fails loudly.

```yaml
task: |
  Run the tests of the project in /workspace, fix the first failure, commit it on a new branch,
  and write what you did to /workspace/out/result.json.
agent:
  name: fixer
  env: { CARGO_TARGET_DIR: /volumes/target }
zone:
  name: myproject
  reach:
    - { host: api.example.com, paths: ["/v1/projects/myproject/**"] }
    - { host: git.example.com, methods: [GET, POST],
        paths: ["/acme/app.git/info/refs", "/acme/app.git/git-upload-pack"] }
  forbid:
    - { host: api.example.com, paths: ["/v1/admin/**"] }
  inject:
    - { host: api.example.com, header: Authorization, format: "Bearer {secret}", secret: example-ro }
  llm: { max_requests: 200, max_output_tokens: 200000 }
  volumes:
    - { name: target, path: /volumes/target, persist: cache }
  limits: { memory: 4g, cpus: 2, timeout: 2h, memory_advice: "one cargo build at a time, CARGO_BUILD_JOBS=2" }
```

## Start narrow, widen from what it asks

1. Begin with `reach: []` and run it: every request the work needs shows in `wicket pending`.
2. Turn what you'd approve every time into **reach** rules. Name hosts exactly; paths as narrowly as
   the work allows (`*` is one segment, `**` any number). Methods default to `GET` and `HEAD`.
   R3/R4 requests (pushes, merges, deletes) still need a grant inside reach unless the rule says
   `allow_dangerous: true`: leave that off unless you mean it
   ([risk classes](https://github.com/public/wicket/blob/main/docs/reference/risk-classes.md)).
3. What you'd approve only sometimes stays out of reach, so a human decides each one.

## The zone's parts

- **`forbid`**: refused outright, checked before reach; no request, no grant. Paths match ignoring
  case. Use it for what must never happen, even by mistake.
- **`unlisted_hosts`**: `escalate` (default) makes any other host a pending request; `hide` makes it
  not exist. Use `hide` for zones that read untrusted content.
- **`inject`**: a vault secret put into one `header` toward one `host`, over HTTPS only. The secret's
  own host binding must cover the host (`wicket secret set NAME --hosts …`). `{basic:USER}` renders
  HTTP Basic (git with a token); `optional: true` runs without it when it isn't stored. Keep write
  credentials out of zones that read untrusted content.
- **`llm`**: the model route and budget. `llm: {}` takes the harness's route (for Claude Code, the
  `claude-oauth` subscription token). `max_requests`, `max_output_tokens` and `max_input_tokens`
  are over the agent's whole life, wakes included. A program has no `llm`.
- **`limits`**: `memory` (swap included; the agent is warned at 90% and the box is killed over it),
  `cpus`, `pids`, `timeout` (total time in a box), `authority`, `output`, `exit_grace`. Every limit
  is a positive bound.
- **`limits.memory_advice`**: one line (at most 300 characters) appended to the 90% warning, for
  what this zone's work should do about memory: `make -j1`, one test run at a time. A spawned zone
  inherits it.
- **`volumes`**: named directories under `/volumes/` that persist between runs of the zone: caches,
  build output, datasets. `persist: cache` is never bundled when an agent hibernates, `node` (the
  default) stays on the node, `durable` travels with the agent.
- **`escalation`**: `{ request, grant }`. `request: false` makes anything outside reach "never
  allowed" (no one is asked); `grant: false` stops the zone's agents deciding their children's
  requests. Programs default to `request: false`.
- **`accept_from`**: who besides parent and children may message this zone's agents or connect to
  their exposed ports: principals or zone names.
- **`images`**: images the zone's agents may start children from. Pin them by digest with
  `wicket zone pin manifest.yaml`.

## Agent or program

- An **agent** (`agent:`) has a model and a harness (`claude-code` by default, or `acp`). Its task is
  its first turn, and it decides when it's done. `max_children` lets it start boxes with `spawn`;
  `adapter_settings` passes a few allowlisted harness settings; `env` passes non-secret variables
  (wicket's own names are refused).
- A **program** (`program:`) is a command with no model: a service, a deterministic job. It may not
  ask for more unless its zone says `escalation: { request: true }`. Pin its source with `digest`
  ([run a program](https://github.com/public/wicket/blob/main/docs/how-to/run-a-program.md)).

## Zones for `spawn`

An agent's `spawn` takes the same `zone` object. It must be a subset of the caller's zone (reach,
credentials, budget, limits, time, images, `max_children`); what it leaves out is narrowed for it
([spawned zones](https://github.com/public/wicket/blob/main/docs/reference/manifest.md#spawned-zones)).

## Check it: `wicket zone`

```sh
wicket zone manifest.yaml
```

It loads the manifest as `wicket run` does (an unknown field or a bad value is an error, said
here rather than at run time), and shows each host the zone reaches:
`SPLICED` (allowed wholesale, decided on its name and relayed without inspection) or `INSPECTED`
(with why), and warns about every wildcard rule (the names under one are a narrow channel out;
`wildcards: { forbid: true }` refuses them). Run it after every change, and read every line before
you widen a zone.
