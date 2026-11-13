# Write a zone for a project

A zone says what a box may reach without asking. Everything else becomes a pending request, is
refused outright (`forbid`), or doesn't exist for the box (`unlisted_hosts: hide`). This page builds
one for a project, narrow first and widened by what the work turns out to need. Every field is in
the [manifest reference](../reference/manifest.md).

## 1. Start from the task, with no reach

Write the task and an agent, and give the zone nothing but a model budget and limits:

```yaml
task: |
  Run the test suite of the project in /workspace and fix the first failing test.
agent:
  name: fixer
  max_turns: 60
zone:
  name: myproject
  reach: []
  llm: { max_requests: 100, max_output_tokens: 150000 }
  limits: { memory: 4g, cpus: 2, timeout: 1h }
```

(The output in step 7 is for the whole zone this page builds.) Run it with the project copied in (`--workdir .`) and watch what it asks for:

```sh
wicket run fixer.yaml --workdir .
wicket pending                     # in another terminal
```

Each out-of-reach request shows its method, host, path, risk class and the agent's reason.

## 2. Add reach for what it needs

Turn the requests you would approve every time into reach rules. Name hosts exactly, and paths as
narrowly as the work allows; `*` matches one path segment and `**` any number:

```yaml
  reach:
    - { host: registry.npmjs.org }                                  # GET and HEAD, every path
    - { host: api.github.com, paths: ["/repos/acme/app", "/repos/acme/app/**"] }
    - { host: github.com, methods: [GET, POST],                     # git fetch over HTTPS
        paths: ["/acme/app.git/info/refs", "/acme/app.git/git-upload-pack"] }
```

- A rule's methods default to GET and HEAD. Add others only where the work writes.
- R3 and R4 requests (pushes, merges, workflow edits, comments on GitHub; cloud APIs) need a grant
  even inside reach unless the rule says `allow_dangerous: true`. Leave that off unless you mean it
  ([risk classes](../reference/risk-classes.md)).
- What you would approve only sometimes stays out of reach: a human decides each one.

## 3. Forbid what must never happen

`forbid` is checked before reach and can't be approved:

```yaml
  forbid:
    - { host: api.github.com, paths: ["/repos/acme/app/actions/**"] }
    - { host: api.github.com, paths: ["/repos/acme/prod/**"] }
```

Forbid paths match ignoring ASCII case, since GitHub and many upstreams fold it.

## 4. Decide what an unlisted host is

`unlisted_hosts: escalate` (the default) lets the agent ask for anything. `hide` makes every host the
zone doesn't name look like it doesn't exist: no requests to approve, and nothing for the agent to
learn about. Use `hide` for zones that read untrusted content.

## 5. Add credentials, bound to their hosts

```yaml
  inject:
    - { host: api.github.com, header: Authorization, format: "Bearer {secret}", secret: github-acme }
```

Store the secret bound to the same host: `wicket secret set github-acme --hosts api.github.com`
([store and link secrets](store-and-link-secrets.md)). Keep write credentials out of zones that read
anything untrusted: wicket checks where a request goes, not what it carries
([limits](../explanation/limits.md#data-inside-a-zones-reach)).

## 6. Keep caches and state

```yaml
agent:
  env: { CARGO_HOME: /volumes/cargo, CARGO_TARGET_DIR: /volumes/target }
zone:
  volumes:
    - { name: cargo, path: /volumes/cargo, persist: cache }
    - { name: target, path: /volumes/target, persist: cache }
```

Volumes persist between runs of the zone. `persist` matters only for long-lived agents: `cache`
volumes are never bundled when an agent hibernates.

## 7. Check it

```sh
wicket zone fixer.yaml
```

```text
zone myproject: egress over HTTPS (HTTP/3 is always terminated and inspected)
  registry.npmjs.org  INSPECTED  reach limits methods, paths or risk
  api.github.com      INSPECTED  a forbid rule names api.github.com
  github.com          INSPECTED  reach limits methods, paths or risk
```

A host allowed wholesale (every method, `/**`, nothing forbidden or injected) is `SPLICED`: decided
on its name and relayed without inspection, which is much cheaper but sees no paths
([performance](../explanation/performance.md#splice-through-for-hosts-allowed-wholesale)). A forbid
rule on the host keeps it inspected.

## 8. Let agents start narrower boxes

With `agent.max_children: N` the agent can `spawn` children in zones it writes, each a subset of
this one; give `images:` any images they may use besides the agent's own, and `accept_from:` the
zones that may message or connect to this one. The [second tutorial](../tutorials/approvals-children-and-links.md)
shows it.

`examples/self-hosting/manifest.yaml` is a whole zone written this way, for wicket's own source.

## 9. Pin its images by digest

A tag (`wicket-self:dev`) means whatever it points to now. Pin the images a zone may start, so what it
allows is exactly what you reviewed:

```
wicket zone pin manifest.yaml --dry-run   # what would change
wicket zone pin manifest.yaml             # rewrites zone.images, agent.image, program.image
```

Each tag becomes `name@sha256:…`, the digest this installation's Docker has for it. A pinned box
starts as that digest on its node, whatever the tag points to later, and the node refuses it if it
doesn't have that image. `wicket image` prints the digest of what it built.
[Image pins](../reference/manifest.md#image-pins) has the rules.

To require pins for every run on the installation, put `require_digests: true` in
`<data dir>/images.yaml`.
