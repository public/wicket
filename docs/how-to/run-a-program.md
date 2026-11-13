# Run a program instead of an agent

A program is a deterministic workload with no model: a script or a service, in the same box, with
the same egress control and audit as an agent. `examples/program-repo-stats.yaml` runs
`programs/repo-stats/stats.sh`.

## 1. Write the manifest

```yaml
task: Weekly public stats for octocat/Hello-World.
program:
  name: repo-stats
  source: ../programs/repo-stats      # relative to the manifest; copied into /workspace
  command: [bash, /workspace/stats.sh]
  on_pending: fail                    # out-of-reach requests fail; nothing is queued for a human
zone:
  name: stats
  reach:
    - { host: api.github.com, paths: ["/repos/octocat/Hello-World"] }
  limits: { memory: 512m, cpus: 1, timeout: 2m }
```

A program zone has no `llm` section. `on_pending: wait` makes out-of-reach requests pending, as an
agent's are, for a program that waits with `await_grant`. `program.image` runs it in another image
(the default agent image has bash, curl, jq, git and python3).

## 2. Run it during development

```sh
wicket run examples/program-repo-stats.yaml
```

```text
[wicket] program repo-stats is not pinned (development run); its digest is sha256:…
```

## 3. Pin the approved source

```sh
wicket program digest programs/repo-stats       # prints sha256:…
```

Put it in the manifest as `program.digest: sha256:…` (as in
`examples/program-repo-stats.pinned.yaml`). From then on a run refuses any other source, and the
digest is recorded in the run's `run.start` audit record.

Programs get identities too, and agents can `spawn` them (a long-running service, say) and reach
their ports through links.
