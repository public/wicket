# Hibernate and wake an agent

A long-lived agent keeps its session between turns, sleeps when idle, and is woken by a follow-up or
a message. This page shows how; [agents](../reference/agents.md#hibernate-and-wake) has the rules
(what is bundled, generations, budgets, nodes).

## Make an agent long-lived

Give the agent an `idle_timeout` and a `hibernate_after` (no shorter than `idle_timeout`):

```yaml
agent:
  name: helper
  idle_timeout: 10m      # after a turn: wait this long for a follow-up, then pause the box
  hibernate_after: 1h    # from the end of the turn: hibernate it
zone:
  name: helper
  volumes:
    - { name: notes, path: /volumes/notes, persist: durable }   # bundled with the agent
  llm: {}
  limits: { timeout: 8h }   # total time in a box over the agent's whole life
```

Run it as usual. After its first turn, `wicket run` prints the agent's id:

```text
  agent agt_… (long-lived; session …): wicket hibernate run_… / wicket wake agt_…
```

## Watch it

```sh
wicket agents            # state, generation, current run and bundle size (--json for scripts)
```

An agent is Active during a turn, Idle (its box paused) after `idle_timeout`, and Hibernated (its box
stopped, its state bundled) after `hibernate_after`.

## Hibernate it now

```sh
wicket hibernate run_…            # or the agent's id; --wait SECONDS for the outcome (default 120)
```

It hibernates at its next quiet point: its turn has ended and nothing but the agent runs in its box.
A box still running something else (a background build, a dev server) stays Idle instead, since a
rebuild restores files, not processes.

## Wake it

Any of these rebuilds its box, restores its state and resumes its session:

```sh
wicket say agt_… "and now the tests"     # a follow-up; wakes it if it is hibernated
wicket wake agt_… ["text"]               # in the foreground, like wicket run
```

A message from another agent (`send_message`) wakes it too. The agent's first turn says it was woken,
and by what. On an installed host `wake.log` in `<data dir>/agents/<agent>/` has the log of a wake
started in the background.

## Keep its state safe

- Back up `<data dir>/state.key` with the data directory: without it no hibernated agent can be
  woken. Keep the copy as private as the key (mode 0600, never in the object store).
- To keep bundles off the host, set `bundles: s3` in the state store
  ([state off the host](state-off-host-and-restore.md)).

## When it won't wake

- An agent that has spent its model budget or its `limits.timeout` isn't woken again, by any source.
- Only a hibernated agent can be woken. One whose session ended otherwise (stopped, timed out
  mid-turn, over its `/tmp` cap) is `ended`.
- An agent whose box may still be running on a node this host can't hear from isn't woken until
  that box's authority has ended; `wicket wake` says from when it can be.

`ci/hibernate.sh` runs all of this end to end with the mock model; `ci/hibernate.sh --node` with the
agent on an enrolled node.
