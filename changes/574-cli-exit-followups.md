---
area: Operations and audit
type: Changed
---
- `wicket run` exits by how its run ended
  ([#574](https://github.com/public/wicket/issues/574)). Since the exit codes landed it exits 1
  when its box failed (a non-zero exit, out of memory, over a cap) or timed out; before, it exited 0
  whatever the box did. So `wicket self update --canary` and `wicket self health` now really switch
  back when the canary's box fails, as docs/explanation/updates.md always said. Now also:
  - an interrupted run exits 128 + the signal (130 for Ctrl-C, 143 for SIGTERM or its parent
    stopping it), and a revoked one exits 6;
  - an agent that runs out of turns (`agent.max_turns`) is a failed run, exit 1 (Claude Code exits
    non-zero then; its last line says `error_max_turns`);
  - `wicket wrap` exits with the wrapped program's own code when that isn't 0.
- Every duration flag (`--ttl`, `--wait`, `--every`, `--window`, `--interval`, `--lifetime`,
  `--ca-ttl`, `--cert-ttl`, `--give-up-silent`, a trigger's `--lasts`) is parsed with the command
  line, by one parser: a bad value is a usage error (2), not a failure (1), and a number alone is
  seconds.
- "No trigger" and a trigger's "no agent" exit 4 (not found).
- wicketd sends the exit code of a command it turns away in a field of its own (a new `REFUSE`
  frame, to a client that says it reads one), not as words at the start of the text, which the
  text could imitate. An older client gets the text as before.
