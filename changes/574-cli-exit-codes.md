---
area: Operations and audit
type: Changed
---
- `wicket` exits with one code per kind of outcome, the same for every command and through the
  daemon, as part of the CLI polish pass ([#574](https://github.com/public/wicket/issues/574)): 0
  done, 1 failed, 2 a usage error, 3 refused, 4 not found, 5 it needs an approval nobody has given
  yet, 75 try again (wicketd is moving to a new build and took no command). Before, everything but
  clap's usage errors exited 1. `wicket run` and `wicket wrap` exit 1 when the box failed or timed
  out (they exited 0 whatever the box did). docs/reference/cli.md lists them with
  examples. `wicket wake` (internal) exits 3, not 2, when the agent is already being woken.
