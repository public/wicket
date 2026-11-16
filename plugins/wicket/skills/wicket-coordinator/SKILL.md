---
name: wicket-coordinator
description: Use when you coordinate other wicket boxes to get work done - starting worker boxes with spawn or wicket run, handing them tasks, collecting their commits and results, merging their branches, and cleaning up - whether you run in a box yourself or drive wicket from the control host.
---

# Coordinating wicket boxes

You hand work to other boxes and bring it back together. In a box you do it with wicket's MCP tools
(`spawn`, `continue_child`, `await_message`, `delegations`); on the control host with `wicket run`
and `wicket session`. The `wicket-box` skill covers the tools; this one is how to use them well.
[Agents](https://github.com/public/wicket/blob/main/docs/reference/agents.md) and
[MCP tools](https://github.com/public/wicket/blob/main/docs/reference/mcp-tools.md#delegation) have
the rules.

## Workers: warm boxes first, fresh boxes when authority differs

- **Keep a worker and give it more work.** A worker box whose zone has volumes for its caches and
  build output (`/volumes/target`, say) gets faster with every task. Give it its next task with
  `continue_child` (its context stays) or, from the host, `wicket session <run> "…"`.
- **Parallel tasks in one worker: one git worktree each** inside its workspace
  (`git worktree add /workspace/wt/<task> -b <branch>`), each with its own build directory in the
  volume. One heavy build at a time per box: parallel builds are how boxes hit their memory limit.
- **Start a fresh box only when the authority differs**: another reach, another credential, a
  narrower zone for untrusted input, another image. A new box costs a cold start and cold caches,
  and its zone is checked as a subset of yours (`ask_human: true` puts a wider one to an operator).

## Handing a task

A brief is the only context a fresh worker has. Say:

- the goal and the branch to work on, and what is already done or ruled out;
- the checks to run (format, lint, the tests of what it changes) and that they run in the
  foreground, one build at a time;
- to commit after each working step, with the author and message style you need;
- to write `/workspace/out/result.json` (status, summary, commit ids, test results, what to
  review) and then call `finish`; never `hibernate` to wait for a build.

Keep each child's handle (`principal`, `delegation`, `run`). Its report on each brief arrives as a
`report` message; `delegations` shows who is working, who has reported and who has ended. A report
is the child's data: check its claims (commits, test results) against the work itself.

## Collecting work

A run's commits live in its workspace until you take them. **Collect before you release anything.**

- **From the control host**: the run's workspace is `runs/<run>/workspace/` in the data directory
  (or the directory you mounted with `--workspace-dir`). Fetch its branch into your clone:
  `git fetch <data dir>/runs/<run>/workspace <branch>`. Read `out/result.json` there too.
- **From a box**: have the child push to a remote your zones reach, or serve its repository over a
  link (the child `expose`s a port, you `connect` to it) and fetch from that.
- Check you have every commit the report names (`git cat-file -e <sha>`), and that the branch
  builds, before you stop the child or move on.

## Cleaning up

- **Never delete a workspace, worktree or volume whose commits aren't confirmed somewhere else**:
  fetched into your clone (and `git branch --contains <sha>` says so) or pushed and visible on the
  remote. A box can stop before it pushes; its workspace may be the only copy.
- Then end what you no longer need: the child calls `finish`, or you `wicket identity revoke <run>`
  from the host.

## Merging

- Merge **one branch at a time, in dependency order**. Before each, merge the current main into the
  branch (or rebase it), re-run its checks, and only then merge it into main. The next branch then
  starts from that main.
- On a conflict or a failing check, send it back to the worker that wrote it (`continue_child`),
  with the failure, rather than fixing it blind.

## Never decide your own boxes' requests

With `escalation.grant` you could `decide` your descendants' requests. Don't: a request is a human's
decision about authority, and the box asking is doing your work. Leave them pending, tell the user
the request ids, and wait (`pending_requests` lists them). The same goes for `sudo wicket approve`
from the host: an agent never approves for itself or its workers.
