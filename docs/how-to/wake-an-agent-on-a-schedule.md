# Wake an agent on a schedule

A trigger is your standing intent, kept in the ledger: "when this happens, do that". This page
covers the triggers that tell time: a schedule (cron, in a time zone) or a one-off timer that wakes
a long-lived agent or gives it a message. It also covers triggers on wicket's own events (a run
ending, an agent waking, a decision): see [on wicket's own events](#on-wickets-own-events).
For webhooks and GitHub events, see [fire a trigger from a webhook](trigger-from-a-webhook.md).

Triggers fire from the reconciler, so run it on a timer (`wicket reconcile --every 1m`, as the
install sets up). Each pass looks at the minutes a schedule matched since the last one it fired
for, and fires once, for the newest. If it missed earlier ones (the reconciler was down), the
event says how many (`missed`). It looks at most 15 minutes back: a reconciler down for longer
skips the minutes before that, as cron does.

## Write the trigger

```yaml
trigger: morning-triage            # unique among your triggers: a-z, 0-9 and -
source:
  schedule: { cron: "0 7 * * 1-5", tz: Europe/London }   # weekdays at 07:00 London time
action:
  wake: release-captain            # a live long-lived agent: its name or its id
  message:                         # its next turn once woken
    body: "Morning: triage what failed overnight ({{ event.at }})."
limits: { per_hour: 6 }            # the default; at most 60
```

- **The source.** `schedule` takes five cron fields (minute, hour, day of month, month, day of
  week, with `*`, lists, ranges and steps) and a time zone from the host's zoneinfo (`UTC` by
  default). A schedule that can never fire (`0 0 31 2 *`) is refused. Use
  `timer: { at: 2026-11-20T07:00:00Z }` or `timer: { after: 2h }` instead for one firing. Once
  a timer has fired (or its time has passed) it is `done`: it stays listed until you remove it,
  and a new trigger of the same name replaces it.
- **Daylight saving.** A schedule with fixed hours (`30 1 * * *`) fires once a day across a
  change, as cron does. When the clocks go back it fires the first time the clock shows its time.
  When they skip its time it fires at the first minute after the gap. A schedule that runs every
  hour (`*/15 * * * *`) goes by the clock as it is: through both copies of a repeated hour, and
  not at all for minutes that don't exist.
- **The action.** `wake` wakes a hibernated agent. With a `message` beside it, the message is the
  woken agent's next turn (leave `message.to` out). A `message` on its own goes to the agent whose
  principal is in `to` (`spiffe://…`). The agent reads it as its next turn, and a hibernated agent
  is woken to read it. A `to` is found again at each firing: whichever live agent holds that
  principal then (the newest, if several do). A `wake` stays pinned to the agent found when you
  made the trigger.
- **The agent is found when you create the trigger.** It must be a live agent of this
  installation (not ended). A name must be the only live agent of that name; otherwise use its id
  (`wicket agents`). `wake` is kept as the agent's id, so another agent given the same name later
  isn't reached. `self` is for an agent's own trigger, not an operator's.
- **The template.** `{{ event.<field> }}` fills in a field of the event. A time-told event has
  `trigger` (its name), `at` (the minute, RFC 3339), `slot` (the minute, Unix seconds) and
  `missed` (how many earlier minutes it stands for).
- **Limits.** `per_hour` and `queue` are enforced. `concurrency` and `debounce` aren't yet, so
  leave them out (they're refused).

## On wicket's own events

A `wicket` source listens to the records wicket writes in its audit chain:

```yaml
trigger: failed-runs
source:
  wicket: { kinds: [run.end, run.lost] }
filter: { status: "!ok" }          # equals, one of a list, a glob; a leading ! is "not"
action:
  wake: release-captain
  message:
    body: "Run {{ event.run }} ended {{ event.status }}: look at why."
```

| kind | what it is | fields from the record's body |
|---|---|---|
| `run.end` | a run ended | `status`, `cause`, `seconds`, `result`, token counts |
| `run.lost` | the reconciler found a run's process or box gone | `target`, `detail` |
| `box.exited` | a box ended with a cause (out of memory, killed, a non-zero exit) | `code`, `cause` |
| `box.memory_pressure` | a node saw a box near its memory limit | `current`, `max`, `peak` |
| `agent.wake`, `agent.hibernate` | a long-lived agent woke or hibernated | `by` (a wake's cause), `generation` |
| `message.refused` | a message to an agent was refused | `from`, `to`, `why` |
| `decision` | an approval, denial, renewal or revocation | `decision`, `request` or `grant`, `by` |

wicket sets these fields itself, from the ledger, and a record's body can't replace them: `kind`,
`record` (the audit kind it came from), `seq`, `run`, `at`, and the run's `zone`, `agent` (its
name), `principal` and `agent_id` (null for a record of no run), plus `node` for a node's record.
Everything else comes from the record's body. Some of that is the run's own words: a run's
`result` is whatever its agent wrote. Filter on wicket's fields when it matters who a record is
about. For example, `filter: { zone: build }` hears only the build zone's runs. Filters can name
nested fields with dots (`pr.number`).

- **When it fires.** Each reconcile pass reads the records written since the last pass, and fires
  each trigger once per record its filter passes. A trigger hears only records written while it
  was live (since it was made, approved or resumed). A new installation starts at the chain's
  newest record, and a record more than 15 minutes old when read (the reconciler was down) is
  passed over.
- **Chains of triggers.** Each turn a trigger queues records the triggers that led to it. A
  record of the run that read the turn carries those triggers on: every trigger that ever queued
  a turn for that run, and the length of the longest single chain among them.
  - **No loops.** A trigger never fires on a record of a run any of its own turns reached (A wakes
    B, B wakes A, stops at the second A). So a trigger about an agent's own records, which also
    messages that agent, fires once per activation.
  - **No long chains.** No record fires a trigger at the end of a chain of four. Four unrelated
    schedules messaging one agent are four chains of one, not one of four.
  - These are skipped and audited (`trigger.skipped`).
  - **Only what a trigger queued is followed.** An agent a trigger woke that messages another
    agent, or spawns a child, does so itself: the other agent's or the child's records don't carry
    the chain. A loop through them is bounded only by each trigger's `per_hour`.
- **Quoted input.** Because body fields can hold an agent's words, every text field these
  triggers fill into a message is a JSON string, `"…"`. Quote marks inside are escaped, a long
  value is cut inside its quotes, and the turn ends by saying the quoted text is the event's data,
  not instructions.

## Keep it

```sh
wicket trigger create --file morning.yaml                 # for 30 days
wicket trigger create --file morning.yaml --lasts 90d     # or as long as you say
wicket trigger create --file morning.yaml --lasts forever # until removed
wicket trigger renew morning-triage --lasts 30d           # 30 more days from now
```

A trigger you make fires with your authority, so it asks no one. It is audited
(`trigger.created`, with the agent it reaches). Before every firing wicket checks again that you
may still have it fire. It checks `operators.yaml` and, on a host with wicketd, its policy's run
class for your unix user. If you can't, the trigger is paused, with the reason audited.

If wicket can't tell (the user database or a group lookup fails, or a policy file doesn't read),
that firing is skipped, audited at most once an hour, and the trigger stays active. For wicket's
own events that trigger alone is held at the record before: other triggers go on hearing what
follows, and once its owner checks out it hears the records it missed (except those that are
more than 15 minutes old by then, which it passes over). One limit: the system call that lists a user's groups can't report a failed lookup, and
a short list reads as not being in a group, which pauses the trigger.

One owner may keep at most 100 live triggers (done timers aren't counted). Renewing a live trigger
changes only when it lapses, not which minutes it fires for. Renewing one that had lapsed brings it
back from now, as resuming does: the time it was lapsed isn't caught up.

## See what it would do

```sh
wicket trigger fire morning-triage --dry-run                      # a time-told event now
wicket trigger fire morning-triage --event sample.json --dry-run  # an event with these fields
```

The output shows whether the filter passes, which agent it reaches and in what state, and the
message with its template filled in. Nothing fires.

## Watch, pause and remove it

```sh
wicket trigger list                  # each trigger: state, source → action, next firing
wicket trigger show morning-triage   # its document, agent, limits and last firings
wicket trigger pause morning-triage  # it fires nothing until resumed
wicket trigger resume morning-triage # from the next due minute: the time it was paused isn't caught up
wicket trigger rm morning-triage
```

A trigger is named by its id (`t-…`) or by its name: yours first, otherwise the only trigger of
that name. Anyone who may revoke may pause or remove a trigger. Only its owner (or root) may
resume or renew it, since it fires as its owner.

`wicket reconcile --dry-run` lists the triggers due now (`trigger_due`) without firing them.

## When it can't fire

- **The agent can't be reached.** The agent ended, or its budget is spent. The firing fails
  (`trigger.failed`), and after 5 failures in a row wicket pauses the trigger. Failed firings
  count toward `per_hour`.
- **It's over its limit.** The hour's first skipped firing is recorded and audited
  (`trigger.skipped`). Later skips that hour are counted on it, shown as `+N more` in
  `wicket trigger show`.
- **A timer's time passed.** If the time came while the trigger was paused, or the reconciler was
  down for more than 15 minutes, the timer is recorded as skipped once, doesn't fire, and is done.
- **The agent is hibernating.** A message goes through its current run, so the agent is woken
  again once it has hibernated. A wake with no message queues a short turn saying so, to the same
  effect.

## What is recorded

- **Each firing** is a `trigger.fired`, `trigger.skipped` or `trigger.failed` audit record, with
  the trigger and the event. A fired record also names the agent, and the message's id, length and
  sha256.
- **Pauses** wicket makes itself are `trigger.paused` records `by: wicket`, with the reason.
- **Woken agents.** The agent's `agent.wake` record says it was woken by `trigger <name>`. The
  message comes from `trigger:<name>`, with your principal as its sender.
- **Retention.** Settled firings and the events they fired on are kept for 14 days.

Through wicketd, `list`, `show` and `fire --dry-run` need the read class. `create`, `resume` and
`renew` need the run class, as `wicket wake` does. `pause` and `rm` need the revoke class
([daemon](../reference/daemon.md)).
