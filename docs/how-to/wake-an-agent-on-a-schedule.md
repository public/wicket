# Wake an agent on a schedule

A trigger is your standing intent, kept in the ledger: "when this happens, do that". This page
covers the triggers that tell time: a schedule (cron, in a time zone) or a one-off timer that wakes
a long-lived agent or gives it a message. Webhooks, GitHub events and wicket's own events come in
later steps of [#578](https://github.com/public/wicket/issues/578); this version refuses them.

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
  `timer: { at: 2026-11-20T07:00:00Z }` or `timer: { after: 2h }` instead for one firing.
- **The action.** `wake` wakes a hibernated agent. With a `message` beside it, the message is the
  woken agent's next turn (leave `message.to` out). A `message` on its own goes to the agent whose
  principal is in `to` (`spiffe://…`). The agent reads it as its next turn, and a hibernated agent
  is woken to read it.
- **The agent is found when you create the trigger.** It must be a live agent of this
  installation (not ended). A name must be the only live agent of that name; otherwise use its id
  (`wicket agents`). `wake` is kept as the agent's id, so another agent given the same name later
  isn't reached. `self` is for an agent's own trigger, not an operator's.
- **The template.** `{{ event.<field> }}` fills in a field of the event. A time-told event has
  `trigger` (its name), `at` (the minute, RFC 3339), `slot` (the minute, Unix seconds) and
  `missed` (how many earlier minutes it stands for).
- **Limits.** `per_hour` and `queue` are enforced. `concurrency` and `debounce` aren't yet, so
  leave them out (they're refused).

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
class for your unix user. If you can't, the trigger is paused, with the reason audited. One owner
may keep at most 100 triggers.

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
  down for more than 15 minutes, the timer is recorded as skipped once, and doesn't fire.
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
