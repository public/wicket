# Wake an agent on a schedule

A trigger is your standing intent, kept in the ledger: "when this happens, do that". This page
covers the triggers that tell time: a schedule (cron, in a time zone) or a one-off timer that wakes
a long-lived agent or gives it a message. Webhooks, GitHub events and wicket's own events come in
later steps of [#578](https://github.com/public/wicket/issues/578).

Triggers fire from the reconciler, so run it on a timer (`wicket reconcile --every 1m`, as the
install sets up). A pass fires each minute a schedule matched since the last pass, up to 15
minutes back. A reconciler down for longer skips the minutes it missed, as cron does.

## Write the trigger

```yaml
trigger: morning-triage            # unique among your triggers: a-z, 0-9 and -
source:
  schedule: { cron: "0 7 * * 1-5", tz: Europe/London }   # weekdays at 07:00 London time
action:
  wake: release-captain            # a long-lived agent: its name, its id, or its principal
  message:
    to: release-captain
    body: "Morning: triage what failed overnight ({{ event.at }})."
limits: { per_hour: 6 }            # the default; at most 60
```

- **The source.** `schedule` takes five cron fields (minute, hour, day of month, month, day of
  week, with `*`, lists, ranges and steps) and a time zone from the host's zoneinfo (`UTC` by
  default). Use `timer: { at: 2026-11-20T07:00:00Z }` or `timer: { after: 2h }` instead for one
  firing.
- **The action.** `wake` wakes a hibernated agent. `message` queues a turn for an agent: the agent
  reads it as its next turn, and a hibernated agent is woken to read it. Use either or both. An
  agent named by its name must be the only one of that name; otherwise name it by its principal.
- **The template.** `{{ event.<field> }}` fills in a field of the event. A time-told event has
  `trigger` (its name), `at` (the minute, RFC 3339) and `slot` (the minute, Unix seconds).

## Keep it

```sh
wicket trigger create --file morning.yaml              # yours until removed
wicket trigger create --file morning.yaml --lasts 30d  # or until then
```

A trigger you make fires with your authority, so it asks no one. It is audited
(`trigger.created`).

## See what it would do

```sh
wicket trigger fire t-… --dry-run                      # a time-told event now
wicket trigger fire t-… --event sample.json --dry-run  # an event with these fields
```

The output shows whether the filter passes, which agent it reaches and in what state, and the
message with its template filled in. Nothing fires.

## Watch, pause and remove it

```sh
wicket trigger list          # each trigger: state, source → action, next firing
wicket trigger show t-…      # its document, limits and last firings, with what each did
wicket trigger pause t-…     # it fires nothing until resumed
wicket trigger resume t-…    # from its next due minute: the minutes it was paused are not caught up
wicket trigger rm t-…
```

`wicket reconcile --dry-run` lists the triggers due now (`trigger_due`) without firing them.

## What is recorded

Each firing is a `trigger.fired`, `trigger.skipped` (its hourly limit was reached) or
`trigger.failed` audit record (no such agent, or it can't be woken), with the trigger and the
event. A woken agent's `agent.wake` record says it was woken by `trigger <name>`, and the message
comes from `trigger:<name>`, with your principal as its sender.

Through wicketd, `list`, `show` and `fire --dry-run` need the read class, `create` and `resume`
the run class (as `wicket wake` does), and `pause` and `rm` the revoke class
([daemon](../reference/daemon.md)).
