---
area: Console
type: Changed
---
- The console is organised around what an operator is there to do, in plain words
  ([design](../docs/explanation/console-design.md)).
  - **Inbox** opens with how things are ("6 agents working · 10 requests waiting for you · 2
    problems"), then what needs you, then what is wrong. A request reads as Who, Wants to, Where, Why
    and its risk said as what could happen ("Only reads", "Others will see it, or it can't be
    undone"), with Allow once, Allow for 1 hour and Don't allow. An agent's ask to be always allowed
    something is a card of the same kind, with what it did so far.
  - **Agents** lists agents as working, waiting for you, finished, failed or asleep. Each has a
    page: what it may reach, where it runs, what it did, its sessions, and **Stop agent…**.
  - **Activity** says what happened in sentences, filtered by Blocked, Decisions, Agents or Servers,
    with **why?** on a request opening its explanation in place.
  - **Settings** holds always-allowed rules, spending limits, servers and the record backup, rented
    servers, API keys and passwords, task setups, organisation rules, notifications and passkeys.

  On a phone the views are a bar at the bottom of the screen. wicket's own terms (risk classes,
  standing reach, capacity grants, ids) stay under each item's Details.
