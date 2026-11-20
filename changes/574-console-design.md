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
- An agent's words are never shown as wicket's (#715 review). An update request's reason and commit,
  and a capacity request's reason and region, are the agent's claims, quoted and labelled as the
  agent's; "wicket says" is kept for text wicket wrote. The ledger keeps an update's claims apart
  (`request_claims`, schema 33, an expand step: older builds ignore it).
- A Stop form opened for one agent can't stop another: leaving the page or opening another agent
  closes it, a submit for another run is refused, and the question names the agent and its run.
- An agent's permissions show all that a grant reaches: a prefix grant "and every path under it", a
  standing grant's methods, paths and whether it allows requests that can't be undone. Who allowed it
  is named (an operator, a parent agent or a capacity grant), never "you"; so is who decided in Activity.
- An "Always allowed" rule that allows requests that can't be undone says so on its row.
