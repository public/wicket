---
area: Approvals and the console
type: Added
---
- An agent decides its descendants' requests within its own authority with the gateway's new
  `decide` tool (approve or deny, uses, ttl), and `pending_requests` lists the ones it could decide.
  It may approve only an HTTP request its own zone allows by reach at the request's risk (and the org
  policy doesn't refuse), for exactly the asked path, to the asking run only, for at most 100 uses
  and no longer than its own authority. Anything else is refused and stays pending for a human.
  Decisions are signed with the agent's identity and audited with the chain from the asking run
  ([#50](https://github.com/public/wicket/issues/50), [#256](https://github.com/public/wicket/issues/256)).
- A zone setting `escalation: { request, grant }`, both on by default: `request: false` makes
  anything outside the zone's reach "never allowed" instead of a pending request, `grant: false`
  takes away `decide`. A spawned zone can't be given a right its parent lacks.
- A blocked request from a run that doesn't escalate (a zone with `request: false`, or a program
  with `on_pending: fail`) now answers with the "Blocked by wicket sandbox: never allowed" status
  line, instead of "Outside this program's reach".
