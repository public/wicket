---
area: Approvals and the console
type: Added
---
- **Standing reach** ([#572](https://github.com/public/wicket/issues/572)): an agent whose work
  needs the same reach again and again (CI logs every hour, say) can ask once for a reach rule that
  lasts, instead of a one-off request each time. It calls `request_access` with `scope: "standing"`,
  with the host from its `url`, `methods` (default GET) and `paths` (globs; default the URL's
  directory and everything under it).
  - **An operator decides it once:** `wicket standing show`, then `wicket standing approve` (or
    `deny`). The operator sees:
    - the rule;
    - the ledger's evidence: the requests the agent's runs raised that the rule covers, over the
      last 14 days;
    - what the rule would allow beyond them.

    The operator may `--narrow` it to the evidence, and approves it for the agent (each later run
    of it) or `--for zone` (every agent of its zone), for 30 days by default (`--lasts`), or
    `forever` (until revoked). `wicket standing list`, `renew` and `revoke` manage approved rules.
    Only a human approves standing reach.
  - **An agent that asks for the same method on a host a third time in a week** is told, with its
    answer, that standing reach would save it asking again.
  - **Needs protocol 16:** the control host and the box's node must both be on this release. A
    node on the previous one is refused standing asks and asks as before.
