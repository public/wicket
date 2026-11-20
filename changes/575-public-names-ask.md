---
area: Identity, spawn and links
type: Added
---
- A box can ask for a public name, a name on the internet, with `request_name` and `kind: public`
  ([#575](https://github.com/public/wicket/issues/575), step 4a).
  - Only a human decides it, with `wicket names approve` (or `deny`), since anyone could then
    connect to the box's port and read what it serves. The box waits on the ask (`n-…`) with
    `await_grant`.
  - Reserved labels and their lookalikes are refused, such as `console`, `c0nsole` and `www`.
  - `scope: standing` asks for every later run of the workload. Its approval is for the agent or its
    zone, for a lifetime, as with standing reach.
  - `wicket names list`, `show` and `revoke` manage names, internal ones included.
  - `operators.yaml` has a new kind, `name`, for an operator who may decide them.
  - wicket doesn't publish public DNS records yet: an approved name is a record only.
