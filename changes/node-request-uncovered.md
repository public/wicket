---
area: Approvals and the console
type: Changed
---
- A box on a node no longer asks for an https host the node can't serve: one outside the node CA's
  name constraints, which the box's zone doesn't allow wholesale. Such a host is refused at the
  node whatever is approved, so `request_access` answers "not requested" with the reason. It also
  names what an operator can do: `wicket node renew-ca <node> --hosts <host>`. Before, the request
  went to a human, and the approval couldn't be used. Plain http, and hosts the zone allows
  wholesale (which the node passes through without its CA), are asked for as before.
