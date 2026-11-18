---
area: Boxes and the egress path
type: Security
---
- The model proxy reaches its zone's model route only at public addresses, as the egress proxy
  does: wicket resolves the route's host itself and refuses a name that resolves to a private,
  loopback or otherwise non-public address, and a connection that doesn't come up in 15 seconds
  fails. A route the zone names by address (`http://127.0.0.1:…`, a local model) is dialled as
  named.
