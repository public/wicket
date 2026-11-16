---
area: Boxes and the egress path
type: Changed
---
- At dial time the egress proxy also refuses a name that resolves to one of the node's own
  interface addresses, public or not, and to Azure's metadata address 168.63.129.16, which lies
  outside the special-purpose ranges ([#366](https://github.com/public/wicket/issues/366)).
