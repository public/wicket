---
area: Principals
type: Changed
---
- A principal named in a zone's `accept_from` may also `connect` to that zone's exposed ports, as it
  may message its agents. Until now only `accept_from`'s zone entries were checked for links. Other
  agents in the principal's zone still need an operator
  ([#253](https://github.com/public/wicket/issues/253)).
