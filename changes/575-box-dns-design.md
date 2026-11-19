---
area: Identity, spawn and links
type: Added
---
- [Names for boxes](../docs/explanation/box-dns.md) designs DNS names for boxes
  ([#575](https://github.com/public/wicket/issues/575)): internal names other boxes resolve through
  wicket's resolver, with links still deciding each connection, and public names in a real zone
  pointing at the box's node, which a human approves. wicket reconciles only the records it owns,
  through a provider chosen in `wicket.yaml`. Nothing is built yet.
