---
area: Operations and audit
type: Added
---
- Kani now checks two more decisions in `wicket-core`
  ([#325](https://github.com/public/wicket/issues/325)):
  - **Which hosts the egress proxy splices (`splice::patterns_overlap`):** if any host matches
    two patterns, they overlap, so a host a forbid rule could name is always inspected. It now
    works on bytes, without allocating.
  - **Image pins (`image::matching`'s rule for an allowed entry):** a pin is never allowed by a
    tag entry. A pinned image is allowed only by its own digest. Named images never match across
    repositories.

  The `accept_from` harnesses now hold their names by value and finish faster.
