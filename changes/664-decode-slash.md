---
area: Boxes and the egress path
type: Changed
---
- Core no longer decodes npm's scoped-package path on its own
  ([#664](https://github.com/public/wicket/issues/664)). A reach rule's `decode_slash` (segment
  numbers, from 1) has wicket decide one encoded slash (`%2F`, `%2f`) in each named segment as
  `/` for that host, and every rule and forbid of the zone reads the decoded path.
  - #143's guarantees stay: the decoded path must still be canonical, and the request goes
    upstream as written.
  - Anywhere else an encoded slash is refused.
  - A spawned or linked zone may use it only where its parent's rule does, and standing reach
    never carries it.
  - The npm-cache example sets `decode_slash: [1]` on `registry.npmjs.org`. **A zone that fetches
    scoped npm packages needs the same**, or `/@scope%2fname` is refused.
