---
area: Boxes and the egress path
type: Changed
---
- Core no longer decodes npm's scoped-package path on its own
  ([#664](https://github.com/public/wicket/issues/664)). A reach rule's `decode_slash` (segment
  numbers, from 1, as the path is written) has wicket decide one encoded slash (`%2F`, `%2f`) in
  each named segment as `/` for that rule's host, which must be named exactly. Every rule and
  forbid of the zone reads the decoded path.
  - #143's guarantees stay: the decoded path must still be canonical, and the request goes
    upstream as written.
  - **Enforcement:** the box's token carries the option, and a node decodes only the segments
    every link of the token allows. Anywhere else an encoded slash is refused.
  - **Widening:** a spawned or linked zone may use it only where its parent's rule for the host
    does. Standing reach never carries it, and a reach rule must name methods and paths.
  - **Protocol 19:** a zone using it runs only on nodes at protocol 19 or later.
  - The npm-cache example sets `decode_slash: [1]` on `registry.npmjs.org`. **A zone that fetches
    scoped npm packages needs the same**, or `/@scope%2fname` is refused.
