---
area: Boxes and the egress path
type: Changed
---
- docs/explanation/limits.md no longer says response bodies aren't scrubbed. Since
  [#381](https://github.com/public/wicket/pull/381), a credential wicket attached that comes back in a
  response is masked: raw, hex, or base64. The page now says which forms are masked and which
  aren't ([#574](https://github.com/public/wicket/issues/574)).
