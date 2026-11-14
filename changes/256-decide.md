---
area: Approvals and the console
type: Changed
---
- `wicket approve`, `wicket deny` and the console decide a request through one function, with one
  set of rules for what a grant may be: a lifetime above 0 and at most 24h, at least one use, and a prefix
  that covers the asked path (or, for a prefix ask, lies within it). The same decision makes the
  same grant and the same audit record from either; the console's record adds only the signed
  decision ([#256](https://github.com/public/wicket/issues/256)).
- The console now refuses a ttl over 24h, a ttl of 0 or 0 uses before asking for the passkey,
  instead of clamping them to 24h, 30s or 1 use. It no longer caps uses at 1000 (unlimited uses
  were always available), matching `wicket approve`.
