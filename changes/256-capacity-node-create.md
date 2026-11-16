---
area: Placement
type: Changed
---
- `wicket node create` no longer asks for the spend on the terminal. Its spend is a request from the
  operator who runs it, `CAPACITY wicket.internal /capacity/node/<name>`, with the plan, region, rate
  and worst case. It is decided by the same function as every approval. If one of that operator's
  live capacity grants covers it, it is approved at once and audited against the grant: the grant,
  the ask, and what the grant's nodes took before. Otherwise it is pending, in `wicket pending` and
  on the console (which sends a notification), for up to `--wait` (default `15m`), and denied if
  nobody decides by then. The money envelope (`--max-hourly`, `--max-total`) is still checked
  first.
