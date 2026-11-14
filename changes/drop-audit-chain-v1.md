---
area: Operations and audit
type: Removed
---
- The audit chain accepts only v2 hashes (every stored field). Ledgers and node logs from
  development builds before #120, hashed over `prev`, `kind` and `body` only, no longer verify, and
  `wicket audit --verify` no longer counts v1 records ([#254](https://github.com/public/wicket/issues/254)).
