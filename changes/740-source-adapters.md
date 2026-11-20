---
area: Development
type: Changed
---
- Webhook trigger sources are adapters outside core
  ([#740](https://github.com/public/wicket/issues/740)). A new library crate, `wicket-sources`,
  holds a source-adapter trait, with the generic webhook and GitHub as its two adapters: how each
  verifies a delivery, its delivery id and event kind, what it never fires on, and its fields.
  `wicket_core::intake` keeps only what every source shares (HMAC, tokens, delivery ids, the caps on
  fields). `wicket node intake` and the control host go through the adapter. Deliveries are checked
  as before, in the same order.
