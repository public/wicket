---
area: Operations and audit
type: Removed
---
- `wicket reap` is gone: `wicket reconcile` does its job, here and on every enrolled node (boxes whose
  run has ended stop; a running run whose process is gone is re-attached or ended as `lost`). `wicket
  doctor` now counts the boxes a reconcile pass would stop
  ([#254](https://github.com/public/wicket/issues/254)).
