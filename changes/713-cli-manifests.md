---
area: Approvals and the console
type: Added
---
- The console's manifest editor is now on the host too
  ([#713](https://github.com/public/wicket/issues/713)). `wicket manifest list`, `show` and
  `check` print the console's views (`--json` for scripts). `save` and `restore` write the
  installation's `manifests` root as the console does: they keep the version they replace, and
  they audit `manifest.saved` with what the change widens (`--dry-run` only shows it).
  `wicket node release-fence` now decides as the console does: within the operator's
  `operators.yaml` authority, and only for a fence whose node is revoked or gone. Root's
  `--break-glass` releases any fence.
