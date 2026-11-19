---
area: Development
type: Added
---
- `Update.tla` is now checked against what really happened. `ci/tla-trail.py` turns the control
  host's audit records of an update (`wicket audit --tail`) into a scrubbed trail, and
  `UpdateTrace.tla` asks TLC whether the model has a behaviour that matches it.

  In CI, 2026-11-18's two installs are checked this way:
  - **The 18:48 install, where both runs survived:** a behaviour of the model as merged.
  - **The 17:58 install, which lost the local box (#529):** not a behaviour of the merged model,
    only of #529's fail variant.

  The 10:04 self update (#487) falls outside the audit export, so it has no trail
  ([#321](https://github.com/public/wicket/issues/321)).
