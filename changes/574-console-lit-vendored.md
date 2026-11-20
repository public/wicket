---
area: Development
type: Added
---
- lit-html's published browser modules are committed under the console's `static/vendor/lit-html/`
  (`ci/vendor-lit.sh` fetches them, checked against the registry's sha512), with a `VENDOR.toml`
  recording the version, licence and each file's sha256. `ci/vendor-check.py` (CI and preflight)
  fails on an edited, missing or unlisted file, and `ci/dep-age.py` holds a vendored version to the
  7-day cooldown, as it does lockfiles ([#574](https://github.com/public/wicket/issues/574)).
