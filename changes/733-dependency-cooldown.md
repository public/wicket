---
area: Build and CI
type: Security
---
- No dependency version younger than 7 days enters wicket's build: CI's `ci/dep-age.py` fails a
  change that adds a crates.io or npm version published less than 7 days ago, `.cargo/config.toml`
  and the session view's `.npmrc` make Cargo 1.100+ and npm 11.10+ skip such versions when they
  resolve, and Renovate waits as long before it proposes one. The only exception is a fix for an
  actively exploited vulnerability, recorded with its advisory in `ci/dep-age-exceptions.toml`
  (design §2, principle 21; [#733](https://github.com/public/wicket/pull/733)).
