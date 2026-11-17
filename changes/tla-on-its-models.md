---
area: Development
type: Changed
---
- A pull request runs TLC on the TLA+ models only when the models or `ci/tla.sh` change, not on
  every change to a crate wicket-cli depends on: TLC reads only the models. Pushes to main and the
  nightly run still run it ([#321](https://github.com/public/wicket/issues/321)).
