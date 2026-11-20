---
area: Updates
type: Changed
---
- `main` is built and signed a batch of merges at a time instead of on every push: a push builds
  when no build ran in the last 6 hours, a schedule builds `main`'s head every 6 hours if it isn't
  built yet, and a manual run builds it at once. `wicket self update --from-ci` and
  `wicket self follow` find builds made by the schedule or by hand as well as by a push
  ([update from CI-signed builds](docs/how-to/update-from-ci.md)).
