---
area: Updates
type: Changed
---
- An operator's approval of an agent's `request_update` is accepted as what it is, the operator's
  one-use `install` grant on the build's digest, through the one "may this digest run" check
  (#258). It is still used up by the update that accepts it, and an approval made before this
  build works unchanged ([#258](https://github.com/public/wicket/issues/258)).
