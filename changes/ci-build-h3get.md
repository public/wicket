---
area: Development
type: Fixed
---
- CI builds the HTTP/3 test client before the gVisor suites, so a pull request that selects only the
  acceptance suite no longer fails for lack of it ([#240](https://github.com/public/wicket/pull/240)).
