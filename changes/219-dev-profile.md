---
area: Development
type: Changed
---
- Development and test builds keep line tables for wicket's own crates and no debug info for
  dependencies: faster links and less memory. With incremental builds and `-j3`, the edit, build and
  test loop after a one-line change takes about half as long on the development host
  ([#219](https://github.com/public/wicket/issues/219)).
