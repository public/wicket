# Changelog fragments

Don't edit CHANGELOG.md in a pull request: add a fragment here instead, so parallel PRs don't
conflict (#220). Name it after the PR (`changes/220.md`), or a short slug before the PR has a number
(`changes/changelog-fragments.md`).

```markdown
---
area: Updates
type: Added
---
- `wicket self update` takes a protocol jump when every node moves with it
  ([#207](https://github.com/public/wicket/issues/207)).
```

- **area**: the CHANGELOG heading it goes under (an existing one such as Updates, Images, DNS,
  Console, Nodes, or a new one).
- **type**: Added, Changed, Fixed, Security or Removed. Fixed, Security and Removed entries are
  marked as such.
- **entries**: one or more `- ` lines in the changelog's style (what a user notices, and the issue
  or PR it comes from), continued with indented lines.

CI (`ci/changelog.py check`) checks every fragment, and that a PR changing more than docs, CI or
notes adds one; a PR nobody using wicket would notice gets the `no changelog` label instead.
`ci/changelog.py preview` shows the unreleased section as fragments would make it, and
`ci/changelog.py assemble --version X.Y.Z` writes them into CHANGELOG.md at release time and
removes them.
