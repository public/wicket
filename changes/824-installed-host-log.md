---
area: Development
type: Fixed
---
- The acceptance job's "kept on the host" flood check is skipped, saying why, where the box's
  Docker log isn't on the test's own file system: the installed system runs in a container on the
  host's Docker ([#824](https://github.com/public/wicket/issues/824)). Before #826 it passed there on
  a 0 that measured nothing. Since #826 it failed. Elsewhere, a size of 0 now fails it.
