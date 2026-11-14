---
area: Approvals
type: Changed
---
- One approval per git push: a push's ref discovery and its upload are one request naming the
  repository, and one approval covers both, with git's retries, for 5 minutes. An agent asking ahead
  with `request_access` asks for that same request, and `wicket approve` shows the terms the grant
  was made with. Which refs a push may update is left to the forge (a scoped token, branch rules);
  wicket doesn't read the push ([#26](https://github.com/public/wicket/issues/26)).
