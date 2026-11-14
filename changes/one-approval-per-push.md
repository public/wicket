---
area: Approvals
type: Added
---
- One approval per git push: a push's ref discovery and its upload are one request naming the
  repository (and the refs, where the upload names them). One approval covers both, with git's
  retries, for 5 minutes, and an agent asking ahead with `request_access` asks for that same request.
  Refs protected by a forbid rule on their ref path (`{repo}/git-receive-pack/{ref}`), GitHub's
  read-only `refs/pull/…`, and pushes whose commands can't be read are refused before anything is
  asked. Decided on the node from the box's token like any request
  ([#26](https://github.com/public/wicket/issues/26)).
